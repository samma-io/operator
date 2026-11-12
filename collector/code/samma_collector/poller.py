"""One poll: local Ingress hosts -> matching samma.io targets -> their latest
results -> gauges and finding log lines.

Plain Python: the Ingress listing, the samma.io client, the log writer and
the clock are passed in, so the tests run without a cluster or a network.

A poll is all or nothing for the gauges: any failure leaves the previous
values in place and counts the poll as failed, so a dashboard outage does
not drop every series to zero.
"""

import logging
import time
from datetime import datetime

from .dashboard import RESULT_LIMIT, DashboardError, NotFound
from .kube import KubeError

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
# A finding without a recognised severity (legacy nmap/nikto rows).
UNKNOWN = "UNKNOWN"

# Fields of a finding that go to the log. evidence, remediation and the raw
# record are left out on purpose: evidence can carry what a scanner saw,
# credentials included, and the log leaves the cluster with the rest.
LOGGED_FIELDS = ("checkId", "severity", "title", "host", "port", "endpoint", "cveIds", "time")

log = logging.getLogger("samma.collector")


def parse_time(value):
    """RFC 3339 (as the API writes it) to Unix seconds, or None."""
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def run_time(run):
    return parse_time(run.get("finishedAt")) or parse_time(run.get("lastSeenAt")) or 0.0


def run_key(run):
    """What identifies a run: its runId, or for legacy scanners without one
    the time of their newest row."""
    return run.get("runId") or run.get("lastSeenAt") or ""


def severity_counts(run):
    counts = {severity: 0 for severity in SEVERITIES}
    for name, count in (run.get("severity") or {}).items():
        key = str(name).upper()
        if key not in counts:
            key = UNKNOWN
        try:
            counts[key] = counts.get(key, 0) + int(count)
        except (TypeError, ValueError):
            continue
    return counts


class Poller(object):
    def __init__(self, dashboard, hosts, metrics, emit, clock=time.time, log_findings=True):
        """``hosts()`` returns the set of local hosts (may raise KubeError);
        ``emit(record)`` writes one finding log line."""
        self.dashboard = dashboard
        self.hosts = hosts
        self.metrics = metrics
        self.emit = emit
        self.clock = clock
        self.log_findings = log_findings
        # (target, scanner) -> run_key of the run whose findings were logged.
        self.logged_runs = {}

    def poll(self):
        """One poll. Returns True on success."""
        started = self.clock()
        try:
            snapshot = self._collect()
        except KubeError as exc:
            log.error("%s", exc)
            self.metrics.polls.inc("kube")
            return False
        except DashboardError as exc:
            log.error("samma.io: %s", exc)
            self.metrics.polls.inc(exc.kind)
            return False
        self._publish(snapshot)
        if self.log_findings:
            self._log_new_runs(snapshot)
        self.metrics.polls.inc("ok")
        now = self.clock()
        self.metrics.last_success.set(now)
        self.metrics.poll_seconds.observe(max(0.0, now - started))
        return True

    def _collect(self):
        hosts = set(self.hosts())
        matched = {}
        for target in self.dashboard.targets():
            value = str(target.get("value") or "").strip().lower().rstrip(".")
            if value in hosts:
                matched.setdefault(value, []).append(target)

        snapshot = {"hosts": hosts, "targets": {}}
        for value, targets in sorted(matched.items()):
            entry = {"targets": [], "runs": {}, "results": []}
            for target in targets:
                try:
                    body = self.dashboard.results(target["id"])
                except NotFound:
                    continue  # deleted between the listing and now
                entry["targets"].append(target)
                results = body.get("results") or []
                if len(results) >= RESULT_LIMIT:
                    self.metrics.truncated.inc()
                    log.warning("%s: %d results, the API limit; findings beyond it are not logged", value, len(results))
                entry["results"].extend(results)
                # The same host can be a target in more than one profile:
                # per scanner, the newest run wins.
                for run in body.get("runs") or []:
                    scanner = run.get("scanner")
                    if not scanner:
                        continue
                    current = entry["runs"].get(scanner)
                    if current is None or run_time(run) > run_time(current):
                        entry["runs"][scanner] = run
            if entry["targets"]:
                snapshot["targets"][value] = entry
        return snapshot

    def _publish(self, snapshot):
        findings, finished, outcome, info = {}, {}, {}, {}
        for value, entry in snapshot["targets"].items():
            for target in entry["targets"]:
                labels = (value, target.get("id", ""), target.get("scannerStatus") or "", target.get("reachabilityStatus") or "")
                info[labels] = 1
            for scanner, run in entry["runs"].items():
                for severity, count in severity_counts(run).items():
                    findings[(value, scanner, severity)] = count
                finished[(value, scanner)] = run_time(run)
                outcome[(value, scanner, run.get("outcome") or "unknown")] = 1
        self.metrics.findings.replace(findings)
        self.metrics.last_finished.replace(finished)
        self.metrics.outcome.replace(outcome)
        self.metrics.target_info.replace(info)
        self.metrics.targets.set(len(snapshot["targets"]))
        self.metrics.unmatched.set(len(snapshot["hosts"] - set(snapshot["targets"])))

    def _log_new_runs(self, snapshot):
        seen = {}
        for value, entry in snapshot["targets"].items():
            for scanner, run in entry["runs"].items():
                key = run_key(run)
                seen[(value, scanner)] = key
                if self.logged_runs.get((value, scanner)) == key:
                    continue
                run_id = run.get("runId")
                for finding in entry["results"]:
                    if finding.get("scanner") != scanner:
                        continue
                    if run_id and finding.get("runId") != run_id:
                        continue
                    self.emit(self._record(value, scanner, run, finding))
                    self.metrics.findings_logged.inc()
        # Forget targets and scanners that are gone, so a comeback logs again.
        self.logged_runs = seen

    @staticmethod
    def _record(value, scanner, run, finding):
        record = {
            "event": "samma.finding",
            "target": value,
            "targetId": finding.get("targetId"),
            "scanner": scanner,
            "runId": run.get("runId"),
            "outcome": run.get("outcome"),
        }
        for field in LOGGED_FIELDS:
            if finding.get(field) not in (None, "", []):
                record[field] = finding[field]
        if "severity" in record:
            record["severity"] = str(record["severity"]).upper()
        return record
