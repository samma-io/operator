"""What happens to a message: validate, check the target, accumulate, and
turn a finished run into a ScanReport write.

The Pipeline is synchronous and takes its collaborators as arguments
(the report store, the Scanner index, the metrics), so bridge/tests can
run it end to end with fakes. bridge.py calls it from the NATS handler
and a ticker task.
"""

import logging
import time

from . import messages, reports
from .accumulator import Accumulator

DROP_UNKNOWN_TARGET = "unknown-target"
DROP_SCANNERS_UNAVAILABLE = "scanners-unavailable"
DROP_ORPHAN_RUN = "orphan-run"


class Pipeline(object):
    def __init__(self, namespace, store, index, metrics, accumulator=None, clock=None, logger=None):
        self.namespace = namespace
        self.store = store
        self.index = index
        self.metrics = metrics
        self.accumulator = accumulator or Accumulator()
        self.clock = clock or time.monotonic
        self.log = logger or logging.getLogger("samma.bridge")

    # --- in -------------------------------------------------------------------

    def parse(self, payload):
        """messages.parse with the counters. Returns the message or None."""
        try:
            message = messages.parse(payload)
        except messages.Rejected as exc:
            self.metrics.rejected.inc(exc.reason)
            self.log.warning("Rejected message (%s): %s", exc.reason, exc.detail)
            return None
        self.metrics.received.inc(message.kind)
        return message

    def accept(self, message):
        """Validate a v2 message against the current Scanners and feed the
        accumulator. Returns the runs that are now ready to be written."""
        if message.kind == messages.KIND_LEGACY:
            return []
        if not self.index.loaded and not self.index.refresh():
            self.metrics.dropped.inc(DROP_SCANNERS_UNAVAILABLE)
            self.log.warning("Dropped %s for %s: the Scanner list is not available yet", message.kind, message.target)
            return []
        if not self.index.is_target(message.target):
            self.metrics.dropped.inc(DROP_UNKNOWN_TARGET)
            self.log.warning("Dropped %s from %s: %s is not the target of any Scanner in %s", message.kind, message.scanner, message.target, self.namespace)
            return []
        finished = self.accumulator.add(message, self.clock())
        self.metrics.runs_pending.set(len(self.accumulator))
        return finished

    def handle(self, payload):
        """parse + accept in one call for the NATS handler."""
        message = self.parse(payload)
        if message is None:
            return None, []
        return message, self.accept(message)

    def tick(self):
        """Finalise runs whose straggler wait is over and drop runs that
        never got a run message. Returns the runs to write."""
        now = self.clock()
        finished = self.accumulator.due(now)
        for key, received in self.accumulator.expire(now):
            self.metrics.dropped.inc(DROP_ORPHAN_RUN)
            self.log.warning("Dropped %d findings of run %s: no run message arrived", received, key)
        self.metrics.runs_pending.set(len(self.accumulator))
        return finished

    # --- out ------------------------------------------------------------------

    def write(self, finalized):
        """Write one finished run as a ScanReport. Never raises: a failed
        write is counted and logged, and the next run tries again."""
        run = finalized.run
        started = self.clock()
        try:
            outcome = self._write(finalized)
        except Exception as exc:
            self.metrics.report_errors.inc()
            self.log.error("Could not write ScanReport for %s %s run %s: %s", run.scanner, run.target, run.run_id, exc)
            return None
        self.metrics.reports_written.inc(outcome)
        if finalized.run_received_at is not None:
            self.metrics.finalize_seconds.observe(max(0.0, self.clock() - finalized.run_received_at))
        return outcome

    def _write(self, finalized):
        run = finalized.run
        _, samma_io_id = self.index.for_run(run.scanner, run.target, run.samma_io_id)
        owners = self.index.owners(run.scanner, run.target, run.samma_io_id)
        extra_labels = self.index.extra_labels(run.scanner, run.target, run.samma_io_id)
        body = reports.report_body(run.scanner, run.template, run.target, self.namespace, owners=owners, extra_labels=extra_labels, tier=run.tier, samma_io_id=samma_io_id)
        name = body["metadata"]["name"]
        if run.outcome == messages.OUTCOME_SUCCEEDED and not finalized.complete:
            # Fewer findings than the scanner sent: an incomplete picture
            # must not replace the previous findings (that would resolve
            # findings that are still there), so it is recorded as failed.
            self.metrics.runs_incomplete.inc()
            run = run.with_outcome(
                messages.OUTCOME_FAILED,
                "bridge received {0} of {1} findings".format(finalized.received, finalized.expected),
            )
        if run.outcome == messages.OUTCOME_SUCCEEDED:
            entries = reports.sort_findings(reports.dedupe([finding.report_entry() for finding in finalized.findings]))
            entries, notes = reports.cap_findings(entries)
            for reason, count in (("over-limit", notes["over_limit"]), ("info-size", notes["info_dropped"]), ("tail-size", notes["tail_dropped"])):
                if count:
                    self.metrics.findings_dropped.inc(reason, amount=count)
                    self.log.warning("ScanReport %s: %d findings left out (%s)", name, count, reason)
            action = reports.upsert(self.store, body, lambda current: reports.succeeded_status(current, run, entries))
            self.log.info("ScanReport %s %s: %d findings from %s run %s", name, action, len(entries), run.scanner, run.run_id)
        else:
            action = reports.upsert(self.store, body, lambda current: reports.failed_status(current, run))
            self.log.info("ScanReport %s %s: run %s %s (%s); findings kept", name, action, run.run_id, run.outcome, run.message or "no message")
        return run.outcome
