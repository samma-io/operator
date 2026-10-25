"""The whole path from a NATS payload to a ScanReport, with fakes."""

import json
import unittest

from .helpers import LEGACY, RUN_ID, TARGET, Clock, FakeStore, finding, run, scanner_object  # noqa: F401
from samma_bridge import reports
from samma_bridge.accumulator import Accumulator
from samma_bridge.metrics import BridgeMetrics
from samma_bridge.pipeline import Pipeline
from samma_bridge.scanners import ScannerIndex

REPORT = reports.report_name("tls-scanner", None, TARGET)


def payload(data):
    return json.dumps(data).encode("utf-8")


class PipelineHarness(object):
    def __init__(self, scanners=None, clock=None):
        self.clock = clock or Clock()
        self.store = FakeStore(scanners=scanners if scanners is not None else [scanner_object(uid="u1", labels={reports.LABEL_INGRESS_NAMESPACE: "shop", reports.LABEL_INGRESS_NAME: "api"})])
        self.index = ScannerIndex(self.store.list_scanners, ttl_seconds=30, clock=self.clock)
        self.metrics = BridgeMetrics()
        self.pipeline = Pipeline("samma-io", self.store, self.index, self.metrics, accumulator=Accumulator(30, 3600, clock=self.clock), clock=self.clock)

    def feed(self, *datas):
        """Handle messages and write every finished run; returns outcomes."""
        outcomes = []
        for data in datas:
            _, finished = self.pipeline.handle(payload(data))
            for item in finished:
                outcomes.append(self.pipeline.write(item))
        return outcomes

    def tick(self):
        return [self.pipeline.write(item) for item in self.pipeline.tick()]

    @property
    def report(self):
        return self.store.objects.get(REPORT)


class SucceededRunTests(unittest.TestCase):
    def test_report_is_created_with_findings_summary_and_owners(self):
        h = PipelineHarness()
        outcomes = h.feed(finding(), finding(checkId="SAMMA-TLS-CERT-EXPIRING", severity="MEDIUM"), run(findingCount=2))
        self.assertEqual(outcomes, ["succeeded"])
        report = h.report
        self.assertIsNotNone(report)
        self.assertEqual(report["spec"], {"target": TARGET, "scanner": "tls-scanner"})
        self.assertEqual(report["metadata"]["labels"][reports.LABEL_INGRESS_NAMESPACE], "shop")
        self.assertEqual(report["metadata"]["annotations"][reports.ANNOTATION_TARGET], TARGET)
        self.assertEqual([o["uid"] for o in report["metadata"]["ownerReferences"]], ["u1"])
        status = report["status"]
        self.assertEqual([f["checkId"] for f in status["findings"]], ["SAMMA-TLS-PROTOCOL-DEPRECATED", "SAMMA-TLS-CERT-EXPIRING"])
        self.assertNotIn("raw", status["findings"][0])
        self.assertEqual(status["summary"], {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0})
        self.assertEqual(status["lastRun"]["outcome"], "succeeded")
        self.assertEqual(status["lastRun"]["runId"], RUN_ID)
        self.assertEqual(status["lastSuccessAt"], "2026-10-15T02:00:21Z")
        self.assertEqual(status["scannerVersion"], "1.4.0")
        self.assertEqual(h.metrics.reports_written.value("succeeded"), 1)
        self.assertEqual(h.metrics.received.value("finding"), 2)
        self.assertEqual(h.metrics.received.value("run"), 1)
        self.assertEqual(h.metrics.finalize_seconds.count, 1)

    def test_second_success_replaces_findings(self):
        h = PipelineHarness()
        h.feed(finding(), run(findingCount=1))
        h.feed(finding(runId="run-2", checkId="SAMMA-TLS-CIPHER-WEAK", severity="MEDIUM"), run(runId="run-2", findingCount=1, finishedAt="2026-10-16T02:00:21Z"))
        status = h.report["status"]
        self.assertEqual([f["checkId"] for f in status["findings"]], ["SAMMA-TLS-CIPHER-WEAK"])
        self.assertEqual(status["summary"]["high"], 0)
        self.assertEqual(status["lastSuccessAt"], "2026-10-16T02:00:21Z")
        self.assertEqual(status["lastRun"]["runId"], "run-2")

    def test_clean_success_empties_findings(self):
        h = PipelineHarness()
        h.feed(finding(), run(findingCount=1))
        h.feed(run(runId="run-2", findingCount=0))
        self.assertEqual(h.report["status"]["findings"], [])
        self.assertEqual(h.report["status"]["summary"]["high"], 0)

    def test_duplicates_collapse_and_the_cap_applies(self):
        h = PipelineHarness()
        datas = [finding(), finding(evidence="again")]
        datas += [finding(checkId="SAMMA-TLS-X-{0:04d}".format(i), severity="INFO", endpoint={"host": TARGET, "port": 1 + i}) for i in range(250)]
        datas.append(run(findingCount=len(datas)))
        h.feed(*datas)
        findings = h.report["status"]["findings"]
        self.assertEqual(len(findings), reports.MAX_FINDINGS)
        self.assertEqual(findings[0]["checkId"], "SAMMA-TLS-PROTOCOL-DEPRECATED")
        self.assertEqual(findings[0]["evidence"], "negotiated TLSv1", "the first duplicate wins")
        self.assertEqual(h.metrics.findings_dropped.value("over-limit"), 51)


class TenantTests(unittest.TestCase):
    def test_two_tenants_on_one_host_get_their_own_reports(self):
        a = scanner_object(name="tls-a", uid="ua")
        a["spec"]["samma_io_id"] = "tenant-a"
        b = scanner_object(name="tls-b", uid="ub")
        b["spec"]["samma_io_id"] = "tenant-b"
        h = PipelineHarness(scanners=[a, b])
        for sid, run_id in (("tenant-a", "tls-a-run"), ("tenant-b", "tls-b-run")):
            block = {"scanner": "tls-scanner", "id": sid, "tags": [], "json": "{}"}
            h.feed(finding(runId=run_id, **{"samma-io": block}), run(runId=run_id, findingCount=1, **{"samma-io": block}))
        for sid, uid in (("tenant-a", "ua"), ("tenant-b", "ub")):
            report = h.store.objects.get(reports.report_name("tls-scanner", None, TARGET, sid))
            self.assertIsNotNone(report, sid)
            self.assertEqual(report["metadata"]["annotations"][reports.ANNOTATION_SAMMA_IO_ID], sid)
            self.assertEqual([o["uid"] for o in report["metadata"]["ownerReferences"]], [uid])
        self.assertIsNone(h.report)


class FailedRunTests(unittest.TestCase):
    def test_failed_run_keeps_findings(self):
        h = PipelineHarness()
        h.feed(finding(), run(findingCount=1))
        outcomes = h.feed(run(runId="run-2", outcome="failed", message="OSError: name resolution failed", findingCount=0))
        self.assertEqual(outcomes, ["failed"])
        status = h.report["status"]
        self.assertEqual(len(status["findings"]), 1)
        self.assertEqual(status["summary"]["high"], 1)
        self.assertEqual(status["lastSuccessAt"], "2026-10-15T02:00:21Z")
        self.assertEqual(status["lastRun"]["outcome"], "failed")
        self.assertEqual(status["lastRun"]["runId"], "run-2")
        self.assertEqual(status["lastRun"]["message"], "OSError: name resolution failed")

    def test_failed_run_with_partial_findings_discards_them(self):
        h = PipelineHarness()
        h.feed(finding(), run(findingCount=1))
        h.feed(finding(runId="run-2", checkId="SAMMA-TLS-CIPHER-WEAK"), run(runId="run-2", outcome="timed_out", message="SIGTERM received", findingCount=1))
        status = h.report["status"]
        self.assertEqual([f["checkId"] for f in status["findings"]], ["SAMMA-TLS-PROTOCOL-DEPRECATED"])
        self.assertEqual(status["lastRun"]["outcome"], "timed_out")
        self.assertEqual(h.metrics.reports_written.value("timed_out"), 1)

    def test_first_run_failing_creates_a_report_without_findings(self):
        h = PipelineHarness()
        h.feed(run(outcome="failed", message="boom", findingCount=0))
        status = h.report["status"]
        self.assertNotIn("findings", status)
        self.assertNotIn("lastSuccessAt", status)
        self.assertEqual(status["lastRun"]["outcome"], "failed")

    def test_incomplete_run_is_recorded_as_failed(self):
        h = PipelineHarness()
        h.feed(finding(), run(findingCount=1))
        h.feed(finding(runId="run-2", checkId="SAMMA-TLS-CIPHER-WEAK"), run(runId="run-2", findingCount=3))
        self.assertEqual(h.report["status"]["lastRun"]["runId"], RUN_ID, "nothing written while waiting for stragglers")
        h.clock.advance(31)
        outcomes = h.tick()
        self.assertEqual(outcomes, ["failed"])
        status = h.report["status"]
        self.assertEqual([f["checkId"] for f in status["findings"]], ["SAMMA-TLS-PROTOCOL-DEPRECATED"], "old findings kept")
        self.assertEqual(status["lastRun"]["runId"], "run-2")
        self.assertEqual(status["lastRun"]["outcome"], "failed")
        self.assertEqual(status["lastRun"]["message"], "bridge received 1 of 3 findings")
        self.assertEqual(h.metrics.runs_incomplete.value(), 1)


class DropTests(unittest.TestCase):
    def test_unknown_target_is_dropped(self):
        h = PipelineHarness()
        outcomes = h.feed(finding(target="evil.example.com"), run(target="evil.example.com", findingCount=1))
        self.assertEqual(outcomes, [])
        self.assertIsNone(h.store.objects.get(reports.report_name("tls-scanner", None, "evil.example.com")))
        self.assertEqual(h.metrics.dropped.value("unknown-target"), 2)
        self.assertEqual(len(h.pipeline.accumulator), 0)

    def test_messages_are_dropped_until_the_scanner_list_loads(self):
        h = PipelineHarness()
        h.store.list_scanners = lambda: (_ for _ in ()).throw(RuntimeError("down"))
        h.index.lister = h.store.list_scanners
        h.feed(run(findingCount=0))
        self.assertEqual(h.metrics.dropped.value("scanners-unavailable"), 1)
        self.assertIsNone(h.report)

    def test_legacy_messages_pass_through_without_a_report(self):
        h = PipelineHarness()
        message, finished = h.pipeline.handle(payload(LEGACY))
        self.assertEqual(message.kind, "legacy")
        self.assertEqual(finished, [])
        self.assertEqual(h.metrics.received.value("legacy"), 1)
        self.assertEqual(h.store.objects, {})
        self.assertEqual(message.legacy_row()["scanner"], "nmap")

    def test_rejected_messages_are_counted_not_raised(self):
        h = PipelineHarness()
        self.assertEqual(h.pipeline.handle(b"{not json"), (None, []))
        self.assertEqual(h.pipeline.handle(payload(finding(severity="HUGE"))), (None, []))
        self.assertEqual(h.metrics.rejected.value("payload"), 1)
        self.assertEqual(h.metrics.rejected.value("finding"), 1)

    def test_orphaned_findings_expire(self):
        h = PipelineHarness()
        h.feed(finding(runId="lost"))
        h.clock.advance(3601)
        self.assertEqual(h.tick(), [])
        self.assertEqual(h.metrics.dropped.value("orphan-run"), 1)
        self.assertEqual(h.metrics.runs_pending.value(), 0)


class WriteFailureTests(unittest.TestCase):
    def test_store_errors_are_counted_not_raised(self):
        h = PipelineHarness()

        def broken(name):
            raise RuntimeError("apiserver 500")

        h.store.get = broken
        outcomes = h.feed(run(findingCount=0))
        self.assertEqual(outcomes, [None])
        self.assertEqual(h.metrics.report_errors.value(), 1)

    def test_owner_added_when_a_second_scanner_appears(self):
        h = PipelineHarness()
        h.feed(run(findingCount=0))
        h.store.scanners.append(scanner_object(name="second", uid="u2"))
        h.clock.advance(31)
        h.feed(run(runId="run-2", findingCount=0))
        self.assertEqual([o["uid"] for o in h.report["metadata"]["ownerReferences"]], ["u1", "u2"])


if __name__ == "__main__":
    unittest.main()
