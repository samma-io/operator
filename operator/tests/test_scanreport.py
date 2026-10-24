"""Unit tests for operator/code/scanreport.py, the ScanReport CRD copies
and the agreement between the operator and the bridge on names and labels.

    python3 -m unittest discover -s operator/tests -t operator
"""

import os
import sys
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OPERATOR_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(OPERATOR_DIR)
CODE_DIR = os.path.join(OPERATOR_DIR, "code")
BRIDGE_CODE_DIR = os.path.join(REPO_DIR, "bridge", "code")
for path in (CODE_DIR, BRIDGE_CODE_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

import jobspec  # noqa: E402
import scanreport  # noqa: E402
import target_policy  # noqa: E402
from samma_bridge import messages as bridge_messages  # noqa: E402
from samma_bridge import reports as bridge_reports  # noqa: E402

CRD_FILES = [
    os.path.join(REPO_DIR, "helm", "samma-operator", "crds", "scanreports.samma.io.yaml"),
    os.path.join(REPO_DIR, "manifest", "samma-operator.yaml"),
]

TARGET = "api.example.com"
OWNER = jobspec.owner_reference("samma.io/v1", "Scanner", "tls-api", "uid-1")


def job_metadata(scanner="tls-scanner", template=None, recorded=False, ingress=True):
    labels = {
        jobspec.LABEL_MANAGED_BY: jobspec.MANAGED_BY,
        jobspec.LABEL_SCANNER: scanner,
        jobspec.LABEL_TEMPLATE: template or scanner,
        jobspec.LABEL_TARGET_HASH: jobspec.target_hash(TARGET),
    }
    if ingress:
        labels[jobspec.LABEL_INGRESS_NAMESPACE] = "shop"
        labels[jobspec.LABEL_INGRESS_NAME] = "api"
    annotations = {jobspec.ANNOTATION_TARGET: TARGET}
    if recorded:
        annotations[scanreport.ANNOTATION_OUTCOME_RECORDED] = "true"
    return {
        "name": jobspec.object_name(scanner, template or scanner, TARGET),
        "labels": labels,
        "annotations": annotations,
        "owner_references": [
            {"api_version": "samma.io/v1", "kind": "Scanner", "name": "tls-api", "uid": "uid-1", "controller": True, "block_owner_deletion": False},
            {"api_version": "v1", "kind": "ConfigMap", "name": "x", "uid": "uid-cm", "controller": False, "block_owner_deletion": False},
        ],
    }


def failed_status(reason="BackoffLimitExceeded", message="Job has reached the specified backoff limit", snake=True):
    when = datetime(2026, 10, 15, 2, 0, 21, tzinfo=timezone.utc)
    start = datetime(2026, 10, 15, 2, 0, 4, tzinfo=timezone.utc)
    if snake:
        return {
            "start_time": start,
            "conditions": [
                {"type": "FailureTarget", "status": "True", "reason": reason, "message": message, "last_transition_time": when},
                {"type": "Failed", "status": "True", "reason": reason, "message": message, "last_transition_time": when},
            ],
        }
    return {
        "startTime": "2026-10-15T02:00:04Z",
        "conditions": [{"type": "Failed", "status": "True", "reason": reason, "message": message, "lastTransitionTime": "2026-10-15T02:00:21Z"}],
    }


class OutcomeTests(unittest.TestCase):
    def test_failed_job(self):
        outcome, message, started, finished = scanreport.job_outcome(failed_status())
        self.assertEqual(outcome, "failed")
        self.assertEqual(message, "BackoffLimitExceeded: Job has reached the specified backoff limit")
        self.assertEqual(started, "2026-10-15T02:00:04Z")
        self.assertEqual(finished, "2026-10-15T02:00:21Z")

    def test_deadline_is_timed_out(self):
        outcome, message, _, _ = scanreport.job_outcome(failed_status("DeadlineExceeded", "Job was active longer than specified deadline", snake=False))
        self.assertEqual(outcome, "timed_out")
        self.assertEqual(message, "DeadlineExceeded: Job was active longer than specified deadline")

    def test_running_and_complete_jobs_have_no_outcome(self):
        self.assertIsNone(scanreport.job_outcome({}))
        self.assertIsNone(scanreport.job_outcome(None))
        self.assertIsNone(scanreport.job_outcome({"conditions": [{"type": "Complete", "status": "True"}]}))
        self.assertIsNone(scanreport.job_outcome({"conditions": [{"type": "Failed", "status": "False", "reason": "x"}]}))
        self.assertIsNone(scanreport.job_outcome({"conditions": [{"type": "FailureTarget", "status": "True", "reason": "DeadlineExceeded"}]}),
                          "FailureTarget comes before Failed and is not terminal yet")

    def test_message_is_capped_and_falls_back(self):
        outcome, message, _, _ = scanreport.job_outcome({"conditions": [{"type": "Failed", "status": "True", "message": "m" * 2000}]})
        self.assertEqual(len(message), scanreport.MESSAGE_MAX_LENGTH)
        _, message, _, _ = scanreport.job_outcome({"conditions": [{"type": "Failed", "status": "True"}]})
        self.assertEqual(message, "Job failed")
        _, message, _, _ = scanreport.job_outcome({"conditions": [{"type": "Failed", "status": "True", "reason": "PodFailurePolicy"}]})
        self.assertEqual(message, "PodFailurePolicy")

    def test_rfc3339(self):
        self.assertEqual(scanreport.rfc3339(datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=timezone.utc)), "2026-01-02T03:04:05Z")
        self.assertEqual(scanreport.rfc3339(datetime(2026, 1, 2, 3, 4, 5)), "2026-01-02T03:04:05Z")
        self.assertEqual(scanreport.rfc3339("2026-01-02T03:04:05Z"), "2026-01-02T03:04:05Z")
        self.assertIsNone(scanreport.rfc3339(None))
        self.assertRegex(scanreport.now_rfc3339(), r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class JobMetadataTests(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(scanreport.job_identity(job_metadata()), ("tls-scanner", "tls-scanner", TARGET))
        self.assertEqual(scanreport.job_identity(job_metadata("nmap", "http")), ("nmap", "http", TARGET))
        self.assertIsNone(scanreport.job_identity({"labels": {jobspec.LABEL_SCANNER: "nmap"}, "annotations": {}}))
        self.assertIsNone(scanreport.job_identity({}))

    def test_recorded_flag(self):
        self.assertFalse(scanreport.outcome_recorded(job_metadata()))
        self.assertTrue(scanreport.outcome_recorded(job_metadata(recorded=True)))

    def test_scanner_owners_in_api_shape(self):
        owners = scanreport.scanner_owners(job_metadata())
        self.assertEqual(owners, [{"apiVersion": "samma.io/v1", "kind": "Scanner", "name": "tls-api", "uid": "uid-1", "controller": True, "blockOwnerDeletion": False}])
        camel = {"ownerReferences": [{"apiVersion": "samma.io/v1", "kind": "Scanner", "name": "a", "uid": "u"}]}
        self.assertEqual(scanreport.scanner_owners(camel)[0]["uid"], "u")
        self.assertEqual(scanreport.scanner_owners({}), [])

    def test_ingress_labels(self):
        self.assertEqual(scanreport.ingress_labels(job_metadata()), {jobspec.LABEL_INGRESS_NAMESPACE: "shop", jobspec.LABEL_INGRESS_NAME: "api"})
        self.assertEqual(scanreport.ingress_labels(job_metadata(ingress=False)), {})

    def test_wants_report(self):
        for name in jobspec.DETECT_SCANNERS:
            self.assertTrue(scanreport.wants_report(name), name)
        for name in ("nmap", "nikto", "tsunami", "base", "unknown"):
            self.assertFalse(scanreport.wants_report(name), name)

    def test_latest_pod_name(self):
        pods = [
            {"name": "job-aaaaa", "creation_timestamp": datetime(2026, 10, 15, 2, 0, 0, tzinfo=timezone.utc)},
            {"name": "job-bbbbb", "creation_timestamp": datetime(2026, 10, 15, 2, 5, 0, tzinfo=timezone.utc)},
            {"name": "job-ccccc", "creationTimestamp": "2026-10-15T02:01:00Z"},
        ]
        self.assertEqual(scanreport.latest_pod_name(pods), "job-bbbbb")
        self.assertIsNone(scanreport.latest_pod_name([]))
        self.assertEqual(scanreport.latest_pod_name([{"name": "only"}]), "only")


class ReportBodyTests(unittest.TestCase):
    def test_body_matches_the_job(self):
        spec, variant = jobspec.resolve_runs(["tls-scanner"])[0][0]
        job = jobspec.build_job(spec, variant, TARGET, {}, jobspec.Settings(), owner=OWNER, extra_labels={jobspec.LABEL_INGRESS_NAME: "api"})
        body = scanreport.report_body("tls-scanner", "tls-scanner", TARGET, "samma-io", owners=scanreport.scanner_owners(job["metadata"]),
                                      extra_labels=scanreport.ingress_labels(job["metadata"]))
        self.assertEqual(body["metadata"]["name"], job["metadata"]["name"])
        self.assertEqual(body["apiVersion"], "samma.io/v1alpha1")
        self.assertEqual(body["kind"], "ScanReport")
        for key in (jobspec.LABEL_SCANNER, jobspec.LABEL_TEMPLATE, jobspec.LABEL_TARGET_HASH, jobspec.LABEL_INGRESS_NAME, jobspec.LABEL_MANAGED_BY):
            self.assertEqual(body["metadata"]["labels"][key], job["metadata"]["labels"][key])
        self.assertNotIn(jobspec.LABEL_SCANNER_UID, body["metadata"]["labels"])
        self.assertNotIn(jobspec.LABEL_ROLE, body["metadata"]["labels"])
        self.assertEqual(body["metadata"]["annotations"], {jobspec.ANNOTATION_TARGET: TARGET})
        self.assertEqual(body["metadata"]["ownerReferences"], [OWNER])
        self.assertEqual(body["spec"], {"target": TARGET, "scanner": "tls-scanner"})

    def test_template_and_tier(self):
        body = scanreport.report_body("nmap", "http", TARGET, "samma-io", tier="deep")
        self.assertEqual(body["spec"], {"target": TARGET, "scanner": "nmap", "template": "http", "tier": "deep"})
        self.assertEqual(body["metadata"]["name"], "nmap-http-" + jobspec.target_hash(TARGET))
        self.assertNotIn("ownerReferences", body["metadata"])


class StatusTests(unittest.TestCase):
    def test_failed_run_status_keeps_findings(self):
        existing = {"findings": [{"checkId": "SAMMA-X"}], "summary": {"high": 1}, "lastSuccessAt": "2026-01-01T00:00:00Z", "scannerVersion": "1.0.0",
                    "lastRun": {"runId": "old", "outcome": "succeeded"}}
        status = scanreport.failed_run_status(existing, "pod-1", "job-1", "timed_out", "DeadlineExceeded: too slow", "2026-10-15T02:00:04Z", "2026-10-15T02:15:04Z")
        self.assertEqual(status["findings"], existing["findings"])
        self.assertEqual(status["summary"], {"high": 1})
        self.assertEqual(status["lastSuccessAt"], "2026-01-01T00:00:00Z")
        self.assertEqual(status["scannerVersion"], "1.0.0")
        self.assertEqual(status["lastRun"], {"runId": "pod-1", "jobName": "job-1", "outcome": "timed_out", "message": "DeadlineExceeded: too slow",
                                             "startedAt": "2026-10-15T02:00:04Z", "finishedAt": "2026-10-15T02:15:04Z"})
        self.assertEqual(existing["lastRun"]["runId"], "old", "input not changed in place")

    def test_missing_times_are_filled_or_omitted(self):
        status = scanreport.failed_run_status(None, "pod-1", "job-1", "failed", "x")
        self.assertNotIn("startedAt", status["lastRun"])
        self.assertRegex(status["lastRun"]["finishedAt"], r"Z$")

    def test_only_failed_outcomes(self):
        with self.assertRaises(ValueError):
            scanreport.failed_run_status({}, "pod", "job", "succeeded", "")

    def test_run_already_recorded(self):
        self.assertTrue(scanreport.run_already_recorded({"lastRun": {"runId": "pod-1"}}, "pod-1"))
        self.assertFalse(scanreport.run_already_recorded({"lastRun": {"runId": "pod-1"}}, "pod-2"))
        self.assertFalse(scanreport.run_already_recorded({}, "pod-1"))
        self.assertFalse(scanreport.run_already_recorded(None, ""))


class CrdTests(unittest.TestCase):
    def _crd_text(self, path):
        with open(path, "r") as handle:
            text = handle.read()
        start = text.index("name: scanreports.samma.io")
        end = text.find("\n---", start)
        return text[start:end if end > 0 else len(text)].rstrip()

    def test_both_copies_are_identical(self):
        helm, manifest = (self._crd_text(path) for path in CRD_FILES)
        self.assertEqual(helm, manifest)

    def test_schema_carries_the_contract(self):
        text = self._crd_text(CRD_FILES[0])
        self.assertIn("pattern: '{0}'".format(target_policy.TARGET_PATTERN), text)
        self.assertIn("maxLength: {0}".format(target_policy.MAX_TARGET_LENGTH), text)
        self.assertIn("maxLength: {0}".format(scanreport.MESSAGE_MAX_LENGTH), text)
        for outcome in scanreport.OUTCOMES:
            self.assertIn("- " + outcome, text)
        self.assertIn("shortNames:", text)
        self.assertIn("- sr", text)
        self.assertIn("plural: scanreports", text)
        self.assertIn("kind: ScanReport", text)
        self.assertIn("name: v1alpha1", text)
        self.assertIn("status: {}", text)
        self.assertIn("additionalPrinterColumns:", text)
        for column in (".spec.target", ".spec.scanner", ".status.lastRun.outcome", ".status.summary.high", ".status.lastSuccessAt"):
            self.assertIn("jsonPath: " + column, text)
        self.assertNotIn("raw:", text)


class BridgeAgreementTests(unittest.TestCase):
    """The bridge has its own copy of the naming and label code."""

    def test_names_and_hashes_agree(self):
        for target in (TARGET, "2001:db8::1", "a" * 63 + ".example"):
            self.assertEqual(bridge_reports.target_hash(target), jobspec.target_hash(target))
            for scanner, template in (("tls-scanner", None), ("tls-scanner", "tls-scanner"), ("nmap", "http")):
                self.assertEqual(bridge_reports.report_name(scanner, template, target), scanreport.report_name(scanner, template, target))
                self.assertEqual(bridge_reports.report_name(scanner, template, target), jobspec.object_name(scanner, template, target))

    def test_labels_and_patterns_agree(self):
        self.assertEqual(bridge_reports.LABEL_MANAGED_BY, jobspec.LABEL_MANAGED_BY)
        self.assertEqual(bridge_reports.MANAGED_BY, jobspec.MANAGED_BY)
        self.assertEqual(bridge_reports.LABEL_SCANNER, jobspec.LABEL_SCANNER)
        self.assertEqual(bridge_reports.LABEL_TEMPLATE, jobspec.LABEL_TEMPLATE)
        self.assertEqual(bridge_reports.LABEL_TARGET_HASH, jobspec.LABEL_TARGET_HASH)
        self.assertEqual(bridge_reports.LABEL_INGRESS_NAMESPACE, jobspec.LABEL_INGRESS_NAMESPACE)
        self.assertEqual(bridge_reports.LABEL_INGRESS_NAME, jobspec.LABEL_INGRESS_NAME)
        self.assertEqual(bridge_reports.ANNOTATION_TARGET, jobspec.ANNOTATION_TARGET)
        self.assertEqual((bridge_reports.GROUP, bridge_reports.VERSION, bridge_reports.PLURAL, bridge_reports.KIND),
                         (scanreport.GROUP, scanreport.VERSION, scanreport.PLURAL, scanreport.KIND))
        self.assertEqual(bridge_messages.TARGET_PATTERN, target_policy.TARGET_PATTERN)
        self.assertEqual(bridge_messages.OUTCOMES, scanreport.OUTCOMES)
        self.assertEqual(bridge_messages.MAX_MESSAGE, scanreport.MESSAGE_MAX_LENGTH)
        for value in ("plain", "x" * 90, "ends-with-dash-" + "x" * 60):
            self.assertEqual(bridge_reports.label_value(value), jobspec.label_value(value))

    def test_bodies_agree(self):
        owners = [OWNER]
        extra = {jobspec.LABEL_INGRESS_NAMESPACE: "shop", jobspec.LABEL_INGRESS_NAME: "api"}
        ours = scanreport.report_body("tls-scanner", None, TARGET, "samma-io", owners=owners, extra_labels=extra)
        theirs = bridge_reports.report_body("tls-scanner", None, TARGET, "samma-io", owners=owners, extra_labels=extra)
        self.assertEqual(ours, theirs)


if __name__ == "__main__":
    unittest.main()
