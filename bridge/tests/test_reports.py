"""ScanReport naming, dedup, caps, status bodies and the upsert loop."""

import json
import os
import re
import unittest

from .helpers import REPO_DIR, TARGET, FakeStore, finding, run, scanner_object  # noqa: F401
from samma_bridge import messages, reports

CRD_FILES = [
    os.path.join(REPO_DIR, "helm", "samma-operator", "templates", "crd-scanreport.yaml"),
    os.path.join(REPO_DIR, "manifest", "samma-operator.yaml"),
]


def entry(check_id="SAMMA-TLS-PROTOCOL-DEPRECATED", severity="HIGH", host=TARGET, port=443, scheme="https", evidence="e", **extra):
    item = {
        "checkId": check_id,
        "severity": severity,
        "title": "t",
        "endpoint": {"host": host, "port": port, "scheme": scheme},
        "evidence": evidence,
        "remediation": "r",
    }
    item.update(extra)
    return item


def parsed_run(**overrides):
    return messages.parse(json.dumps(run(**overrides)))


class NamingTests(unittest.TestCase):
    def test_report_name_is_the_job_name(self):
        name = reports.report_name("tls-scanner", None, TARGET)
        self.assertRegex(name, r"^tls-scanner-[0-9a-f]{8}$")
        self.assertEqual(reports.report_name("tls-scanner", "tls-scanner", TARGET), name)
        self.assertEqual(reports.report_name("nmap", "http", TARGET), "nmap-http-" + reports.target_hash(TARGET))
        self.assertEqual(reports.target_hash(TARGET), reports.target_hash(TARGET))
        self.assertNotEqual(reports.target_hash("a.example"), reports.target_hash("b.example"))

    def test_report_body(self):
        owners = [reports.owner_reference(scanner_object(uid="u1")), reports.owner_reference(scanner_object(name="other", uid="u2"))]
        body = reports.report_body("tls-scanner", None, TARGET, "samma-io", owners=owners,
                                   extra_labels={reports.LABEL_INGRESS_NAMESPACE: "shop", reports.LABEL_INGRESS_NAME: "x" * 80})
        self.assertEqual(body["apiVersion"], "samma.io/v1alpha1")
        self.assertEqual(body["kind"], "ScanReport")
        meta = body["metadata"]
        self.assertEqual(meta["name"], reports.report_name("tls-scanner", None, TARGET))
        self.assertEqual(meta["namespace"], "samma-io")
        self.assertEqual(meta["labels"][reports.LABEL_SCANNER], "tls-scanner")
        self.assertEqual(meta["labels"][reports.LABEL_TEMPLATE], "tls-scanner")
        self.assertEqual(meta["labels"][reports.LABEL_TARGET_HASH], reports.target_hash(TARGET))
        self.assertEqual(meta["labels"][reports.LABEL_INGRESS_NAMESPACE], "shop")
        self.assertLessEqual(len(meta["labels"][reports.LABEL_INGRESS_NAME]), 63)
        self.assertEqual(meta["annotations"], {reports.ANNOTATION_TARGET: TARGET})
        self.assertEqual([o["uid"] for o in meta["ownerReferences"]], ["u1", "u2"])
        self.assertEqual(meta["ownerReferences"][0]["kind"], "Scanner")
        self.assertIs(meta["ownerReferences"][0]["blockOwnerDeletion"], False)
        self.assertEqual(body["spec"], {"target": TARGET, "scanner": "tls-scanner"})
        with_template = reports.report_body("nmap", "http", TARGET, "samma-io", tier="deep")
        self.assertEqual(with_template["spec"], {"target": TARGET, "scanner": "nmap", "template": "http", "tier": "deep"})
        self.assertNotIn("ownerReferences", with_template["metadata"])


class FindingListTests(unittest.TestCase):
    def test_dedupe_on_check_id_and_endpoint(self):
        items = [entry(evidence="first"), entry(evidence="second"), entry(port=8443), entry(check_id="SAMMA-TLS-CIPHER-WEAK")]
        kept = reports.dedupe(items)
        self.assertEqual(len(kept), 3)
        self.assertEqual(kept[0]["evidence"], "first")

    def test_sort_by_severity_then_check_id(self):
        items = [entry(check_id="SAMMA-B", severity="LOW"), entry(check_id="SAMMA-C", severity="CRITICAL"),
                 entry(check_id="SAMMA-A", severity="INFO"), entry(check_id="SAMMA-B", severity="HIGH"), entry(check_id="SAMMA-A", severity="HIGH")]
        ordered = [(e["severity"], e["checkId"]) for e in reports.sort_findings(items)]
        self.assertEqual(ordered, [("CRITICAL", "SAMMA-C"), ("HIGH", "SAMMA-A"), ("HIGH", "SAMMA-B"), ("LOW", "SAMMA-B"), ("INFO", "SAMMA-A")])

    def test_entry_cap(self):
        items = reports.sort_findings([entry(check_id="SAMMA-X-{0:04d}".format(i), severity="INFO" if i % 2 else "HIGH") for i in range(250)])
        kept, notes = reports.cap_findings(items)
        self.assertEqual(len(kept), reports.MAX_FINDINGS)
        self.assertEqual(notes["over_limit"], 50)
        self.assertEqual(kept[0]["severity"], "HIGH")
        self.assertTrue(all(e["severity"] == "HIGH" for e in kept[:125]))

    def test_size_cap_shortens_evidence_first(self):
        items = [entry(check_id="SAMMA-X-{0:04d}".format(i), evidence="e" * 1024, remediation="r" * 600, port=i + 1) for i in range(200)]
        self.assertGreater(reports.serialized_size(items), reports.MAX_FINDINGS_BYTES)
        kept, notes = reports.cap_findings(items)
        self.assertEqual(len(kept), 200)
        self.assertEqual(notes["evidence_shortened"], 200)
        self.assertEqual(notes["info_dropped"], 0)
        self.assertTrue(all(len(e["evidence"]) == reports.SHORT_EVIDENCE for e in kept))
        self.assertLessEqual(reports.serialized_size(kept), reports.MAX_FINDINGS_BYTES)
        self.assertEqual(items[0]["evidence"], "e" * 1024, "the input is not changed in place")

    def test_size_cap_drops_info_then_the_tail(self):
        big = "r" * 1000
        items = reports.sort_findings(
            [entry(check_id="SAMMA-I-{0:04d}".format(i), severity="INFO", evidence="e", remediation=big, port=i + 1) for i in range(100)]
            + [entry(check_id="SAMMA-L-{0:04d}".format(i), severity="LOW", evidence="e", remediation=big, port=i + 1) for i in range(100)]
        )
        kept, notes = reports.cap_findings(items, max_bytes=60 * 1024)
        self.assertEqual(notes["info_dropped"], 100)
        self.assertGreater(notes["tail_dropped"], 0)
        self.assertTrue(all(e["severity"] == "LOW" for e in kept))
        self.assertLessEqual(reports.serialized_size(kept), 60 * 1024)

    def test_summary(self):
        items = [entry(severity="HIGH"), entry(severity="HIGH"), entry(severity="INFO"), entry(severity="CRITICAL")]
        self.assertEqual(reports.summary(items), {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1})
        self.assertEqual(reports.summary([]), {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})


class StatusTests(unittest.TestCase):
    def test_succeeded_replaces_findings(self):
        existing = {"findings": [entry(check_id="SAMMA-OLD")], "summary": {"high": 1}, "lastSuccessAt": "2026-01-01T00:00:00Z", "scannerVersion": "1.0.0"}
        status = reports.succeeded_status(existing, parsed_run(), [entry()])
        self.assertEqual([e["checkId"] for e in status["findings"]], ["SAMMA-TLS-PROTOCOL-DEPRECATED"])
        self.assertEqual(status["summary"]["high"], 1)
        self.assertEqual(status["lastSuccessAt"], "2026-10-15T02:00:21Z")
        self.assertEqual(status["scannerVersion"], "1.4.0")
        self.assertEqual(status["lastRun"], {"runId": "tls-scanner-d0c43d38-x7k2p", "outcome": "succeeded", "startedAt": "2026-10-15T02:00:04Z", "finishedAt": "2026-10-15T02:00:21Z"})
        self.assertEqual(existing["findings"][0]["checkId"], "SAMMA-OLD", "input not changed in place")

    def test_succeeded_with_no_findings_empties_the_list(self):
        status = reports.succeeded_status({"findings": [entry()]}, parsed_run(findingCount=0), [])
        self.assertEqual(status["findings"], [])
        self.assertEqual(status["summary"]["high"], 0)

    def test_failed_keeps_findings(self):
        existing = {"findings": [entry()], "summary": {"high": 1}, "lastSuccessAt": "2026-01-01T00:00:00Z"}
        status = reports.failed_status(existing, parsed_run(outcome="timed_out", message="SIGTERM received"))
        self.assertEqual(status["findings"], existing["findings"])
        self.assertEqual(status["summary"], {"high": 1})
        self.assertEqual(status["lastSuccessAt"], "2026-01-01T00:00:00Z")
        self.assertEqual(status["lastRun"]["outcome"], "timed_out")
        self.assertEqual(status["lastRun"]["message"], "SIGTERM received")


class MetadataChangeTests(unittest.TestCase):
    def test_nothing_to_do_when_equal(self):
        body = reports.report_body("tls-scanner", None, TARGET, "samma-io", owners=[reports.owner_reference(scanner_object())])
        self.assertIsNone(reports.metadata_changes(body["metadata"], body["metadata"]))

    def test_new_owner_is_added_and_old_ones_kept(self):
        existing = reports.report_body("tls-scanner", None, TARGET, "samma-io", owners=[reports.owner_reference(scanner_object(uid="u1"))])["metadata"]
        desired = reports.report_body("tls-scanner", None, TARGET, "samma-io", owners=[reports.owner_reference(scanner_object(name="b", uid="u2"))],
                                      extra_labels={reports.LABEL_INGRESS_NAME: "web"})["metadata"]
        patch = reports.metadata_changes(existing, desired)
        self.assertEqual([o["uid"] for o in patch["ownerReferences"]], ["u1", "u2"])
        self.assertEqual(patch["labels"], {reports.LABEL_INGRESS_NAME: "web"})
        self.assertNotIn("annotations", patch)


class UpsertTests(unittest.TestCase):
    def body(self):
        return reports.report_body("tls-scanner", None, TARGET, "samma-io")

    def test_create_then_status(self):
        store = FakeStore()
        action = reports.upsert(store, self.body(), lambda current: reports.succeeded_status(current, parsed_run(), [entry()]))
        self.assertEqual(action, "created")
        stored = store.objects[self.body()["metadata"]["name"]]
        self.assertEqual(len(stored["status"]["findings"]), 1)
        self.assertEqual([c[0] if isinstance(c, tuple) else c for c in store.calls], ["get", "create", "replace_status"])

    def test_update_keeps_what_make_status_keeps(self):
        store = FakeStore()
        reports.upsert(store, self.body(), lambda current: reports.succeeded_status(current, parsed_run(), [entry()]))
        action = reports.upsert(store, self.body(), lambda current: reports.failed_status(current, parsed_run(outcome="failed", message="boom")))
        self.assertEqual(action, "updated")
        stored = store.objects[self.body()["metadata"]["name"]]
        self.assertEqual(len(stored["status"]["findings"]), 1)
        self.assertEqual(stored["status"]["lastRun"]["outcome"], "failed")

    def test_conflict_is_retried_from_a_fresh_read(self):
        store = FakeStore(conflicts=2)
        reports.upsert(store, self.body(), lambda current: reports.failed_status(current, parsed_run(outcome="failed")))
        gets = [c for c in store.calls if isinstance(c, tuple) and c[0] == "get"]
        self.assertEqual(len(gets), 3)

    def test_too_many_conflicts_raise(self):
        store = FakeStore(conflicts=10)
        with self.assertRaises(reports.Conflict):
            reports.upsert(store, self.body(), lambda current: reports.failed_status(current, parsed_run(outcome="failed")))

    def test_metadata_catch_up_after_the_status_write(self):
        store = FakeStore()
        reports.upsert(store, self.body(), lambda current: reports.failed_status(current, parsed_run(outcome="failed")))
        body = reports.report_body("tls-scanner", None, TARGET, "samma-io", owners=[reports.owner_reference(scanner_object(uid="u9"))])
        reports.upsert(store, body, lambda current: reports.failed_status(current, parsed_run(outcome="failed")))
        stored = store.objects[body["metadata"]["name"]]
        self.assertEqual([o["uid"] for o in stored["metadata"]["ownerReferences"]], ["u9"])
        self.assertEqual(store.calls[-1], ("patch_metadata", body["metadata"]["name"]))


class CrdLimitsTests(unittest.TestCase):
    """The limits the bridge applies are the limits the CRD enforces."""

    def _crd_text(self, path):
        with open(path, "r") as handle:
            text = handle.read()
        start = text.index("name: scanreports.samma.io")
        end = text.find("\n---", start)
        return text[start:end if end > 0 else len(text)]

    def test_crd_copies_carry_the_bridge_limits(self):
        for path in CRD_FILES:
            with self.subTest(path=os.path.relpath(path, REPO_DIR)):
                text = self._crd_text(path)
                self.assertIn("maxItems: {0}".format(reports.MAX_FINDINGS), text)
                self.assertIn("pattern: '{0}'".format(messages.CHECK_ID_PATTERN), text)
                self.assertIn("pattern: '{0}'".format(messages.CVE_ID_PATTERN), text)
                self.assertIn("pattern: '{0}'".format(messages.TARGET_PATTERN), text)
                for limit in (messages.MAX_TITLE, messages.MAX_EVIDENCE, messages.MAX_REMEDIATION, messages.MAX_MESSAGE, messages.MAX_REFERENCE, messages.MAX_SCANNER_VERSION):
                    self.assertIn("maxLength: {0}".format(limit), text)
                self.assertIn("maxItems: {0}".format(messages.MAX_REFERENCES), text)
                self.assertIn("maxItems: {0}".format(messages.MAX_COMPLIANCE), text)
                self.assertIn("maxItems: {0}".format(messages.MAX_CVE_IDS), text)
                for severity in messages.SEVERITIES:
                    self.assertRegex(text, r"- {0}\b".format(severity))
                for outcome in messages.OUTCOMES:
                    self.assertRegex(text, r"- {0}\b".format(outcome))
                self.assertIn("status: {}", text)

    def test_crd_copies_are_identical(self):
        texts = [self._crd_text(path) for path in CRD_FILES]
        self.assertEqual(texts[0].rstrip(), texts[1].rstrip())

    def test_name_is_a_valid_dns_label_for_long_targets(self):
        long_host = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
        for target in (TARGET, "2001:db8::1", "10.0.0.1", long_host):
            name = reports.report_name("http-redirect-scanner", None, target)
            self.assertRegex(name, r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
            self.assertLessEqual(len(name), 63)


if __name__ == "__main__":
    unittest.main()
