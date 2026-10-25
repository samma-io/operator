"""Message validation: schema v2 findings and runs, legacy passthrough."""

import json
import unittest

from .helpers import LEGACY, RUN_ID, TARGET, finding, run  # noqa: F401
from samma_bridge import messages


def parse(data):
    return messages.parse(json.dumps(data).encode("utf-8"))


class LegacyTests(unittest.TestCase):
    def test_message_without_schema_is_legacy(self):
        message = parse(LEGACY)
        self.assertEqual(message.kind, "legacy")
        self.assertIsNone(message.schema)
        row = message.legacy_row()
        self.assertEqual(row["host"], TARGET)
        self.assertEqual(row["port"], "22")
        self.assertEqual(row["status"], "open")
        self.assertEqual(row["type"], "ssh-banner")
        self.assertEqual(row["scanner"], "nmap")
        self.assertEqual(row["samma_id"], "1234")
        self.assertEqual(json.loads(row["tags"]), ["scanner"])
        self.assertEqual(json.loads(row["raw"]), LEGACY)

    def test_v1_end_marker_is_legacy_too(self):
        message = parse({"scan": "done"})
        self.assertEqual(message.kind, "legacy")
        row = message.legacy_row()
        self.assertIsNone(row["host"])
        self.assertEqual(row["port"], "")


class FindingTests(unittest.TestCase):
    def test_parses_every_field(self):
        message = parse(finding())
        self.assertEqual(message.kind, "finding")
        self.assertEqual(message.scanner, "tls-scanner")
        self.assertEqual(message.scanner_version, "1.4.0")
        self.assertEqual(message.target, TARGET)
        self.assertEqual(message.run_id, RUN_ID)
        self.assertEqual(message.emitted_at, "2026-10-15T02:00:10Z")
        self.assertEqual(message.key, ("tls-scanner", None, TARGET, RUN_ID))
        self.assertEqual(message.check_id, "SAMMA-TLS-PROTOCOL-DEPRECATED")
        self.assertEqual(message.severity, "HIGH")
        self.assertEqual(message.endpoint, {"host": TARGET, "port": 443, "scheme": "https"})
        self.assertEqual(message.cve_ids, [])
        self.assertEqual(message.compliance, ["pci-dss:4.2.1"])

    def test_report_entry_has_no_raw_and_no_empty_lists(self):
        entry = parse(finding(cveIds=["cve-2024-1234"])).report_entry()
        self.assertEqual(entry, {
            "checkId": "SAMMA-TLS-PROTOCOL-DEPRECATED",
            "severity": "HIGH",
            "title": "Deprecated TLS protocol version negotiated",
            "endpoint": {"host": TARGET, "port": 443, "scheme": "https"},
            "evidence": "negotiated TLSv1",
            "remediation": "Disable TLS 1.0 and 1.1.",
            "references": ["https://datatracker.ietf.org/doc/html/rfc8996"],
            "cveIds": ["CVE-2024-1234"],
            "compliance": ["pci-dss:4.2.1"],
        })
        bare = parse(finding(references=[], compliance=[], endpoint={"host": TARGET})).report_entry()
        self.assertNotIn("references", bare)
        self.assertNotIn("compliance", bare)
        self.assertNotIn("cveIds", bare)
        self.assertEqual(bare["endpoint"], {"host": TARGET})

    def test_legacy_row_from_v2_uses_the_mirrored_keys(self):
        row = parse(finding()).legacy_row()
        self.assertEqual((row["host"], row["port"], row["status"], row["type"], row["scanner"]), (TARGET, "443", "open", "tls", "tls-scanner"))

    def test_endpoint_defaults_to_the_target(self):
        message = parse(finding(endpoint=None))
        self.assertEqual(message.endpoint, {"host": TARGET, "port": None, "scheme": None})
        message = parse(finding(endpoint={"host": "", "port": None, "scheme": None}))
        self.assertEqual(message.endpoint["host"], TARGET)

    def test_text_fields_are_cut_not_rejected(self):
        message = parse(finding(title="t" * 500, evidence="e" * 5000, remediation="r" * 5000))
        self.assertEqual(len(message.title), messages.MAX_TITLE)
        self.assertTrue(message.title.endswith("..."))
        self.assertEqual(len(message.evidence), messages.MAX_EVIDENCE)
        self.assertEqual(len(message.remediation), messages.MAX_REMEDIATION)

    def test_whitespace_is_folded(self):
        message = parse(finding(evidence="  a\n\n b\t c  "))
        self.assertEqual(message.evidence, "a b c")

    def test_lists_are_capped_and_deduplicated(self):
        refs = ["https://example/{0}".format(i) for i in range(15)] + ["https://example/0", "https://" + "x" * 600]
        message = parse(finding(references=refs, compliance=["c{0}".format(i) for i in range(30)]))
        self.assertEqual(len(message.references), messages.MAX_REFERENCES)
        self.assertEqual(message.references[0], "https://example/0")
        self.assertNotIn("https://" + "x" * 600, message.references)
        self.assertEqual(len(message.compliance), messages.MAX_COMPLIANCE)

    def test_template_and_tier_are_optional(self):
        message = parse(finding())
        self.assertIsNone(message.template)
        self.assertIsNone(message.tier)
        message = parse(finding(template="http", tier="passive"))
        self.assertEqual(message.template, "http")
        self.assertEqual(message.tier, "passive")
        self.assertEqual(message.key, ("tls-scanner", "http", TARGET, RUN_ID))

    def test_missing_scanner_version_becomes_unknown(self):
        data = finding()
        del data["scannerVersion"]
        self.assertEqual(parse(data).scanner_version, "unknown")

    def test_rejections(self):
        cases = [
            ("finding", finding(checkId="tls-weak")),
            ("finding", finding(checkId="SAMMA-TLS-" + "X" * 80)),
            ("finding", finding(severity="SEVERE")),
            ("finding", finding(title="")),
            ("finding", finding(title=None)),
            ("finding", finding(endpoint="api.example.com")),
            ("finding", finding(endpoint={"host": TARGET, "port": 70000})),
            ("finding", finding(endpoint={"host": TARGET, "port": "443"})),
            ("finding", finding(endpoint={"host": TARGET, "port": True})),
            ("finding", finding(cveIds=["CVE-1"])),
            ("finding", finding(references="https://example")),
            ("finding", finding(evidence={"a": 1})),
            ("finding", finding(scanner="TLS Scanner")),
            ("finding", finding(target="a.com; id")),
            ("finding", finding(target="*.example.com")),
            ("finding", finding(target="https://api.example.com")),
            ("finding", finding(runId="")),
            ("finding", finding(runId="r" * 300)),
            ("finding", finding(emittedAt="yesterday")),
            ("finding", finding(template="HTTP")),
            ("finding", finding(tier="Deep Tier")),
        ]
        for reason, data in cases:
            with self.subTest(data=dict((k, data[k]) for k in ("checkId", "severity", "title", "endpoint", "target", "runId") if k in data)):
                with self.assertRaises(messages.Rejected) as caught:
                    parse(data)
                self.assertEqual(caught.exception.reason, reason)


class RunTests(unittest.TestCase):
    def test_parses_every_field(self):
        message = parse(run())
        self.assertEqual(message.kind, "run")
        self.assertEqual(message.outcome, "succeeded")
        self.assertEqual(message.message, "")
        self.assertEqual(message.started_at, "2026-10-15T02:00:04Z")
        self.assertEqual(message.finished_at, "2026-10-15T02:00:21Z")
        self.assertEqual(message.finding_count, 1)
        self.assertEqual(message.key, ("tls-scanner", None, TARGET, RUN_ID))

    def test_timestamps_are_normalised_to_utc_seconds(self):
        message = parse(run(startedAt="2026-10-15T04:00:04.123456+02:00", finishedAt="2026-10-15T02:00:21.5Z"))
        self.assertEqual(message.started_at, "2026-10-15T02:00:04Z")
        self.assertEqual(message.finished_at, "2026-10-15T02:00:21Z")
        self.assertEqual(parse(run(startedAt="2026-10-15 02:00:04")).started_at, "2026-10-15T02:00:04Z")

    def test_message_is_capped(self):
        message = parse(run(outcome="failed", message="x" * 2000))
        self.assertEqual(len(message.message), messages.MAX_MESSAGE)

    def test_with_outcome_copies(self):
        original = parse(run())
        changed = original.with_outcome("failed", "bridge received 1 of 3 findings")
        self.assertEqual(original.outcome, "succeeded")
        self.assertEqual(changed.outcome, "failed")
        self.assertEqual(changed.message, "bridge received 1 of 3 findings")
        self.assertEqual(changed.run_id, original.run_id)
        self.assertEqual(changed.kind, "run")

    def test_rejections(self):
        cases = [
            run(outcome="ok"),
            run(findingCount=-1),
            run(findingCount="3"),
            run(findingCount=True),
            run(findingCount=None),
            run(startedAt=None),
            run(finishedAt="2026-13-45T00:00:00Z"),
            run(message=["not", "text"]),
        ]
        for data in cases:
            with self.subTest(data=dict((k, data[k]) for k in ("outcome", "findingCount", "startedAt", "finishedAt", "message"))):
                with self.assertRaises(messages.Rejected) as caught:
                    parse(data)
                self.assertEqual(caught.exception.reason, "run")


class EnvelopeTests(unittest.TestCase):
    def test_payload_rejections(self):
        with self.assertRaises(messages.Rejected) as caught:
            messages.parse(b"not json")
        self.assertEqual(caught.exception.reason, "payload")
        with self.assertRaises(messages.Rejected) as caught:
            messages.parse(b"[1, 2]")
        self.assertEqual(caught.exception.reason, "payload")
        with self.assertRaises(messages.Rejected) as caught:
            messages.parse(b"\xff\xfe")
        self.assertEqual(caught.exception.reason, "payload")
        with self.assertRaises(messages.Rejected) as caught:
            messages.parse(b'{"schema": "samma.io/scan/v2", "pad": "' + b"x" * messages.MAX_PAYLOAD_BYTES + b'"}')
        self.assertEqual(caught.exception.reason, "payload")

    def test_unknown_schema_and_kind(self):
        with self.assertRaises(messages.Rejected) as caught:
            parse(finding(schema="samma.io/scan/v9"))
        self.assertEqual(caught.exception.reason, "schema")
        with self.assertRaises(messages.Rejected) as caught:
            parse(finding(kind="result"))
        self.assertEqual(caught.exception.reason, "kind")

    def test_str_payload_is_accepted(self):
        self.assertEqual(messages.parse(json.dumps(run())).kind, "run")

    def test_cap_text(self):
        self.assertEqual(messages.cap_text(None, 10), "")
        self.assertEqual(messages.cap_text("abc", 10), "abc")
        self.assertEqual(messages.cap_text("abcdefghijkl", 10), "abcdefg...")
        self.assertEqual(len(messages.cap_text("x" * 100, 10)), 10)


if __name__ == "__main__":
    unittest.main()
