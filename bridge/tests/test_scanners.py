"""The cached Scanner list that decides which targets are real."""

import unittest

from .helpers import TARGET, Clock, scanner_object  # noqa: F401
from samma_bridge import reports
from samma_bridge.scanners import ScannerIndex, scanner_names


class ListerSpy(object):
    def __init__(self, items=None, fail=False):
        self.items = list(items or [])
        self.fail = fail
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("apiserver unavailable")
        return list(self.items)


class ScannerIndexTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.lister = ListerSpy([
            scanner_object(name="tls-api", target=TARGET, scanners=["tls-scanner"], uid="u1",
                           labels={reports.LABEL_INGRESS_NAMESPACE: "shop", reports.LABEL_INGRESS_NAME: "api"}),
            scanner_object(name="nmap-api", target=TARGET, scanners=["nmap/http", "nikto"], uid="u2"),
            scanner_object(name="anything-api", target=TARGET, scanners=[], uid="u3"),
            scanner_object(name="dns-other", target="other.example.com", scanners=["dns-scanner"], uid="u4"),
        ])
        self.index = ScannerIndex(self.lister, ttl_seconds=30, clock=self.clock)

    def test_scanner_names(self):
        self.assertEqual(scanner_names(scanner_object(scanners=["nmap/http", "nikto", "nmap"])), ["nmap", "nikto"])
        self.assertEqual(scanner_names(scanner_object(scanners=[])), [])

    def test_is_target(self):
        self.assertFalse(self.index.loaded)
        self.assertTrue(self.index.is_target(TARGET))
        self.assertTrue(self.index.loaded)
        self.assertTrue(self.index.is_target("other.example.com"))
        self.assertFalse(self.index.is_target("evil.example.com"))

    def test_matching_owners_and_labels(self):
        self.assertEqual([o["uid"] for o in self.index.owners("tls-scanner", TARGET)], ["u1", "u3"])
        self.assertEqual([o["uid"] for o in self.index.owners("nmap", TARGET)], ["u2", "u3"])
        self.assertEqual([o["uid"] for o in self.index.owners("dns-scanner", TARGET)], ["u3"])
        self.assertEqual(self.index.owners("dns-scanner", "evil.example.com"), [])
        self.assertEqual(self.index.extra_labels("tls-scanner", TARGET), {reports.LABEL_INGRESS_NAMESPACE: "shop", reports.LABEL_INGRESS_NAME: "api"})
        self.assertEqual(self.index.extra_labels("nmap", TARGET), {})
        owner = self.index.owners("tls-scanner", TARGET)[0]
        self.assertEqual(owner["kind"], "Scanner")
        self.assertEqual(owner["apiVersion"], "samma.io/v1")
        self.assertEqual(owner["name"], "tls-api")

    def test_for_run_picks_the_tenant(self):
        """operator#14: a run is reported under the Scanners of its tenant."""
        a = scanner_object(name="tls-a", uid="ua")
        a["spec"]["samma_io_id"] = "tenant-a"
        b = scanner_object(name="tls-b", uid="ub")
        b["spec"]["samma_io_id"] = "tenant-b"
        shared = scanner_object(name="tls-ingress", uid="ui")
        index = ScannerIndex(ListerSpy([a, b, shared]), ttl_seconds=30, clock=self.clock)
        items, sid = index.for_run("tls-scanner", TARGET, "tenant-a")
        self.assertEqual(([i["metadata"]["uid"] for i in items], sid), (["ua"], "tenant-a"))
        self.assertEqual([o["uid"] for o in index.owners("tls-scanner", TARGET, "tenant-b")], ["ub"])
        # No id, or an id no Scanner has: the Scanners without an id, keyed by target.
        for unknown in (None, "1234"):
            items, sid = index.for_run("tls-scanner", TARGET, unknown)
            self.assertEqual(([i["metadata"]["uid"] for i in items], sid), (["ui"], None))

    def test_cache_ttl(self):
        self.index.is_target(TARGET)
        self.index.is_target(TARGET)
        self.assertEqual(self.lister.calls, 1)
        self.clock.advance(29)
        self.index.is_target(TARGET)
        self.assertEqual(self.lister.calls, 1)
        self.clock.advance(1)
        self.lister.items.append(scanner_object(name="new", target="new.example.com", uid="u5"))
        self.assertTrue(self.index.is_target("new.example.com"))
        self.assertEqual(self.lister.calls, 2)

    def test_failed_refresh_keeps_the_previous_list(self):
        self.assertTrue(self.index.is_target(TARGET))
        self.lister.fail = True
        self.clock.advance(31)
        self.assertTrue(self.index.is_target(TARGET))
        self.assertEqual(self.lister.calls, 2)
        self.clock.advance(5)
        self.index.is_target(TARGET)
        self.assertEqual(self.lister.calls, 2, "a failed list is not retried before ttl")

    def test_nothing_matches_before_the_first_successful_list(self):
        lister = ListerSpy(fail=True)
        index = ScannerIndex(lister, clock=self.clock)
        self.assertFalse(index.refresh())
        self.assertFalse(index.loaded)
        self.assertFalse(index.is_target(TARGET))
        lister.fail = False
        lister.items = [scanner_object()]
        self.clock.advance(31)
        self.assertTrue(index.is_target(TARGET))

    def test_force_refresh(self):
        self.index.is_target(TARGET)
        self.index.refresh(force=True)
        self.assertEqual(self.lister.calls, 2)


if __name__ == "__main__":
    unittest.main()
