"""The poller: matching, gauges, finding log lines."""

import unittest

from .helpers import FakeDashboard, finding, run
from samma_collector.dashboard import DashboardError
from samma_collector.kube import KubeError
from samma_collector.metrics import CollectorMetrics
from samma_collector.poller import Poller, severity_counts


def target(id_, value, status="DEPLOYED"):
    return {"id": id_, "value": value, "scannerStatus": status, "reachabilityStatus": "UP"}


class PollerTests(unittest.TestCase):
    def setUp(self):
        self.hosts = {"app.example.com"}
        self.dashboard = FakeDashboard(
            targets=[target("t1", "app.example.com"), target("t2", "other.example.org")],
            results={
                "t1": {
                    "runs": [run("tls-scanner", HIGH=2, INFO=1)],
                    "results": [finding("tls-scanner"), finding("tls-scanner", check="TLS-WEAK-CIPHER"), finding("tls-scanner", severity="INFO", check="TLS-INFO")],
                },
                "t2": {"runs": [run("tls-scanner", CRITICAL=5)], "results": []},
            },
        )
        self.metrics = CollectorMetrics(version="test")
        self.lines = []
        self.now = [1000.0]
        self.poller = Poller(self.dashboard, lambda: self.hosts, self.metrics, self.lines.append, clock=lambda: self.now[0])

    def test_only_local_hosts_are_exported(self):
        self.assertTrue(self.poller.poll())
        self.assertNotIn("t2", self.dashboard.calls, "a target no local Ingress serves is not fetched")
        series = self.metrics.findings.series()
        self.assertEqual(series[("app.example.com", "tls-scanner", "HIGH")], 2)
        self.assertEqual(series[("app.example.com", "tls-scanner", "CRITICAL")], 0, "known severities are zero-filled")
        self.assertFalse(any(k[0] == "other.example.org" for k in series))
        self.assertEqual(self.metrics.targets.value(), 1)
        self.assertEqual(self.metrics.unmatched.value(), 0)
        self.assertEqual(self.metrics.polls.value("ok"), 1)
        self.assertEqual(self.metrics.last_success.value(), 1000.0)
        self.assertIn(("app.example.com", "t1", "DEPLOYED", "UP"), self.metrics.target_info.series())
        self.assertIn(("app.example.com", "tls-scanner", "succeeded"), self.metrics.outcome.series())
        finished = self.metrics.last_finished.series()[("app.example.com", "tls-scanner")]
        self.assertAlmostEqual(finished, 1794312000.0)

    def test_host_matching_ignores_case_and_trailing_dot(self):
        self.dashboard.target_list = [target("t1", "App.Example.com.")]
        self.poller.poll()
        self.assertEqual(self.metrics.targets.value(), 1)

    def test_unmatched_hosts_are_counted(self):
        self.hosts = {"app.example.com", "new.example.com"}
        self.poller.poll()
        self.assertEqual(self.metrics.unmatched.value(), 1)

    def test_findings_logged_once_per_run_without_evidence(self):
        self.poller.poll()
        self.assertEqual(len(self.lines), 3)
        line = self.lines[0]
        self.assertEqual(line["event"], "samma.finding")
        self.assertEqual(line["target"], "app.example.com")
        self.assertEqual(line["runId"], "r1")
        self.assertNotIn("evidence", line)
        self.assertNotIn("remediation", line)
        self.assertNotIn("hunter2", repr(self.lines))
        self.poller.poll()
        self.assertEqual(len(self.lines), 3, "the same run is not logged twice")
        self.assertEqual(self.metrics.findings_logged.value(), 3)

    def test_new_run_is_logged(self):
        self.poller.poll()
        self.dashboard.result_map["t1"] = {
            "runs": [run("tls-scanner", run_id="r2", finished="2026-11-11T12:00:00Z", HIGH=1)],
            "results": [finding("tls-scanner", run_id="r2"), finding("tls-scanner", run_id="r1", check="OLD")],
        }
        self.poller.poll()
        self.assertEqual(len(self.lines), 4, "only the new run's finding")
        self.assertEqual(self.lines[-1]["runId"], "r2")

    def test_logging_can_be_turned_off(self):
        self.poller.log_findings = False
        self.poller.poll()
        self.assertEqual(self.lines, [])

    def test_gone_target_loses_its_series(self):
        self.poller.poll()
        self.hosts = set()
        self.poller.poll()
        self.assertEqual(self.metrics.findings.series(), {})
        self.assertEqual(self.metrics.target_info.series(), {})
        self.assertEqual(self.metrics.targets.value(), 0)

    def test_failed_poll_keeps_previous_values(self):
        self.poller.poll()
        before = self.metrics.findings.series()
        self.dashboard.fail = DashboardError("auth", "HTTP 401")
        self.assertFalse(self.poller.poll())
        self.assertEqual(self.metrics.findings.series(), before)
        self.assertEqual(self.metrics.polls.value("auth"), 1)

    def test_kube_failure_is_counted(self):
        def broken():
            raise KubeError("forbidden")

        self.poller.hosts = broken
        self.assertFalse(self.poller.poll())
        self.assertEqual(self.metrics.polls.value("kube"), 1)

    def test_target_deleted_mid_poll_is_skipped(self):
        self.dashboard.target_list.append(target("gone", "app.example.com"))
        self.assertTrue(self.poller.poll())
        self.assertEqual(self.metrics.target_info.series(), {("app.example.com", "t1", "DEPLOYED", "UP"): 1})

    def test_duplicate_targets_newest_run_wins(self):
        self.dashboard.target_list.append(target("t3", "app.example.com"))
        self.dashboard.result_map["t3"] = {
            "runs": [run("tls-scanner", run_id="r9", finished="2026-11-11T00:00:00Z", HIGH=7)],
            "results": [],
        }
        self.poller.poll()
        self.assertEqual(self.metrics.findings.series()[("app.example.com", "tls-scanner", "HIGH")], 7)
        self.assertEqual(len(self.metrics.target_info.series()), 2)

    def test_legacy_run_without_run_id(self):
        self.dashboard.result_map["t1"] = {
            "runs": [run("nmap", run_id=None, NONE=4)],
            "results": [finding("nmap", run_id=None, severity=None)],
        }
        self.poller.poll()
        self.assertEqual(self.metrics.findings.series()[("app.example.com", "nmap", "UNKNOWN")], 4)
        self.assertIn(("app.example.com", "nmap", "unknown"), self.metrics.outcome.series())
        self.assertEqual(len(self.lines), 1)

    def test_truncated_results_are_counted(self):
        self.dashboard.result_map["t1"]["results"] = [finding("tls-scanner", check="C-%03d" % i) for i in range(500)]
        self.poller.poll()
        self.assertEqual(self.metrics.truncated.value(), 1)


class SeverityTests(unittest.TestCase):
    def test_counts(self):
        counts = severity_counts({"severity": {"HIGH": 2, "low": 1, "NONE": 3, "BOGUS": 1}})
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["UNKNOWN"], 4)
        self.assertEqual(counts["CRITICAL"], 0)


if __name__ == "__main__":
    unittest.main()
