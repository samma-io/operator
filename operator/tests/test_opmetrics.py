"""Unit tests for operator/code/opmetrics.py: the operator's metrics and
that its exposition code is still the bridge's."""

import os
import sys
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(os.path.dirname(HERE), "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import opmetrics  # noqa: E402

BRIDGE_METRICS = os.path.join(os.path.dirname(os.path.dirname(HERE)), "bridge", "code", "samma_bridge", "metrics.py")


def _between(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


class OperatorMetricsTests(unittest.TestCase):
    def test_render(self):
        om = opmetrics.OperatorMetrics()
        text = om.render()
        for name in ("samma_operator_jobs_created_total 0\n", "samma_operator_scan_queue_pending 0\n",
                     "samma_operator_scan_jobs_running 0\n", "samma_operator_queue_last_tick_timestamp_seconds 0\n"):
            self.assertIn(name, text, "unlabelled metrics render before the first event")
        om.scanners_handled.inc("create")
        om.scanners_rejected.inc("target-rejected")
        om.jobs_created.inc()
        om.job_outcomes.inc("timed_out")
        om.registrations.inc("ok")
        om.queue_pending.set(3)
        text = om.render()
        self.assertIn('samma_operator_scanners_handled_total{event="create"} 1\n', text)
        self.assertIn('samma_operator_scanners_rejected_total{reason="target-rejected"} 1\n', text)
        self.assertIn("samma_operator_jobs_created_total 1\n", text)
        self.assertIn('samma_operator_job_outcomes_total{outcome="timed_out"} 1\n', text)
        self.assertIn('samma_operator_target_registrations_total{result="ok"} 1\n', text)
        self.assertIn("samma_operator_scan_queue_pending 3\n", text)

    def test_http_endpoint(self):
        om = opmetrics.OperatorMetrics()
        om.jobs_created.inc()
        server = opmetrics.start_http_server(om.registry, 0, host="127.0.0.1")
        try:
            port = server.server_address[1]
            with urllib.request.urlopen("http://127.0.0.1:{0}/metrics".format(port), timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("samma_operator_jobs_created_total 1\n", resp.read().decode("utf-8"))
            with urllib.request.urlopen("http://127.0.0.1:{0}/healthz".format(port), timeout=5) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            server.shutdown()
            server.server_close()

    def test_exposition_is_the_bridges(self):
        """The metric classes are a copy; a fix in one must reach the other."""
        with open(BRIDGE_METRICS) as handle:
            bridge = handle.read()
        with open(opmetrics.__file__) as handle:
            operator = handle.read()
        self.assertEqual(_between(operator, "def _escape", "class OperatorMetrics"),
                         _between(bridge, "def _escape", "class BridgeMetrics"))
        self.assertEqual(_between(operator, "class _IPv6HTTPServer", "def start_http_server"),
                         _between(bridge, "class _IPv6HTTPServer", "def start_http_server"))


if __name__ == "__main__":
    unittest.main()
