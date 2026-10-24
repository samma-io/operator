"""The metrics endpoint and the environment settings."""

import unittest
import urllib.request

from .helpers import CODE_DIR  # noqa: F401
from samma_bridge import metrics
from samma_bridge.config import Config


class MetricsTests(unittest.TestCase):
    def test_exposition_format(self):
        registry = metrics.Registry()
        counter = registry.counter("samma_test_total", "A counter.", ("reason",))
        plain = registry.counter("samma_plain_total", "No labels.")
        gauge = registry.gauge("samma_pending", "A gauge.")
        summary = registry.summary("samma_seconds", "A summary.")
        counter.inc("bad")
        counter.inc("bad")
        counter.inc('we"ird', amount=3)
        gauge.set(4)
        summary.observe(0.5)
        summary.observe(1.5)
        text = registry.render()
        self.assertIn("# HELP samma_test_total A counter.\n# TYPE samma_test_total counter\n", text)
        self.assertIn('samma_test_total{reason="bad"} 2\n', text)
        self.assertIn('samma_test_total{reason="we\\"ird"} 3\n', text)
        self.assertIn("samma_plain_total 0\n", text, "an unlabelled counter renders even before the first inc")
        self.assertIn("samma_pending 4\n", text)
        self.assertIn("samma_seconds_count 2\n", text)
        self.assertIn("samma_seconds_sum 2.0\n", text)
        self.assertEqual(counter.value("bad"), 2)
        plain.inc()
        self.assertEqual(plain.value(), 1)
        with self.assertRaises(ValueError):
            counter.inc()

    def test_bridge_metrics_render(self):
        bm = metrics.BridgeMetrics()
        bm.received.inc("finding")
        bm.rejected.inc("schema")
        bm.reports_written.inc("succeeded")
        bm.finalize_seconds.observe(0.25)
        text = bm.render()
        for name in ("samma_bridge_messages_received_total", "samma_bridge_messages_rejected_total", "samma_bridge_reports_written_total",
                     "samma_bridge_finalize_seconds_count", "samma_bridge_runs_pending", "samma_bridge_db_rows_total"):
            self.assertIn(name, text)

    def test_http_server(self):
        bm = metrics.BridgeMetrics()
        bm.received.inc("legacy")
        state = {"ready": False}
        server = metrics.start_http_server(bm.registry, 0, host="127.0.0.1", ready=lambda: state["ready"])
        try:
            port = server.server_address[1]
            body = urllib.request.urlopen("http://127.0.0.1:{0}/metrics".format(port), timeout=5).read().decode()
            self.assertIn('samma_bridge_messages_received_total{kind="legacy"} 1', body)
            self.assertEqual(urllib.request.urlopen("http://127.0.0.1:{0}/healthz".format(port), timeout=5).status, 200)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen("http://127.0.0.1:{0}/readyz".format(port), timeout=5)
            self.assertEqual(caught.exception.code, 503)
            state["ready"] = True
            self.assertEqual(urllib.request.urlopen("http://127.0.0.1:{0}/readyz".format(port), timeout=5).status, 200)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen("http://127.0.0.1:{0}/nope".format(port), timeout=5)
            self.assertEqual(caught.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        config = Config.from_env({})
        self.assertEqual(config.nats_url, "nats://nats:4222")
        self.assertEqual(config.subjects, ["samma-io.scan", "samma-io.scan.>"])
        self.assertEqual(config.namespace, "samma-io")
        self.assertEqual(config.metrics_port, 9100)
        self.assertEqual(config.scanner_cache_seconds, 30)
        self.assertEqual(config.straggler_wait_seconds, 30)
        self.assertEqual(config.run_idle_timeout_seconds, 3600)
        self.assertFalse(config.database_enabled)
        self.assertTrue(config.scanreports_enabled)
        self.assertEqual(config.nats_connect_options(), {"servers": ["nats://nats:4222"]})

    def test_values(self):
        config = Config.from_env({
            "NATS_URL": "nats://broker:4222", "NATS_SUBJECT": "scans.", "NATS_USER": "bridge", "NATS_PASSWORD": "p@ss word",
            "DATABASE_URL": "postgresql://x", "SAMMA_NAMESPACE": "scans", "METRICS_PORT": "9999",
            "SCANNER_CACHE_SECONDS": "0", "STRAGGLER_WAIT_SECONDS": "5", "RUN_IDLE_TIMEOUT_SECONDS": "10", "SCANREPORTS_ENABLED": "false",
        })
        self.assertEqual(config.subjects, ["scans", "scans.>"])
        self.assertEqual(config.nats_connect_options(), {"servers": ["nats://broker:4222"], "user": "bridge", "password": "p@ss word"})
        self.assertTrue(config.database_enabled)
        self.assertEqual(config.namespace, "scans")
        self.assertEqual(config.metrics_port, 9999)
        self.assertEqual(config.scanner_cache_seconds, 1, "minimum 1")
        self.assertEqual(config.straggler_wait_seconds, 5)
        self.assertEqual(config.run_idle_timeout_seconds, 60, "minimum 60")
        self.assertFalse(config.scanreports_enabled)

    def test_credentials_file_wins(self):
        config = Config.from_env({"NATS_CREDS": "/etc/nats/bridge.creds", "NATS_USER": "bridge", "NATS_PASSWORD": "x"})
        self.assertEqual(config.nats_connect_options(), {"servers": ["nats://nats:4222"], "user_credentials": "/etc/nats/bridge.creds"})

    def test_bad_numbers_fall_back(self):
        config = Config.from_env({"METRICS_PORT": "many", "STRAGGLER_WAIT_SECONDS": "-3"})
        self.assertEqual(config.metrics_port, 9100)
        self.assertEqual(config.straggler_wait_seconds, 0)


if __name__ == "__main__":
    unittest.main()
