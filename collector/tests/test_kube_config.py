"""Ingress opt-in rules, settings, and the metrics endpoint."""

import unittest
import urllib.request

from .helpers import ingress
from samma_collector import metrics
from samma_collector.config import Config
from samma_collector.kube import KubeError, InClusterIngresses, opted_in_hosts


class OptInTests(unittest.TestCase):
    def test_rules(self):
        items = [
            ingress("a", ["App.Example.com", "*.example.com", None]),
            ingress("b", ["off.example.com"], enable="false"),
            ingress("c", ["none.example.com"], enable=None),
            ingress("d", ["blank.example.com"], enable=""),
            ingress("e", ["other-ns.example.com"], namespace="web"),
        ]
        self.assertEqual(opted_in_hosts(items, "samma-io", []), {"app.example.com", "blank.example.com"})
        self.assertIn("other-ns.example.com", opted_in_hosts(items, "samma-io", ["web"]))
        self.assertIn("other-ns.example.com", opted_in_hosts(items, "samma-io", ["*"]))

    def test_outside_cluster(self):
        with self.assertRaises(KubeError):
            InClusterIngresses.from_env({})

    def test_operator_copy_agrees(self):
        """The opt-in words and annotation match the operator's."""
        import os
        from .helpers import REPO_DIR
        from samma_collector import kube
        with open(os.path.join(REPO_DIR, "operator", "code", "operator_handler.py")) as handle:
            source = handle.read()
        self.assertIn("FALSE_WORDS = {0!r}".format(kube.FALSE_WORDS), source)
        with open(os.path.join(REPO_DIR, "operator", "code", "ingress_optin.py")) as handle:
            self.assertIn("'samma-io.alpha.kubernetes.io/'", handle.read())


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        config = Config.from_env({})
        self.assertEqual(config.api_url, "https://www.samma.io")
        self.assertEqual(config.poll_interval_seconds, 300)
        self.assertEqual(config.metrics_port, 9100)
        self.assertTrue(config.log_findings)
        self.assertEqual(len(config.problems()), 1, "no token")

    def test_values(self):
        config = Config.from_env({
            "SAMMA_IO_API_URL": "https://samma.example/ ",
            "SAMMA_IO_API_TOKEN": "abc",
            "POLL_INTERVAL_SECONDS": "5",
            "LOG_FINDINGS": "false",
            "SAMMA_INGRESS_NAMESPACES": "web, shop",
            "COLLECTOR_HOSTS": "A.example.com,",
        })
        self.assertEqual(config.api_url, "https://samma.example")
        self.assertEqual(config.poll_interval_seconds, 30, "floored")
        self.assertFalse(config.log_findings)
        self.assertEqual(config.ingress_namespaces, ["web", "shop"])
        self.assertEqual(config.static_hosts, ["a.example.com"])
        self.assertEqual(config.problems(), [])

    def test_bad_url(self):
        config = Config(api_url="ftp://x", api_token="t")
        self.assertEqual(len(config.problems()), 1)


class MetricsEndpointTests(unittest.TestCase):
    def test_serves_metrics_and_replace(self):
        m = metrics.CollectorMetrics(version="1.2.3")
        m.findings.replace({("a.example.com", "tls-scanner", "HIGH"): 2})
        m.findings.replace({("b.example.com", "tls-scanner", "LOW"): 1})
        server = metrics.start_http_server(m.registry, 0, host="127.0.0.1", ready=lambda: False)
        try:
            port = server.server_address[1]
            text = urllib.request.urlopen("http://127.0.0.1:{0}/metrics".format(port)).read().decode()
            self.assertIn('samma_collector_info{version="1.2.3"} 1', text)
            self.assertIn('samma_findings{target="b.example.com",scanner="tls-scanner",severity="LOW"} 1', text)
            self.assertNotIn("a.example.com", text)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen("http://127.0.0.1:{0}/readyz".format(port))
            self.assertEqual(caught.exception.code, 503)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
