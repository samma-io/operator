"""The samma.io client against a local HTTP server."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .helpers import CODE_DIR  # noqa: F401
from samma_collector.dashboard import Dashboard, DashboardError, NotFound

TOKEN = "s3cret-token"


class Handler(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Handler.seen.append((self.path, self.headers.get("Authorization")))
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self._json(401, {"error": "Unauthorized"})
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        if parts.path == "/api/v1/targets":
            if "cursor" not in query:
                return self._json(200, {"targets": [{"id": "t1", "value": "a"}], "nextCursor": "t1"})
            return self._json(200, {"targets": [{"id": "t2", "value": "b"}]})
        if parts.path == "/api/v1/targets/t1/results":
            return self._json(200, {"targetId": "t1", "runs": [], "results": [], "limit": query["limit"][0]})
        if parts.path == "/api/v1/targets/broken/results":
            return self._json(503, {"error": "Scan results unavailable"})
        return self._json(404, {"error": "Target not found"})

    def _json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:{0}/".format(cls.server.server_address[1])

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_pages_targets(self):
        client = Dashboard(self.url, TOKEN)
        self.assertEqual([t["id"] for t in client.targets()], ["t1", "t2"])

    def test_results(self):
        body = Dashboard(self.url, TOKEN).results("t1")
        self.assertEqual(body["limit"], "500")

    def test_errors(self):
        client = Dashboard(self.url, TOKEN)
        with self.assertRaises(NotFound):
            client.results("nope")
        with self.assertRaises(DashboardError) as caught:
            client.results("broken")
        self.assertEqual(caught.exception.kind, "http")

    def test_bad_token_is_auth_and_not_echoed(self):
        with self.assertRaises(DashboardError) as caught:
            Dashboard(self.url, "wrong-token").targets()
        self.assertEqual(caught.exception.kind, "auth")
        self.assertNotIn("wrong-token", str(caught.exception))

    def test_network_error(self):
        with self.assertRaises(DashboardError) as caught:
            Dashboard("http://127.0.0.1:1", TOKEN, timeout=2).targets()
        self.assertEqual(caught.exception.kind, "network")


if __name__ == "__main__":
    unittest.main()
