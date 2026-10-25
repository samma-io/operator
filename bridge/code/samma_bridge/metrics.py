"""A very small Prometheus exposition: counters, gauges, one summary, and an
HTTP endpoint from the standard library. prometheus_client is not a
dependency of the bridge and this is all it needs.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _label_text(labelnames, values):
    if not labelnames:
        return ""
    return "{" + ",".join('{0}="{1}"'.format(name, _escape(value)) for name, value in zip(labelnames, values)) + "}"


class _Metric(object):
    kind = ""

    def __init__(self, name, help_text, labelnames=()):
        self.name = name
        self.help = help_text
        self.labelnames = tuple(labelnames)
        self._values = {}
        self._lock = threading.Lock()

    def _key(self, labels):
        if len(labels) != len(self.labelnames):
            raise ValueError("{0} takes labels {1}, got {2!r}".format(self.name, self.labelnames, labels))
        return tuple(str(value) for value in labels)

    def value(self, *labels):
        with self._lock:
            return self._values.get(self._key(labels), 0)

    def render(self):
        lines = ["# HELP {0} {1}".format(self.name, self.help), "# TYPE {0} {1}".format(self.name, self.kind)]
        with self._lock:
            items = sorted(self._values.items())
        if not items and not self.labelnames:
            items = [((), 0)]
        for labels, value in items:
            lines.append("{0}{1} {2}".format(self.name, _label_text(self.labelnames, labels), _format(value)))
        return lines


class Counter(_Metric):
    kind = "counter"

    def inc(self, *labels, **kwargs):
        amount = kwargs.pop("amount", 1)
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0) + amount


class Gauge(_Metric):
    kind = "gauge"

    def set(self, value, *labels):
        key = self._key(labels)
        with self._lock:
            self._values[key] = value


class Summary(object):
    """count and sum of observed values (no quantiles)."""

    kind = "summary"

    def __init__(self, name, help_text):
        self.name = name
        self.help = help_text
        self.count = 0
        self.sum = 0.0
        self._lock = threading.Lock()

    def observe(self, value):
        with self._lock:
            self.count += 1
            self.sum += float(value)

    def render(self):
        with self._lock:
            count, total = self.count, self.sum
        return [
            "# HELP {0} {1}".format(self.name, self.help),
            "# TYPE {0} summary".format(self.name),
            "{0}_count {1}".format(self.name, count),
            "{0}_sum {1}".format(self.name, _format(total)),
        ]


def _format(value):
    if isinstance(value, float):
        return repr(value)
    return str(value)


class Registry(object):
    def __init__(self):
        self._metrics = []

    def counter(self, name, help_text, labelnames=()):
        metric = Counter(name, help_text, labelnames)
        self._metrics.append(metric)
        return metric

    def gauge(self, name, help_text, labelnames=()):
        metric = Gauge(name, help_text, labelnames)
        self._metrics.append(metric)
        return metric

    def summary(self, name, help_text):
        metric = Summary(name, help_text)
        self._metrics.append(metric)
        return metric

    def render(self):
        lines = []
        for metric in self._metrics:
            lines.extend(metric.render())
        return "\n".join(lines) + "\n"


class BridgeMetrics(object):
    """Every metric the bridge exposes, in one place."""

    def __init__(self, registry=None):
        self.registry = registry or Registry()
        r = self.registry
        self.received = r.counter("samma_bridge_messages_received_total", "Messages read from NATS, by kind (finding, run, legacy).", ("kind",))
        self.rejected = r.counter("samma_bridge_messages_rejected_total", "Messages that failed validation, by reason.", ("reason",))
        self.dropped = r.counter("samma_bridge_messages_dropped_total", "Valid messages not acted on, by reason (unknown-target, scanners-unavailable, orphan-run).", ("reason",))
        self.reports_written = r.counter("samma_bridge_reports_written_total", "ScanReport status writes, by recorded outcome.", ("outcome",))
        self.report_errors = r.counter("samma_bridge_report_write_errors_total", "ScanReport writes that failed.")
        self.findings_dropped = r.counter("samma_bridge_findings_dropped_total", "Findings left out of a report, by reason (over-limit, info-size, tail-size).", ("reason",))
        self.runs_incomplete = r.counter("samma_bridge_runs_incomplete_total", "Runs finalised with fewer findings than the scanner reported sending.")
        self.runs_pending = r.gauge("samma_bridge_runs_pending", "Runs waiting for their run message or for stragglers.")
        self.db_rows = r.counter("samma_bridge_db_rows_total", "Rows inserted into TimescaleDB.")
        self.db_errors = r.counter("samma_bridge_db_errors_total", "TimescaleDB inserts that failed.")
        self.finalize_seconds = r.summary("samma_bridge_finalize_seconds", "Seconds from a run message to its ScanReport write.")

    def render(self):
        return self.registry.render()


def make_handler(registry, ready=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?", 1)[0] == "/metrics":
                body = registry.render().encode("utf-8")
                self._reply(200, body, "text/plain; version=0.0.4; charset=utf-8")
            elif self.path in ("/healthz", "/livez"):
                self._reply(200, b"ok\n", "text/plain")
            elif self.path == "/readyz":
                ok = ready() if ready is not None else True
                self._reply(200 if ok else 503, b"ok\n" if ok else b"not ready\n", "text/plain")
            else:
                self._reply(404, b"not found\n", "text/plain")

        def _reply(self, status, body, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # keep the bridge log for the bridge
            pass

    return Handler


def start_http_server(registry, port, host="0.0.0.0", ready=None):
    """Serve /metrics, /healthz and /readyz in a daemon thread. Returns the
    server; its server_address tells the port that was bound (useful with
    port 0 in tests)."""
    server = ThreadingHTTPServer((host, int(port)), make_handler(registry, ready))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="samma-bridge-metrics", daemon=True)
    thread.start()
    return server
