"""Prometheus metrics of the operator: a copy of the bridge's small
exposition (bridge/code/samma_bridge/metrics.py; counters, gauges, an HTTP
endpoint from the standard library) plus OperatorMetrics. prometheus_client
is not a dependency of the operator and this is all it needs.
"""

import socket
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


class OperatorMetrics(object):
    """Every metric the operator exposes, in one place. No label carries a
    target, a tenant id or an object name."""

    def __init__(self, registry=None):
        self.registry = registry or Registry()
        r = self.registry
        self.scanners_handled = r.counter("samma_operator_scanners_handled_total", "Scanner events handled to the end, by event (create, resume, update, delete).", ("event",))
        self.scanners_rejected = r.counter("samma_operator_scanners_rejected_total", "Scanners refused or put on retry, by reason (target-rejected, target-unresolvable, scanner-rejected, no-scanner).", ("reason",))
        self.jobs_created = r.counter("samma_operator_jobs_created_total", "Scan Jobs the operator created (first scans; scheduled runs are created by their CronJobs).")
        self.job_outcomes = r.counter("samma_operator_job_outcomes_total", "Scan Jobs that ended badly and were written to a ScanReport, by outcome (failed, timed_out).", ("outcome",))
        self.queue_pending = r.gauge("samma_operator_scan_queue_pending", "First scans waiting in the queue for a free slot.")
        self.jobs_running = r.gauge("samma_operator_scan_jobs_running", "Unfinished scan Jobs holding a slot, as of the last queue tick.")
        self.jobs_suspended = r.gauge("samma_operator_scan_jobs_suspended", "Scheduled scan Jobs waiting suspended for a slot, as of the last queue tick.")
        self.last_tick = r.gauge("samma_operator_queue_last_tick_timestamp_seconds", "Unix time of the last completed queue tick. The queue thread is stuck when this stops moving.")
        self.registrations = r.counter("samma_operator_target_registrations_total", "Targets sent to samma.io (PUT /api/v1/targets), by result (ok, refused, error).", ("result",))

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

        def log_message(self, format, *args):  # keep the operator log for the operator
            pass

    return Handler


class _IPv6HTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class _DualStackHTTPServer(_IPv6HTTPServer):
    """Listens on "::" with IPV6_V6ONLY off, so IPv4 clients arrive as
    IPv4-mapped addresses on the same socket."""

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def _make_server(host, port, handler):
    if host is None:
        # Every address of both families. A pod's address is IPv6 on an
        # IPv6 or IPv6-first dual-stack cluster, and the kubelet probes that
        # address: a "0.0.0.0" listener refuses it and the pod never gets
        # ready. Without IPv6 in the kernel (ipv6.disable=1) the AF_INET6
        # socket cannot be made, and IPv4 is all there is.
        if socket.has_ipv6:
            try:
                return _DualStackHTTPServer(("::", port), handler)
            except OSError:
                pass
        return ThreadingHTTPServer(("0.0.0.0", port), handler)
    if ":" in host:
        return _IPv6HTTPServer((host, port), handler)
    return ThreadingHTTPServer((host, port), handler)


def start_http_server(registry, port, host=None, ready=None):
    """Serve /metrics, /healthz and /readyz in a daemon thread. Returns the
    server; its server_address tells the port that was bound (useful with
    port 0 in tests). host None listens on every IPv4 and IPv6 address."""
    server = _make_server(host, int(port), make_handler(registry, ready))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="samma-operator-metrics", daemon=True)
    thread.start()
    return server
