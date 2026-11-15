"""A very small Prometheus exposition: counters, gauges, one summary, and an
HTTP endpoint from the standard library. A copy of the bridge's
samma_bridge/metrics.py plus Gauge.replace; the collector's own metrics are
in CollectorMetrics. prometheus_client is not a dependency.
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

    def replace(self, values):
        """Swap every series at once: ``values`` maps label tuples to values.
        A series missing from it is gone from the next scrape, so a target or
        scanner that disappeared does not keep its last value."""
        fresh = {self._key(labels): value for labels, value in values.items()}
        with self._lock:
            self._values = fresh

    def series(self):
        with self._lock:
            return dict(self._values)


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


class CollectorMetrics(object):
    """Every metric the collector exposes, in one place. Labels are bounded:
    target is a host of an opted-in Ingress of this cluster, scanner one of
    the scanner names, severity one of SEVERITY_LABELS."""

    def __init__(self, registry=None, version="dev"):
        self.registry = registry or Registry()
        r = self.registry
        self.info = r.gauge("samma_collector_info", "Always 1; the collector's release.", ("version",))
        self.info.set(1, version)
        self.findings = r.gauge("samma_findings", "Findings of the latest run of a scanner against a target, by severity.", ("target", "scanner", "severity"))
        self.last_finished = r.gauge("samma_scan_last_finished_timestamp_seconds", "When the latest run of a scanner against a target finished (Unix time).", ("target", "scanner"))
        self.outcome = r.gauge("samma_scan_outcome", "1 for the outcome of the latest run of a scanner against a target.", ("target", "scanner", "outcome"))
        self.target_info = r.gauge("samma_target_info", "1 per target on samma.io that a local Ingress serves.", ("target", "target_id", "scanner_status", "reachability"))
        self.polls = r.counter("samma_collector_polls_total", "Polls of samma.io, by result (ok, auth, http, network, kube, config, error).", ("result",))
        self.last_success = r.gauge("samma_collector_last_success_timestamp_seconds", "When the last poll succeeded (Unix time); 0 before the first.")
        self.targets = r.gauge("samma_collector_targets", "Targets on samma.io that match a local Ingress host.")
        self.unmatched = r.gauge("samma_collector_unmatched_hosts", "Opted-in Ingress hosts with no target on samma.io (yet).")
        self.truncated = r.counter("samma_collector_results_truncated_total", "Result fetches that hit the API's limit, so some findings were not logged.")
        self.findings_logged = r.counter("samma_collector_findings_logged_total", "Finding log lines written.")
        self.poll_seconds = r.summary("samma_collector_poll_seconds", "Seconds a successful poll took.")

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

        def log_message(self, format, *args):  # keep the collector log for findings
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
    thread = threading.Thread(target=server.serve_forever, name="samma-collector-metrics", daemon=True)
    thread.start()
    return server
