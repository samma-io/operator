"""Collector settings, read from the environment once at startup."""

import os
from urllib.parse import urlsplit


class Config(object):
    def __init__(
        self,
        api_url="https://www.samma.io",
        api_token="",
        poll_interval_seconds=300,
        request_timeout_seconds=15,
        metrics_port=9100,
        log_findings=True,
        namespace="samma-io",
        ingress_namespaces=(),
        static_hosts=(),
        version="dev",
    ):
        self.api_url = (api_url or "").strip().rstrip("/")
        self.api_token = api_token
        self.poll_interval_seconds = poll_interval_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.metrics_port = metrics_port
        self.log_findings = log_findings
        self.namespace = namespace
        # The operator's rule (ingress_optin.ingress_namespace_allowed): its
        # own namespace always, plus these; '*' is every namespace.
        self.ingress_namespaces = list(ingress_namespaces)
        # For a local run without a cluster: these hosts instead of the
        # Ingress listing. Empty in the chart.
        self.static_hosts = [h.strip().lower() for h in static_hosts if h.strip()]
        self.version = (version or "").strip() or "dev"

    def problems(self):
        """What keeps the collector from polling, as sentences; [] is fine."""
        found = []
        if not self.api_token:
            found.append("SAMMA_IO_API_TOKEN is empty: create a read-only token on the samma.io tokens page")
        parts = urlsplit(self.api_url)
        if parts.scheme not in ("https", "http") or not parts.netloc:
            found.append("SAMMA_IO_API_URL must be an http(s) URL, got {0!r}".format(self.api_url))
        return found

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ

        def text(name, default=""):
            value = env.get(name)
            return default if value is None else value.strip()

        def number(name, default, minimum=0):
            raw = text(name)
            if not raw:
                return default
            try:
                return max(minimum, int(raw))
            except ValueError:
                return default

        def flag(name, default):
            raw = text(name).lower()
            if not raw:
                return default
            return raw in ("1", "true", "yes", "on")

        def items(name):
            return [entry.strip() for entry in text(name).split(",") if entry.strip()]

        return cls(
            api_url=text("SAMMA_IO_API_URL", "https://www.samma.io"),
            api_token=text("SAMMA_IO_API_TOKEN"),
            poll_interval_seconds=number("POLL_INTERVAL_SECONDS", 300, minimum=30),
            request_timeout_seconds=number("REQUEST_TIMEOUT_SECONDS", 15, minimum=1),
            metrics_port=number("METRICS_PORT", 9100),
            log_findings=flag("LOG_FINDINGS", True),
            namespace=text("SAMMA_NAMESPACE", "samma-io"),
            ingress_namespaces=items("SAMMA_INGRESS_NAMESPACES"),
            static_hosts=items("COLLECTOR_HOSTS"),
            version=text("SAMMA_VERSION", "dev"),
        )
