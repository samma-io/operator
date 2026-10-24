"""Bridge settings, read from the environment once at startup."""

import os


class Config(object):
    def __init__(
        self,
        nats_url="nats://nats:4222",
        nats_subject="samma-io.scan",
        nats_user="",
        nats_password="",
        nats_creds="",
        database_url="",
        namespace="samma-io",
        metrics_port=9100,
        scanner_cache_seconds=30,
        straggler_wait_seconds=30,
        run_idle_timeout_seconds=3600,
        scanreports_enabled=True,
    ):
        self.nats_url = nats_url
        self.nats_subject = (nats_subject or "samma-io.scan").strip().rstrip(".") or "samma-io.scan"
        self.nats_user = nats_user
        self.nats_password = nats_password
        self.nats_creds = nats_creds
        self.database_url = database_url
        self.namespace = namespace
        self.metrics_port = metrics_port
        self.scanner_cache_seconds = scanner_cache_seconds
        self.straggler_wait_seconds = straggler_wait_seconds
        self.run_idle_timeout_seconds = run_idle_timeout_seconds
        self.scanreports_enabled = scanreports_enabled

    @property
    def subjects(self):
        """The subjects the bridge subscribes to: the base subject the
        classic scanners still publish on, and <base>.> for the per-scanner
        subjects the operator hands out."""
        return [self.nats_subject, self.nats_subject + ".>"]

    @property
    def database_enabled(self):
        return bool(self.database_url)

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

        return cls(
            nats_url=text("NATS_URL", "nats://nats:4222"),
            nats_subject=text("NATS_SUBJECT", "samma-io.scan"),
            nats_user=text("NATS_USER"),
            nats_password=env.get("NATS_PASSWORD", "") or "",
            nats_creds=text("NATS_CREDS"),
            database_url=text("DATABASE_URL"),
            namespace=text("SAMMA_NAMESPACE", "samma-io"),
            metrics_port=number("METRICS_PORT", 9100),
            scanner_cache_seconds=number("SCANNER_CACHE_SECONDS", 30, minimum=1),
            straggler_wait_seconds=number("STRAGGLER_WAIT_SECONDS", 30),
            run_idle_timeout_seconds=number("RUN_IDLE_TIMEOUT_SECONDS", 3600, minimum=60),
            scanreports_enabled=flag("SCANREPORTS_ENABLED", True),
        )

    def nats_connect_options(self):
        """Keyword arguments for nats.connect(). A credentials file
        (NATS_CREDS) wins over a user and password; with neither, the URL's
        own userinfo, if any, is used by the client."""
        options = {"servers": [self.nats_url]}
        if self.nats_creds:
            options["user_credentials"] = self.nats_creds
        elif self.nats_user:
            options["user"] = self.nats_user
            options["password"] = self.nats_password
        return options
