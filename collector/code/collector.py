"""samma collector: pulls the scan results of this cluster's opted-in Ingress
hosts from samma.io and exposes them as Prometheus metrics on METRICS_PORT
and as one JSON log line per finding on stdout.

Operational messages go to stderr; stdout carries finding lines only, so a
log shipper can take stdout as is.
"""

import json
import logging
import os
import signal
import sys
import threading

from samma_collector.config import Config
from samma_collector.dashboard import Dashboard
from samma_collector.kube import InClusterIngresses, KubeError, opted_in_hosts
from samma_collector.metrics import CollectorMetrics, start_http_server
from samma_collector.poller import Poller

log = logging.getLogger("samma.collector")


def emit(record):
    sys.stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def make_hosts(config):
    if config.static_hosts:
        static = set(config.static_hosts)
        log.info("COLLECTOR_HOSTS set: using %d fixed hosts instead of the Ingress listing", len(static))
        return lambda: static
    try:
        client = InClusterIngresses.from_env(os.environ, timeout=config.request_timeout_seconds)
    except KubeError as exc:
        error = exc

        def failing():
            raise error

        return failing
    return lambda: opted_in_hosts(client.list(), config.namespace, config.ingress_namespaces)


def main():
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = Config.from_env()
    metrics = CollectorMetrics(version=config.version)
    problems = config.problems()
    start_http_server(metrics.registry, config.metrics_port, ready=lambda: not problems)
    log.info(
        "samma collector %s: polling %s every %ds, Ingress namespaces %s, finding logs %s",
        config.version, config.api_url, config.poll_interval_seconds,
        ", ".join([config.namespace] + config.ingress_namespaces), "on" if config.log_findings else "off",
    )

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    poller = None
    if not problems:
        dashboard = Dashboard(config.api_url, config.api_token, timeout=config.request_timeout_seconds, version=config.version)
        poller = Poller(dashboard, make_hosts(config), metrics, emit, log_findings=config.log_findings)

    while not stop.is_set():
        if poller is None:
            for problem in problems:
                log.error("%s", problem)
            metrics.polls.inc("config")
        else:
            try:
                poller.poll()
            except Exception:  # keep serving metrics; the next poll may work
                log.exception("poll failed")
                metrics.polls.inc("error")
        stop.wait(config.poll_interval_seconds)
    log.info("samma collector stopping")


if __name__ == "__main__":
    main()
