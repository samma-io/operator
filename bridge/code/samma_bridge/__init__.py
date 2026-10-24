"""The samma bridge: NATS messages in, ScanReports (and TimescaleDB rows) out.

The package is split so that everything that decides something is plain
Python with no third-party import:

    config.py       settings from the environment
    messages.py     parse and validate one NATS message (schema v2 or legacy v1)
    accumulator.py  collect the findings of one run until its run message
    reports.py      ScanReport naming, deduplication, size caps, status bodies,
                    and the create-or-update loop against an injected store
    scanners.py     the cached list of Scanners a message must match
    metrics.py      a tiny Prometheus registry and HTTP endpoint

    kube.py         the kubernetes client adapter (imported lazily)
    ../bridge.py    the asyncio entry point: NATS, asyncpg and the wiring

bridge/tests exercises the pure modules without nats-py, asyncpg or the
kubernetes client installed.
"""

__version__ = "0.2.0"
