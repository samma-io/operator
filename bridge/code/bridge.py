"""The samma bridge: NATS in, ScanReports and TimescaleDB rows out.

Subscribes to the scan subjects (NATS_SUBJECT and NATS_SUBJECT.>), stores
every message in TimescaleDB when DATABASE_URL is set (as it always did),
and turns schema v2 messages into ScanReports in SAMMA_NAMESPACE: the
findings of a run are collected until its run message, then written in one
go when the run succeeded, or recorded as a failed run with the previous
findings kept. Metrics on :METRICS_PORT (default 9100).

Everything that decides something lives in the samma_bridge package and
has unit tests; this file is the asyncio wiring.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from samma_bridge import messages as message_schema  # noqa: E402
from samma_bridge.accumulator import Accumulator  # noqa: E402
from samma_bridge.config import Config  # noqa: E402
from samma_bridge.metrics import BridgeMetrics, start_http_server  # noqa: E402
from samma_bridge.pipeline import Pipeline  # noqa: E402
from samma_bridge.scanners import ScannerIndex  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("samma.bridge")

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scan_results (
    time       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    host       TEXT,
    port       TEXT,
    status     TEXT,
    type       TEXT,
    scanner    TEXT,
    samma_id   TEXT,
    tags       TEXT,
    raw        JSONB
);
SELECT create_hypertable('scan_results', 'time', if_not_exists => TRUE);
"""

CREATE_READER_ROLE = """
DO $ BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'samma_reader') THEN
        CREATE ROLE samma_reader NOLOGIN;
    END IF;
END $;
GRANT SELECT ON scan_results TO samma_reader;
"""

INSERT_ROW = """INSERT INTO scan_results
   (host, port, status, type, scanner, samma_id, tags, raw)
   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"""

TICK_SECONDS = 1.0


async def connect_database(url):
    import asyncpg  # third-party, installed in the image

    while True:
        try:
            db = await asyncpg.connect(url)
            break
        except Exception as exc:
            log.warning("DB not ready, retrying in 5s: %s", exc)
            await asyncio.sleep(5)
    await db.execute(CREATE_TABLE)
    await db.execute(CREATE_READER_ROLE)
    log.info("TimescaleDB ready")
    log.info("samma_reader role ready")
    return db


async def connect_nats(config):
    import nats  # third-party, installed in the image

    options = config.nats_connect_options()
    options.update({
        "name": "samma-bridge",
        "max_reconnect_attempts": -1,
        "reconnect_time_wait": 2,
        "error_cb": _nats_error,
        "disconnected_cb": _nats_disconnected,
        "reconnected_cb": _nats_reconnected,
    })
    nc = await nats.connect(**options)
    how = "credentials file" if config.nats_creds else ("user {0}".format(config.nats_user) if config.nats_user else "no credentials")
    log.info("Connected to NATS at %s with %s", config.nats_url, how)
    return nc


async def _nats_error(exc):
    log.warning("NATS error: %s", exc)


async def _nats_disconnected():
    log.warning("NATS disconnected")


async def _nats_reconnected():
    log.info("NATS reconnected")


async def main():
    config = Config.from_env()
    metrics = BridgeMetrics()
    state = {"ready": False}
    start_http_server(metrics.registry, config.metrics_port, ready=lambda: state["ready"])
    log.info("samma bridge %s: metrics on :%d, namespace %s, ScanReports %s, TimescaleDB %s",
             config.version, config.metrics_port, config.namespace,
             "on" if config.scanreports_enabled else "off", "on" if config.database_enabled else "off")

    db = await connect_database(config.database_url) if config.database_enabled else None

    pipeline = None
    index = None
    if config.scanreports_enabled or config.database_enabled:
        # The Scanner list also gates the TimescaleDB rows (issue #12): a
        # row is stored only when a current Scanner owns the message's
        # target and tenant id, so a scanner pod cannot plant findings
        # under another tenant's id.
        from samma_bridge.kube import KubeStore

        store = KubeStore(config.namespace)
        index = ScannerIndex(store.list_scanners, ttl_seconds=config.scanner_cache_seconds)
        index.refresh(force=True)

    if config.scanreports_enabled:
        pipeline = Pipeline(
            config.namespace, store, index, metrics,
            accumulator=Accumulator(config.straggler_wait_seconds, config.run_idle_timeout_seconds),
        )

    nc = await connect_nats(config)
    writes = asyncio.Queue()
    loop = asyncio.get_running_loop()

    async def store_row(message):
        if db is None:
            return
        row = message.legacy_row()
        # index exists whenever the database is on (see above); a message
        # whose target and tenant id no current Scanner owns is dropped.
        if not index.allows(row["host"], row["samma_id"]):
            metrics.dropped.inc("unknown-tenant")
            log.warning("Dropped row for %s under tenant id %s: no Scanner in %s owns that target and id",
                        row["host"], row["samma_id"], config.namespace)
            return
        try:
            await db.execute(INSERT_ROW, row["host"], row["port"], row["status"], row["type"],
                             row["scanner"], row["samma_id"], row["tags"], row["raw"])
            metrics.db_rows.inc()
        except Exception as exc:
            metrics.db_errors.inc()
            log.error("Failed to store message: %s", exc)

    def parse_counted(payload):
        """messages.parse with the counters, for the TimescaleDB-only mode."""
        try:
            parsed = message_schema.parse(payload)
        except message_schema.Rejected as exc:
            metrics.rejected.inc(exc.reason)
            log.warning("Rejected message (%s): %s", exc.reason, exc.detail)
            return None
        metrics.received.inc(parsed.kind)
        return parsed

    async def handler(msg):
        if pipeline is None:
            parsed = parse_counted(msg.data)
            if parsed is not None:
                await store_row(parsed)
            return
        message, finished = pipeline.handle(msg.data)
        if message is None:
            return
        await store_row(message)
        for item in finished:
            await writes.put(item)

    async def writer():
        while True:
            item = await writes.get()
            try:
                await loop.run_in_executor(None, pipeline.write, item)
            finally:
                writes.task_done()

    async def ticker():
        while True:
            await asyncio.sleep(TICK_SECONDS)
            for item in pipeline.tick():
                await writes.put(item)

    for subject in config.subjects:
        await nc.subscribe(subject, cb=handler)
        log.info("Subscribed to %s", subject)
    state["ready"] = True

    tasks = []
    if pipeline is not None:
        tasks.append(asyncio.create_task(writer()))
        tasks.append(asyncio.create_task(ticker()))
    log.info("Bridge running")
    try:
        await asyncio.Event().wait()
    finally:
        for task in tasks:
            task.cancel()
        await nc.drain()


if __name__ == "__main__":
    asyncio.run(main())
