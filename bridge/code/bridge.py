import asyncio
import json
import logging
import os

import nats
import asyncpg

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

NATS_URL     = os.getenv("NATS_URL",     "nats://nats:4222")
NATS_SUBJECT = os.getenv("NATS_SUBJECT", "samma-io.scan")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://samma:samma@timescaledb:5432/samma")

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


async def main():
    db = None
    while db is None:
        try:
            db = await asyncpg.connect(DATABASE_URL)
        except Exception as e:
            logging.warning("DB not ready, retrying in 5s: %s", e)
            await asyncio.sleep(5)
    await db.execute(CREATE_TABLE)
    logging.info("TimescaleDB ready")

    nc = await nats.connect(NATS_URL)
    logging.info("Connected to NATS, subscribing to %s", NATS_SUBJECT)

    async def handler(msg):
        try:
            data  = json.loads(msg.data.decode())
            samma = data.get("samma-io", {})
            await db.execute(
                """INSERT INTO scan_results
                   (host, port, status, type, scanner, samma_id, tags, raw)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
                data.get("host"),
                str(data.get("port", "")),
                data.get("status"),
                data.get("type"),
                samma.get("scanner"),
                samma.get("id"),
                json.dumps(samma.get("tags", [])),
                json.dumps(data),
            )
            logging.info("Stored %s for %s", data.get("type"), data.get("host"))
        except Exception as e:
            logging.error("Failed to store message: %s", e)

    await nc.subscribe(NATS_SUBJECT, cb=handler)
    logging.info("Bridge running")
    await asyncio.sleep(float("inf"))


asyncio.run(main())
