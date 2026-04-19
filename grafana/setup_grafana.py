#!/usr/bin/env python3
"""
Push a TimescaleDB datasource and Samma security dashboards to an existing Grafana instance.

Required env vars:
  GRAFANA_URL       e.g. http://grafana.metrics.svc.cluster.local:3000
  GRAFANA_USER      e.g. admin
  GRAFANA_PASSWORD  e.g. secret

Optional env vars (TimescaleDB connection):
  TSDB_HOST         default: timescaledb.samma-io.svc.cluster.local
  TSDB_PORT         default: 5432
  TSDB_DB           default: samma
  TSDB_USER         default: samma
  TSDB_PASSWORD     default: samma
"""

import json
import os
import sys
import urllib.request
import urllib.error
import base64

GRAFANA_URL = os.environ.get("GRAFANA_URL", "").rstrip("/")
GRAFANA_USER = os.environ.get("GRAFANA_USER", "admin")
GRAFANA_PASSWORD = os.environ.get("GRAFANA_PASSWORD", "")

TSDB_HOST = os.environ.get("TSDB_HOST", "timescaledb.samma-io.svc.cluster.local")
TSDB_PORT = os.environ.get("TSDB_PORT", "5432")
TSDB_DB = os.environ.get("TSDB_DB", "samma")
TSDB_USER = os.environ.get("TSDB_USER", "samma")
TSDB_PASSWORD = os.environ.get("TSDB_PASSWORD", "samma")

DATASOURCE_NAME = "TimescaleDB-Samma"


def _auth_header():
    token = base64.b64encode(f"{GRAFANA_USER}:{GRAFANA_PASSWORD}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def api(method, path, body=None):
    url = f"{GRAFANA_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=_auth_header(), method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        content = e.read().decode()
        # 409 = already exists — treat as ok for datasource creation
        if e.code == 409:
            return {"message": "already exists", "status": 409}
        print(f"  HTTP {e.code} for {method} {path}: {content}", file=sys.stderr)
        raise


def create_datasource():
    print("Creating datasource...")
    body = {
        "name": DATASOURCE_NAME,
        "type": "postgres",
        "url": f"{TSDB_HOST}:{TSDB_PORT}",
        "database": TSDB_DB,
        "user": TSDB_USER,
        "secureJsonData": {"password": TSDB_PASSWORD},
        "jsonData": {
            "sslmode": "disable",
            "timescaledb": True,
            "postgresVersion": 1500,
        },
        "access": "proxy",
        "isDefault": False,
    }
    result = api("POST", "/api/datasources", body)
    if result.get("status") == 409:
        print(f"  Datasource '{DATASOURCE_NAME}' already exists — skipping.")
        # Fetch existing id
        sources = api("GET", "/api/datasources")
        for s in sources:
            if s["name"] == DATASOURCE_NAME:
                return s["uid"]
        return None
    uid = result.get("datasource", {}).get("uid") or result.get("uid")
    print(f"  Created datasource uid={uid}")
    return uid


def make_dashboard(title, uid, panels):
    return {
        "uid": uid,
        "title": title,
        "tags": ["samma", "security"],
        "timezone": "browser",
        "schemaVersion": 38,
        "refresh": "5m",
        "time": {"from": "now-7d", "to": "now"},
        "panels": panels,
    }


def panel_stat(id_, title, sql, ds_uid, grid_pos):
    return {
        "id": id_,
        "type": "stat",
        "title": title,
        "gridPos": grid_pos,
        "datasource": {"type": "postgres", "uid": ds_uid},
        "targets": [{"rawSql": sql, "format": "table", "refId": "A"}],
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}},
    }


def panel_timeseries(id_, title, sql, ds_uid, grid_pos):
    return {
        "id": id_,
        "type": "timeseries",
        "title": title,
        "gridPos": grid_pos,
        "datasource": {"type": "postgres", "uid": ds_uid},
        "targets": [{"rawSql": sql, "format": "time_series", "refId": "A"}],
        "options": {"tooltip": {"mode": "multi"}},
    }


def panel_piechart(id_, title, sql, ds_uid, grid_pos):
    return {
        "id": id_,
        "type": "piechart",
        "title": title,
        "gridPos": grid_pos,
        "datasource": {"type": "postgres", "uid": ds_uid},
        "targets": [{"rawSql": sql, "format": "table", "refId": "A"}],
        "options": {"pieType": "donut", "displayLabels": ["name", "percent"]},
    }


def panel_table(id_, title, sql, ds_uid, grid_pos):
    return {
        "id": id_,
        "type": "table",
        "title": title,
        "gridPos": grid_pos,
        "datasource": {"type": "postgres", "uid": ds_uid},
        "targets": [{"rawSql": sql, "format": "table", "refId": "A"}],
        "options": {"sortBy": [{"displayName": "time", "desc": True}]},
    }


def panel_barchart(id_, title, sql, ds_uid, grid_pos):
    return {
        "id": id_,
        "type": "barchart",
        "title": title,
        "gridPos": grid_pos,
        "datasource": {"type": "postgres", "uid": ds_uid},
        "targets": [{"rawSql": sql, "format": "table", "refId": "A"}],
    }


def build_overview_dashboard(ds_uid):
    panels = [
        panel_stat(1, "Total scans (selected range)",
            "SELECT count(*) AS value FROM scan_results WHERE $__timeFilter(time)",
            ds_uid, {"x": 0, "y": 0, "w": 4, "h": 4}),
        panel_stat(2, "Unique hosts scanned",
            "SELECT count(DISTINCT host) AS value FROM scan_results WHERE $__timeFilter(time)",
            ds_uid, {"x": 4, "y": 0, "w": 4, "h": 4}),
        panel_stat(3, "Open ports found",
            "SELECT count(*) AS value FROM scan_results WHERE type='port' AND status='open' AND $__timeFilter(time)",
            ds_uid, {"x": 8, "y": 0, "w": 4, "h": 4}),
        panel_stat(4, "Invalid TLS",
            "SELECT count(*) AS value FROM scan_results WHERE type='tls' AND status!='valid' AND $__timeFilter(time)",
            ds_uid, {"x": 12, "y": 0, "w": 4, "h": 4}),
        panel_timeseries(5, "Scans over time by scanner",
            "SELECT time_bucket('1h', time) AS time, scanner, count(*) AS value "
            "FROM scan_results WHERE $__timeFilter(time) "
            "GROUP BY time, scanner ORDER BY time",
            ds_uid, {"x": 0, "y": 4, "w": 16, "h": 8}),
        panel_piechart(6, "Results by type",
            "SELECT type AS name, count(*) AS value "
            "FROM scan_results WHERE $__timeFilter(time) GROUP BY type ORDER BY value DESC",
            ds_uid, {"x": 16, "y": 4, "w": 8, "h": 8}),
        panel_table(7, "Latest 50 scan results",
            "SELECT time, host, port, status, type, scanner "
            "FROM scan_results WHERE $__timeFilter(time) "
            "ORDER BY time DESC LIMIT 50",
            ds_uid, {"x": 0, "y": 12, "w": 24, "h": 10}),
    ]
    return make_dashboard("Samma — Security Overview", "samma-overview", panels)


def build_ports_dashboard(ds_uid):
    panels = [
        panel_table(1, "Open ports by host",
            "SELECT host, port, count(*) AS occurrences "
            "FROM scan_results WHERE type='port' AND status='open' AND $__timeFilter(time) "
            "GROUP BY host, port ORDER BY occurrences DESC",
            ds_uid, {"x": 0, "y": 0, "w": 12, "h": 10}),
        panel_barchart(2, "Most common open ports",
            "SELECT port, count(*) AS count "
            "FROM scan_results WHERE type='port' AND status='open' AND $__timeFilter(time) "
            "GROUP BY port ORDER BY count DESC LIMIT 20",
            ds_uid, {"x": 12, "y": 0, "w": 12, "h": 10}),
        panel_timeseries(3, "Open port discoveries over time",
            "SELECT time_bucket('1d', time) AS time, count(*) AS value "
            "FROM scan_results WHERE type='port' AND status='open' AND $__timeFilter(time) "
            "GROUP BY time ORDER BY time",
            ds_uid, {"x": 0, "y": 10, "w": 24, "h": 8}),
        panel_table(4, "SSH banner findings",
            "SELECT time, host, port, status "
            "FROM scan_results WHERE type='ssh-banner' AND $__timeFilter(time) "
            "ORDER BY time DESC",
            ds_uid, {"x": 0, "y": 18, "w": 12, "h": 8}),
        panel_table(5, "Traceroute results",
            "SELECT time, host, status "
            "FROM scan_results WHERE type='traceroute' AND $__timeFilter(time) "
            "ORDER BY time DESC",
            ds_uid, {"x": 12, "y": 18, "w": 12, "h": 8}),
    ]
    return make_dashboard("Samma — Open Ports & Network", "samma-ports", panels)


def build_web_tls_dashboard(ds_uid):
    panels = [
        panel_stat(1, "Hosts with invalid TLS",
            "SELECT count(DISTINCT host) AS value FROM scan_results "
            "WHERE type='tls' AND status!='valid' AND $__timeFilter(time)",
            ds_uid, {"x": 0, "y": 0, "w": 6, "h": 4}),
        panel_stat(2, "HTTP redirect failures",
            "SELECT count(*) AS value FROM scan_results "
            "WHERE type='http-redirect' AND status NOT IN ('301','302','200') AND $__timeFilter(time)",
            ds_uid, {"x": 6, "y": 0, "w": 6, "h": 4}),
        panel_table(3, "TLS status per host",
            "SELECT host, status, MAX(time) AS last_seen "
            "FROM scan_results WHERE type='tls' AND $__timeFilter(time) "
            "GROUP BY host, status ORDER BY last_seen DESC",
            ds_uid, {"x": 0, "y": 4, "w": 12, "h": 10}),
        panel_table(4, "HTTP redirect status",
            "SELECT host, port, status, MAX(time) AS last_seen "
            "FROM scan_results WHERE type='http-redirect' AND $__timeFilter(time) "
            "GROUP BY host, port, status ORDER BY last_seen DESC",
            ds_uid, {"x": 12, "y": 4, "w": 12, "h": 10}),
        panel_table(5, "HTTP headers findings",
            "SELECT time, host, port, status "
            "FROM scan_results WHERE type='http-headers' AND $__timeFilter(time) "
            "ORDER BY time DESC",
            ds_uid, {"x": 0, "y": 14, "w": 12, "h": 8}),
        panel_table(6, "DNS results",
            "SELECT host, status, MAX(time) AS last_seen "
            "FROM scan_results WHERE type='dns' AND $__timeFilter(time) "
            "GROUP BY host, status ORDER BY last_seen DESC",
            ds_uid, {"x": 12, "y": 14, "w": 12, "h": 8}),
    ]
    return make_dashboard("Samma — Web & TLS", "samma-web-tls", panels)


def push_dashboard(dashboard_model):
    print(f"  Pushing dashboard '{dashboard_model['title']}'...")
    body = {"dashboard": dashboard_model, "overwrite": True, "folderId": 0}
    result = api("POST", "/api/dashboards/db", body)
    print(f"    → {result.get('url', result)}")


def main():
    if not GRAFANA_URL:
        print("ERROR: GRAFANA_URL is not set.", file=sys.stderr)
        sys.exit(1)
    if not GRAFANA_PASSWORD:
        print("ERROR: GRAFANA_PASSWORD is not set.", file=sys.stderr)
        sys.exit(1)

    print(f"Grafana: {GRAFANA_URL}")
    print(f"TimescaleDB: {TSDB_HOST}:{TSDB_PORT}/{TSDB_DB}")
    print()

    ds_uid = create_datasource()
    if not ds_uid:
        print("ERROR: could not determine datasource UID.", file=sys.stderr)
        sys.exit(1)

    print("\nPushing dashboards...")
    push_dashboard(build_overview_dashboard(ds_uid))
    push_dashboard(build_ports_dashboard(ds_uid))
    push_dashboard(build_web_tls_dashboard(ds_uid))

    print("\nDone. Open Grafana and look under General for the Samma dashboards.")


if __name__ == "__main__":
    main()
