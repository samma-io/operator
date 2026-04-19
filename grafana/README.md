# Grafana Setup for Samma

Pushes a TimescaleDB datasource and three security dashboards into an existing Grafana instance via the HTTP API. No manual UI clicks needed — re-run any time to update.

## Dashboards created

| Dashboard | Contents |
|-----------|----------|
| **Samma — Security Overview** | Stat panels (total scans, unique hosts, open ports, invalid TLS), scans-over-time time series, pie chart by type, latest results table |
| **Samma — Open Ports & Network** | Open ports by host, most common ports bar chart, discovery trend, SSH banner + traceroute tables |
| **Samma — Web & TLS** | TLS validity per host, HTTP redirect status, HTTP headers, DNS results |

## Dashboard JSON files

Pre-built dashboard JSON files are included so you can import them without running the script:

| File | Dashboard |
|------|-----------|
| `dashboard-overview.json` | Samma — Security Overview |
| `dashboard-ports.json` | Samma — Open Ports & Network |
| `dashboard-web-tls.json` | Samma — Web & TLS |

To import manually: **Grafana → Dashboards → Import → Upload JSON file**. Set the datasource to your TimescaleDB/PostgreSQL datasource when prompted.

## Usage

```bash
export GRAFANA_URL=http://<grafana-host>:<port>   # e.g. http://localhost:3000
export GRAFANA_USER=admin
export GRAFANA_PASSWORD=<your-grafana-password>

# Optional — only needed if different from defaults
export TSDB_HOST=timescaledb.samma-io.svc.cluster.local
export TSDB_PORT=5432
export TSDB_DB=samma
export TSDB_USER=samma
export TSDB_PASSWORD=samma

python grafana/setup_grafana.py
```

The script is idempotent — running it again updates existing dashboards and skips the datasource if it already exists.

## From inside the cluster

```bash
kubectl run grafana-setup --rm -it --restart=Never \
  --image=python:3.12-slim \
  --env="GRAFANA_URL=http://grafana.metrics.svc.cluster.local:3000" \
  --env="GRAFANA_USER=admin" \
  --env="GRAFANA_PASSWORD=<password>" \
  -- python -c "$(cat grafana/setup_grafana.py)"
```

Or port-forward Grafana locally:
```bash
kubectl port-forward -n metrics svc/grafana 3000:3000
GRAFANA_URL=http://localhost:3000 GRAFANA_USER=admin GRAFANA_PASSWORD=<pw> python grafana/setup_grafana.py
```
