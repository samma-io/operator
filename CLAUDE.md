# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Samma is a Kubernetes operator that deploys security scanners as Jobs and CronJobs into a cluster. When a target is registered, the operator always creates both: an immediate one-time Job and a weekly CronJob. Results are published to NATS and stored in TimescaleDB via a bridge service.

Two components: **operator** (watches CRDs, deploys scanners) and **API** (REST interface for managing targets/scanners).

## Architecture

### Operator (`operator/`)
Python-based Kubernetes operator using [kopf](https://kopf.readthedocs.io/). Entry point: `operator/code/operator_handler.py`.

- **operator_handler.py** — Watches `Scanner` CRD (samma.io/v1) create/delete events and Ingress create/delete events. On Scanner create, always calls both `deployJob()` AND `deployCron()`. On delete, calls both delete functions.
- **deployJob.py** — Deploys scanners as Kubernetes Jobs. Reads Jinja2-templated YAML from `/code/scanners/<scanner>/job/` and renders with `NAME`, `TARGET`, `ENV`, `SCANNERFirst`.
- **deploycron.py** — Deploys scanners as Kubernetes CronJobs. Same pattern but reads from `/code/scanners/<scanner>/cron/`. Default schedule: `SAMMA_IO_WEEKLY_SCHEDULE` env var (default `0 0 * * 0`).
- **profile_resolver.py** — Reads the `scanner-profiles` ConfigMap and resolves profile names into `(scanner, template_or_none)` tuples.

The operator also watches Ingress resources: if an Ingress has `samma-io.alpha.kubernetes.io/enable` annotation, it auto-creates Scanner CRDs for each host.

### Scanner Templates (`operator/code/scanners/`)

Two scanner families — both follow the same single-container, no-sidecar pattern with NATS env vars injected via the `{% for user in ENV %}` loop:

**detect** (`port-scanner/`, `dns-scanner/`, `http-headers-scanner/`, `tls-scanner/`) — use `ghcr.io/samma-io/detect-*:latest` images; publish results directly to NATS.

**classic** (`nikto/`, `nmap/`, `tsunami/`) — use `sammascanner/*` images; NATS vars passed through ENV. nmap has three sub-templates (`port`, `http`, `tls`) with different `command` entrypoints. tsunami uses `SCANNERFirst` Jinja2 conditional to switch between `--ip-v4-target` and `--hostname-target` args.

Template variables: `NAME` (scanner-targetName), `TARGET` (raw hostname/IP), `SCHEDULER` (cron expression, cron templates only), `ENV` (dict of all env vars), `SCANNERFirst` (int if target starts with digit, else string `"string"`).

Safe-escaping: both `deployJob.py` and `deploycron.py` escape double quotes in env values before rendering:
```python
safe_env = {k: str(v).replace('"', '\\"') for k, v in env_data.items()}
```

### Scanner profiles

Stored in the `scanner-profiles` ConfigMap in `samma-io`. Defined in `initOperator()` in `operator_handler.py`. Since `initOperator` only creates the ConfigMap if absent, adding a profile to the code also requires `kubectl patch` for running clusters.

| Profile | Value |
|---|---|
| `detect` | `port-scanner,dns-scanner,http-headers-scanner,tls-scanner` |
| `classic` | `nikto,nmap/port,nmap/http,nmap/tls,tsunami` |
| `all` | detect + classic combined |
| `default` | `nmap,nikto` |
| `web` | `nikto,nmap/http` |
| `network` | `nmap/port,nmap/tls` |
| `full` | `nmap,nikto,tsunami,base` |

### API (`api/`)
Flask app (`api/code/app.py`) providing REST interface and web UI.

Endpoints:
- `GET /` — HTML page listing scanners
- `GET /scanner` — List all Scanner CRDs as JSON
- `PUT /scanner` — Create a Scanner CRD (low-level, explicit scanner list)
- `DELETE /scanner` — Delete a Scanner CRD by name
- `GET /target` — List all unique targets aggregated from CRD `spec.target` fields
- `PUT /target` — Resolve profile → create one CRD per scanner. Also calls external API if `SAMMA_IO_API_TOKEN` is set.
- `DELETE /target` — Delete all Scanner CRDs whose `spec.target` matches
- `GET /health`, `GET /ready` — Kubernetes probes
- `GET /metrics` — Prometheus metrics via `prometheus-flask-exporter`

#### Profile resolution
`api/code/profile_resolver.py` (copy of `operator/code/profile_resolver.py`) resolves profile names to `(scanner, template_or_none)` tuples. Both copies must be kept in sync.

#### CRD naming
`PUT /target` names CRDs as `{scanner}-{sanitized_target}[-{template}]`. Sanitization: lowercase, non-alphanumeric → `-`. Max 63 chars (Kubernetes limit).

#### External API integration
`post_target_to_api(target, target_id)` POSTs to the sama.io API on `PUT /target`. Skipped if `SAMMA_IO_API_TOKEN` is empty. Env vars: `SAMMA_IO_API_URL`, `SAMMA_IO_API_TOKEN`, `SAMMA_IO_PROFILE_ID`.

### NATS + TimescaleDB + Bridge (`bridge/`)

NATS (`nats:2`) is deployed in `samma-io` on port 4222. All scanners publish results to subject `samma-io.scan`.

The bridge (`bridge/code/bridge.py`) is an async Python service that subscribes to NATS and inserts rows into TimescaleDB. It retries the DB connection on startup (TimescaleDB is slow to init). Table: `scan_results` (hypertable on `time` column).

TimescaleDB uses `PGDATA=/var/lib/postgresql/data/pgdata` to avoid conflicts with the `lost+found` directory at the PVC mount root.

### CRD & Manifests (`manifest/`)
- `manifest/samma-operator.yaml` — Full cluster deployment: namespace, CRD, RBAC, operator Deployment + Service (8080), API Deployment + Service (8080), NATS Deployment + Service (4222/8222), TimescaleDB PVC + Deployment + Service (5432), Bridge Deployment.
- `manifest/test/` — Example Scanner CRDs for testing.

## Build & Development Commands

### Docker (local)
```bash
docker compose build          # Build operator and api images
docker compose up             # Run locally
```

### Skaffold (Kubernetes dev)
```bash
cd operator && skaffold dev   # Build + deploy operator to cluster
cd api && skaffold dev        # Build + deploy API to cluster
```

### Deploy to Kubernetes
```bash
kubectl apply -f manifest/samma-operator.yaml
kubectl apply -f manifest/test/nmap.yaml
```

### Building and pushing images (production)
```bash
docker build --platform linux/amd64 -t mattiashem/samma-operator:latest ./operator/
docker push mattiashem/samma-operator:latest
kubectl rollout restart deployment/samma-operator -n samma-io

docker build --platform linux/amd64 -t sammascanner/api:beta ./api/
docker push sammascanner/api:beta
kubectl rollout restart deployment/samma-api -n samma-io
```

### Patching the scanner-profiles ConfigMap
`initOperator` only creates the ConfigMap on first run. For running clusters, add profiles manually:
```bash
kubectl patch configmap scanner-profiles -n samma-io --type merge \
  -p '{"data":{"my-profile":"nikto,nmap/http"}}'
```

### Devcontainer
Open in VS Code → "Reopen in Container". Provides Python 3.12, kubectl, helm, skaffold, k3d, Docker-in-Docker. Post-create script installs dependencies and creates a local k3d cluster.

### CI/CD (GitHub Actions)
`.github/workflows/build.yaml` — builds `operator/` and `api/` images on push/PR to `main`. Pushes to `ghcr.io/<owner>/samma-operator` and `ghcr.io/<owner>/samma-api` tagged with git SHA and `latest`.

## Key Concepts

- All scanners and services deploy into the `samma-io` namespace.
- Every Scanner CRD create event triggers both `deployJob()` (immediate run) and `deployCron()` (weekly recurring).
- Target names are sanitized (lowercase, non-alphanumeric → `-`) for Kubernetes resource names. Max 63 chars.
- `SCANNERFirst` is set to `int(target[0])` when the target starts with a digit (IP address), else `"string"`. Used in tsunami templates to switch between `--ip-v4-target` and `--hostname-target`.
- NATS vars (`NATS_URL`, `NATS_ENABLED`, `NATS_SUBJECT`) are injected into every scanner's env_data by `create_fn`.
- `profile_resolver.py` exists in both `operator/code/` and `api/code/` — keep them in sync.
- The operator and API images use `nodeSelector: kubernetes.io/arch: amd64`.
- Python 3.12 is used for operator, API, and bridge images.
