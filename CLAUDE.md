# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Samma is a Kubernetes operator that deploys security scanners (nmap, nikto, tsunami) as Jobs or CronJobs into a cluster. It consists of two components: the **operator** and the **API**.

## Architecture

### Operator (`operator/`)
A Python-based Kubernetes operator using [kopf](https://kopf.readthedocs.io/). Entry point: `operator/code/operator_handler.py`.

- **operator_handler.py** — Watches for `Scanner` CRD (samma.io/v1) create/delete events and Ingress create/delete events. On Scanner create, it delegates to either `deployCron()` or `deployJob()` depending on whether a `scheduler` field is present.
- **deployJob.py** — Deploys scanners as Kubernetes Jobs. Reads Jinja2-templated YAML from `/code/scanners/<scanner>/job/` and renders with target, env_data, etc.
- **deploycron.py** — Deploys scanners as Kubernetes CronJobs. Same pattern but reads from `/code/scanners/<scanner>/cron/`.
- **operator_api.py** — Placeholder for watching service/ingress changes (currently minimal).

The operator also watches Ingress resources: if an Ingress has `samma-io.alpha.kubernetes.io/enable` annotation, it auto-creates Scanner CRDs for each host in the Ingress rules.

### Scanner Templates (`operator/code/scanners/`)
Each scanner (nmap, nikto, tsunami, base) has `job/` and `cron/` subdirectories containing Jinja2-templated Kubernetes YAML manifests. Templates use variables: `NAME`, `TARGET`, `SCHEDULER`, `ENV`, `SCANNERFirst`.

### API (`api/`)
A Flask app (`api/code/app.py`) providing a REST interface and web UI for managing scanners:
- `GET /` — HTML page listing scanners
- `GET /scanner` — List all Scanner CRDs as JSON
- `PUT /scanner` — Create a Scanner CRD from JSON
- `DELETE /scanner` — Delete a Scanner CRD by name
- `GET /health`, `GET /ready` — Kubernetes health/readiness probes
- Prometheus metrics via `prometheus-flask-exporter`

### CRD & Manifests (`manifest/`)
- `samma-operator.yaml` — Full cluster deployment: namespace `samma-io`, CRD definition for `Scanner`, RBAC, operator Deployment, API Deployment, and Service.
- `manifest/test/` — Example Scanner CRDs for testing.

## Build & Development Commands

### Docker (local)
```bash
docker compose build          # Build both operator and api images
docker compose up             # Run locally
```

### Skaffold (Kubernetes dev)
```bash
cd operator && skaffold dev   # Build + deploy operator to cluster
cd api && skaffold dev        # Build + deploy API to cluster
```

### Deploy to Kubernetes
```bash
kubectl apply -f manifest/samma-operator.yaml   # Deploy CRD, RBAC, operator, and API
kubectl apply -f manifest/test/nmap.yaml         # Deploy a test scanner
```

### Devcontainer
Open in VS Code and select "Reopen in Container". The devcontainer provides:
- Python 3.12, kubectl, helm, skaffold, k3d, Docker-in-Docker
- Post-create script installs all dependencies and creates a local k3d cluster
- Port forwarding for API (8080) and operator debug (8888)

### CI/CD (GitHub Actions)
On push/PR to `main`, the `.github/workflows/build.yaml` workflow:
- Builds `operator/` and `api/` Docker images
- Pushes to `ghcr.io/<owner>/samma-operator` and `ghcr.io/<owner>/samma-api` (on `main` only)
- Tags with git SHA and `latest`

### Operator Dependencies (`operator/requirements.txt`)
kopf, kubernetes, redis, PyYAML, Jinja2

### API Dependencies (`api/code/requirements.txt`)
flask, gunicorn, prometheus-flask-exporter, PyYAML, kopf, kubernetes, redis

## Key Concepts

- All scanners deploy into the `samma-io` namespace.
- Target names are sanitized by replacing `.` with `-` for use in Kubernetes resource names.
- The operator initializes by ensuring `filebeat` and `live` ConfigMaps exist in `samma-io` namespace (from `scanners/core/` configs).
- Scanner results are written to files and shipped to Elasticsearch via Filebeat sidecars when `write_to_file` and `elasticsearch` are set.
- Environment config is passed via env vars: `SAMMA_IO_ID`, `SAMMA_IO_TAGS`, `SAMMA_IO_JSON`, `SAMMA_IO_SCANNER`, `WRITE_TO_FILE`, `ELASTICSEARCH`.
- CronJob templates use `apiVersion: batch/v1` and the operator uses `client.BatchV1Api()`.
- Python 3.12 is used for both operator and API images.
