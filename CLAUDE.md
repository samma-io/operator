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
- `PUT /scanner` — Create a Scanner CRD from JSON (low-level, explicit scanner list)
- `DELETE /scanner` — Delete a Scanner CRD by name
- `GET /target` — List all unique targets aggregated from Scanner CRD `spec.target` fields
- `PUT /target` — Add a target: resolves a profile to a scanner list and creates one Scanner CRD per scanner. Also calls the external samma.io API (`post_target_to_api`) with `targetId` if `SAMMA_IO_API_TOKEN` is set.
- `DELETE /target` — Remove a target: lists all Scanner CRDs and deletes every one whose `spec.target` matches
- `GET /health`, `GET /ready` — Kubernetes health/readiness probes
- Prometheus metrics via `prometheus-flask-exporter`

#### Profile resolution in the API
`api/code/profile_resolver.py` (copied from `operator/code/profile_resolver.py`) reads the `scanner-profiles` ConfigMap and resolves profile names (e.g. `default`, `web`, `network`, `full`) into `(scanner, template_or_none)` tuples. The API requires `client.CoreV1Api()` (stored as `core_v1_api`) in addition to `CustomObjectsApi()` to read that ConfigMap.

#### External API validation
When `PUT /target` is called, `post_target_to_api(target, target_id)` POSTs the target to the external samma.io API for validation/registration. Controlled by three env vars:
- `SAMMA_IO_API_URL` — base URL of the external API
- `SAMMA_IO_API_TOKEN` — Bearer token; if empty, the call is skipped
- `SAMMA_IO_PROFILE_ID` — optional profile ID added to the payload

#### CRD naming convention
`PUT /target` names Scanner CRDs as `{scanner}-{sanitized_target}[-{template}]` (matching the Ingress handler pattern), where sanitization lowercases and replaces non-alphanumeric characters with `-`. Max 63 characters (Kubernetes limit).

### CRD & Manifests (`manifest/`)
- `samma-operator.yaml` — Full cluster deployment: namespace `samma-io`, CRD definition for `Scanner`, RBAC, operator Deployment with a ClusterIP Service (port 8080), API Deployment with a ClusterIP Service (port 8080).
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
kopf, kubernetes, redis, PyYAML, Jinja2, requests

### API Dependencies (`api/code/requirements.txt`)
flask, gunicorn, prometheus-flask-exporter, PyYAML, kopf, kubernetes, redis, requests

## Key Concepts

- All scanners deploy into the `samma-io` namespace.
- Target names are sanitized (lowercase, non-alphanumeric → `-`) for use in Kubernetes resource names. Max 63 chars.
- The operator initializes by ensuring `filebeat`, `live`, and `scanner-profiles` ConfigMaps exist in `samma-io` namespace.
- Scanner results are written to files and shipped to Elasticsearch via Filebeat sidecars when `write_to_file` and `elasticsearch` are set.
- Environment config is passed via env vars: `SAMMA_IO_ID`, `SAMMA_IO_TAGS`, `SAMMA_IO_JSON`, `SAMMA_IO_SCANNER`, `WRITE_TO_FILE`, `ELASTICSEARCH`.
- External API integration uses `SAMMA_IO_API_URL`, `SAMMA_IO_API_TOKEN`, `SAMMA_IO_PROFILE_ID` (both operator and API).
- CronJob templates use `apiVersion: batch/v1` and the operator uses `client.BatchV1Api()`.
- Python 3.12 is used for both operator and API images.
- `profile_resolver.py` exists in both `operator/code/` and `api/code/` — keep them in sync if the profile logic changes.
