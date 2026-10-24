# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Samma is a Kubernetes operator that deploys security scanners as Jobs and CronJobs into a cluster. When a target is registered, the operator always creates both: an immediate one-time Job and a weekly CronJob. Results are published to NATS and stored in TimescaleDB via a bridge service.

Two components: **operator** (watches CRDs, deploys scanners) and **API** (REST interface for managing targets/scanners).

## Architecture

### Operator (`operator/`)
Python-based Kubernetes operator using [kopf](https://kopf.readthedocs.io/). Entry point: `operator/code/operator_handler.py`.

- **operator_handler.py**: the kopf handlers. Scanner create builds the Jobs and CronJobs through `jobspec`, creates the CronJobs and submits the Jobs to the scan queue; Scanner update (`field='spec'`) recreates the CronJobs whose `samma.io/spec-hash` changed; Scanner resume re-queues first Jobs still marked `samma.io/initial-scan: queued`; Scanner delete (`optional=True`, no finalizer) forgets queued work and removes objects an older operator created under the pre-hash names. Ingress create and update (`field='metadata.annotations'` and `field='spec.rules'`) call `reconcile_ingress`, which creates, updates and deletes the Scanners for the Ingress by label; Ingress delete (`optional=True`) removes them by label. `init_operator()` and the queue's drain thread start from the `on.startup` handler.
- **jobspec.py**: the `SCANNERS` table (image, variants with their entrypoints, extra env, `sudo`, `raw_sockets`, sidecars) and the builders `build_job()` and `build_cronjob()`, which return plain dictionaries. Also `Settings.from_env()`, naming (`object_name`, `target_hash`, `legacy_names`), `cron_schedule` (hashed minute for the default schedule), `scanner_env`, `image_for` and `job_finished`. Imports only `target_policy`.
- **scanqueue.py**: `ScanQueue`, a FIFO queue that launches queued Job bodies while fewer than `max_concurrent` scan Jobs are unfinished in the namespace, and `start_drainer()`, a daemon thread that drains it every few seconds. Pure Python; the API calls are injected.
- **uninstall_cleanup.py**: deletes every Scanner and leftover scanner Job and CronJob in the namespace. The Helm pre-delete hook runs it with the operator image.
- **profile_resolver.py**: reads the `scanner-profiles` ConfigMap (namespace from `SAMMA_NAMESPACE`) and resolves profile names into `(scanner, template_or_none)` tuples.
- **target_policy.py**: validates `Scanner.spec.target` (hostname or IP pattern shared with the CRD, optional Ingress-served check, public-address check through DNS) plus scanner names and schedules. Imports neither kopf nor the kubernetes client; the API client is passed in. Tests in `operator/tests/`.

The operator also watches Ingress resources: if an Ingress has `samma-io.alpha.kubernetes.io/enable` annotation, it auto-creates Scanner CRDs for each host.

### Scanner table (`operator/code/jobspec.py`)

There are no YAML templates. `SCANNERS` maps a scanner name to a `ScannerSpec`:

**detect** (`port-scanner`, `dns-scanner`, `http-headers-scanner`, `tls-scanner`, `http-redirect-scanner`, `traceroute-scanner`, `ssh-banner-scanner`, `whois-scanner`): `ghcr.io/samma-io/detect-*:latest`, one variant named after the scanner, no command (the image's entrypoint runs), results published to NATS.

**classic** (`nikto`, `nmap`, `tsunami`, `base`): `sammascanner/*` images. nmap has three variants (`port`, `http`, `tls`) with their own `command`; `nikto` and `nmap` have `sudo=True` because the images call sudo, which keeps `allowPrivilegeEscalation: true` for them; nmap has `raw_sockets=True` and gets `NET_RAW` plus `NMAP_PRIVILEGED=1` only when `SAMMA_NMAP_RAW_SOCKETS=true`, otherwise `NMAP_UNPRIVILEGED=1`. tsunami takes the target as an argument (`--ip-v4-target`, `--ip-v6-target` or `--hostname-target`, decided with `target_policy.parse_ip_literal`). `base` keeps its filebeat sidecar and the `filebeat` and `live` ConfigMaps; `operator/code/scanners/core/` holds those two ConfigMaps and nothing else.

Every scanner container gets `TARGET`, `SAMMA_IO_SCANNER`, the Scanner's env (see `scanner_env`), `drop: [ALL]`, `readOnlyRootFilesystem` with emptyDirs at `/out` and `/tmp`, `runAsNonRoot`, seccomp `RuntimeDefault`, resources from the settings, the `samma-scanner` ServiceAccount and no mounted token. Jobs: `backoffLimit: 1`, `activeDeadlineSeconds`, `ttlSecondsAfterFinished`, an `ownerReference` to the Scanner. CronJobs: `concurrencyPolicy: Forbid`, history limits 1, `startingDeadlineSeconds: 600`, a `samma.io/spec-hash` annotation.

Image references: `SAMMA_SCANNER_IMAGE_<NAME>` (full reference, `-` as `_`), else `SAMMA_SCANNER_IMAGE_PREFIX` plus the image base name and `SAMMA_SCANNER_IMAGE_TAG`, else the table default. The chart maps `scanners.images`, `scanners.imagePrefix` and `scanners.imageTag` to these.

Adding a scanner: add a `ScannerSpec` to `SCANNERS`, add it to the profiles in `init_operator()`, extend `operator/tests/test_jobspec.py`. `/add-scanner` in `.claude/commands/` walks through it.

### Scanner profiles

Stored in the `scanner-profiles` ConfigMap in `samma-io`. Defined in `initOperator()` in `operator_handler.py`. Since `initOperator` only creates the ConfigMap if absent, adding a profile to the code also requires `kubectl patch` for running clusters.

| Profile | Value |
|---|---|
| `default` | All 12 detect + classic scanners (no tsunami) |
| `web` | `http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http` |
| `network` | `port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls` |
| `dns` | `dns-scanner,whois-scanner` |
| `detect` | All 8 detect scanners (port, dns, http-headers, tls, http-redirect, traceroute, ssh-banner, whois) |
| `classic` | `nikto,nmap/port,nmap/http,nmap/tls,tsunami` |
| `all` | All 12 scanners + tsunami |
| `full` | `nmap,nikto,tsunami,base` (legacy) |

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

### RBAC and ServiceAccounts

Four ServiceAccounts: `samma-operator` (ClusterRole: Ingresses get/list/watch/patch, `scanner.samma.io` full, `scanreports.samma.io` read and write, events create/patch, CRDs list/watch; Role in the namespace: Jobs and CronJobs full, ConfigMaps get/list/watch/create/patch, Secrets get/list, Pods get/list), `samma-api` (Role: Scanners get/list/create/patch/delete, ConfigMaps get/list), `samma-bridge` (Role: ScanReports write, Scanners read; for the coming bridge rewrite) and `samma-scanner` (nothing; scanner pods). `helm/samma-operator/templates/rbac.yaml` and `manifest/samma-operator.yaml` must stay identical in content. The namespace comes from `SAMMA_NAMESPACE`, set from the Downward API in the chart and the manifest.

### CRD & Manifests (`manifest/`)
- `manifest/samma-operator.yaml` — Full cluster deployment: namespace, CRD, ServiceAccounts, ClusterRole, Roles and bindings, operator Deployment + Service (8080), API Deployment + Service (8080), NATS Deployment + Service (4222/8222), TimescaleDB PVC + Deployment + Service (5432), Bridge Deployment. No Helm hook: delete the Scanners by hand before deleting the manifest.
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

### Unit tests
```bash
python3 -m unittest discover -s operator/tests -t operator
```
No cluster, network or kubernetes client needed: DNS and the Ingress listing are faked, `jobspec` builds dictionaries, and `scanqueue` takes its API calls as arguments. `operator_handler.py` imports kopf and is not imported by the tests; check it with `python3 -m py_compile`.

### Devcontainer
Open in VS Code → "Reopen in Container". Provides Python 3.12, kubectl, helm, skaffold, k3d, Docker-in-Docker. Post-create script installs dependencies and creates a local k3d cluster.

### CI/CD (GitHub Actions)
`.github/workflows/build.yaml` — builds `operator/` and `api/` images on push/PR to `main`. Pushes to `ghcr.io/<owner>/samma-operator` and `ghcr.io/<owner>/samma-api` tagged with git SHA and `latest`.

## Key Concepts

- All scanners and services deploy into one namespace, `SAMMA_NAMESPACE` (default `samma-io`); nothing in the code names the namespace directly.
- Every Scanner create event creates one CronJob per scanner and queues one Job per scanner (`SAMMA_MAX_CONCURRENT_SCANS`, default 2, unfinished scan Jobs at a time). A Scanner spec change recreates the CronJobs only.
- Jobs and CronJobs are named `<scanner>[-<template>]-<8 hex of sha256(target)>` and labelled `samma.io/scanner`, `samma.io/template`, `samma.io/target-hash`, `samma.io/scanner-uid` (plus `samma.io/ingress-namespace` and `samma.io/ingress-name` when they came from an Ingress); the target is in the `samma.io/target` annotation. Ingress-made Scanners are named `<scanner>[-<template>]-<hash of namespace/name/host>`.
- Cleanup is ownerReferences plus garbage collection: Scanner owns Job and CronJob; an Ingress in the operator namespace owns its Scanners; for other namespaces `ingress_delete` deletes by label. No finalizers anywhere.
- NATS vars (`NATS_URL`, `NATS_ENABLED`, `NATS_SUBJECT`) reach every scanner through `jobspec.scanner_env`.
- `profile_resolver.py` exists in both `operator/code/` and `api/code/` — keep them in sync.
- `Scanner.spec.target` is validated before anything is deployed (`target_policy.check_target`): hostname or IP only, the same regex as the CRD `pattern`. `SAMMA_ALLOW_UNMANAGED_TARGETS` (default `true`) and `SAMMA_ALLOW_PRIVATE_TARGETS` (default `false`) control the Ingress-served and public-address checks. A rejection raises `kopf.PermanentError` and emits a Kubernetes event; an unresolvable name is retried every 5 minutes up to `MAX_RESOLVE_RETRIES`. Wildcard Ingress hosts are skipped. Keep the CRD patterns (helm and manifest copies) identical to the module constants; `operator/tests/test_target_policy.py` checks that.
- The operator and API images use `nodeSelector: kubernetes.io/arch: amd64`.
- Python 3.12 is used for operator, API, and bridge images.
