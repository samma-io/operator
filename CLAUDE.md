# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Samma is a Kubernetes operator that deploys security scanners as Jobs and CronJobs into a cluster. When a target is registered, the operator always creates both: an immediate one-time Job and a weekly CronJob. Results are published to NATS; the bridge writes them as `ScanReport` objects (`scanreports.samma.io/v1alpha1`) and stores them in TimescaleDB.

Three components: **operator** (watches CRDs, deploys scanners, records failed scan Jobs in ScanReports), **bridge** (NATS to ScanReports and TimescaleDB) and **API** (REST interface for managing targets/scanners).

## Architecture

### Operator (`operator/`)
Python-based Kubernetes operator using [kopf](https://kopf.readthedocs.io/). Entry point: `operator/code/operator_handler.py`.

- **operator_handler.py**: the kopf handlers. Scanner create builds the Jobs and CronJobs through `jobspec`, creates the CronJobs and submits the Jobs to the scan queue; Scanner update (`field='spec'`) recreates the CronJobs whose `samma.io/spec-hash` changed; Scanner resume re-queues first Jobs still marked `samma.io/initial-scan: queued`; Scanner delete (`optional=True`, no finalizer) forgets queued work and removes objects an older operator created under the pre-hash names. Ingress create and update (`field='metadata.annotations'` and `field='spec.rules'`), all filtered with `annotations={ENABLE_ANNOTATION: kopf.PRESENT}`, call `reconcile_ingress`, which creates, updates and deletes the Scanners for the Ingress by label; `ingress_opted_out` (`field=ENABLE_FIELD, old=kopf.PRESENT, new=kopf.ABSENT`) does the same when the annotation is removed, since the filtered handlers no longer match then; Ingress delete (`optional=True`, same filter) removes them by label. `configure()` installs `ingress_optin.make_diffbase_storage()`: kopf stores its `last-handled-configuration` annotation on every watched object, handlers or not, and this storage writes it on opted-in Ingresses only and removes a leftover when such an Ingress next changes (`ingress_optin.py` is the pure part, tests in `operator/tests/test_ingress_optin.py`). `init_operator()` and the queue's drain thread start from the `on.startup` handler. `record_job_outcomes()` runs on every drain tick (`on_tick`): for each scan Job that failed and whose scanner has `reports=True`, it writes `status.lastRun` of the matching ScanReport (get, then replace through the status subresource with the read resourceVersion, 409 retried), creating the report with its spec when missing, skipping it when the bridge already recorded the same `runId`, then annotates the Job `samma.io/outcome-recorded: "true"`.
- **jobspec.py**: the `SCANNERS` table (image, variants with their entrypoints, extra env, `sudo`, `raw_sockets`, sidecars, `reports`) and the builders `build_job()` and `build_cronjob()`, which return plain dictionaries. Also `Settings.from_env()`, naming (`object_name`, `target_hash`, `legacy_names`), `cron_schedule` (hashed minute for the default schedule), `scanner_env`, `scanner_subject` (`<NATS_SUBJECT>.<scanner>`), `nats_url_with_credentials` (`nats://$(NATS_USER):$(NATS_PASSWORD)@host`), `image_for` and `job_finished`. Imports only `target_policy`.
- **scanreport.py**: the operator's side of ScanReports: `job_outcome()` maps a Job's `Failed` condition to `failed`, or `timed_out` when the reason is `DeadlineExceeded`; `report_body()`, `failed_run_status()`, `report_name()` (same as the Job name), `scanner_owners()`, `latest_pod_name()`. Imports only `jobspec`.
- **scanqueue.py**: `ScanQueue`, a FIFO queue that launches queued Job bodies while fewer than `max_concurrent` scan Jobs are unfinished in the namespace, and `start_drainer(queue, interval, on_tick=None)`, a daemon thread that drains it every few seconds and then calls `on_tick`. Pure Python; the API calls are injected.
- **uninstall_cleanup.py**: deletes every Scanner and leftover scanner Job and CronJob in the namespace. The Helm pre-delete hook runs it with the operator image.
- **profile_resolver.py**: reads the `scanner-profiles` ConfigMap (namespace from `SAMMA_NAMESPACE`) and resolves profile names into `(scanner, template_or_none)` tuples.
- **target_policy.py**: validates `Scanner.spec.target` (hostname or IP pattern shared with the CRD, optional Ingress-served check, public-address check through DNS) plus scanner names and schedules. Imports neither kopf nor the kubernetes client; the API client is passed in. Tests in `operator/tests/`.

The operator also watches Ingress resources: if an Ingress has `samma-io.alpha.kubernetes.io/enable` annotation, it auto-creates Scanner CRDs for each host.

### Scanner table (`operator/code/jobspec.py`)

There are no YAML templates. `SCANNERS` maps a scanner name to a `ScannerSpec`:

**detect** (`port-scanner`, `dns-scanner`, `http-headers-scanner`, `tls-scanner`, `http-redirect-scanner`, `traceroute-scanner`, `ssh-banner-scanner`, `whois-scanner`): `ghcr.io/samma-io/detect-*` (the table's own default tag is `latest`; the chart and the raw manifest pin them to the detect release `scanners.detectTag`, `2.0.0`, through `SAMMA_SCANNER_IMAGE_<NAME>`), one variant named after the scanner, no command (the image's entrypoint runs), results published to NATS in schema v2 (`reports=True`: they have ScanReports). `http-headers-scanner` gets `HTTPS=True` and `PORT=443` (`DETECT_ENV`): it judges HSTS only over HTTPS, and detect up to 2.0.1 let `config.yaml`'s port 80 beat the HTTPS default when only `HTTPS` was set.

**classic** (`nikto`, `nmap`, `tsunami`, `base`): `sammascanner/*` images. nmap has three variants (`port`, `http`, `tls`) with their own `command`; `nikto` and `nmap` have `sudo=True` because the images call sudo, which keeps `allowPrivilegeEscalation: true` for them; nmap has `raw_sockets=True` and gets `NET_RAW` plus `NMAP_PRIVILEGED=1` only when `SAMMA_NMAP_RAW_SOCKETS=true`, otherwise `NMAP_UNPRIVILEGED=1`. tsunami takes the target as an argument (`--ip-v4-target`, `--ip-v6-target` or `--hostname-target`, decided with `target_policy.parse_ip_literal`). `base` keeps its filebeat sidecar, which mounts the `filebeat` and `live` ConfigMaps; `init_operator()` creates them only with `SAMMA_LEGACY_BASE_SCANNER=true` (chart `scanners.legacyBaseScanner`), and `validate_scanner` emits a `LegacyScanner` warning when `base` is requested without it; `operator/code/scanners/core/` holds those two ConfigMaps and nothing else.

Every scanner container gets `TARGET`, `SAMMA_IO_SCANNER`, the Scanner's env (see `scanner_env`) with `NATS_SUBJECT` rewritten to `<base>.<scanner>`, and, when `SAMMA_NATS_SECRET` is set, `NATS_USER`, `NATS_PASSWORD` (secretKeyRef, key `scanner-password`) before a `NATS_URL` carrying `$(NATS_USER):$(NATS_PASSWORD)@`. Pods run with `drop: [ALL]`, `readOnlyRootFilesystem` with emptyDirs at `/out` and `/tmp`, `runAsNonRoot`, seccomp `RuntimeDefault`, resources from the settings, the `samma-scanner` ServiceAccount and no mounted token, and carry the label `samma.io/role: scanner` that the scanner NetworkPolicy selects. Jobs: `backoffLimit: 1`, `activeDeadlineSeconds`, `ttlSecondsAfterFinished`, an `ownerReference` to the Scanner. CronJobs: `concurrencyPolicy: Forbid`, history limits 1, `startingDeadlineSeconds: 600`, a `samma.io/spec-hash` annotation.

Image references: `SAMMA_SCANNER_IMAGE_<NAME>` (full reference, `-` as `_`), else `SAMMA_SCANNER_IMAGE_PREFIX` plus the image base name and `SAMMA_SCANNER_IMAGE_TAG`, else the table default. The chart maps `scanners.images`, `scanners.imagePrefix` and `scanners.imageTag` to these, and renders one `SAMMA_SCANNER_IMAGE_<NAME>` per name in `scanners.detectScanners` as `<imagePrefix, else ghcr.io/samma-io>/detect-<name>:<imageTag, else detectTag>` unless `scanners.images` names that scanner (`templates/operator.yaml`).

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

### NATS + Bridge + ScanReports + TimescaleDB (`bridge/`)

NATS (`nats:2`) is deployed in `samma-io` on port 4222 with the config in the `nats-config` ConfigMap: two users, `scanner` (publish only on `samma-io.scan` and `samma-io.scan.>`) and `bridge` (subscribe only on them), passwords from the Secret `samma-nats-auth` (keys `scanner-password`, `bridge-password`) through `$SAMMA_NATS_SCANNER_PASSWORD` / `$SAMMA_NATS_BRIDGE_PASSWORD` in the server config. The chart keeps the Secret stable across upgrades with `lookup` (`templates/nats-auth.yaml`); `nats.existingSecret` and `nats.auth.*Password` override; `nats.auth.enabled=false` removes authentication. Every scanner pod publishes on `samma-io.scan.<scanner>`.

The bridge (`bridge/code/bridge.py` plus the package `bridge/code/samma_bridge/`) subscribes to `NATS_SUBJECT` and `NATS_SUBJECT.>`. `bridge.py` is only the asyncio wiring (nats-py, asyncpg, the kubernetes adapter in `kube.py`, all imported lazily); everything that decides something is plain Python with unit tests in `bridge/tests`:

- `messages.py` parses one message: no `schema` key is a legacy v1 message (TimescaleDB only, as before); `samma.io/scan/v2` `finding` and `run` messages are validated (types, enums, patterns; `Rejected` with a reason label) and text fields are cut to the CRD limits.
- `accumulator.py` collects findings per `(scanner, template, target, runId)` until the run message; waits `STRAGGLER_WAIT_SECONDS` when the run message counts more findings than arrived; drops runs without a run message after `RUN_IDLE_TIMEOUT_SECONDS`.
- `scanners.py` caches the Scanner list (`SCANNER_CACHE_SECONDS`); a message whose target is not a current Scanner's target is dropped; the matching Scanners become the report's owners and give it the Ingress labels.
- `reports.py` names and labels the report like the Job (a copy of the `jobspec` code; `operator/tests/test_scanreport.py` checks the copies agree), dedupes on checkId plus endpoint, caps at 200 findings and 256 KiB (shorten evidence, drop INFO, drop the tail), builds the status bodies and runs `upsert()`: get, create when missing, replace status with the read resourceVersion (409 retried), then patch labels and owners.
- `pipeline.py` ties them together: a succeeded run replaces findings, summary and `lastSuccessAt`; `failed`/`timed_out` writes `lastRun` only; a run that arrived incomplete is recorded as `failed` with `bridge received N of M findings`.
- `metrics.py` is a stdlib Prometheus endpoint on `METRICS_PORT` (9100) with `/metrics`, `/healthz`, `/readyz`.

TimescaleDB (`DATABASE_URL`, empty for none) keeps the `scan_results` hypertable; v2 messages are inserted too, through their mirrored top-level `host`, `port`, `status`, `type` keys. It uses `PGDATA=/var/lib/postgresql/data/pgdata` to avoid conflicts with the `lost+found` directory at the PVC mount root.

### ScanReport CRD

`scanreports.samma.io/v1alpha1`, namespaced, short name `sr`, status subresource, printer columns target, scanner, outcome, high, lastSuccess. `spec` {target (same pattern as Scanner), scanner, template?, tier?}; `status` {scannerVersion, lastRun {runId, jobName?, startedAt, finishedAt, outcome succeeded|failed|timed_out, message <= 512}, lastSuccessAt, summary {critical, high, medium, low, info}, findings (<= 200) [{checkId `^[A-Z0-9-]{3,80}$`, severity CRITICAL|HIGH|MEDIUM|LOW|INFO, title <= 200, endpoint {host, port, scheme}, evidence <= 1024, remediation <= 1024, references <= 10, cveIds `^CVE-\d{4}-\d{4,}$`, compliance <= 20}]}. No raw scanner record. The two copies in `helm/samma-operator/crds/scanreports.samma.io.yaml` and `manifest/samma-operator.yaml` must stay identical; `operator/tests/test_scanreport.py` and `bridge/tests/test_reports.py` compare them and check the limits against the bridge constants.

### Network policies

`helm/samma-operator/templates/networkpolicies.yaml` (`networkPolicies.enabled`, default true) and the same three objects in the raw manifest: `samma-nats` (ingress to NATS from the namespace only), `samma-bridge` (egress to NATS, TimescaleDB, DNS, the API server by port), `samma-scanners` (pods labelled `app.kubernetes.io/managed-by=samma-operator` and `samma.io/role=scanner`: egress to DNS, NATS and non-private address space; the except lists go away when `config.allowPrivateTargets` is `"true"`). Only a CNI that implements NetworkPolicy enforces them.

### RBAC and ServiceAccounts

Four ServiceAccounts: `samma-operator` (ClusterRole: Ingresses get/list/watch/patch, `scanner.samma.io` full, `scanreports.samma.io` read and write, events create/patch, CRDs list/watch; Role in the namespace: Jobs and CronJobs full, ConfigMaps get/list/watch/create/patch, Secrets get/list, Pods get/list), `samma-api` (Role: Scanners get/list/create/patch/delete, ConfigMaps get/list), `samma-bridge` (Role: ScanReports get/list/watch/create/update/patch, Scanners get/list/watch) and `samma-scanner` (nothing; scanner pods). `helm/samma-operator/templates/rbac.yaml` and `manifest/samma-operator.yaml` must stay identical in content. The namespace comes from `SAMMA_NAMESPACE`, set from the Downward API in the chart and the manifest.

### Helm chart (`helm/samma-operator/`)

Published as OCI to `oci://ghcr.io/samma-io/charts/samma-operator` by the release workflow; `Chart.yaml` `version` and `appVersion` are the release and must equal the tag (`v<version>`). Points that are easy to break:

- `crds/` holds the two CRDs (`scanner.samma.io.yaml`, `scanreports.samma.io.yaml`): Helm installs them before the templates and never upgrades them (README, "Upgrading"). They contain no template syntax. `helm template` prints them only with `--include-crds`.
- `templates/_helpers.tpl`: `samma.image` renders `image@sha256:...` when `digest` is set, else `image:<tag, else .Chart.AppVersion>`; `samma.consentGate` calls `fail` while `acceptScanningTerms` is false and is included at the top of every workload template (operator, api, bridge, nats, timescaledb), so the consent error is the first one whatever order Helm renders in (`helm lint` ignores `fail`, so lint passes with defaults). `samma.storeInTimescaleDB` is true only when `timescaledb.enabled` and `bridge.storeInTimescaleDB` both are; `samma.timescaledbSecret` is `timescaledb.existingSecret` or `samma-timescaledb`.
- `api.enabled` gates `api.yaml` and the API ServiceAccount, Role and RoleBinding in `rbac.yaml`. `timescaledb.enabled` gates `timescaledb.yaml` (Secret, PVC, Deployment, Service), the bridge's `DATABASE_URL` (built from `$(TIMESCALEDB_PASSWORD)`, a secretKeyRef, so the password never appears in a Deployment) and the bridge NetworkPolicy's egress rule to it. `timescaledb.yaml` fails the render when enabled without `password` or `existingSecret`; there is no default password.
- Every image block has `image`, `tag`, `digest`, `pullPolicy` (`IfNotPresent`); `operator.image` is `ghcr.io/samma-io/samma-operator`, likewise `samma-api` and `samma-bridge`. Release notes carry the digests.
- With defaults, `helm template` renders 30 objects (32 with `--include-crds`); with `api.enabled=false,timescaledb.enabled=false` it renders 21.

### CRD & Manifests (`manifest/`)
- `manifest/samma-operator.yaml`: the chart with its defaults as plain YAML, kept by hand: namespace, the Scanner and ScanReport CRDs (identical to `helm/samma-operator/crds/`), ServiceAccounts, ClusterRole, Roles and bindings, operator Deployment + Service (8080), API Deployment + Service (8080), the NATS Secret (placeholder passwords, set them) + ConfigMap + Deployment + Service (4222), the TimescaleDB Secret (placeholder password) + PVC + Deployment + Service (5432), Bridge Deployment (metrics 9100), three NetworkPolicies. Images are the release's pinned ones (`ghcr.io/samma-io/samma-*:<version>`, detect scanners through `SAMMA_SCANNER_IMAGE_*`); bump them with `Chart.yaml`. No Helm hook: delete the Scanners by hand before deleting the manifest. No consent switch: the header says applying it is the acceptance. Releases attach a rendered copy (`samma-operator-<version>.yaml`).
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

### Releases (images and chart)
Nothing is built or pushed by hand. A release is a tag `v<version>` on `main` with `version` and `appVersion` in `helm/samma-operator/Chart.yaml` equal to `<version>`, a `CHANGELOG.md` entry, and the pinned images in `manifest/samma-operator.yaml` bumped. `.github/workflows/release.yaml` then verifies the tag against `Chart.yaml`, runs the unit tests and `helm lint`, builds `operator/`, `api/` and `bridge/` for linux/amd64 and linux/arm64 as `ghcr.io/<owner>/samma-<component>:<version>` and `:<version>-<short sha>` (never `latest`), packages and pushes the chart to `oci://ghcr.io/<owner>/charts`, renders the raw manifest with placeholder passwords, and creates the GitHub release (or adds to one created by hand) with the chart archive, the manifest and every image digest. A new GHCR package is private until its visibility is set once. The detect scanner images come from samma-io/detect's own release workflow; bump `scanners.detectTag` (values.yaml, README, manifest) to move to a new one.

For a development build, push an image of your own and point the chart at it (`operator.image`/`operator.tag`, README "Build & push images").

### Patching the scanner-profiles ConfigMap
`initOperator` only creates the ConfigMap on first run. For running clusters, add profiles manually:
```bash
kubectl patch configmap scanner-profiles -n samma-io --type merge \
  -p '{"data":{"my-profile":"nikto,nmap/http"}}'
```

### Unit tests
```bash
python3 -m unittest discover -s operator/tests -t operator
python3 -m unittest discover -s bridge/tests -t bridge
```
No cluster, network, nats-py, asyncpg or kubernetes client needed: DNS and the Ingress listing are faked, `jobspec` builds dictionaries, `scanqueue` takes its API calls as arguments, and the bridge tests drive `samma_bridge.pipeline` with an in-memory store. `operator_handler.py` imports kopf and `bridge/code/bridge.py` imports nats-py; neither is imported by the tests; check them with `python3 -m py_compile`. CI runs both suites (`unit-tests` job in `.github/workflows/build.yaml`).

### Devcontainer
Open in VS Code → "Reopen in Container". Provides Python 3.12, kubectl, helm, skaffold, k3d, Docker-in-Docker. Post-create script installs dependencies and creates a local k3d cluster.

### CI/CD (GitHub Actions)
`.github/workflows/build.yaml`: runs the unit tests and `helm lint`, then builds the `operator/`, `api/` and `bridge/` images on push and PR to `main`. Pushes (push only, never from a PR) to `ghcr.io/<owner>/samma-operator`, `samma-api` and `samma-bridge` tagged with the git SHA and `latest`.
`.github/workflows/release.yaml`: on tags `v*`, see "Releases (images and chart)" above.

## Key Concepts

- All scanners and services deploy into one namespace, `SAMMA_NAMESPACE` (default `samma-io`); nothing in the code names the namespace directly.
- Every Scanner create event creates one CronJob per scanner and queues one Job per scanner (`SAMMA_MAX_CONCURRENT_SCANS`, default 2, unfinished scan Jobs at a time). A Scanner spec change recreates the CronJobs only.
- Jobs and CronJobs are named `<scanner>[-<template>]-<8 hex of sha256(target)>` and labelled `samma.io/scanner`, `samma.io/template`, `samma.io/target-hash`, `samma.io/scanner-uid` (plus `samma.io/ingress-namespace` and `samma.io/ingress-name` when they came from an Ingress); the target is in the `samma.io/target` annotation. Ingress-made Scanners are named `<scanner>[-<template>]-<hash of namespace/name/host>`.
- Cleanup is ownerReferences plus garbage collection: Scanner owns Job and CronJob; an Ingress in the operator namespace owns its Scanners; for other namespaces `ingress_delete` deletes by label. No finalizers anywhere.
- NATS vars (`NATS_URL`, `NATS_ENABLED`, `NATS_SUBJECT`) reach every scanner through `jobspec.scanner_env`; `build_container` then makes the subject per scanner and adds the credentials from `SAMMA_NATS_SECRET`.
- A ScanReport is written only by the bridge (findings, on a succeeded run) and the operator (`lastRun` of a failed Job); never by hand. Its name equals the scan Job's name. Findings replace only on `outcome: succeeded`.
- `profile_resolver.py` exists in both `operator/code/` and `api/code/` — keep them in sync.
- `Scanner.spec.target` is validated before anything is deployed (`target_policy.check_target`): hostname or IP only, the same regex as the CRD `pattern`. `SAMMA_ALLOW_UNMANAGED_TARGETS` (default `true`) and `SAMMA_ALLOW_PRIVATE_TARGETS` (default `false`) control the Ingress-served and public-address checks. A rejection raises `kopf.PermanentError` and emits a Kubernetes event; an unresolvable name is retried every 5 minutes up to `MAX_RESOLVE_RETRIES`. Wildcard Ingress hosts are skipped. Keep the CRD patterns (helm and manifest copies) identical to the module constants; `operator/tests/test_target_policy.py` checks that.
- The operator and API images use `nodeSelector: kubernetes.io/arch: amd64`.
- Python 3.12 is used for operator, API, and bridge images.
