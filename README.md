# Samma Security Scanner Operator

![Samma-io!](assets/samma_logo.png)

## Overview

Samma is a Kubernetes operator that automatically deploys security scanners as Jobs and CronJobs into your cluster. When a scan target is registered, the operator immediately runs a one-time Job and schedules a weekly CronJob. Results are published to NATS and stored in TimescaleDB.

The system has two components:

- **Operator** — watches `Scanner` CRDs and Ingress resources, deploys scanner Jobs and CronJobs
- **API** — REST interface for managing scan targets and scanners

To see all available scanners, go to [Samma.io](https://samma.io).

---

## Architecture

```
PUT /target  →  API creates Scanner CRDs  →  Operator watches CRDs
                                                     │
                                          ┌──────────┴──────────┐
                                     deployJob()          deployCron()
                                     (runs now)           (weekly 0 0 * * 0)
                                          │                     │
                                    Scanner Pod          CronJob Pod
                                          │
                                        NATS (samma-io.scan)
                                          │
                                       Bridge
                                          │
                                     TimescaleDB
```

### Scanner types

There are two scanner families:

**detect** — Modern scanners (`ghcr.io/samma-io/detect-*:latest`). Single container, results published directly to NATS.

| Scanner | Image |
|---|---|
| `port-scanner` | `ghcr.io/samma-io/detect-port-scanner:latest` |
| `dns-scanner` | `ghcr.io/samma-io/detect-dns-scanner:latest` |
| `http-headers-scanner` | `ghcr.io/samma-io/detect-http-headers-scanner:latest` |
| `tls-scanner` | `ghcr.io/samma-io/detect-tls-scanner:latest` |
| `http-redirect-scanner` | `ghcr.io/samma-io/detect-http-redirect-scanner:latest` |
| `traceroute-scanner` | `ghcr.io/samma-io/detect-traceroute-scanner:latest` |
| `ssh-banner-scanner` | `ghcr.io/samma-io/detect-ssh-banner-scanner:latest` |
| `whois-scanner` | `ghcr.io/samma-io/detect-whois-scanner:latest` |

**classic** — Traditional scanners (`sammascanner/*`). Single container, NATS vars passed through env.

| Scanner | Image | Templates |
|---|---|---|
| `nikto` | `sammascanner/nikto:v0.2` | — |
| `nmap` | `sammascanner/nmap:v0.2` | `port`, `http`, `tls` |
| `tsunami` | `sammascanner/tsunami:v0.1` | — |

---

## Deployment methods

### 1. REST API (recommended)

The API service runs at `http://api.samma-io.svc:8080` inside the cluster.

See the [API Reference](#api-reference) section below for full documentation.

### 2. Scanner CRD (YAML)

Apply a `Scanner` resource directly:

```yaml
apiVersion: samma.io/v1
kind: Scanner
metadata:
  name: nmap-www-example-com
  namespace: samma-io
spec:
  target: www.example.com
  scanners: ["nmap"]
  samma_io_id: "12345"
  samma_io_tags: ["scanner", "prod"]
```

```bash
kubectl apply -f manifest/test/nmap.yaml
```

The operator will immediately create a Job and a weekly CronJob for each scanner.

### 3. Ingress annotations

Add annotations to any Ingress and the operator auto-creates Scanner CRDs for each host:

```yaml
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: my-app
  namespace: samma-io
  annotations:
    samma-io.alpha.kubernetes.io/enable: "true"
    samma-io.alpha.kubernetes.io/profile: "detect"
    samma-io.alpha.kubernetes.io/scheduler: "0 2 * * *"
    samma-io.alpha.kubernetes.io/samma_io_id: "12345"
    samma-io.alpha.kubernetes.io/samma_io_tags: "scanner,prod"
spec:
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 8080
```

---

## Scanner profiles

Profiles are stored in the `scanner-profiles` ConfigMap in the `samma-io` namespace. Pass `"profile": "<name>"` to `PUT /target` to select one.

| Profile | Scanners | Use when |
|---|---|---|
| `default` | All 12 detect + classic scanners (no tsunami) | Full scan of a new target |
| `web` | http-headers, http-redirect, tls, nikto, nmap/http | Web application targets |
| `network` | port, traceroute, ssh-banner, nmap/port, nmap/tls | Infrastructure / server targets |
| `dns` | dns-scanner, whois-scanner | Domain intelligence only |
| `detect` | All 8 modern detect scanners | NATS-native lightweight scan |
| `classic` | nikto, nmap (port/http/tls), tsunami | Traditional deep scan |
| `all` | All 12 scanners + tsunami | Maximum coverage |
| `full` | nmap, nikto, tsunami, base | Legacy full scan |

Customise profiles by patching the ConfigMap:

```bash
kubectl patch configmap scanner-profiles -n samma-io --type merge \
  -p '{"data":{"my-profile":"nikto,nmap/http"}}'
```

---

## API Reference

Base URL (inside cluster): `http://api.samma-io.svc:8080`

For local access, port-forward first:
```bash
kubectl port-forward svc/api 8080:8080 -n samma-io
```

Or use the test scripts in `api/test/`:
```bash
export API_URL=http://localhost:8080
./api/test/add_target.sh
./api/test/list_targets.sh
./api/test/del_target.sh
```

---

### Targets

The `/target` endpoint is the primary way to manage scan targets. The API resolves a profile to the correct scanner list and creates one Scanner CRD per scanner.

Every target gets both an immediate Job (runs once now) and a weekly CronJob (`0 0 * * 0`).

#### Add a target

```
PUT /target
```

Minimal request:
```bash
curl -X PUT http://localhost:8080/target \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "profile": "detect"
  }'
```

Full request with all options:
```bash
curl -X PUT http://localhost:8080/target \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "profile": "classic",
    "scheduler": "0 3 * * 0",
    "samma_io_id": "12345",
    "samma_io_tags": "scanner,prod",
    "samma_io_json": "{\"env\":\"prod\"}",
    "write_to_file": "true"
  }'
```

Request fields:

| Field | Required | Description |
|---|---|---|
| `target` | Yes | Hostname or IP to scan |
| `profile` | No | Scanner profile name (default: `default`) |
| `scheduler` | No | Override cron schedule for the CronJob (default: `0 0 * * 0`) |
| `samma_io_id` | No | Asset or target identifier |
| `samma_io_tags` | No | Comma-separated tags, e.g. `"scanner,prod"` |
| `samma_io_json` | No | Extra JSON metadata attached to scan results |
| `write_to_file` | No | Write results to file (`"true"`/`"false"`) |

Response `201 Created`:
```json
{
  "target": "www.example.com",
  "profile": "detect",
  "created": [
    "port-scanner-www-example-com",
    "dns-scanner-www-example-com",
    "http-headers-scanner-www-example-com",
    "tls-scanner-www-example-com"
  ],
  "skipped": []
}
```

`skipped` lists CRDs that already existed (idempotent). Status `207` is returned when some were skipped.

#### List all targets

```
GET /target
```

```bash
curl http://localhost:8080/target
```

Response:
```json
{
  "targets": [
    {
      "target": "www.example.com",
      "scanners": [
        "dns-scanner-www-example-com",
        "http-headers-scanner-www-example-com",
        "port-scanner-www-example-com",
        "tls-scanner-www-example-com"
      ]
    }
  ]
}
```

#### Remove a target

Deletes all Scanner CRDs for the target (operator then deletes the Jobs/CronJobs).

```
DELETE /target
```

```bash
curl -X DELETE http://localhost:8080/target \
  -H 'Content-Type: application/json' \
  -d '{"target": "www.example.com"}'
```

Response `200 OK`:
```json
{
  "target": "www.example.com",
  "deleted": ["port-scanner-www-example-com", "dns-scanner-www-example-com"],
  "errors": []
}
```

---

### Scanners (low-level)

Use `/scanner` for direct control when you don't want profile resolution.

#### List all scanners

```
GET /scanner
```

```bash
curl http://localhost:8080/scanner
```

Returns all Scanner CRDs in the `samma-io` namespace as JSON.

#### Create a scanner

```
PUT /scanner
```

```bash
curl -X PUT http://localhost:8080/scanner \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "samma_io_scanners": "nmap,nikto",
    "samma_io_id": "12345",
    "samma_io_tags": "scanner,prod"
  }'
```

#### Delete a scanner by name

```
DELETE /scanner
```

```bash
curl -X DELETE http://localhost:8080/scanner \
  -H 'Content-Type: application/json' \
  -d '{"name": "nmap-www-example-com"}'
```

---

### Health endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Liveness probe — returns `200` when the pod is running |
| `GET /ready` | Readiness probe — returns `200` when ready to serve traffic |
| `GET /metrics` | Prometheus metrics |

---

## Environment variables

### Operator

| Variable | Default | Description |
|---|---|---|
| `SAMMA_IO_ID` | `1234` | Default asset ID attached to scans |
| `SAMMA_IO_TAGS` | `["samma"]` | Default tags |
| `SAMMA_IO_JSON` | `{"samma":"scanner"}` | Default extra JSON |
| `WRITE_TO_FILE` | `true` | Write results to file |
| `NATS_URL` | `nats://nats:4222` | NATS server URL |
| `NATS_ENABLED` | `True` | Enable NATS publishing |
| `NATS_SUBJECT` | `samma-io.scan` | NATS subject for scan results |
| `SAMMA_IO_WEEKLY_SCHEDULE` | `0 0 * * 0` | Default CronJob schedule |
| `SAMMA_IO_API_URL` | — | External samma.io API base URL |
| `SAMMA_IO_API_TOKEN` | — | Bearer token for external API (skipped if empty) |
| `SAMMA_IO_PROFILE_ID` | — | Profile ID sent to external API |

### API

Same env vars as operator, plus the external API vars above.

---

## Deploying the operator

### Prerequisites

- Kubernetes cluster (1.21+)
- `kubectl` configured against the cluster
- Helm 3 (for Helm install)

---

### Option 1 — Raw manifest (quickest)

Deploys everything into the `samma-io` namespace with default settings.

```bash
kubectl apply -f manifest/samma-operator.yaml
```

Verify:

```bash
kubectl get pods -n samma-io
```

Expected pods: `samma-operator`, `samma-api`, `nats`, `timescaledb`, `samma-bridge`.

Access the API from inside the cluster at `http://api.samma-io.svc:8080`, or port-forward for local access:

```bash
kubectl port-forward svc/api 8080:8080 -n samma-io
curl http://localhost:8080/health
```

---

### Option 2 — Helm chart

The Helm chart is in `helm/samma-operator/` and exposes all images, credentials, and config as values.

**Install with defaults:**

```bash
helm install samma-operator helm/samma-operator/
```

**Install with custom values:**

```bash
helm install samma-operator helm/samma-operator/ \
  --set timescaledb.password=mysecretpassword \
  --set config.sammaIoId=my-org-id \
  --set config.apiToken=my-token
```

**Or use a values file** (recommended for production):

```yaml
# my-values.yaml
namespace: samma-io

timescaledb:
  password: mysecretpassword
  storage: 50Gi

config:
  sammaIoId: my-org-id
  sammaIoTags: "['scanner','prod']"
  apiUrl: https://www.samma.io
  apiToken: my-token
  profileId: my-profile-id
```

```bash
helm install samma-operator helm/samma-operator/ -f my-values.yaml
```

**Upgrade after changing values:**

```bash
helm upgrade samma-operator helm/samma-operator/ -f my-values.yaml
```

**Uninstall:**

```bash
helm uninstall samma-operator
kubectl delete namespace samma-io   # removes all data
```

**Key Helm values:**

| Value | Default | Description |
|---|---|---|
| `namespace` | `samma-io` | Namespace to deploy into |
| `operator.image` / `operator.tag` | `mattiashem/samma-operator:latest` | Operator image |
| `api.image` / `api.tag` | `sammascanner/api:latest` | API image |
| `timescaledb.password` | `samma` | Database password — change in production |
| `timescaledb.storage` | `10Gi` | PVC size for scan results |
| `config.sammaIoId` | `""` | Default asset ID attached to all scans |
| `config.sammaIoTags` | `['scanner']` | Default tags |
| `config.apiToken` | `""` | External samma.io API token |
| `config.natsUrl` | `nats://nats:4222` | NATS server URL |
| `nodeSelector` | `kubernetes.io/arch: amd64` | Node selector for all pods |

---

## Build & push images

```bash
# Operator
docker build --platform linux/amd64 -t mattiashem/samma-operator:latest ./operator/
docker push mattiashem/samma-operator:latest
kubectl rollout restart deployment/samma-operator -n samma-io

# API
docker build --platform linux/amd64 -t sammascanner/api:latest ./api/
docker push sammascanner/api:latest
kubectl rollout restart deployment/samma-api -n samma-io
```

## Build & Development

```bash
# Local Docker
docker compose build
docker compose up

# Kubernetes (skaffold)
cd operator && skaffold dev
cd api && skaffold dev
```

### Devcontainer

Open in VS Code and select "Reopen in Container". Provides Python 3.12, kubectl, helm, skaffold, k3d, and Docker-in-Docker. A local k3d cluster is created automatically on container start.
