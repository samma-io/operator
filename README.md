# Samma Security Scanner Operator

![Samma-io!](assets/samma_logo.png)


## Samma Security Scanners

This is a Kubernetes operator that deploys security scanners (nmap, nikto, tsunami) as Jobs or CronJobs into your cluster. Results are written to Elasticsearch and visualised in Kibana or Grafana.

To see all the scanners please go to [Samma.io](https://samma.io)


## Deployment methods

### 1. Scanner CRD (YAML)

Apply a `Scanner` resource directly to the cluster:

```yaml
apiVersion: samma.io/v1
kind: Scanner
metadata:
  name: samma-nmap
  namespace: samma-io
spec:
  target: www.samma.io
  scheduler: "2 19 * * *"   # omit for a one-time Job
  samma_io_id: "12345"
  samma_io_tags:
    - scanner
    - prod
  write_to_file: "true"
  elasticsearch: elasticsearch
  scanners: ['nmap']
```

```bash
kubectl apply -f manifest/test/nmap.yaml
```

### 2. Ingress annotations

Add annotations to any Ingress and the operator will automatically create Scanner CRDs for each host:

```yaml
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: my-app
  namespace: samma-io
  annotations:
    samma-io.alpha.kubernetes.io/enable: "true"
    samma-io.alpha.kubernetes.io/profile: "default"
    samma-io.alpha.kubernetes.io/scheduler: "0 2 * * *"
    samma-io.alpha.kubernetes.io/samma_io_id: "12345"
    samma-io.alpha.kubernetes.io/samma_io_tags: "scanner,prod"
    samma-io.alpha.kubernetes.io/write_to_file: "true"
    samma-io.alpha.kubernetes.io/elasticsearch: elasticsearch
spec:
  rules:
    - host: api.samma.io
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
```

### 3. REST API

The API service runs at port 8080 (`http://api.samma-io.svc:8080`).

---

#### Targets

The `/target` endpoint is the simplest way to add or remove a scan target. The API resolves a profile to the correct scanner list automatically.

**Add a target**

```bash
curl -X PUT http://api.samma-io.svc:8080/target \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "profile": "default"
  }'
```

With a cron schedule and optional metadata:

```bash
curl -X PUT http://api.samma-io.svc:8080/target \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "profile": "web",
    "scheduler": "0 2 * * *",
    "samma_io_id": "12345",
    "samma_io_tags": "scanner,prod",
    "write_to_file": "true",
    "elasticsearch": "elasticsearch"
  }'
```

Response `201 Created`:
```json
{
  "target": "www.example.com",
  "profile": "web",
  "created": ["nikto-www-example-com", "nmap-www-example-com-http"],
  "skipped": []
}
```

**List all targets**

```bash
curl http://api.samma-io.svc:8080/target
```

Response:
```json
{
  "targets": [
    {
      "target": "www.example.com",
      "scanners": ["nikto-www-example-com", "nmap-www-example-com-http"]
    }
  ]
}
```

**Remove a target**

Deletes all Scanner CRDs associated with the target:

```bash
curl -X DELETE http://api.samma-io.svc:8080/target \
  -H 'Content-Type: application/json' \
  -d '{"target": "www.example.com"}'
```

Response `200 OK`:
```json
{
  "target": "www.example.com",
  "deleted": ["nikto-www-example-com", "nmap-www-example-com-http"],
  "errors": []
}
```

---

#### Scanners (low-level)

Use `/scanner` when you need direct control over which scanners run.

**List scanners**

```bash
curl http://api.samma-io.svc:8080/scanner
```

**Create a scanner**

```bash
curl -X PUT http://api.samma-io.svc:8080/scanner \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "samma_io_scanners": "nmap,nikto",
    "samma_io_id": "12345",
    "samma_io_tags": "scanner,prod",
    "write_to_file": "true",
    "elasticsearch": "elasticsearch"
  }'
```

**Delete a scanner**

```bash
curl -X DELETE http://api.samma-io.svc:8080/scanner \
  -H 'Content-Type: application/json' \
  -d '{"name": "www-example-com"}'
```

---

## Scanner profiles

Profiles are stored in the `scanner-profiles` ConfigMap in `samma-io` and group scanner/template combinations:

| Profile   | Scanners                        |
|-----------|---------------------------------|
| `default` | nmap, nikto                     |
| `web`     | nikto, nmap/http                |
| `network` | nmap/port, nmap/tls             |
| `full`    | nmap, nikto, tsunami, base      |

Pass `"profile": "<name>"` to `PUT /target` to select a profile.

---

## Scanner spec reference

| Field           | Description |
|-----------------|-------------|
| `target`        | Hostname or IP to scan. Used as the Job/CronJob target. |
| `scheduler`     | Cron expression (e.g. `"2 19 * * *"`). Omit to run as a one-time Job. |
| `scanners`      | Array of scanner names: `nmap`, `nikto`, `tsunami`, `base`. |
| `templates`     | Optional array of scanner templates, e.g. `["http", "port"]` for nmap. |
| `samma_io_id`   | Identifier for the target (e.g. git SHA, asset ID). |
| `samma_io_tags` | Array of tags (e.g. `["prod", "scanner"]`) added to all log entries. |
| `samma_io_json` | Custom JSON string appended to scan results. |
| `write_to_file` | `"true"` — write results to a file for the Filebeat sidecar to ship. |
| `elasticsearch` | Elasticsearch service name. Filebeat uses this to ship results. |

---

## Build & Development

```bash
# Local Docker
docker compose build
docker compose up

# Kubernetes (skaffold)
cd operator && skaffold dev
cd api && skaffold dev

# Deploy to cluster
kubectl apply -f manifest/samma-operator.yaml
kubectl apply -f manifest/test/nmap.yaml
```
