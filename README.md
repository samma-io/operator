# Samma Security Scanner Operator

![Samma-io!](assets/samma_logo.png)

## Overview

Samma is a Kubernetes operator that deploys open-source security scanners into your cluster. When
a scan target is registered, the operator immediately runs a one-time Job and schedules a weekly
CronJob. Results are published to NATS; the bridge writes them as `ScanReport` objects you can
read with kubectl (see [Scan reports](#scan-reports)) and stores them in TimescaleDB for Grafana.

The system has two components:

- **Operator**: watches `Scanner` CRDs and Ingress resources, and deploys scanner Jobs and CronJobs.
- **API**: a REST interface for managing scan targets and scanners.

### What you get

- **Scanners that follow your Ingresses.** Annotate an Ingress and the operator scans every host in
  it from inside the cluster: TLS, security headers, open ports and OWASP-style web findings.
  Delete the Ingress and its scanners are removed.
- **External scanners from samma.io.** [Connect the operator to samma.io](#connect-to-sammaio) and
  your Ingress hosts are shared with the portal. samma.io adds external scanners, which give you an
  outside-in security baseline.
- **Vendor and compliance scanners.** Tag an Ingress with `compliance: pci-dss` and samma.io runs a
  validated vendor scanner, such as a PCI DSS ASV, against that endpoint. Use different vendors for
  different targets.
- **Results in your own Grafana.** In-cluster, external and vendor findings all land in
  [Grafana inside your cluster](#grafana-dashboards), per target.
- **Controlled from git.** Scanning is set by Ingress annotations, so it is versioned and reviewed
  with your manifests.

Each endpoint gets the scanners it needs, and nothing keeps scanning, or costing money, once a target is
gone. The [Samma guide](https://github.com/samma-io/guide/blob/main/1a-the-scanners/README.md)
describes every scanner and what to use it for.

---

## Architecture

```
PUT /target  →  API creates Scanner CRDs  →  Operator watches CRDs
                                                     │
                                          ┌──────────┴──────────┐
                                    Job (runs now,         CronJob (weekly,
                                    bounded queue)         hashed minute)
                                          │                     │
                                    Scanner Pod          CronJob Pod
                                          │
                                        NATS (samma-io.scan.<scanner>, authenticated)
                                          │
                                       Bridge
                                       │     │
                            ScanReport CRs   TimescaleDB
                            (kubectl get sr)  (Grafana)
```

### Scanner types

There are two scanner families:

**detect**: the modern scanners (`ghcr.io/samma-io/detect-*`, from
[samma-io/detect](https://github.com/samma-io/detect)). Single container, results published
directly to NATS in schema v2, so they have [ScanReports](#scan-reports).

The detect scanners are released together, and the chart pins all of them to one tag,
`scanners.detectTag` (default `2.0.2`, the detect release this operator was tested with). Point
them at a mirror with `scanners.imagePrefix` (and `scanners.imageTag`), or pin one scanner to a
tag or a digest with `scanners.images.<scanner>` (see [Scan Jobs and CronJobs](#scan-jobs-and-cronjobs)).

| Scanner | Image |
|---|---|
| `port-scanner` | `ghcr.io/samma-io/detect-port-scanner:2.0.2` |
| `dns-scanner` | `ghcr.io/samma-io/detect-dns-scanner:2.0.2` |
| `http-headers-scanner` | `ghcr.io/samma-io/detect-http-headers-scanner:2.0.2` |
| `tls-scanner` | `ghcr.io/samma-io/detect-tls-scanner:2.0.2` |
| `http-redirect-scanner` | `ghcr.io/samma-io/detect-http-redirect-scanner:2.0.2` |
| `traceroute-scanner` | `ghcr.io/samma-io/detect-traceroute-scanner:2.0.2` |
| `ssh-banner-scanner` | `ghcr.io/samma-io/detect-ssh-banner-scanner:2.0.2` |
| `whois-scanner` | `ghcr.io/samma-io/detect-whois-scanner:2.0.2` |

**classic**: the traditional scanners (`sammascanner/*`). Single container, NATS vars passed
through env. Their image references are the defaults built into `operator/code/jobspec.py`; they
move to rebuilt, pinned images in a later release.

| Scanner | Image | Templates |
|---|---|---|
| `nikto` | `sammascanner/nikto:v0.2` | none |
| `nmap` | `sammascanner/nmap:v0.2` | `port`, `http`, `tls` |
| `tsunami` | `sammascanner/tsunami:v0.1` | none |

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

The operator creates a Job now and a weekly CronJob for each scanner, both owned by the Scanner
(see [Scan Jobs and CronJobs](#scan-jobs-and-cronjobs)). The target must pass
[target validation](#target-validation). A scanner can be named with a template, as in
`scanners: ["nmap/http"]`, or the `templates` list can select variants for every scanner.

### 3. Ingress annotations

Add annotations to an Ingress and the operator auto-creates Scanner CRDs for each host. The
Ingress has to be in the operator's namespace, or in one of the extra namespaces configured with
`ingress.watchNamespaces` (`SAMMA_INGRESS_NAMESPACES`, see [Environment
variables](#environment-variables)):

```yaml
kind: Ingress
apiVersion: networking.k8s.io/v1
metadata:
  name: my-app
  namespace: samma-io
  annotations:
    samma-io.alpha.kubernetes.io/enable: "true"
    samma-io.alpha.kubernetes.io/profile: "web"
    samma-io.alpha.kubernetes.io/scheduler: "0 2 * * *"
    samma-io.alpha.kubernetes.io/samma_io_tags: "scanner,prod"
    samma-io.alpha.kubernetes.io/compliance: "pci-dss"
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

| Annotation (`samma-io.alpha.kubernetes.io/…`) | What it does |
|---|---|
| `enable` | Turns scanning on. `"false"`, `"0"`, `"no"` and `"off"` turn it off, and so does removing the annotation. |
| `profile` | Comma-separated [profiles](#scanner-profiles). Takes priority over `scanners`. |
| `scanners` | An explicit scanner list, used when there is no `profile`. |
| `scheduler` | Cron expression for the repeat scan. The default is weekly. |
| `samma_io_id` | Id added to every finding. |
| `samma_io_tags` | Comma-separated tags added to every finding. |
| `samma_io_json` | Extra JSON added to every finding. |
| `compliance` | Compliance tags, e.g. `pci-dss`. samma.io runs the matching validated vendor scanner. Needs the [samma.io connection](#connect-to-sammaio). |

Without `profile` or `scanners`, the `default` profile is used. Only `scheduler`, `samma_io_id`,
`samma_io_tags`, `samma_io_json`, `write_to_file` and `elasticsearch` are copied into the Scanner;
other annotations under the prefix are ignored.

#### Lifecycle

- **Ingress created:** one `Scanner` per scanner and host in the operator's namespace, named
  `<scanner>[-<template>]-<hash>` where the hash covers the Ingress and the host. Each Scanner
  carries the labels `samma.io/ingress-namespace` and `samma.io/ingress-name` and the annotation
  `samma.io/ingress: <namespace>/<name>`. Each one runs a Job now and a CronJob on its schedule.
- **Annotations or hosts changed:** the operator reconciles. New hosts get Scanners, removed hosts
  lose theirs, and a changed `scheduler` or tag updates the Scanner, which recreates its CronJob.
  Setting `enable` to `"false"` or removing it deletes the Scanners.
- **Ingress deleted:** the Scanners are removed by label, their Jobs and CronJobs follow through
  Kubernetes garbage collection, and samma.io stops its external and vendor scans for the host.
  An Ingress in the operator's own namespace also owns its Scanners through `ownerReferences`;
  Kubernetes does not allow an owner in another namespace, which is why the labels exist.
- **Every other Ingress is left alone.** The handlers match only Ingresses that carry the `enable`
  annotation and sit in the operator's namespace or one of the `SAMMA_INGRESS_NAMESPACES`
  namespaces; an opted-in Ingress anywhere else is skipped with a single log line and creates no
  Scanners. Kopf's own bookkeeping annotation
  (`kopf.zalando.org/last-handled-configuration`) is stored on opted-in Ingresses in any
  namespace; it goes away with the Scanners when the annotation is removed. Operators up to 0.2.1 wrote it on every Ingress in the
  cluster: such a leftover is removed the next time that Ingress changes, or by hand with
  `kubectl annotate ingress <name> -n <namespace> kopf.zalando.org/last-handled-configuration-`.
  Scanners an older operator created for Ingresses in a namespace you now leave out are not
  removed by the operator; delete them with
  `kubectl -n samma-io delete scanner -l samma.io/ingress-namespace=<namespace>`.

Two Ingresses that serve the same host each get their own Scanners; the Jobs and CronJobs for the
host are shared between them and go away when the last one does. Scanners created through the API
carry the tenant's `samma_io_id`, and their Jobs, CronJobs and ScanReports are keyed by that id as
well as the target: two tenants that register the same host never share a scan, because a Job runs
with a single `SAMMA_IO_ID`.

Keep the annotations in git with the rest of the Ingress. Your scanning setup is then reviewed and
versioned, and ArgoCD or Flux applies it.

## Target validation

A Scanner target ends up as a command line argument inside a scanner pod and as a value in the
rendered Job and CronJob YAML, so the operator checks it before it creates anything. Ingress hosts
are validated by the Kubernetes API server; `Scanner.spec.target` was a free string until now.

1. **Syntax.** The CRD schema and the operator accept a DNS hostname (lowercase labels, no
   wildcard, no scheme, no path, no whitespace) or an IPv4 or IPv6 address of at most 253
   characters. `spec.scanners`, `spec.scheduler`, `spec.samma_io_id` and `spec.samma_io_tags` have
   patterns too. The API server rejects a Scanner that does not match; the operator checks again
   so Scanners created before the schema was tightened get the same treatment.
2. **Served by an Ingress.** With `SAMMA_ALLOW_UNMANAGED_TARGETS=false` the target must be the
   host of an Ingress rule somewhere in the cluster, matched exactly (a wildcard rule does not
   count). The default is `true`, which keeps the REST API and hand written Scanners working.
3. **Public address.** With `SAMMA_ALLOW_PRIVATE_TARGETS=false` (the default) the target must
   resolve only to public addresses. Loopback, RFC 1918, link-local, multicast, carrier-grade NAT
   (`100.64.0.0/10`) and IPv6 unique local addresses are refused. An IP literal is checked without
   DNS. Set it to `true` to scan internal services, or when your public hostnames resolve to
   private addresses from inside the cluster (split-horizon DNS).

A rejected Scanner is not deployed. The reason is logged and written as a Kubernetes event on the
Scanner (`kubectl -n samma-io describe scanner <name>`). The resource stays in the cluster so the
reason is easy to find; delete it and create it again after fixing the target.

Wildcard Ingress hosts (`*.example.com`) are skipped with an event on the Ingress: a wildcard is
not an endpoint that can be scanned. A host that does not resolve yet, for example because DNS is
created after the Ingress, is checked again every five minutes for an hour before the operator
gives up on it.

The checks live in `operator/code/target_policy.py` and have unit tests in `operator/tests`:

```bash
python3 -m unittest discover -s operator/tests -t operator
python3 -m unittest discover -s bridge/tests -t bridge
```

---

## Scan Jobs and CronJobs

Jobs and CronJobs are built as objects in `operator/code/jobspec.py` from a table of scanner
definitions (image, entrypoint per variant, extra environment); nothing is rendered from YAML
templates any more. Every object the operator creates carries these labels and annotations:

| Label or annotation | Value |
|---|---|
| `app.kubernetes.io/managed-by` | `samma-operator` |
| `samma.io/role` | `scanner`; the [network policy](#network-policies) for scan pods selects it |
| `samma.io/scanner` | the scanner, for example `nmap` |
| `samma.io/template` | the variant, for example `port`; equal to the scanner name when it has one variant |
| `samma.io/target-hash` | the first eight hex characters of `sha256(target)` |
| `samma.io/scanner-uid` | the uid of the owning Scanner |
| `samma.io/ingress-namespace`, `samma.io/ingress-name` | on everything that came from an Ingress |
| `samma.io/target` (annotation) | the target |
| `samma.io/scanner-name` (annotation) | the Scanner's name |
| `samma.io/spec-hash` (annotation, CronJobs) | hash of the built spec; a change recreates the CronJob |

### Names

Jobs and CronJobs are named `<scanner>[-<template>]-<target hash>`, for example
`nmap-port-3f2a9b1c` or `tls-scanner-9c0ffee1`. The old names carried the target with dots turned
into hyphens, which is not a valid name for an IPv6 address and is too long for many hostnames.
The target itself is in the `samma.io/target` annotation:

```bash
kubectl -n samma-io get jobs,cronjobs -l samma.io/scanner=nmap \
  -o custom-columns='NAME:.metadata.name,TARGET:.metadata.annotations.samma\.io/target'
```

### Ownership and cleanup

Every Job and CronJob has an `ownerReference` to its Scanner, so deleting the Scanner removes them
through Kubernetes garbage collection. The kopf delete handlers are `optional=True`: they add no
finalizers, so a Scanner or an Ingress can always be deleted, with or without the operator running.
Finished Jobs are removed after `ttlSecondsAfterFinished` (default one hour), a Job retries once
(`backoffLimit: 1`) and is stopped after `activeDeadlineSeconds` (default 900 seconds).

When a Scanner is deleted the operator also removes Jobs and CronJobs an older version created
under the pre-hash names, so an upgrade does not leave them behind.

`helm uninstall` runs a pre-delete hook Job (`operator/code/uninstall_cleanup.py`) that deletes
every Scanner and every leftover scanner Job and CronJob in the namespace before the operator and
the CRD are removed, so removal never blocks on the CRD. Turn it off with `hooks.preDeleteCleanup=false`
or `helm uninstall --no-hooks`.

### Pod security

Scanner pods run under the `samma-scanner` ServiceAccount, which has no rights, with
`automountServiceAccountToken: false`. Every scanner container runs with:

- `runAsNonRoot: true` and `runAsUser` from `scanners.runAsUser` (default 1000, the uid `useradd`
  gives the `samma` user in the images),
- `seccompProfile: RuntimeDefault`,
- `capabilities: drop: [ALL]`,
- `readOnlyRootFilesystem: true` with `emptyDir` volumes at `/out` and `/tmp`,
- requests and limits from `scanners.resources`,
- `allowPrivilegeEscalation: false`, except for `nikto` and `nmap`: those images run the tool
  through `sudo`, which needs privilege escalation. The flag goes away once the images run the tool
  directly. The detect scanners and tsunami do not get it.

nmap SYN scans need raw sockets. With `scanners.nmapRawSockets=false` (the default) no capability
is added and the nmap containers get `NMAP_UNPRIVILEGED=1`, which nmap reads itself and which makes
it use connect scans; the nmap image has to pass that through (and use `-sT` for the port scan).
With `true` the nmap containers get `NET_RAW` and `NMAP_PRIVILEGED=1`, which is today's behaviour.
Only nmap ever receives the capability.

The legacy `base` scanner keeps its filebeat sidecar; it is the only multi-container scanner. The
sidecar mounts the `filebeat` and `live` ConfigMaps, which the operator creates at startup only
with `scanners.legacyBaseScanner: true` (`SAMMA_LEGACY_BASE_SCANNER`). Nothing else uses them, so
by default they are not created, and a Scanner that asks for `base` gets a `LegacyScanner` warning
event instead of a pod that never starts.

Pod Security admission: the chart labels the namespace it creates (`createNamespace: true`, the
default) `pod-security.kubernetes.io/enforce: baseline` and
`pod-security.kubernetes.io/warn: restricted`. Baseline enforce blocks privileged pods, host
namespaces, host paths and added capabilities (beyond `NET_BIND_SERVICE`) — every operator, API,
bridge, NATS and scanner pod complies. Restricted warn only logs violations, and the API, NATS and
TimescaleDB pods run without a full restricted securityContext, so expect warnings for them (and
for nikto and nmap, which keep `allowPrivilegeEscalation` for their `sudo`); they still run. A
namespace you create yourself needs the same labels applied by hand. One trade-off to know:
`scanners.nmapRawSockets=true` adds `NET_RAW`, which baseline enforce rejects — such nmap pods are
not scheduled until you relax the namespace's enforce label.

### Concurrency and scheduling

A Scanner's first Jobs go through a queue. At most `scanners.maxConcurrentScans` scan Jobs
(default 2) run at the same time in the namespace; Jobs started by CronJobs count too. Queued
Jobs start in order as slots free up, checked every `SAMMA_QUEUE_INTERVAL_SECONDS` (default 15).
A Scanner whose first scan is waiting carries the annotation `samma.io/initial-scan: queued` and
an event `ScanQueued`; it becomes `launched` once every Job exists. After an operator restart,
Scanners still marked `queued` are queued again. `maxConcurrentScans: 0` removes the limit.

CronJobs use `concurrencyPolicy: Forbid`, keep one successful and one failed Job, and skip a run
that could not start within `startingDeadlineSeconds: 600`. A Scanner on the default weekly
schedule gets a minute derived from the target hash, so many targets registered on the same day do
not all fire in the same minute; a `scheduler` you set is used unchanged.

Changing a Scanner's `spec` recreates its CronJobs. The first Job is not run again.

---

## RBAC

The operator no longer binds to `cluster-admin`. Four ServiceAccounts are created
(`serviceAccounts.*` in the chart):

| ServiceAccount | Rights |
|---|---|
| `samma-operator` | ClusterRole: Ingresses get, list, watch, patch (kopf keeps its progress and diff base as annotations on the opted-in Ingresses, and only on those); `scanner.samma.io` full; `scanreports.samma.io` get, list, watch, create, update, patch (it records failed scan Jobs there, see [Scan reports](#scan-reports)); events create, patch; CustomResourceDefinitions list, watch. Role in the namespace: Jobs and CronJobs full; ConfigMaps get, list, watch, create, patch; Secrets get, list; Pods get, list. |
| `samma-api` | Role: `scanner.samma.io` get, list, create, patch, delete; ConfigMaps get, list. |
| `samma-bridge` | Role: `scanreports.samma.io` get, list, watch, create, update, patch (it writes the reports); `scanner.samma.io` get, list, watch (it drops results for targets no Scanner has). |
| `samma-scanner` | Nothing. Scanner pods run under it with no token mounted. |

The operator runs in the namespace it is deployed to: `SAMMA_NAMESPACE` is set from the pod's
own namespace through the Downward API, and the API and the bridge read the same variable. The
raw manifest in `manifest/samma-operator.yaml` carries the same ServiceAccounts, roles and bindings.

---

## Scan reports

Every scan result is also a Kubernetes object: a `ScanReport` (`scanreports.samma.io/v1alpha1`,
short name `sr`), one per scanner and target, in the operator's namespace. Nothing else is needed
to read results, no database and no dashboard:

```bash
kubectl -n samma-io get scanreports
NAME                   TARGET            SCANNER       OUTCOME     HIGH   LASTSUCCESS
tls-scanner-d0c43d38   api.example.com   tls-scanner   succeeded   1      3m
kubectl -n samma-io get sr tls-scanner-d0c43d38 -o yaml
```

A report has the same name as the scan Job, `<scanner>[-<template>]-<target hash>`, the same
labels (`samma.io/scanner`, `samma.io/template`, `samma.io/target-hash`, and the Ingress labels
when the target came from an Ingress), the target in the `samma.io/target` annotation, and the
Scanners for that target and scanner as its owners, so it is garbage collected with them.

```yaml
apiVersion: samma.io/v1alpha1
kind: ScanReport
metadata:
  name: tls-scanner-d0c43d38
  namespace: samma-io
  labels:
    samma.io/scanner: tls-scanner
    samma.io/template: tls-scanner
    samma.io/target-hash: d0c43d38
    samma.io/ingress-namespace: shop
    samma.io/ingress-name: api
  annotations:
    samma.io/target: api.example.com
  ownerReferences:
    - apiVersion: samma.io/v1
      kind: Scanner
      name: tls-scanner-9c0ffee1
spec:
  target: api.example.com
  scanner: tls-scanner
status:
  scannerVersion: "1.4.0"
  lastRun:
    runId: tls-scanner-d0c43d38-x7k2p      # the scanner pod
    startedAt: "2026-10-15T02:00:04Z"
    finishedAt: "2026-10-15T02:00:21Z"
    outcome: succeeded                     # succeeded, failed or timed_out
  lastSuccessAt: "2026-10-15T02:00:21Z"
  summary: {critical: 0, high: 1, medium: 1, low: 0, info: 2}
  findings:
    - checkId: SAMMA-TLS-PROTOCOL-DEPRECATED
      severity: HIGH
      title: Deprecated TLS protocol version negotiated
      endpoint: {host: api.example.com, port: 443, scheme: https}
      evidence: negotiated TLSv1
      remediation: Disable SSLv3, TLS 1.0 and TLS 1.1 in the ingress controller or server TLS options.
      references: ["https://datatracker.ietf.org/doc/html/rfc8996"]
      compliance: ["pci-dss:4.2.1"]
```

### How a report is written

The bridge subscribes to NATS. The detect scanners publish messages in schema v2
(`samma.io/scan/v2`, from [samma-io/detect](https://github.com/samma-io/detect)): one `finding`
per failing check with a stable `checkId`, a `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`,
`INFO`), the endpoint, a short `evidence` summary and a `remediation`, and exactly one `run`
message at the end with the outcome. The bridge collects the findings of a run and, when the run
message arrives:

- **outcome `succeeded`:** the report's findings are replaced by this run's, `summary` is
  recomputed and `lastSuccessAt` is set. A clean scan produces an empty list, which is how a
  fixed finding disappears.
- **outcome `failed` or `timed_out`:** only `lastRun` is written. The previous findings stay, so
  a scan that could not run never looks like a scan that found nothing.

A run message that reports more findings than the bridge received waits 30 seconds for the rest
(`bridge.stragglerWaitSeconds`) and is then recorded as `failed` with the message
`bridge received N of M findings`, for the same reason: an incomplete picture must not replace a
complete one.

Scan Jobs can also die before they send anything: an image that cannot be pulled, an out-of-memory
kill, or the Job deadline hitting a pod that was still starting. The operator checks finished
scan Jobs every queue tick and writes `lastRun` for the ones that failed (`outcome: failed`, or
`timed_out` when the Job's condition reason is `DeadlineExceeded`), creating the report with only
its `spec` when there is none yet. So a target that never had a successful scan still shows up,
with the reason. Each Job is annotated `samma.io/outcome-recorded: "true"` once that is done.

### What goes in, what stays out

Messages are validated against the schema before anything is written (wrong types, unknown
severities, malformed check ids and CVE ids are rejected and counted), and a message whose target
is not the target of a current Scanner in the namespace is dropped. That means a pod that can
reach NATS cannot plant findings for a host nobody asked to scan. Findings are deduplicated on
check id plus endpoint, kept to 200 per report (highest severity first) and to 256 KiB serialised
(evidence is shortened first, then `INFO` findings are dropped). Evidence is a summary of at most
1 KiB; response bodies never enter a report. The scanner's raw record is not stored in the report
either; it still goes to TimescaleDB.

Only scanners that speak schema v2 get reports. Today those are the detect scanners; the classic
scanners (`nmap`, `nikto`, `tsunami`) still publish v1 messages, which the bridge stores in
TimescaleDB exactly as before and never turns into a report.

The ScanReport CRD carries an OpenAPI schema with these limits, so a malformed report is refused
by the API server. The bridge exposes Prometheus metrics on port 9100 (`/metrics`; messages
received, rejected and dropped by reason, reports written by outcome, finalise latency) and
readiness on `/readyz`. `bridge.scanReports=false` turns report writing off and
`bridge.storeInTimescaleDB=false` removes the database connection; the bridge works with either
one alone.

---

## NATS authentication

NATS no longer accepts anonymous connections. The chart configures two users:

| User | May | May not |
|---|---|---|
| `scanner` | publish on `samma-io.scan` and `samma-io.scan.>` | subscribe to anything |
| `bridge` | subscribe to `samma-io.scan` and `samma-io.scan.>` | publish anything |

Every scanner pod publishes on its own subject, `samma-io.scan.<scanner>`; the bridge listens to
both the wildcard and the old plain subject, so scanners that still use `samma-io.scan` keep
working.

The passwords live in the Secret `samma-nats-auth` with the keys `scanner-password` and
`bridge-password`. Scanner pods get `NATS_USER` and `NATS_PASSWORD` (from the Secret) and a
`NATS_URL` of the form `nats://$(NATS_USER):$(NATS_PASSWORD)@nats:4222`, which the kubelet expands;
the NATS client library reads the credentials from the URL, so no scanner image had to change. The
bridge gets `NATS_USER` and `NATS_PASSWORD` too, and accepts a credentials file in `NATS_CREDS`
instead when you point it at a NATS of your own. Passwords must be URL safe: the chart generates
alphanumeric ones.

Where the passwords come from, in order:

1. `nats.existingSecret`: a Secret you manage, with the two keys above. The chart renders none.
2. `nats.auth.scannerPassword` and `nats.auth.bridgePassword` set as values.
3. The Secret already in the cluster, read back with Helm's `lookup`, so `helm upgrade` keeps
   the passwords stable.
4. Generated at install time.

`helm template` and `helm install --dry-run` have no cluster to look in, so with 3 and 4 every
render produces new passwords. That is a limitation of Helm's `lookup`, not drift: a GitOps tool
that renders the chart itself (Argo CD, Flux's `helm template` mode) should use 1 or 2. The raw
manifest ships the Secret with placeholder values that you must replace before applying.

`nats.auth.enabled=false` restores the old unauthenticated NATS: no Secret, no credentials in any
pod. The operator passes credentials to scanner pods only when `SAMMA_NATS_SECRET` names a Secret.

### External NATS

The NATS URL and subject come from the chart values `config.natsUrl` and `config.natsSubject`
only: the operator reads `NATS_URL` and `NATS_SUBJECT` from its own environment and hands them to
every scanner Job and CronJob, and the bridge reads the same two values. No Scanner field, Ingress
annotation or target can change them.

`nats.enabled=false` leaves the bundled NATS out: its Deployment, Service, the `nats-config`
ConfigMap, the `samma-nats-auth` Secret and the `samma-nats` NetworkPolicy. The operator, the
bridge and the scanner pods then connect to `config.natsUrl`, which you point at a NATS you run.
That NATS has to accept, on `config.natsSubject` and `<natsSubject>.>`:

- **With `nats.auth.enabled=true`** (the default): publishes from the user `nats.auth.scannerUser`
  (`scanner`) and subscriptions from `nats.auth.bridgeUser` (`bridge`), with the passwords in the
  Secret named by `nats.existingSecret` (keys `scanner-password` and `bridge-password`, URL-safe).
  `nats.existingSecret` is required then: the chart renders no Secret for an external NATS and
  refuses to render without one rather than connect anonymously. `SAMMA_NATS_SECRET` is that
  Secret, so scanner pods get `NATS_USER`, `NATS_PASSWORD` and a `NATS_URL` with credentials as
  above, and the bridge gets its user and password from the same Secret. Give the two users the
  same publish-only and subscribe-only rights as the bundled config (`templates/nats-auth.yaml`).
- **With `nats.auth.enabled=false`**: anonymous connections. `SAMMA_NATS_SECRET` is empty and no
  pod gets credentials.

The bridge also accepts a credentials file (`NATS_CREDS`), which the chart does not mount.

With `networkPolicies.enabled`, the bridge and scanner policies allow egress to the external NATS
through `networkPolicies.externalNats`: its `ports` (`[4222]`) to the NetworkPolicy peers in `to`.
A NetworkPolicy cannot name a host, so list the NATS server's address (`ipBlock`) or, for a NATS in
the same cluster, its namespace and pods (`namespaceSelector` and `podSelector`). While `to` is
empty the ports are allowed to any address, private ones included; set it.

```yaml
nats:
  enabled: false
  existingSecret: my-nats-passwords
config:
  natsUrl: nats://<your NATS>:4222
networkPolicies:
  externalNats:
    to:
      - ipBlock: {cidr: <its address>/32}
```

---

## Network policies

The chart ships five NetworkPolicies (`networkPolicies.enabled`, default `true`; also in the raw
manifest):

| Policy | Selects | Allows |
|---|---|---|
| `samma-nats` | the NATS pod (while `nats.enabled` is on) | ingress on 4222 from pods in the release namespace only; on 8222 too while `nats.monitoring` is true |
| `samma-api` | the API pod | ingress on 8080 from pods in the release namespace and from the namespaces in `networkPolicies.apiClients` only |
| `samma-bridge` | the bridge | egress to NATS (the external one through `networkPolicies.externalNats` while `nats.enabled` is off, see [External NATS](#external-nats)), TimescaleDB (while `bridge.storeInTimescaleDB` is on), DNS, and the Kubernetes API server |
| `samma-scanners` | scan pods (`app.kubernetes.io/managed-by=samma-operator`, `samma.io/role=scanner`) | egress to DNS, NATS (likewise) and public addresses only |
| `samma-timescaledb` | the TimescaleDB pod (while `timescaledb.enabled` is on) | ingress on 5432 from the bridge and from the namespaces in `networkPolicies.timescaledbClients` only |

"Public addresses only" means `0.0.0.0/0` except `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
`100.64.0.0/10`, `169.254.0.0/16` and `127.0.0.0/8`, and `::/0` except `fc00::/7`, `fe80::/10`
and `::1/128`. A scan pod therefore cannot be used to reach other pods, Services or nodes. When
`config.allowPrivateTargets` is `"true"` (the same switch that lets a Scanner target a private
address) the except lists are left out, and the scanners can reach the cluster network.

The API server is not a pod, so the bridge's policy reaches it by port: 443 and 6443 to any
address by default (`networkPolicies.apiServer.ports`). Set `networkPolicies.apiServer.cidrs` to
restrict that to your control plane's addresses.

The `samma-timescaledb` policy renders while `timescaledb.enabled` is on and closes TimescaleDB
itself: on 5432, only the bridge pod and pods in the `networkPolicies.timescaledbClients`
namespaces get in. Client namespaces are matched through the automatic
`kubernetes.io/metadata.name` label every namespace carries, so listing a namespace needs no extra
labels — and allows every pod in it on 5432. The policy also restricts pods of the release
namespace itself, so a reader running in `samma-io` (a Grafana there, say) has to be listed too:
`timescaledbClients: [samma-io]`. See [TimescaleDB roles](#timescaledb-roles) for what may log in.

The `samma-api` policy closes the API the same way: on 8080, only pods of the release namespace
and pods in the `networkPolicies.apiClients` namespaces get in. Client namespaces are matched
through the automatic `kubernetes.io/metadata.name` label too, and listing a namespace allows
every pod in it. When you run the samma.io dashboard (or any other client) outside the release
namespace, its namespace must be listed in `networkPolicies.apiClients`, or its calls to the API
are dropped. The default (`[]`) allows same-namespace pods only.

A NetworkPolicy is only enforced by a CNI that implements it (Calico, Cilium, Antrea, kube-router,
and most managed offerings do; Flannel on its own does not). Without such a CNI the objects are
accepted and do nothing. Check with your cluster's documentation, or create a policy that denies
everything in a test namespace and see whether it holds.

---

## Connect to samma.io

Give the operator a samma.io API token (create one under **Dashboard → Tokens**):

```bash
helm upgrade samma-operator helm/samma-operator --reuse-values \
  --set config.apiUrl=https://www.samma.io \
  --set config.apiToken=<token> \
  --set config.profileId=<profile id, optional>
```

Once it has a token:

- every host from an annotated Ingress is registered as a target in your samma.io organisation;
- samma.io adds **external scanners** to that target, for an outside-in baseline;
- Ingresses tagged with `compliance` get the matching **validated vendor scanner**, such as a PCI
  DSS ASV. Vendors are connected on the samma.io side, so the cluster needs no vendor accounts;
- results come back to the same targets, so they show up in your Grafana and the samma.io
  dashboard.

These map to the `SAMMA_IO_API_URL`, `SAMMA_IO_API_TOKEN` and `SAMMA_IO_PROFILE_ID`
[environment variables](#environment-variables).

Note the difference between the two tokens: `SAMMA_IO_API_TOKEN` is outbound — it authenticates
this operator to samma.io — while `SAMMA_API_TOKEN` is inbound — it is the bearer token callers of
this operator's own REST API must send, and the API exits at startup without one.

---

## Scanner profiles

Profiles are stored in the `scanner-profiles` ConfigMap in the operator's namespace. Pass `"profile": "<name>"` to `PUT /target` to select one.

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

All endpoints except `GET /health`, `GET /ready` and `GET /metrics` require the header
`Authorization: Bearer $SAMMA_API_TOKEN` (see [Environment variables](#environment-variables));
a missing, wrongly scoped or wrong token gets `401 {"error": "unauthorized"}`.

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

Every target gets both an immediate Job (runs once now) and a weekly CronJob (`0 0 * * 0`). The
Scanner CRDs and the Jobs/CronJobs behind them are named from your `samma_io_id` (default `1234`),
not from the hostname, so two tenants can register the same host and each get their own scans.

#### Add a target

```
PUT /target
```

Minimal request:
```bash
curl -X PUT http://localhost:8080/target \
  -H 'Authorization: Bearer $SAMMA_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "www.example.com",
    "profile": "detect"
  }'
```

Full request with all options:
```bash
curl -X PUT http://localhost:8080/target \
  -H 'Authorization: Bearer $SAMMA_API_TOKEN' \
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
    "port-scanner-1234",
    "dns-scanner-1234",
    "http-headers-scanner-1234",
    "tls-scanner-1234"
  ],
  "skipped": []
}
```

`skipped` lists CRDs that already existed for this target + `samma_io_id` pair (idempotent). Status `207` is returned when some were skipped.

#### List all targets

```
GET /target
```

```bash
curl -H 'Authorization: Bearer $SAMMA_API_TOKEN' http://localhost:8080/target
```

Response:
```json
{
  "targets": [
    {
      "target": "www.example.com",
      "samma_io_id": "1234",
      "scanners": [
        "dns-scanner-1234",
        "http-headers-scanner-1234",
        "port-scanner-1234",
        "tls-scanner-1234"
      ]
    }
  ]
}
```

A host registered by two tenants (two `samma_io_id` values) is listed once per id.

#### Remove a target

Deletes the Scanner CRDs for the target (the operator deletes the Jobs/CronJobs, and Kubernetes
garbage-collects them with the CRs). Pass the optional `samma_io_id` to delete only one tenant's
scanners; without it, every Scanner for the host is removed.

```
DELETE /target
```

```bash
curl -X DELETE http://localhost:8080/target \
  -H 'Authorization: Bearer $SAMMA_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"target": "www.example.com"}'
```

Response `200 OK`:
```json
{
  "target": "www.example.com",
  "deleted": ["port-scanner-1234", "dns-scanner-1234"],
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
curl -H 'Authorization: Bearer $SAMMA_API_TOKEN' http://localhost:8080/scanner
```

Returns all Scanner CRDs in the `samma-io` namespace as JSON.

#### Create a scanner

```
PUT /scanner
```

```bash
curl -X PUT http://localhost:8080/scanner \
  -H 'Authorization: Bearer $SAMMA_API_TOKEN' \
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
  -H 'Authorization: Bearer $SAMMA_API_TOKEN' \
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
| `SAMMA_ALLOW_PRIVATE_TARGETS` | `false` | `true` lets a target resolve to a private, loopback, link-local, multicast or carrier-grade NAT address. See [Target validation](#target-validation). |
| `SAMMA_ALLOW_UNMANAGED_TARGETS` | `true` | `false` refuses a Scanner whose target is not the host of an Ingress in the cluster. |
| `SAMMA_INGRESS_NAMESPACES` | empty | Comma-separated extra namespaces whose Ingresses are handled (` shop , ,api ` parses to `shop`, `api`); `*` restores every namespace, the behaviour before this restriction. The operator's own namespace is always handled. See [Ingress annotations](#ingress-annotations). |
| `SAMMA_NAMESPACE` | `samma-io` | The namespace Scanners, Jobs and CronJobs live in. The chart sets it from the pod's namespace. |
| `SAMMA_SCANNER_SERVICE_ACCOUNT` | `samma-scanner` | ServiceAccount of scanner pods. |
| `SAMMA_MAX_CONCURRENT_SCANS` | `2` | Scan Jobs allowed to run at the same time; `0` for no limit. See [Concurrency and scheduling](#concurrency-and-scheduling). |
| `SAMMA_QUEUE_INTERVAL_SECONDS` | `15` | How often the queue checks for a free slot. |
| `SAMMA_SCAN_DEADLINE_SECONDS` | `900` | `activeDeadlineSeconds` of every scan Job. |
| `SAMMA_JOB_TTL_SECONDS` | `3600` | `ttlSecondsAfterFinished` of every scan Job. |
| `SAMMA_NMAP_RAW_SOCKETS` | `false` | `true` adds `NET_RAW` to the nmap containers. See [Pod security](#pod-security). |
| `SAMMA_SCANNER_RUN_AS_USER` | `1000` | uid of scanner containers. |
| `SAMMA_SCANNER_IMAGE_PREFIX` | unset | Registry and organisation that replace the default of every scanner image. |
| `SAMMA_SCANNER_IMAGE_TAG` | unset | Tag used together with the prefix (default: each image's own tag). |
| `SAMMA_SCANNER_IMAGE_PULL_POLICY` | unset | `imagePullPolicy` of scanner containers. |
| `SAMMA_SCANNER_IMAGE_<NAME>` | unset | Full image reference for one scanner, for example `SAMMA_SCANNER_IMAGE_HTTP_HEADERS_SCANNER`. |
| `SAMMA_SCANNER_CPU_REQUEST`, `SAMMA_SCANNER_MEMORY_REQUEST`, `SAMMA_SCANNER_CPU_LIMIT`, `SAMMA_SCANNER_MEMORY_LIMIT` | `100m`, `128Mi`, `1`, `512Mi` | Resources of every scanner container. |
| `SAMMA_NATS_SECRET` | unset | Secret with the key `scanner-password`; scanner pods get `NATS_USER`, `NATS_PASSWORD` and a `NATS_URL` with credentials from it. Unset: no credentials. See [NATS authentication](#nats-authentication). |
| `SAMMA_NATS_SCANNER_USER` | `scanner` | The NATS user scanner pods log in as. |

### API

Same env vars as operator, plus the external API vars above.

| Variable | Default | Description |
|---|---|---|
| `SAMMA_API_TOKEN` | — | Required. Inbound bearer token for the API itself: every endpoint except `GET /health`, `GET /ready` and `GET /metrics` must send `Authorization: Bearer <token>` and receives `401 {"error": "unauthorized"}` otherwise. The process exits at startup when the variable is unset or empty. Distinct from `SAMMA_IO_API_TOKEN`, the outbound token the API uses when posting targets to samma.io. |

### Bridge

| Variable | Default | Description |
|---|---|---|
| `NATS_URL` | `nats://nats:4222` | NATS server URL |
| `NATS_SUBJECT` | `samma-io.scan` | Base subject; the bridge subscribes to it and to `<base>.>` |
| `NATS_USER`, `NATS_PASSWORD` | unset | NATS credentials (the `bridge` user) |
| `NATS_CREDS` | unset | Path to a NATS credentials file; wins over user and password |
| `DATABASE_URL` | unset | TimescaleDB connection string. Empty: no database, ScanReports only |
| `SAMMA_NAMESPACE` | `samma-io` | Where Scanners are listed and ScanReports written |
| `SCANREPORTS_ENABLED` | `true` | `false` stores rows only and never touches the Kubernetes API |
| `METRICS_PORT` | `9100` | Prometheus metrics, `/healthz` and `/readyz` |
| `SCANNER_CACHE_SECONDS` | `30` | How long the list of Scanners is cached |
| `STRAGGLER_WAIT_SECONDS` | `30` | How long a run waits for findings still in flight after its run message |
| `RUN_IDLE_TIMEOUT_SECONDS` | `3600` | A run without a run message is dropped after this long |

---

## Deploying the operator

### Before you install

The operator scans hosts. Once installed, it runs security scanners from inside the cluster
against every host of an Ingress you annotate, and against any target a `Scanner` resource names.
Only scan hosts you own or are allowed to test: scanning other people's hosts may break the law or
your provider's terms of service. The chart will not render the operator until you say so with
`acceptScanningTerms=true`.

### Prerequisites

- Kubernetes 1.25 or newer
- `kubectl` configured against the cluster
- Helm 3.8 or newer (OCI registries) for the chart install

---

### Option 1: Helm chart (recommended)

The chart is published to `oci://ghcr.io/samma-io/charts/samma-operator`. Every release pins its
own images: the chart's `appVersion` is the tag of the operator, API and bridge images, and
`scanners.detectTag` is the tag of the detect scanner images.

```bash
helm install samma oci://ghcr.io/samma-io/charts/samma-operator --version 0.2.0 \
  --set acceptScanningTerms=true \
  --set timescaledb.password=<alphanumeric password>
```

This installs the operator, the REST API, NATS, TimescaleDB (with a PVC) and the bridge into the
namespace `samma-io`, which the chart creates. The two CRDs come from the chart's `crds/` directory
and are installed first.

**A values file** (recommended for anything you keep):

```yaml
# my-values.yaml
acceptScanningTerms: true

timescaledb:
  password: <alphanumeric password>   # or existingSecret: <Secret with the key "password">
  storage: 50Gi

config:
  sammaIoId: my-org-id
  sammaIoTags: "['scanner','prod']"
  apiToken: my-token          # optional samma.io connection
  profileId: my-profile-id
```

```bash
helm install samma oci://ghcr.io/samma-io/charts/samma-operator --version 0.2.0 -f my-values.yaml
```

**Without the API and the database.** Targets can come from Ingress annotations and `Scanner`
resources alone, and results live in `ScanReport` objects, so the API and TimescaleDB are optional:

```bash
helm install samma oci://ghcr.io/samma-io/charts/samma-operator --version 0.2.0 \
  --set acceptScanningTerms=true \
  --set api.enabled=false \
  --set timescaledb.enabled=false
```

With `timescaledb.enabled=false` the bridge gets no `DATABASE_URL` and writes ScanReports only; no
PVC and no password are needed.

**Pin by digest.** Every image takes a `digest` (`operator.digest`, `api.digest`, `bridge.digest`,
`nats.digest`, `timescaledb.digest`), rendered as `image@sha256:...`. The release notes list the
digest of every image, and `scanners.images.<scanner>` pins one scanner image the same way.

**Upgrade** (see [Upgrading](#upgrading) for the CRDs):

```bash
helm upgrade samma oci://ghcr.io/samma-io/charts/samma-operator --version <new version> -f my-values.yaml
```

**Uninstall:**

```bash
helm uninstall samma                # the pre-delete hook removes every Scanner first
kubectl delete namespace samma-io   # removes all data
kubectl delete crd scanner.samma.io scanreports.samma.io   # Helm leaves CRDs in place
```

**Key Helm values:**

| Value | Default | Description |
|---|---|---|
| `acceptScanningTerms` | `false` | Must be `true`: you accept that the operator actively scans the hosts your Ingresses serve |
| `namespace` | `samma-io` | Namespace to deploy into |
| `createNamespace` | `true` | Create the Namespace as part of the release |
| `operator.image`, `.tag`, `.digest`, `.pullPolicy` | `ghcr.io/samma-io/samma-operator`, `""` (the chart's `appVersion`), `""`, `IfNotPresent` | Operator image; a digest wins over the tag |
| `api.enabled` | `true` | Deploy the REST API |
| `api.image`, `.tag`, `.digest`, `.pullPolicy` | `ghcr.io/samma-io/samma-api`, `""`, `""`, `IfNotPresent` | API image |
| `bridge.image`, `.tag`, `.digest`, `.pullPolicy` | `ghcr.io/samma-io/samma-bridge`, `""`, `""`, `IfNotPresent` | Bridge image |
| `nats.enabled` | `true` | Deploy the bundled NATS; `false` uses the NATS at `config.natsUrl`, see [External NATS](#external-nats) |
| `nats.image`, `.tag`, `.digest`, `.pullPolicy` | `nats`, `2`, `""`, `IfNotPresent` | NATS image |
| `timescaledb.enabled` | `true` | Deploy TimescaleDB and its PVC |
| `timescaledb.password`, `timescaledb.existingSecret` | `""`, `""` | One of the two is required when enabled: the password (stored in the Secret `samma-timescaledb`) or your own Secret with the key `password`. No default |
| `timescaledb.image`, `.tag`, `.digest`, `.pullPolicy` | `timescale/timescaledb`, `latest-pg15`, `""`, `IfNotPresent` | TimescaleDB image |
| `timescaledb.storage` | `10Gi` | PVC size for scan results |
| `config.sammaIoId` | `""` | Default asset ID attached to all scans |
| `config.sammaIoTags` | `['scanner']` | Default tags |
| `config.apiToken` | `""` | External samma.io API token |
| `config.natsUrl` | `nats://nats:4222` | NATS server URL for the operator's scanner Jobs and CronJobs and the bridge; required |
| `config.natsSubject` | `samma-io.scan` | Base subject; scanners publish on `<natsSubject>.<scanner>` |
| `config.allowPrivateTargets`, `config.allowUnmanagedTargets` | `"false"`, `"true"` | See [Target validation](#target-validation) |
| `nodeSelector` | `kubernetes.io/arch: amd64` | Node selector for all pods |
| `serviceAccounts.operator` / `api` / `bridge` / `scanner` | `samma-operator`, `samma-api`, `samma-bridge`, `samma-scanner` | ServiceAccount names, see [RBAC](#rbac) |
| `scanners.detectTag` | `2.0.2` | Tag of every detect scanner image, see [Scanner types](#scanner-types) |
| `scanners.imagePrefix`, `scanners.imageTag`, `scanners.images` | `""`, `""`, `{}` | Mirror and per-scanner image references, see [Scan Jobs and CronJobs](#scan-jobs-and-cronjobs) |
| `scanners.pullPolicy` | `IfNotPresent` | `imagePullPolicy` of scanner containers |
| `scanners.resources` | 100m/128Mi requests, 1/512Mi limits | Resources of every scanner container |
| `scanners.maxConcurrentScans` | `2` | Scan Jobs allowed to run at the same time |
| `scanners.scanDeadlineSeconds` | `900` | `activeDeadlineSeconds` of scan Jobs |
| `scanners.ttlSecondsAfterFinished` | `3600` | When finished Jobs are removed |
| `scanners.nmapRawSockets` | `false` | Give nmap `NET_RAW` for SYN scans |
| `scanners.runAsUser` | `1000` | uid of scanner containers |
| `hooks.preDeleteCleanup` | `true` | Pre-delete hook that removes every Scanner on uninstall |
| `nats.auth.enabled` | `true` | NATS users with publish-only and subscribe-only rights, see [NATS authentication](#nats-authentication) |
| `nats.existingSecret` | `""` | Your own Secret with `scanner-password` and `bridge-password`; required with `nats.enabled=false` while `nats.auth.enabled` is on |
| `nats.auth.scannerPassword`, `nats.auth.bridgePassword` | `""` | Fixed passwords; empty means kept from the cluster or generated |
| `nats.monitoring` | `false` | Serves the NATS HTTP monitoring endpoint on 8222: the server config's `http` line, the container port, the Service port and the `samma-nats` policy entry follow this switch |
| `bridge.scanReports` | `true` | Write ScanReport objects, see [Scan reports](#scan-reports) |
| `bridge.storeInTimescaleDB` | `true` | Insert every message into TimescaleDB (needs `timescaledb.enabled`) |
| `networkPolicies.enabled` | `true` | NetworkPolicies for NATS, the API, the bridge and scan pods, see [Network policies](#network-policies) |
| `networkPolicies.apiServer.ports`, `.cidrs` | `[443, 6443]`, `[]` | How the bridge may reach the API server |
| `networkPolicies.externalNats.ports`, `.to` | `[4222]`, `[]` | With `nats.enabled=false`: egress of the bridge and scan pods to the external NATS, see [External NATS](#external-nats) |
| `networkPolicies.apiClients` | `[]` | Namespace names (matched via `kubernetes.io/metadata.name`) whose pods may reach the API on 8080; the dashboard's namespace must be listed or its calls are dropped. See [Network policies](#network-policies) |

---

### Option 2: Raw manifest

Every release attaches `samma-operator-<version>.yaml`, the chart rendered with its defaults and
the CRDs inline; `manifest/samma-operator.yaml` in the repository is the same deployment for the
current version. Set the three `CHANGE-ME` passwords (NATS scanner and bridge, TimescaleDB) before
applying. Applying the manifest is your acceptance of the scanning terms above: there is no
`acceptScanningTerms` switch in plain YAML.

```bash
kubectl apply -f samma-operator-0.2.0.yaml
kubectl get pods -n samma-io
```

Expected pods: `samma-operator`, `samma-api`, `nats`, `timescaledb`, `samma-bridge`.

Access the API from inside the cluster at `http://api.samma-io.svc:8080`, or port-forward for local access:

```bash
kubectl port-forward svc/api 8080:8080 -n samma-io
curl http://localhost:8080/health
```

---

## Upgrading

`helm upgrade` to a newer chart version rolls the operator, API, bridge and (if you did not pin
them) the detect scanner images to the versions that release was tested with. Two things to know:

**CRDs.** The CRDs live in the chart's `crds/` directory. Helm installs them on `helm install` and
never touches them again, so a release that changes a CRD needs one extra step after the upgrade:

```bash
helm pull oci://ghcr.io/samma-io/charts/samma-operator --version <version> --untar
kubectl apply -f samma-operator/crds/
```

The release notes say when a CRD changed. Helm 3.17 and newer can also do it in one go with
`helm upgrade --take-ownership`, as long as the CRDs are already in the cluster. The raw manifest
carries the CRDs inline, so `kubectl apply -f samma-operator-<version>.yaml` updates them as part
of the apply.

**From 0.2.1 or earlier.** Those operators wrote kopf's `kopf.zalando.org/last-handled-configuration`
annotation on every Ingress in the cluster; newer ones write it on opted-in Ingresses only and remove
a leftover when that Ingress next changes (see [Lifecycle](#lifecycle) for the one-liner). The
`filebeat` and `live` ConfigMaps are created only with `scanners.legacyBaseScanner: true` from now
on; existing ones are left in place.

**From a chart before 0.2.0.** Those charts installed the CRDs as ordinary templates and used a
default TimescaleDB password. Before upgrading, set `acceptScanningTerms: true` and
`timescaledb.password: samma` (the old default, or your own) in your values, then run
`kubectl apply -f samma-operator/crds/` once after the upgrade so the CRDs are the 0.2.0 ones. The
CRD objects keep their data; only their definitions are rewritten.

---

## Releases

A release is a git tag `v<version>` on `main`, where `<version>` equals `version` and `appVersion`
in `helm/samma-operator/Chart.yaml`. Pushing the tag, or creating a GitHub release for it, runs
`.github/workflows/release.yaml`, which

1. checks that the tag matches `Chart.yaml`, runs the unit tests and lints the chart;
2. builds the operator, API and bridge images for `linux/amd64` and `linux/arm64` and pushes them
   to `ghcr.io/samma-io/samma-operator`, `samma-api` and `samma-bridge`, tagged `<version>` and
   `<version>-<short sha>`. A release never moves `latest`;
3. packages the chart with that version and pushes it to `oci://ghcr.io/samma-io/charts`;
4. creates the GitHub release with the chart archive, the rendered raw manifest and a table of
   every image's digest.

To release: set `version` and `appVersion` in `Chart.yaml`, add the entry to `CHANGELOG.md`, merge,
then `git tag v<version> && git push origin v<version>`. New packages on GHCR are private until
their visibility is set to public once in the organisation's package settings.

The detect scanner images are released from [samma-io/detect](https://github.com/samma-io/detect)
the same way; a new detect release is a one-line change of `scanners.detectTag` here.

Every image and the chart can be pulled by digest, which is how downstream distributions mirror a
release into their own registry without depending on GHCR at deploy time.

---

## Grafana dashboards

All findings for all your targets end up in TimescaleDB in your cluster, and Grafana is where you
read them. The operator chart does not install Grafana: use the one you already run, or install
one, and point it at TimescaleDB. The `grafana/` directory contains a setup script and pre-built dashboard JSON files.

### TimescaleDB roles

At every startup the bridge ensures the read-only role `samma_reader`: `NOLOGIN`, with `SELECT` on
`scan_results`. It is idempotent — the `CREATE ROLE` runs inside a `DO` block that checks
`pg_catalog.pg_roles` first — so it is safe on an existing database as much as on a fresh one.

Giving the dashboard a login is a manual step; the bridge never creates a login or a password.
Create one and grant it membership of `samma_reader`, for example through `kubectl exec` into the
timescaledb pod:

```bash
kubectl -n samma-io exec deploy/timescaledb -- psql -U samma -d samma \
  -c "CREATE ROLE dashboard LOGIN PASSWORD '<generated>' IN ROLE samma_reader"
```

Generate the password yourself (`openssl rand -base64 24`) and store it in a Secret. Point the
Grafana datasource at the `dashboard` role — never connect a reader as `samma`, the table owner,
which can write and drop. Namespace-wise, the dashboard (and any Grafana) may only reach the
database where the `samma-timescaledb` network policy allows it: put their namespaces into
`networkPolicies.timescaledbClients` (see [Network policies](#network-policies)).

### Dashboards

| Dashboard | File | Contents |
|---|---|---|
| **Samma — Security Overview** | `grafana/dashboard-overview.json` | Total scans, scans over time by scanner, results by type, latest results table |
| **Samma — Open Ports & Network** | `grafana/dashboard-ports.json` | Open ports by host, most common ports, SSH banner and traceroute findings |
| **Samma — Web & TLS** | `grafana/dashboard-web-tls.json` | TLS validity per host, HTTP redirect status, HTTP headers, DNS results |

### Setup

The script pushes a PostgreSQL datasource (pointing at TimescaleDB) and all three dashboards into an existing Grafana via the HTTP API. It is idempotent — safe to re-run.

Four variables are required and have no defaults — the script exits 1 without them: `GRAFANA_URL`, `GRAFANA_USER`, `GRAFANA_PASSWORD` and `TSDB_PASSWORD`. Source the Grafana credentials from your Grafana admin secret and supply the TimescaleDB password you deployed with.

**Port-forward Grafana and run:**

```bash
kubectl port-forward -n <grafana-namespace> svc/grafana 3000:80

GRAFANA_URL=http://localhost:3000 \
GRAFANA_USER=<grafana-admin-user> \
GRAFANA_PASSWORD=$(kubectl get secret -n <grafana-namespace> <grafana-secret> -o jsonpath='{.data.admin-password}' | base64 -d) \
TSDB_PASSWORD=<timescaledb-password> \
python grafana/setup_grafana.py
```

To mint a new password instead, generate one and store it in a secret — never hard-code it:

```bash
openssl rand -base64 24
```

TimescaleDB is reachable cluster-wide at `timescaledb.samma-io.svc.cluster.local:5432`, so the datasource works from any namespace. Override the connection with env vars if needed (`TSDB_PASSWORD` stays required — no default):

```bash
TSDB_HOST=timescaledb.samma-io.svc.cluster.local \
TSDB_PORT=5432 \
TSDB_DB=samma \
TSDB_USER=samma
```

### Import dashboards manually

To import a dashboard through the Grafana UI instead of using the script: **Dashboards → Import → Upload JSON file** and select one of the `grafana/dashboard-*.json` files. Set the datasource to your TimescaleDB/PostgreSQL datasource when prompted.

---

## Build & push images

Images are built by GitHub Actions: `.github/workflows/build.yaml` on every push to `main`
(`ghcr.io/samma-io/samma-{operator,api,bridge}` tagged `sha-<short sha>` and `latest`) and
`.github/workflows/release.yaml` on every tag `v*` (see [Releases](#releases)). To try a build of
your own on a development cluster:

```bash
docker build -t ghcr.io/<you>/samma-operator:dev ./operator/
docker push ghcr.io/<you>/samma-operator:dev
helm upgrade samma oci://ghcr.io/samma-io/charts/samma-operator --version 0.2.0 --reuse-values \
  --set operator.image=ghcr.io/<you>/samma-operator --set operator.tag=dev
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
