# Changelog

A release is a tag `v<version>` on `main`. Pushing it runs
`.github/workflows/release.yaml`, which publishes the chart to
`oci://ghcr.io/samma-io/charts/samma-operator` and the images to
`ghcr.io/samma-io/samma-{operator,api,bridge}` (README, "Releases").

## 0.2.4

The same code as 0.2.3. The 0.2.3 release workflow published the chart and
images but failed at rendering the raw manifest (the chart now requires an
API token), so it has no GitHub release. The workflow renders the raw
manifest with `api.existingSecret=samma-api-token` (create that Secret before
applying it) and the install line names `api.token`. Use 0.2.4.

## 0.2.3

Security hardening from the samma.io audit, plus the detect 2.0.2 scanners.
**Breaking for installs:** the chart now needs `api.token` (or
`api.existingSecret`), and the new NetworkPolicies and Ingress namespace
filter change what can reach and what gets scanned; see "Upgrading" below.

- Scanner targets are validated, and Job and CronJob bodies are built as
  objects, never from text templates, so a target cannot inject into a pod
  spec (operator#11, operator#19; #5, #20, #10).
- Jobs, CronJobs and ScanReports are keyed by the tenant's `samma_io_id` as
  well as the target, so two tenants scanning the same host never share a
  scan or its `SAMMA_IO_ID` (operator#14; #23, #10).
- The API requires `Authorization: Bearer <SAMMA_API_TOKEN>` on every route
  except `/health`, `/ready` and `/metrics`, and refuses to start without the
  token. The chart reads it from `api.token` or `api.existingSecret`
  (operator#15, operator#24; #25, #26).
- The bridge stores a TimescaleDB row only when its target and `samma-io.id`
  match a current Scanner, so a pod on NATS cannot plant results for a
  tenant it is not scanning (operator#12; #27).
- The bridge creates the read-only NOLOGIN role `samma_reader` (SELECT on
  `scan_results`) on every start; the `samma-timescaledb` NetworkPolicy lets
  only the bridge and `networkPolicies.timescaledbClients` reach 5432
  (operator#13; #30).
- Opted-in Ingresses create Scanners only in the operator's own namespace,
  plus `ingress.watchNamespaces` (`"*"` for all) (operator#16; #28).
- The `samma-io` namespace carries PodSecurity `enforce: baseline`,
  `warn: restricted`; the `samma-api` NetworkPolicy lets only the namespace
  and `networkPolicies.apiClients` reach 8080; NATS monitoring on 8222 is off
  unless `nats.monitoring: true` (operator#17; #31).
- Grafana setup has no default credentials (`GRAFANA_USER`,
  `TSDB_PASSWORD` required); nats and timescaledb images are pinned by
  digest (operator#18; #21).
- detect scanners move to `2.0.2` (`scanners.detectTag`): schema v2 plus
  traceroute `--`, no `file://` redirects and a safe `PARSER` file name
  (samma-io/detect#10, samma-io/detect#12).

### Upgrading

- Set `api.token` (or `api.existingSecret`) and give the dashboard the same
  value as `OPERATOR_API_TOKEN`.
- List the dashboard's namespace in `networkPolicies.apiClients` and
  `networkPolicies.timescaledbClients`, and give it a login role that is a
  member of `samma_reader`.
- Add any namespace whose Ingresses should still be scanned to
  `ingress.watchNamespaces`; Scanners made earlier for other namespaces stay
  until deleted by hand.

## 0.2.2

Found by the first soak of 0.2.1 on a Cilium cluster behind Traefik. Pull
request samma-io/operator#10.

- The operator touches only the Ingresses that carry
  `samma-io.alpha.kubernetes.io/enable`. The Ingress handlers are filtered
  on the annotation, and kopf's diff-base annotation
  (`kopf.zalando.org/last-handled-configuration`) is stored on those
  Ingresses only; 0.2.x wrote it on every Ingress in the cluster. A
  leftover is removed the next time such an Ingress changes.
- `http-headers-scanner` Jobs get `PORT=443` next to `HTTPS=True`. detect up
  to 2.0.1 let `config.yaml`'s `port: 80` win over the HTTPS default, so the
  scanner completed a TLS handshake on port 80 and judged the proxy's 404
  (fixed on the detect side in samma-io/detect#9).
- The `filebeat` and `live` ConfigMaps of the legacy `base` scanner are
  created only with `scanners.legacyBaseScanner: true`
  (`SAMMA_LEGACY_BASE_SCANNER`); nothing else uses them.
- The bridge prints the release it belongs to from `SAMMA_VERSION`, which
  the chart sets from `appVersion` (the raw manifest sets it by hand);
  0.2.1 still said 0.2.0.

## 0.2.1

Pull request samma-io/operator#9.

- The operator, bridge, API and NATS pods run as uid 1000 (values
  `operator.runAsUser`, `bridge.runAsUser`, `api.runAsUser`,
  `nats.runAsUser`), so the kubelet can verify `runAsNonRoot` and the pods
  start. 0.2.0 named the user in the images, which Kubernetes refuses with
  `CreateContainerConfigError`. The images set a numeric `USER` as well, and
  the API and NATS pods drop every capability like the others.

## 0.2.0

The first published release of the chart and the images. Pull requests
samma-io/operator#5, #6, #7 and #8.

### Scanning

- `Scanner.spec.target` is validated before anything runs: a DNS name or an
  IP literal, the same pattern in the CRD and in `target_policy.py`. Private,
  loopback, link-local and carrier-grade NAT addresses are refused unless
  `config.allowPrivateTargets` is `"true"`; `config.allowUnmanagedTargets:
  "false"` refuses a target that no Ingress in the cluster serves. Wildcard
  Ingress hosts are skipped (#5).
- Scan Jobs and CronJobs are built as objects, named
  `<scanner>[-<template>]-<target hash>`, owned by their Scanner, with
  `backoffLimit`, `activeDeadlineSeconds`, `ttlSecondsAfterFinished`, a
  concurrency limit (`scanners.maxConcurrentScans`), pod security settings
  and a hashed CronJob minute. Ingress annotation and host changes are
  reconciled. No finalizers; a pre-delete hook removes Scanners on
  uninstall (#6).
- Least-privilege RBAC: one ServiceAccount per component, scanner pods with
  no rights and no token (#6).

### Results

- `ScanReport` (`scanreports.samma.io/v1alpha1`): one object per scanner and
  target with findings, a summary and the outcome of the last run. Findings
  change only when a run succeeded. The bridge validates, dedupes and caps
  what it writes; the operator records Jobs that died before reporting (#7).
- NATS authentication with a publish-only `scanner` user and a
  subscribe-only `bridge` user; NetworkPolicies for NATS, the bridge and the
  scan pods (#7).

### Packaging

- The chart is published as OCI; the images are built for linux/amd64 and
  linux/arm64 and tagged `<version>` and `<version>-<short sha>`, with the
  digests in the release notes. Image defaults moved from
  `mattiashem/samma-operator:latest`, `sammascanner/api:latest` and
  `sammascanner/bridge:latest` to `ghcr.io/samma-io/samma-*:<appVersion>`;
  every image takes a `digest`; `pullPolicy` is `IfNotPresent`. The detect
  scanner images are pinned to `scanners.detectTag` (`2.0.0`) (#8).
- The CRDs live in `crds/`: installed before anything else, never changed by
  `helm upgrade` (README, "Upgrading") (#8).
- `acceptScanningTerms` (default `false`): the chart does not render the
  operator until it is `true` (#8).
- `api.enabled` and `timescaledb.enabled` (both default `true`). Without
  TimescaleDB the bridge writes ScanReports only. The default TimescaleDB
  password is gone: set `timescaledb.password` or
  `timescaledb.existingSecret` (#8).
- `.github/workflows/docker-publish.yml` is replaced by `release.yaml`;
  `build.yaml` also builds the bridge image (#8).
