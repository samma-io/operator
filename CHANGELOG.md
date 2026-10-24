# Changelog

A release is a tag `v<version>` on `main`. Pushing it runs
`.github/workflows/release.yaml`, which publishes the chart to
`oci://ghcr.io/samma-io/charts/samma-operator` and the images to
`ghcr.io/samma-io/samma-{operator,api,bridge}` (README, "Releases").

## Unreleased

Found by the first soak of 0.2.1 on a Cilium cluster behind Traefik.

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
