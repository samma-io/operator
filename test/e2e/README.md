# End-to-end test

`run.sh` installs the chart on a throwaway k3d cluster with images built from the checkout and
checks the whole path: Pod Security, a scan from an annotated Ingress to a ScanReport, the CRD
refusing an injected target, NATS authentication, the suspended scheduled Jobs the queue resumes,
cleanup through garbage collection, and `helm uninstall` with its pre-delete hook. The header of
`run.sh` lists every check. CI runs it on every pull request and push to `main`
(`.github/workflows/e2e.yaml`, about 10 minutes).

| File | What it is |
|---|---|
| `run.sh` | The checks, in order. Prints `diagnostics.sh` on failure. |
| `diagnostics.sh` | Objects, events and logs (operator, bridge, NATS, API, scanner pods) of `samma-io`. |
| `values.yaml` | Chart values: the local images with `pullPolicy: Never`, the namespace made by the test, TimescaleDB off (its pod does not meet `restricted`). NetworkPolicies stay on. |
| `manifests/` | The Ingress, the Scanners and the NATS client pod the checks use. |

The only scan target is `example.com` with `dns-scanner`, which sends DNS queries through the
cluster's resolver and nothing else. Keep it that way: never point an active scanner at a host you
do not own.

## Run it locally

Needs Docker, k3d, kubectl, helm and jq on an amd64 machine (the chart's default `nodeSelector`
is amd64). It creates and deletes things in the cluster, so it only runs against a k3d context
named in `E2E_KUBE_CONTEXT`.

```bash
k3d cluster create samma-e2e --no-lb \
  --k3s-arg '--disable=traefik@server:0' --k3s-arg '--disable=metrics-server@server:0' --wait
for c in operator bridge api; do docker build -t samma-e2e/samma-$c:e2e $c; done
k3d image import -c samma-e2e samma-e2e/samma-operator:e2e samma-e2e/samma-bridge:e2e samma-e2e/samma-api:e2e
E2E_KUBE_CONTEXT=k3d-samma-e2e test/e2e/run.sh
k3d cluster delete samma-e2e
```

The test needs a cluster without `samma-io`; delete and recreate the cluster between runs.
