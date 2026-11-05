#!/usr/bin/env bash
# What explains a failed end-to-end run: the objects and events in samma-io,
# the logs of the operator, the bridge, NATS and the API, and every scanner
# pod's log. run.sh calls it when a check fails; e2e.yaml calls it when the
# run step itself timed out. Read-only.

set -uo pipefail

NS=samma-io

section() { printf '\n----- %s -----\n' "$*"; }

context="$(kubectl config current-context 2>/dev/null)"
if [[ "$context" != k3d-* ]]; then
  echo "diagnostics: kubectl context '$context' is not a k3d cluster, nothing dumped" >&2
  exit 1
fi

section "Objects in $NS"
kubectl -n "$NS" get all,ingress,networkpolicy,configmap,scanner.samma.io,scanreports.samma.io -o wide

section "Events in $NS (oldest first)"
kubectl -n "$NS" get events --sort-by=.lastTimestamp

for deploy in samma-operator samma-bridge; do
  section "Logs of $deploy"
  kubectl -n "$NS" logs "deployment/$deploy" --all-containers --timestamps --tail=-1
  section "Logs of $deploy, previous container (if it restarted)"
  kubectl -n "$NS" logs "deployment/$deploy" --all-containers --timestamps --previous --tail=-1 2>&1 | tail -n 200
done

for deploy in nats samma-api; do
  section "Logs of $deploy (last 100 lines)"
  kubectl -n "$NS" logs "deployment/$deploy" --all-containers --timestamps --tail=100
done

for pod in $(kubectl -n "$NS" get pods -l samma.io/role=scanner -o name 2>/dev/null); do
  section "Scanner $pod"
  kubectl -n "$NS" get "$pod" -o jsonpath='{.status.phase} {range .status.containerStatuses[*]}{.state}{end}{"\n"}'
  kubectl -n "$NS" logs "$pod" --all-containers --timestamps --tail=-1
done

section "Jobs and CronJobs"
kubectl -n "$NS" get jobs.batch,cronjobs.batch -o yaml

section "Scanners"
kubectl -n "$NS" get scanner.samma.io -o yaml

section "ScanReports"
kubectl -n "$NS" get scanreports.samma.io -o yaml

section "Helm release"
helm -n "$NS" status samma
helm -n "$NS" history samma

section "Nodes and every pod"
kubectl get nodes -o wide
kubectl get pods -A -o wide

section "Events in kube-system (last 50)"
kubectl -n kube-system get events --sort-by=.lastTimestamp | tail -n 50

exit 0
