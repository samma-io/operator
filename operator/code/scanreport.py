"""The operator's side of ScanReport (scanreports.samma.io/v1alpha1).

The bridge writes a ScanReport when a scan publishes its run message. A Job
that never gets that far (an image that cannot be pulled, an out-of-memory
kill, a pod that was still starting when the deadline hit) publishes
nothing, and without this module such a scan would be invisible: the
report would keep its last state and nothing would say the scan did not
run. The operator therefore walks the scan Jobs on every queue tick
(operator_handler.record_job_outcomes) and, for a Job that finished
without success, writes status.lastRun of the matching report, creating the
report with only its spec when it does not exist yet. Findings are never
touched here; only the bridge replaces them, and only on a succeeded run.

A report has the same name as the Job: <scanner>[-<template>]-<target hash>
(jobspec.object_name), so the two are easy to match by eye.

This module imports neither kopf nor the kubernetes client; it turns Job
dictionaries into ScanReport bodies and the handler does the API calls.
"""

from datetime import datetime, timezone

import jobspec

GROUP = "samma.io"
VERSION = "v1alpha1"
PLURAL = "scanreports"
KIND = "ScanReport"
API_VERSION = "{0}/{1}".format(GROUP, VERSION)

# Set on a Job once its failed outcome is in the ScanReport, so a tick
# never writes the same failure twice.
ANNOTATION_OUTCOME_RECORDED = "samma.io/outcome-recorded"

OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOME_TIMED_OUT = "timed_out"
OUTCOMES = (OUTCOME_SUCCEEDED, OUTCOME_FAILED, OUTCOME_TIMED_OUT)

# status.lastRun.message in the CRD schema.
MESSAGE_MAX_LENGTH = 512

# The Job condition reason the Job controller uses when activeDeadlineSeconds
# passed.
REASON_DEADLINE = "DeadlineExceeded"


def report_name(scanner, template, target, samma_io_id=None):
    """Same as the Job's name: <scanner>[-<template>]-<hash>, the hash
    covering the tenant's samma_io_id when there is one."""
    return jobspec.object_name(scanner, template, target, samma_io_id)


def wants_report(scanner):
    """True for scanners that publish schema v2 and so have a ScanReport."""
    spec = jobspec.SCANNERS.get(scanner)
    return bool(spec is not None and spec.reports)


def _get(mapping, camel, snake):
    """Read a key from a dict that may come from the API (camelCase) or from
    the kubernetes client's to_dict() (snake_case)."""
    if not mapping:
        return None
    value = mapping.get(camel)
    if value is None:
        value = mapping.get(snake)
    return value


def job_identity(metadata):
    """(scanner, template, target) of a scan Job, or None when the labels
    and the target annotation are not all there."""
    labels = metadata.get("labels") or {}
    annotations = metadata.get("annotations") or {}
    scanner = labels.get(jobspec.LABEL_SCANNER)
    template = labels.get(jobspec.LABEL_TEMPLATE)
    target = annotations.get(jobspec.ANNOTATION_TARGET)
    if not scanner or not target:
        return None
    return scanner, template or None, target


def job_samma_io_id(metadata):
    """The tenant id a scan Job was built for, or None."""
    annotations = metadata.get("annotations") or {}
    return annotations.get(jobspec.ANNOTATION_SAMMA_IO_ID) or None


def outcome_recorded(metadata):
    annotations = metadata.get("annotations") or {}
    return str(annotations.get(ANNOTATION_OUTCOME_RECORDED, "")).lower() == "true"


def scanner_owners(metadata):
    """The Job's ownerReferences that point at Scanners, in API shape."""
    owners = []
    for ref in _get(metadata, "ownerReferences", "owner_references") or []:
        if ref.get("kind") != "Scanner":
            continue
        owners.append({
            "apiVersion": _get(ref, "apiVersion", "api_version"),
            "kind": "Scanner",
            "name": ref.get("name"),
            "uid": ref.get("uid"),
            "controller": bool(ref.get("controller")),
            "blockOwnerDeletion": False,
        })
    return owners


def ingress_labels(metadata):
    labels = metadata.get("labels") or {}
    extra = {}
    for key in (jobspec.LABEL_INGRESS_NAMESPACE, jobspec.LABEL_INGRESS_NAME):
        if key in labels:
            extra[key] = labels[key]
    return extra


def job_outcome(status):
    """(outcome, message, started_at, finished_at) for a Job that failed,
    None for one that is still running or completed. A Failed condition
    with reason DeadlineExceeded is a timed_out run; any other failure is
    failed. The message is the condition's reason and message, capped to
    what the CRD allows."""
    status = status or {}
    for condition in status.get("conditions") or []:
        if condition.get("type") != "Failed" or str(condition.get("status", "")).lower() != "true":
            continue
        reason = (condition.get("reason") or "").strip()
        detail = (condition.get("message") or "").strip()
        outcome = OUTCOME_TIMED_OUT if reason == REASON_DEADLINE else OUTCOME_FAILED
        if reason and detail:
            message = "{0}: {1}".format(reason, detail)
        else:
            message = reason or detail or "Job failed"
        started = rfc3339(_get(status, "startTime", "start_time"))
        finished = rfc3339(_get(condition, "lastTransitionTime", "last_transition_time"))
        return outcome, cap_text(message, MESSAGE_MAX_LENGTH), started, finished
    return None


def rfc3339(value):
    """A timestamp as the CRD wants it (second precision, UTC, Z), from a
    datetime or an API string; None stays None."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(value)


def now_rfc3339():
    return rfc3339(datetime.now(timezone.utc))


def cap_text(text, limit):
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def latest_pod_name(pods):
    """The name of the most recently created pod among Job pods (a Job with
    backoffLimit 1 can have two); None when there are none. Each pod is a
    metadata dict, camelCase or snake_case."""
    best = None
    best_key = None
    for metadata in pods or []:
        name = metadata.get("name")
        if not name:
            continue
        created = _get(metadata, "creationTimestamp", "creation_timestamp")
        key = rfc3339(created) or ""
        if best is None or key > best_key or (key == best_key and name > best):
            best, best_key = name, key
    return best


def report_body(scanner, template, target, namespace, owners=None, extra_labels=None, tier=None, samma_io_id=None):
    """A ScanReport with metadata and spec only; status is written through
    the status subresource afterwards."""
    labels = {
        jobspec.LABEL_MANAGED_BY: jobspec.MANAGED_BY,
        jobspec.LABEL_SCANNER: scanner,
        jobspec.LABEL_TEMPLATE: template or scanner,
        jobspec.LABEL_TARGET_HASH: jobspec.target_hash(target),
    }
    for key, value in (extra_labels or {}).items():
        labels[key] = jobspec.label_value(value)
    spec = {"target": target, "scanner": scanner}
    if template and template != scanner:
        spec["template"] = template
    if tier:
        spec["tier"] = tier
    annotations = {jobspec.ANNOTATION_TARGET: target}
    if samma_io_id not in (None, ""):
        annotations[jobspec.ANNOTATION_SAMMA_IO_ID] = str(samma_io_id)
    metadata = {
        "name": report_name(scanner, template, target, samma_io_id),
        "namespace": namespace,
        "labels": labels,
        "annotations": annotations,
    }
    if owners:
        metadata["ownerReferences"] = [dict(owner) for owner in owners]
    return {"apiVersion": API_VERSION, "kind": KIND, "metadata": metadata, "spec": spec}


def run_already_recorded(status, run_id):
    """True when status.lastRun already describes this run (the bridge got
    the scanner's own run message first, which carries a better message)."""
    last_run = (status or {}).get("lastRun") or {}
    return bool(run_id) and last_run.get("runId") == run_id


def failed_run_status(existing_status, run_id, job_name, outcome, message, started_at=None, finished_at=None):
    """The status to write for a failed run: everything the report has
    stays (findings, summary, lastSuccessAt, scannerVersion), lastRun is
    replaced."""
    if outcome not in (OUTCOME_FAILED, OUTCOME_TIMED_OUT):
        raise ValueError("not a failed outcome: {0!r}".format(outcome))
    status = dict(existing_status or {})
    last_run = {
        "runId": run_id,
        "jobName": job_name,
        "outcome": outcome,
        "message": cap_text(message, MESSAGE_MAX_LENGTH),
        "finishedAt": finished_at or now_rfc3339(),
    }
    if started_at:
        last_run["startedAt"] = started_at
    status["lastRun"] = last_run
    return status
