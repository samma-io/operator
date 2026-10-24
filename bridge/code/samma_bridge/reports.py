"""ScanReport bodies and the create-or-update loop.

Naming and labels follow the operator's Jobs so the two match by eye:

    name:        <scanner>[-<template>]-<8 hex of sha256(target)>
    labels:      samma.io/scanner, samma.io/template, samma.io/target-hash,
                 samma.io/ingress-namespace and samma.io/ingress-name when the
                 Scanner came from an Ingress
    annotation:  samma.io/target
    owners:      the Scanners with this target and scanner

The naming and label code is a copy of operator/code/jobspec.py; the two
images are built from separate directories. operator/tests/test_scanreport.py
checks that the copies agree.

Findings in a report are bounded: deduplicated on check id plus endpoint,
at most MAX_FINDINGS entries (highest severity first), and under
MAX_FINDINGS_BYTES serialised, which is reached by cutting evidence first
and dropping INFO findings second.
"""

import hashlib
import json
import re

GROUP = "samma.io"
VERSION = "v1alpha1"
PLURAL = "scanreports"
KIND = "ScanReport"
API_VERSION = "{0}/{1}".format(GROUP, VERSION)

LABEL_MANAGED_BY = "app.kubernetes.io/managed-by"
MANAGED_BY = "samma-operator"
LABEL_SCANNER = "samma.io/scanner"
LABEL_TEMPLATE = "samma.io/template"
LABEL_TARGET_HASH = "samma.io/target-hash"
LABEL_INGRESS_NAMESPACE = "samma.io/ingress-namespace"
LABEL_INGRESS_NAME = "samma.io/ingress-name"
ANNOTATION_TARGET = "samma.io/target"

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SUMMARY_KEYS = ("critical", "high", "medium", "low", "info")

MAX_FINDINGS = 200
MAX_FINDINGS_BYTES = 256 * 1024
# Evidence is cut to this many characters when a report is over the byte
# limit, before any finding is dropped.
SHORT_EVIDENCE = 256

_LABEL_VALUE_RE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")


class Conflict(Exception):
    """The store saw a resourceVersion mismatch (HTTP 409)."""


# --- naming and labels (same as the operator) --------------------------------

def target_hash(target):
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:8]


def report_name(scanner, template, target):
    if template and template != scanner:
        base = "{0}-{1}".format(scanner, template)
    else:
        base = scanner
    return "{0}-{1}".format(base, target_hash(target))


def label_value(value):
    value = str(value)
    if _LABEL_VALUE_RE.match(value):
        return value
    return "{0}-{1}".format(value[:54].rstrip("-_."), hashlib.sha256(value.encode("utf-8")).hexdigest()[:8])


def owner_reference(scanner_object):
    """An ownerReference to a Scanner object as the API returns it."""
    metadata = scanner_object.get("metadata") or {}
    return {
        "apiVersion": scanner_object.get("apiVersion") or "samma.io/v1",
        "kind": scanner_object.get("kind") or "Scanner",
        "name": metadata.get("name"),
        "uid": metadata.get("uid"),
        "controller": False,
        "blockOwnerDeletion": False,
    }


def report_body(scanner, template, target, namespace, owners=None, extra_labels=None, tier=None):
    labels = {
        LABEL_MANAGED_BY: MANAGED_BY,
        LABEL_SCANNER: scanner,
        LABEL_TEMPLATE: template or scanner,
        LABEL_TARGET_HASH: target_hash(target),
    }
    for key, value in (extra_labels or {}).items():
        labels[key] = label_value(value)
    spec = {"target": target, "scanner": scanner}
    if template and template != scanner:
        spec["template"] = template
    if tier:
        spec["tier"] = tier
    metadata = {
        "name": report_name(scanner, template, target),
        "namespace": namespace,
        "labels": labels,
        "annotations": {ANNOTATION_TARGET: target},
    }
    if owners:
        metadata["ownerReferences"] = [dict(owner) for owner in owners if owner.get("uid")]
    return {"apiVersion": API_VERSION, "kind": KIND, "metadata": metadata, "spec": spec}


# --- findings ----------------------------------------------------------------

def finding_key(entry):
    endpoint = entry.get("endpoint") or {}
    return (entry.get("checkId"), endpoint.get("host"), endpoint.get("port"), endpoint.get("scheme"))


def dedupe(entries):
    """Keep the first finding for each (checkId, endpoint)."""
    seen = set()
    kept = []
    for entry in entries:
        key = finding_key(entry)
        if key in seen:
            continue
        seen.add(key)
        kept.append(entry)
    return kept


def sort_findings(entries):
    """Highest severity first, then check id, then endpoint, so the cap
    always keeps the same findings for the same input."""
    def key(entry):
        endpoint = entry.get("endpoint") or {}
        return (
            SEVERITY_RANK.get(entry.get("severity"), len(SEVERITY_RANK)),
            entry.get("checkId") or "",
            endpoint.get("host") or "",
            endpoint.get("port") or 0,
            endpoint.get("scheme") or "",
        )
    return sorted(entries, key=key)


def serialized_size(entries):
    return len(json.dumps(entries, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def cap_findings(entries, max_findings=MAX_FINDINGS, max_bytes=MAX_FINDINGS_BYTES, short_evidence=SHORT_EVIDENCE):
    """Apply the report limits to sorted, deduplicated entries.

    Returns (entries, notes). notes counts what happened: over_limit (cut
    by the entry cap), evidence_shortened (how many evidence strings were
    cut for size), info_dropped, tail_dropped (lowest-severity findings
    removed because the report was still too large).
    """
    notes = {"over_limit": 0, "evidence_shortened": 0, "info_dropped": 0, "tail_dropped": 0}
    kept = list(entries)
    if len(kept) > max_findings:
        notes["over_limit"] = len(kept) - max_findings
        kept = kept[:max_findings]
    if serialized_size(kept) <= max_bytes:
        return kept, notes
    shortened = []
    for entry in kept:
        evidence = entry.get("evidence") or ""
        if len(evidence) > short_evidence:
            entry = dict(entry)
            entry["evidence"] = evidence[: max(short_evidence - 3, 0)] + "..."
            notes["evidence_shortened"] += 1
        shortened.append(entry)
    kept = shortened
    if serialized_size(kept) <= max_bytes:
        return kept, notes
    without_info = [entry for entry in kept if entry.get("severity") != "INFO"]
    notes["info_dropped"] = len(kept) - len(without_info)
    kept = without_info
    while kept and serialized_size(kept) > max_bytes:
        kept.pop()  # sorted by severity, so the least severe goes first
        notes["tail_dropped"] += 1
    return kept, notes


def summary(entries):
    counts = dict((key, 0) for key in SUMMARY_KEYS)
    for entry in entries:
        key = str(entry.get("severity", "")).lower()
        if key in counts:
            counts[key] += 1
    return counts


# --- status bodies -------------------------------------------------------------

def _last_run(run, job_name=None):
    last_run = {
        "runId": run.run_id,
        "outcome": run.outcome,
        "startedAt": run.started_at,
        "finishedAt": run.finished_at,
    }
    if run.message:
        last_run["message"] = run.message
    if job_name:
        last_run["jobName"] = job_name
    return last_run


def succeeded_status(existing_status, run, entries):
    """A succeeded run replaces findings and summary and sets lastSuccessAt."""
    status = dict(existing_status or {})
    status["scannerVersion"] = run.scanner_version
    status["lastRun"] = _last_run(run)
    status["lastSuccessAt"] = run.finished_at
    status["summary"] = summary(entries)
    status["findings"] = list(entries)
    return status


def failed_status(existing_status, run):
    """A failed or timed-out run records itself and leaves findings,
    summary and lastSuccessAt as they were."""
    status = dict(existing_status or {})
    status["scannerVersion"] = run.scanner_version
    status["lastRun"] = _last_run(run)
    return status


def metadata_changes(existing_metadata, desired_metadata):
    """A merge patch that brings labels, annotations and ownerReferences of
    an existing report up to date, or None when nothing differs. Owners
    are unioned by uid so a second Scanner for the same target is added
    without dropping the first."""
    existing_metadata = existing_metadata or {}
    patch = {}
    for field in ("labels", "annotations"):
        current = existing_metadata.get(field) or {}
        wanted = desired_metadata.get(field) or {}
        missing = dict((k, v) for k, v in wanted.items() if current.get(k) != v)
        if missing:
            patch[field] = missing
    current_owners = existing_metadata.get("ownerReferences") or []
    known = set(ref.get("uid") for ref in current_owners)
    extra = [ref for ref in desired_metadata.get("ownerReferences") or [] if ref.get("uid") not in known]
    if extra:
        patch["ownerReferences"] = list(current_owners) + extra
    return patch or None


def upsert(store, body, make_status, attempts=3):
    """Create the report when it is missing, then write its status.

    store has get(name) -> dict or None, create(body) -> dict,
    replace_status(name, body) -> dict and patch_metadata(name, patch);
    create and replace_status raise Conflict on a 409. make_status takes
    the current status and returns the new one. The status replace carries
    the resourceVersion that was just read, so a concurrent write (the
    operator recording a failed Job) is retried from a fresh read.
    Returns "created" or "updated".
    """
    name = body["metadata"]["name"]
    for _ in range(attempts):
        existing = store.get(name)
        created = False
        if existing is None:
            try:
                existing = store.create(body)
                created = True
            except Conflict:
                continue
        existing = dict(existing)
        existing["status"] = make_status(existing.get("status") or {})
        try:
            store.replace_status(name, existing)
        except Conflict:
            continue
        if not created:
            patch = metadata_changes(existing.get("metadata"), body["metadata"])
            if patch:
                store.patch_metadata(name, {"metadata": patch})
        return "created" if created else "updated"
    raise Conflict("ScanReport {0} kept changing while it was written".format(name))
