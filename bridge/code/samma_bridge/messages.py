"""Parse and validate one NATS message.

Two generations of message arrive on the same subjects:

* schema v2 (samma.io/scan/v2, from samma-io/detect): a ``finding`` per
  failing check and exactly one ``run`` message at the end with the
  outcome. These become ScanReports.
* legacy v1 (no ``schema`` key, from the classic scanners): one JSON
  object per result. These go to TimescaleDB only, exactly as before.

A v2 message that does not satisfy the schema is rejected with a short
reason (used as a metrics label) and never crashes the bridge. Text fields
are cut to what the ScanReport CRD allows instead of being rejected, so a
long title or evidence string loses its tail rather than the whole finding.
"""

import json
import re
from datetime import datetime, timezone

SCHEMA_V2 = "samma.io/scan/v2"

KIND_FINDING = "finding"
KIND_RUN = "run"
KIND_LEGACY = "legacy"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOME_TIMED_OUT = "timed_out"
OUTCOMES = (OUTCOME_SUCCEEDED, OUTCOME_FAILED, OUTCOME_TIMED_OUT)

# The target expression is the one from operator/code/target_policy.py and
# the Scanner and ScanReport CRDs; operator/tests/test_scanreport.py checks
# that the copies agree.
_LABEL = r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"
HOSTNAME_PATTERN = r"{label}(\.{label})*".format(label=_LABEL)
_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_PATTERN = r"({octet}\.){{3}}{octet}".format(octet=_OCTET)
IPV6_PATTERN = r"[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}"
TARGET_PATTERN = "^({0}|{1}|{2})$".format(HOSTNAME_PATTERN, IPV4_PATTERN, IPV6_PATTERN)
SCANNER_PATTERN = r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$"
CHECK_ID_PATTERN = r"^[A-Z0-9-]{3,80}$"
CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,}$"

MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_TARGET = 253
MAX_RUN_ID = 253
MAX_SCANNER_VERSION = 64
MAX_TITLE = 200
MAX_EVIDENCE = 1024
MAX_REMEDIATION = 1024
MAX_REFERENCES = 10
MAX_REFERENCE = 512
MAX_CVE_IDS = 50
MAX_COMPLIANCE = 20
MAX_COMPLIANCE_ITEM = 64
MAX_MESSAGE = 512
MAX_HOST = 253
MAX_SCHEME = 16
MAX_TIER = 32

_TARGET_RE = re.compile(TARGET_PATTERN)
_SCANNER_RE = re.compile(SCANNER_PATTERN)
_CHECK_ID_RE = re.compile(CHECK_ID_PATTERN)
_CVE_ID_RE = re.compile(CVE_ID_PATTERN)
_TIER_RE = re.compile(r"^[a-z0-9-]{1,32}$")

# Rejection reasons (the label of samma_bridge_messages_rejected_total).
REASON_PAYLOAD = "payload"
REASON_SCHEMA = "schema"
REASON_KIND = "kind"
REASON_ENVELOPE = "envelope"
REASON_FINDING = "finding"
REASON_RUN = "run"


class Rejected(ValueError):
    """The message is not something the bridge will act on."""

    def __init__(self, reason, detail):
        self.reason = reason
        self.detail = detail
        super(Rejected, self).__init__("{0}: {1}".format(reason, detail))


def cap_text(value, limit):
    """Fold whitespace and cut to limit characters; a cut string ends in
    three dots and still fits. None becomes the empty string."""
    text = " ".join(str(value if value is not None else "").split())
    if len(text) <= limit:
        return text
    return text[: max(limit - 3, 0)] + "..."


def normalise_time(value, reason, field):
    """An RFC 3339 timestamp as the CRD stores it: UTC, second precision,
    trailing Z. Anything unparsable is rejected."""
    if not isinstance(value, str) or not value.strip():
        raise Rejected(reason, "{0} must be an RFC 3339 timestamp".format(field))
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        raise Rejected(reason, "{0} is not an RFC 3339 timestamp: {1!r}".format(field, value))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Legacy(object):
    """A v1 message: stored in TimescaleDB, never in a ScanReport."""

    kind = KIND_LEGACY
    schema = None

    def __init__(self, data):
        self.data = data

    def legacy_row(self):
        return legacy_row(self.data)


class Envelope(object):
    """What every v2 message carries."""

    schema = SCHEMA_V2

    def __init__(self, data, reason):
        self.data = data
        self.scanner = _pattern(data, "scanner", _SCANNER_RE, reason, limit=63)
        self.target = _pattern(data, "target", _TARGET_RE, reason, limit=MAX_TARGET)
        self.run_id = _identifier(data, "runId", MAX_RUN_ID, reason)
        self.scanner_version = cap_text(data.get("scannerVersion") or "unknown", MAX_SCANNER_VERSION)
        emitted = data.get("emittedAt")
        self.emitted_at = normalise_time(emitted, reason, "emittedAt") if emitted not in (None, "") else None
        template = data.get("template")
        if template in (None, ""):
            self.template = None
        else:
            self.template = _pattern(data, "template", _SCANNER_RE, reason, limit=63)
        tier = data.get("tier")
        if tier in (None, ""):
            self.tier = None
        else:
            self.tier = _pattern(data, "tier", _TIER_RE, reason, limit=MAX_TIER)

    @property
    def key(self):
        """One scan run: the accumulator groups findings by this."""
        return (self.scanner, self.template, self.target, self.run_id)

    def legacy_row(self):
        return legacy_row(self.data)


class Finding(Envelope):
    kind = KIND_FINDING

    def __init__(self, data):
        super(Finding, self).__init__(data, REASON_FINDING)
        reason = REASON_FINDING
        self.check_id = _pattern(data, "checkId", _CHECK_ID_RE, reason, limit=80)
        severity = data.get("severity")
        if severity not in SEVERITIES:
            raise Rejected(reason, "severity must be one of {0}, got {1!r}".format(", ".join(SEVERITIES), severity))
        self.severity = severity
        self.title = _required_text(data, "title", MAX_TITLE, reason)
        self.endpoint = _endpoint(data.get("endpoint"), self.target, reason)
        self.evidence = cap_text(_optional_text(data, "evidence", reason), MAX_EVIDENCE)
        self.remediation = cap_text(_optional_text(data, "remediation", reason), MAX_REMEDIATION)
        references = []
        for item in _string_list(data, "references", reason):
            item = item.strip()
            # A cut URL is useless, so an over-long reference is dropped.
            if item and len(item) <= MAX_REFERENCE and item not in references:
                references.append(item)
        self.references = references[:MAX_REFERENCES]
        cve_ids = []
        for item in _string_list(data, "cveIds", reason):
            item = item.strip().upper()
            if not _CVE_ID_RE.match(item):
                raise Rejected(reason, "cveIds entry is not a CVE id: {0!r}".format(item))
            if item not in cve_ids:
                cve_ids.append(item)
        self.cve_ids = cve_ids[:MAX_CVE_IDS]
        compliance = []
        for item in _string_list(data, "compliance", reason):
            item = cap_text(item, MAX_COMPLIANCE_ITEM)
            if item and item not in compliance:
                compliance.append(item)
        self.compliance = compliance[:MAX_COMPLIANCE]

    def report_entry(self):
        """The finding as it is stored in ScanReport.status.findings: no raw
        record, no empty lists."""
        endpoint = {"host": self.endpoint["host"]}
        if self.endpoint.get("port") is not None:
            endpoint["port"] = self.endpoint["port"]
        if self.endpoint.get("scheme"):
            endpoint["scheme"] = self.endpoint["scheme"]
        entry = {
            "checkId": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "endpoint": endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
        if self.references:
            entry["references"] = list(self.references)
        if self.cve_ids:
            entry["cveIds"] = list(self.cve_ids)
        if self.compliance:
            entry["compliance"] = list(self.compliance)
        return entry


class Run(Envelope):
    kind = KIND_RUN

    def __init__(self, data):
        super(Run, self).__init__(data, REASON_RUN)
        reason = REASON_RUN
        outcome = data.get("outcome")
        if outcome not in OUTCOMES:
            raise Rejected(reason, "outcome must be one of {0}, got {1!r}".format(", ".join(OUTCOMES), outcome))
        self.outcome = outcome
        self.message = cap_text(_optional_text(data, "message", reason), MAX_MESSAGE)
        self.started_at = normalise_time(data.get("startedAt"), reason, "startedAt")
        self.finished_at = normalise_time(data.get("finishedAt"), reason, "finishedAt")
        count = data.get("findingCount")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise Rejected(reason, "findingCount must be a non-negative integer, got {0!r}".format(count))
        self.finding_count = count

    def with_outcome(self, outcome, message):
        """A copy whose outcome and message differ; the bridge uses it to
        record a run it did not receive completely."""
        other = Run.__new__(Run)
        other.__dict__.update(self.__dict__)
        other.outcome = outcome
        other.message = cap_text(message, MAX_MESSAGE)
        return other


def parse(payload):
    """bytes or str -> Legacy, Finding or Run; raises Rejected."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise Rejected(REASON_PAYLOAD, "message of {0} bytes is over the {1} byte limit".format(len(payload), MAX_PAYLOAD_BYTES))
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Rejected(REASON_PAYLOAD, "not JSON: {0}".format(exc))
    if not isinstance(data, dict):
        raise Rejected(REASON_PAYLOAD, "not a JSON object")
    if "schema" not in data:
        return Legacy(data)
    if data.get("schema") != SCHEMA_V2:
        raise Rejected(REASON_SCHEMA, "unknown schema {0!r}".format(data.get("schema")))
    kind = data.get("kind")
    if kind == KIND_FINDING:
        return Finding(data)
    if kind == KIND_RUN:
        return Run(data)
    raise Rejected(REASON_KIND, "unknown kind {0!r}".format(kind))


def legacy_row(data):
    """The TimescaleDB columns the original bridge filled, from any message
    (v2 messages mirror host, port, status and type at the top level)."""
    samma = data.get("samma-io") if isinstance(data.get("samma-io"), dict) else {}
    port = data.get("port")
    return {
        "host": _str_or_none(data.get("host")),
        "port": "" if port is None else str(port),
        "status": _str_or_none(data.get("status")),
        "type": _str_or_none(data.get("type")),
        "scanner": _str_or_none(samma.get("scanner")),
        "samma_id": _str_or_none(samma.get("id")),
        "tags": json.dumps(samma.get("tags", [])),
        "raw": json.dumps(data),
    }


def _str_or_none(value):
    if value is None:
        return None
    return value if isinstance(value, str) else str(value)


def _required_text(data, field, limit, reason):
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise Rejected(reason, "{0} is required".format(field))
    text = cap_text(value, limit)
    return text


def _identifier(data, field, limit, reason):
    """A required string that is used as is (never cut): too long is an
    error."""
    value = data.get(field)
    if not isinstance(value, str) or not value.strip():
        raise Rejected(reason, "{0} is required".format(field))
    value = value.strip()
    if len(value) > limit or any(ch.isspace() for ch in value):
        raise Rejected(reason, "{0} must be at most {1} characters without whitespace".format(field, limit))
    return value


def _optional_text(data, field, reason):
    value = data.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise Rejected(reason, "{0} must be a string".format(field))
    return value


def _pattern(data, field, regex, reason, limit):
    value = data.get(field)
    if not isinstance(value, str) or not value or len(value) > limit or not regex.match(value):
        raise Rejected(reason, "{0} is missing or malformed: {1!r}".format(field, value))
    return value


def _string_list(data, field, reason):
    value = data.get(field)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise Rejected(reason, "{0} must be a list of strings".format(field))
    return value


def _endpoint(value, target, reason):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise Rejected(reason, "endpoint must be an object")
    host = value.get("host")
    if host in (None, ""):
        host = target
    if not isinstance(host, str):
        raise Rejected(reason, "endpoint.host must be a string")
    host = cap_text(host, MAX_HOST)
    port = value.get("port")
    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise Rejected(reason, "endpoint.port must be an integer between 1 and 65535, got {0!r}".format(port))
    scheme = value.get("scheme")
    if scheme is not None:
        if not isinstance(scheme, str):
            raise Rejected(reason, "endpoint.scheme must be a string")
        scheme = cap_text(scheme, MAX_SCHEME) or None
    return {"host": host, "port": port, "scheme": scheme}
