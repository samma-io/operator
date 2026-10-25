"""Build scanner Jobs and CronJobs as plain Kubernetes objects.

The operator used to render Jinja YAML files from operator/code/scanners/
with the target and env values pasted into them. This module replaces those
files with a small table of scanner definitions (SCANNERS) and functions that
return Job and CronJob bodies as dictionaries. The kubernetes client accepts a
dictionary body, and a dictionary is easy to unit test without a cluster.

Everything the operator creates carries the same labels and annotations:

    app.kubernetes.io/managed-by: samma-operator
    samma.io/role:               scanner (the NetworkPolicy for scan pods selects it)
    samma.io/scanner:            the scanner name, for example nmap
    samma.io/template:           the variant, for example port (nmap) or nikto
    samma.io/target-hash:        eight hex characters of sha256(target)
    samma.io/scanner-uid:        the uid of the Scanner that owns the object
    samma.io/ingress-namespace, samma.io/ingress-name:
                                 on Scanners made from an Ingress (and copied
                                 onto their Jobs and CronJobs)
    samma.io/target (annotation): the target itself
    samma.io/spec-hash (annotation, CronJobs): hash of the built spec, so a
                                 changed Scanner recreates its CronJob

Object names are <scanner>[-<template>]-<target hash>. The old names carried
the target with dots turned into hyphens, which is invalid for IPv6 literals
and too long for many hostnames; the hash is always short and always valid.

This module imports neither kopf nor the kubernetes client. It reads its
settings from the environment through Settings.from_env(), and everything
else is passed in by the caller.
"""

import hashlib
import json
import os
import re

import target_policy

# Labels and annotations.
LABEL_MANAGED_BY = "app.kubernetes.io/managed-by"
MANAGED_BY = "samma-operator"
LABEL_ROLE = "samma.io/role"
ROLE_SCANNER = "scanner"
LABEL_SCANNER = "samma.io/scanner"
LABEL_TEMPLATE = "samma.io/template"
LABEL_TARGET_HASH = "samma.io/target-hash"
LABEL_SCANNER_UID = "samma.io/scanner-uid"
LABEL_INGRESS_NAMESPACE = "samma.io/ingress-namespace"
LABEL_INGRESS_NAME = "samma.io/ingress-name"
ANNOTATION_TARGET = "samma.io/target"
ANNOTATION_SCANNER_NAME = "samma.io/scanner-name"
ANNOTATION_SAMMA_IO_ID = "samma.io/samma-io-id"
ANNOTATION_INGRESS = "samma.io/ingress"
ANNOTATION_SPEC_HASH = "samma.io/spec-hash"
# Set on a Scanner by the operator: "queued" while its first Job waits for a
# free scan slot, "launched" once every first Job has been created. The
# resume handler re-queues Scanners still marked "queued" after a restart.
ANNOTATION_INITIAL_SCAN = "samma.io/initial-scan"
INITIAL_SCAN_QUEUED = "queued"
INITIAL_SCAN_LAUNCHED = "launched"

# Environment variables read by Settings.from_env().
ENV_NAMESPACE = "SAMMA_NAMESPACE"
ENV_SCANNER_SERVICE_ACCOUNT = "SAMMA_SCANNER_SERVICE_ACCOUNT"
ENV_MAX_CONCURRENT = "SAMMA_MAX_CONCURRENT_SCANS"
ENV_SCAN_DEADLINE = "SAMMA_SCAN_DEADLINE_SECONDS"
ENV_JOB_TTL = "SAMMA_JOB_TTL_SECONDS"
ENV_NMAP_RAW_SOCKETS = "SAMMA_NMAP_RAW_SOCKETS"
ENV_RUN_AS_USER = "SAMMA_SCANNER_RUN_AS_USER"
ENV_IMAGE_PREFIX = "SAMMA_SCANNER_IMAGE_PREFIX"
ENV_IMAGE_TAG = "SAMMA_SCANNER_IMAGE_TAG"
ENV_IMAGE_PULL_POLICY = "SAMMA_SCANNER_IMAGE_PULL_POLICY"
ENV_IMAGE_OVERRIDE_PREFIX = "SAMMA_SCANNER_IMAGE_"
ENV_CPU_REQUEST = "SAMMA_SCANNER_CPU_REQUEST"
ENV_MEMORY_REQUEST = "SAMMA_SCANNER_MEMORY_REQUEST"
ENV_CPU_LIMIT = "SAMMA_SCANNER_CPU_LIMIT"
ENV_MEMORY_LIMIT = "SAMMA_SCANNER_MEMORY_LIMIT"
ENV_QUEUE_INTERVAL = "SAMMA_QUEUE_INTERVAL_SECONDS"
ENV_DEFAULT_SCHEDULE = "SAMMA_IO_WEEKLY_SCHEDULE"
# The Secret holding the NATS passwords (README, "NATS authentication") and
# the user scanner pods log in as. Empty: scanner pods get no credentials,
# which is what an unauthenticated NATS needs.
ENV_NATS_SECRET = "SAMMA_NATS_SECRET"
ENV_NATS_SCANNER_USER = "SAMMA_NATS_SCANNER_USER"
# Create the filebeat and live ConfigMaps the legacy base scanner mounts.
# Off by default: the detect scanners publish to NATS and need neither.
ENV_LEGACY_BASE_SCANNER = "SAMMA_LEGACY_BASE_SCANNER"

DEFAULT_NAMESPACE = "samma-io"
DEFAULT_SCANNER_SERVICE_ACCOUNT = "samma-scanner"
DEFAULT_SCHEDULE = "0 0 * * 0"
DEFAULT_NATS_SCANNER_USER = "scanner"
# Key of the scanner password in the NATS Secret; the chart and the raw
# manifest write the Secret with this key.
NATS_SECRET_SCANNER_KEY = "scanner-password"
# Environment variables of a scanner container that carry its NATS login.
# NATS_URL is rewritten to nats://$(NATS_USER):$(NATS_PASSWORD)@host, which
# the kubelet expands from the two variables defined before it; nats-py
# reads the user and password from the URL.
ENV_NATS_USER = "NATS_USER"
ENV_NATS_PASSWORD = "NATS_PASSWORD"
DEFAULT_RESOURCES = {
    "requests": {"cpu": "100m", "memory": "128Mi"},
    "limits": {"cpu": "1", "memory": "512Mi"},
}

# Scanner spec fields that become environment variables in the scanner pod,
# and the variable each one sets. A field that is absent from the Scanner
# sets nothing; a field that is present but empty falls back to the
# operator's own default for that variable (this is how it always worked).
SPEC_ENV_FIELDS = (
    ("samma_io_id", "SAMMA_IO_ID"),
    ("samma_io_tags", "SAMMA_IO_TAGS"),
    ("samma_io_json", "SAMMA_IO_JSON"),
    ("write_to_file", "WRITE_TO_FILE"),
    ("elasticsearch", "ELASTICSEARCH"),
)
NATS_ENV_VARS = ("NATS_URL", "NATS_ENABLED", "NATS_SUBJECT")

_LABEL_VALUE_RE = re.compile(r"^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")


class Settings(object):
    """Everything the builders need that comes from the deployment."""

    def __init__(
        self,
        namespace=DEFAULT_NAMESPACE,
        scanner_service_account=DEFAULT_SCANNER_SERVICE_ACCOUNT,
        max_concurrent_scans=2,
        scan_deadline_seconds=900,
        ttl_seconds_after_finished=3600,
        nmap_raw_sockets=False,
        run_as_user=1000,
        image_prefix="",
        image_tag="",
        image_pull_policy="",
        image_overrides=None,
        resources=None,
        queue_interval_seconds=15,
        default_schedule=DEFAULT_SCHEDULE,
        nats_secret="",
        nats_scanner_user=DEFAULT_NATS_SCANNER_USER,
        legacy_base_scanner=False,
    ):
        self.namespace = namespace
        self.scanner_service_account = scanner_service_account
        self.max_concurrent_scans = max_concurrent_scans
        self.scan_deadline_seconds = scan_deadline_seconds
        self.ttl_seconds_after_finished = ttl_seconds_after_finished
        self.nmap_raw_sockets = nmap_raw_sockets
        self.run_as_user = run_as_user
        self.image_prefix = image_prefix.rstrip("/")
        self.image_tag = image_tag
        self.image_pull_policy = image_pull_policy
        self.image_overrides = dict(image_overrides or {})
        self.resources = resources or json.loads(json.dumps(DEFAULT_RESOURCES))
        self.queue_interval_seconds = queue_interval_seconds
        self.default_schedule = default_schedule
        self.nats_secret = (nats_secret or "").strip()
        self.nats_scanner_user = (nats_scanner_user or "").strip() or DEFAULT_NATS_SCANNER_USER
        self.legacy_base_scanner = bool(legacy_base_scanner)

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ

        def text(name, default):
            value = env.get(name)
            return default if value is None or value.strip() == "" else value.strip()

        def number(name, default, minimum=0):
            raw = text(name, None)
            if raw is None:
                return default
            try:
                value = int(raw)
            except ValueError:
                return default
            return max(minimum, value)

        def flag(name, default):
            raw = text(name, None)
            if raw is None:
                return default
            return raw.lower() in ("1", "true", "yes", "on")

        overrides = {}
        for key in env:
            if not key.startswith(ENV_IMAGE_OVERRIDE_PREFIX) or key in (ENV_IMAGE_PREFIX, ENV_IMAGE_TAG, ENV_IMAGE_PULL_POLICY):
                continue
            value = env[key].strip()
            if value:
                overrides[key[len(ENV_IMAGE_OVERRIDE_PREFIX):].lower().replace("_", "-")] = value

        resources = {
            "requests": {
                "cpu": text(ENV_CPU_REQUEST, DEFAULT_RESOURCES["requests"]["cpu"]),
                "memory": text(ENV_MEMORY_REQUEST, DEFAULT_RESOURCES["requests"]["memory"]),
            },
            "limits": {
                "cpu": text(ENV_CPU_LIMIT, DEFAULT_RESOURCES["limits"]["cpu"]),
                "memory": text(ENV_MEMORY_LIMIT, DEFAULT_RESOURCES["limits"]["memory"]),
            },
        }
        return cls(
            namespace=text(ENV_NAMESPACE, DEFAULT_NAMESPACE),
            scanner_service_account=text(ENV_SCANNER_SERVICE_ACCOUNT, DEFAULT_SCANNER_SERVICE_ACCOUNT),
            max_concurrent_scans=number(ENV_MAX_CONCURRENT, 2),
            scan_deadline_seconds=number(ENV_SCAN_DEADLINE, 900, minimum=1),
            ttl_seconds_after_finished=number(ENV_JOB_TTL, 3600),
            nmap_raw_sockets=flag(ENV_NMAP_RAW_SOCKETS, False),
            run_as_user=number(ENV_RUN_AS_USER, 1000, minimum=1),
            image_prefix=text(ENV_IMAGE_PREFIX, ""),
            image_tag=text(ENV_IMAGE_TAG, ""),
            image_pull_policy=text(ENV_IMAGE_PULL_POLICY, ""),
            image_overrides=overrides,
            resources=resources,
            queue_interval_seconds=number(ENV_QUEUE_INTERVAL, 15, minimum=1),
            default_schedule=text(ENV_DEFAULT_SCHEDULE, DEFAULT_SCHEDULE),
            nats_secret=text(ENV_NATS_SECRET, ""),
            nats_scanner_user=text(ENV_NATS_SCANNER_USER, DEFAULT_NATS_SCANNER_USER),
            legacy_base_scanner=flag(ENV_LEGACY_BASE_SCANNER, False),
        )


class Variant(object):
    """One way of running a scanner image.

    nmap has three (port, http, tls), each with its own entrypoint. Every
    other scanner has exactly one variant named after the scanner itself,
    which keeps the old behaviour of `spec.templates` filtering by file stem.
    """

    def __init__(self, name, container=None, command=None):
        self.name = name
        self.container = container or name
        self.command = list(command) if command else None


class ScannerSpec(object):
    def __init__(
        self,
        name,
        image,
        variants=None,
        env=None,
        args=None,
        sudo=False,
        raw_sockets=False,
        run_as_user=None,
        sidecars=None,
        volumes=None,
        reports=False,
    ):
        self.name = name
        self.image = image
        self.variants = list(variants) if variants else [Variant(name)]
        self.env = dict(env or {})
        # True for scanners that publish schema v2 messages (samma.io/scan/v2)
        # and therefore have a ScanReport. The operator records a failed
        # Job's outcome in the ScanReport only for these; the classic
        # scanners still speak v1 and go to TimescaleDB only.
        self.reports = bool(reports)
        # args(target) -> list, for scanners that take the target as an
        # argument rather than from the TARGET environment variable.
        self.args = args
        # The classic images run the tool through sudo (a sudoers line in the
        # image). sudo needs allowPrivilegeEscalation, so those containers
        # keep it until the images run the tool directly.
        self.sudo = sudo
        # True when the scanner can use raw sockets (nmap SYN scans). The
        # capability is only granted when Settings.nmap_raw_sockets is set.
        self.raw_sockets = raw_sockets
        self.run_as_user = run_as_user
        # sidecars(settings) -> list of extra containers; volumes -> list of
        # extra pod volumes. Only the legacy base scanner uses them.
        self.sidecars = sidecars
        self.volumes = volumes


def _tsunami_args(target):
    literal = target_policy.parse_ip_literal(target)
    if literal is None:
        flag = "--hostname-target={0}".format(target)
    elif literal.version == 6:
        flag = "--ip-v6-target={0}".format(target)
    else:
        flag = "--ip-v4-target={0}".format(target)
    return [
        flag,
        "--scan-results-local-output-format=JSON",
        "--scan-results-local-output-filename=/out/tsunami-output.json",
    ]


def _filebeat_sidecar(settings):
    # The legacy base scanner ships its /out files with a filebeat sidecar
    # that reads the "filebeat" and "live" ConfigMaps initOperator creates.
    # filebeat needs a writable data directory, hence the extra emptyDir.
    return [
        {
            "name": "filebeat",
            "image": "docker.elastic.co/beats/filebeat:7.15.0",
            "env": [{"name": "ELASTICSEARCH", "value": "http://elasticsearch:9200"}],
            "livenessProbe": {
                "exec": {"command": ["/bin/sh", "-c", "/live.sh"]},
                "initialDelaySeconds": 10,
                "periodSeconds": 5,
            },
            "resources": settings.resources,
            "securityContext": _container_security_context(sudo=False, net_raw=False),
            "volumeMounts": [
                {"name": "filebeat", "mountPath": "/usr/share/filebeat/filebeat.yml", "subPath": "filebeat.yml"},
                {"name": "liveness", "mountPath": "/live.sh", "subPath": "live.sh"},
                {"name": "filebeat-data", "mountPath": "/usr/share/filebeat/data"},
                {"name": "out", "mountPath": "/out"},
                {"name": "tmp", "mountPath": "/tmp"},
            ],
        }
    ]


_BASE_VOLUMES = [
    {"name": "filebeat", "configMap": {"name": "filebeat"}},
    {"name": "liveness", "configMap": {"name": "live", "defaultMode": 0o777}},
    {"name": "filebeat-data", "emptyDir": {}},
]

DETECT_SCANNERS = (
    "dns-scanner",
    "http-headers-scanner",
    "http-redirect-scanner",
    "port-scanner",
    "ssh-banner-scanner",
    "tls-scanner",
    "traceroute-scanner",
    "whois-scanner",
)

# Extra environment per detect scanner. http-headers-scanner judges HSTS
# only over HTTPS and its image defaults to HTTPS=False. PORT is set with
# it: detect up to 2.0.1 let config.yaml's port 80 win over the HTTPS
# default of 443 when only HTTPS was given, so the scanner spoke TLS to
# port 80 (fixed in samma-io/detect#9, "Settings precedence"). The other
# detect scanners run on their image defaults.
DETECT_ENV = {
    "http-headers-scanner": {"HTTPS": "True", "PORT": "443"},
}

SCANNERS = {}
for _name in DETECT_SCANNERS:
    SCANNERS[_name] = ScannerSpec(
        _name,
        "ghcr.io/samma-io/detect-{0}:latest".format(_name),
        env=DETECT_ENV.get(_name),
        reports=True,
    )

SCANNERS["nikto"] = ScannerSpec("nikto", "sammascanner/nikto:v0.2", sudo=True)
SCANNERS["nmap"] = ScannerSpec(
    "nmap",
    "sammascanner/nmap:v0.2",
    sudo=True,
    raw_sockets=True,
    variants=[
        Variant("port", container="nmap-portscanner", command=["python3", "/code/nmap_portscanner.py"]),
        Variant("http", container="nmap-httprecon", command=["python3", "/code/nmap_httprecon.py"]),
        Variant("tls", container="nmap-tls", command=["python3", "/code/nmap_tlscipher.py"]),
    ],
)
SCANNERS["tsunami"] = ScannerSpec("tsunami", "sammascanner/tsunami:v0.1", args=_tsunami_args)
SCANNERS["base"] = ScannerSpec(
    "base",
    "sammascanner/base:latest",
    env={"PARSER": "base"},
    sidecars=_filebeat_sidecar,
    volumes=_BASE_VOLUMES,
)


def split_scanner_name(raw):
    """"nmap/http" -> ("nmap", "http"); "nikto" -> ("nikto", None)."""
    parts = raw.strip().split("/", 1)
    return (parts[0], parts[1] if len(parts) > 1 and parts[1] else None)


def resolve_runs(scanner_names, templates=None):
    """Turn Scanner.spec.scanners and spec.templates into the list of
    (ScannerSpec, Variant) pairs to run.

    Returns (runs, unknown). `unknown` lists scanner names that are not in
    SCANNERS. A "scanner/template" entry selects one variant; otherwise
    spec.templates, when given, filters the variants of every scanner by
    name, exactly as the template files used to be filtered by file stem.
    """
    runs = []
    seen = set()
    unknown = []
    for raw in scanner_names or []:
        scanner, template = split_scanner_name(str(raw))
        spec = SCANNERS.get(scanner)
        if spec is None:
            unknown.append(raw)
            continue
        if template:
            wanted = {template}
        elif templates:
            wanted = set(templates)
        else:
            wanted = None
        for variant in spec.variants:
            if wanted is not None and variant.name not in wanted:
                continue
            key = (spec.name, variant.name)
            if key not in seen:
                seen.add(key)
                runs.append((spec, variant))
    return runs, unknown


def target_hash(target):
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:8]


def tenant_key(target, samma_io_id=None):
    """What a Job, CronJob and ScanReport are keyed by: the target plus the
    tenant's samma_io_id when the Scanner has one. Two tenants scanning the
    same host must not share a Job, or the second tenant's scans run with
    the first tenant's SAMMA_IO_ID. Without an id this is the target, so
    Scanners made from Ingresses keep sharing as before."""
    if samma_io_id in (None, ""):
        return target
    return "{0}/{1}".format(samma_io_id, target)


def object_name(scanner, variant_name, target, samma_io_id=None):
    """<scanner>[-<variant>]-<hash>: always a valid, short DNS label."""
    if variant_name and variant_name != scanner:
        base = "{0}-{1}".format(scanner, variant_name)
    else:
        base = scanner
    return "{0}-{1}".format(base, target_hash(tenant_key(target, samma_io_id)))


def legacy_names(scanner, variant_name, target):
    """Names the operator used before hashing, so an upgrade can remove the
    objects an older operator created: <scanner>-<target with . as -> with
    and without the template file stem appended."""
    dashed = target.replace(".", "-")
    return sorted({
        "{0}-{1}".format(scanner, dashed),
        "{0}-{1}-{2}".format(scanner, dashed, variant_name or scanner),
    })


def legacy_ingress_scanner_name(scanner, template, host):
    """The name an older operator gave a Scanner made from an Ingress:
    <scanner>-<host with . as ->[-<template>]."""
    name = "{0}-{1}".format(scanner, host.replace(".", "-"))
    if template:
        name = "{0}-{1}".format(name, template)
    return name


def label_value(value):
    """A string that is valid as a label value. Long names are shortened to
    54 characters plus a hash so two different names never collide."""
    value = str(value)
    if _LABEL_VALUE_RE.match(value):
        return value
    return "{0}-{1}".format(value[:54].rstrip("-_."), hashlib.sha256(value.encode("utf-8")).hexdigest()[:8])


def spec_hash(obj):
    """Stable hash of a JSON-serialisable object."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]


def cron_schedule(schedule, target, default_schedule=DEFAULT_SCHEDULE):
    """The schedule for a target's CronJob.

    A Scanner that uses the default weekly schedule ("none", empty or the
    default expression itself) gets a minute derived from the target hash,
    so many targets created on the same day do not all fire in the same
    minute. A schedule the user chose is returned unchanged.
    """
    chosen = (schedule or "").strip()
    default = (default_schedule or DEFAULT_SCHEDULE).strip()
    if chosen not in ("", "none") and chosen != default:
        return chosen
    fields = default.split()
    if len(fields) != 5:
        return default
    fields[0] = str(int(target_hash(target), 16) % 60)
    return " ".join(fields)


def scanner_env(spec_fields, defaults):
    """The environment every scanner container gets, in a stable order.

    spec_fields is Scanner.spec; defaults maps variable names to the
    operator's defaults (SAMMA_IO_ID and friends plus the NATS variables).
    """
    env = {}
    for field, variable in SPEC_ENV_FIELDS:
        if field not in spec_fields:
            continue
        value = spec_fields.get(field)
        if value in (None, "", [], {}):
            value = defaults.get(variable, "elasticsearch" if variable == "ELASTICSEARCH" else "")
        env[variable] = value
    for variable in NATS_ENV_VARS:
        if variable in defaults:
            env[variable] = defaults[variable]
    return {k: str(v) for k, v in env.items()}


def scanner_subject(base_subject, scanner):
    """The NATS subject one scanner publishes on: <base>.<scanner>, so the
    bridge can subscribe to <base>.> and tell publishers apart. An empty
    base falls back to the historical samma-io.scan."""
    base = (base_subject or "").strip().rstrip(".") or "samma-io.scan"
    return "{0}.{1}".format(base, scanner)


def nats_url_with_credentials(url):
    """nats://host:4222 -> nats://$(NATS_USER):$(NATS_PASSWORD)@host:4222.

    The kubelet expands $(NAME) references to variables defined earlier in
    the container's env list. A URL that carries credentials already, or
    one without a scheme, is returned unchanged."""
    url = (url or "").strip()
    scheme, sep, rest = url.partition("://")
    if not sep or "@" in rest.split("/", 1)[0]:
        return url
    return "{0}://$({1}):$({2})@{3}".format(scheme, ENV_NATS_USER, ENV_NATS_PASSWORD, rest)


def image_for(spec, settings):
    """The image reference for a scanner: an explicit override first, then
    the shared prefix (and tag) applied to the image's base name, then the
    default from the table."""
    override = settings.image_overrides.get(spec.name)
    if override:
        return override
    if settings.image_prefix:
        repo, tag = _split_image(spec.image)
        basename = repo.rsplit("/", 1)[-1]
        return "{0}/{1}:{2}".format(settings.image_prefix, basename, settings.image_tag or tag)
    return spec.image


def _split_image(image):
    repo, _, tag = image.rpartition(":")
    if not repo or "/" in tag:
        return image, "latest"
    return repo, tag


def _container_security_context(sudo, net_raw):
    ctx = {
        "allowPrivilegeEscalation": bool(sudo),
        "privileged": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "capabilities": {"drop": ["ALL"]},
    }
    if net_raw:
        ctx["capabilities"]["add"] = ["NET_RAW"]
    return ctx


def base_labels(spec, variant, target, scanner_uid=None, extra=None):
    labels = {
        LABEL_MANAGED_BY: MANAGED_BY,
        LABEL_ROLE: ROLE_SCANNER,
        LABEL_SCANNER: spec.name,
        LABEL_TEMPLATE: variant.name,
        LABEL_TARGET_HASH: target_hash(target),
    }
    if scanner_uid:
        labels[LABEL_SCANNER_UID] = scanner_uid
    for key, value in (extra or {}).items():
        labels[key] = label_value(value)
    return labels


def build_container(spec, variant, target, env, settings):
    net_raw = spec.raw_sockets and settings.nmap_raw_sockets
    container_env = [
        {"name": "TARGET", "value": target},
        {"name": "SAMMA_IO_SCANNER", "value": spec.name},
    ]
    if settings.nats_secret:
        # Defined before NATS_URL so the kubelet can expand them into it.
        container_env.append({"name": ENV_NATS_USER, "value": settings.nats_scanner_user})
        container_env.append({
            "name": ENV_NATS_PASSWORD,
            "valueFrom": {"secretKeyRef": {"name": settings.nats_secret, "key": NATS_SECRET_SCANNER_KEY}},
        })
    for name, value in env.items():
        value = str(value)
        if name == "NATS_SUBJECT":
            value = scanner_subject(value, spec.name)
        elif name == "NATS_URL" and settings.nats_secret:
            value = nats_url_with_credentials(value)
        container_env.append({"name": name, "value": value})
    for name, value in spec.env.items():
        container_env.append({"name": name, "value": str(value)})
    if spec.raw_sockets:
        # nmap reads these itself: NMAP_UNPRIVILEGED makes it use connect
        # scans and no raw packets, NMAP_PRIVILEGED tells it the capability
        # is there even though the process is not root.
        container_env.append({"name": "NMAP_PRIVILEGED" if net_raw else "NMAP_UNPRIVILEGED", "value": "1"})
    container = {
        "name": variant.container,
        "image": image_for(spec, settings),
        "env": container_env,
        "resources": settings.resources,
        "securityContext": _container_security_context(spec.sudo, net_raw),
        "volumeMounts": [
            {"name": "out", "mountPath": "/out"},
            {"name": "tmp", "mountPath": "/tmp"},
        ],
    }
    if settings.image_pull_policy:
        container["imagePullPolicy"] = settings.image_pull_policy
    if variant.command:
        container["command"] = list(variant.command)
    if spec.args:
        container["args"] = spec.args(target)
    return container


def build_pod_template(spec, variant, target, env, settings, labels, annotations):
    containers = [build_container(spec, variant, target, env, settings)]
    if spec.sidecars:
        containers.extend(spec.sidecars(settings))
    volumes = [{"name": "out", "emptyDir": {}}, {"name": "tmp", "emptyDir": {}}]
    if spec.volumes:
        volumes.extend(json.loads(json.dumps(spec.volumes)))
    return {
        "metadata": {"labels": dict(labels), "annotations": dict(annotations)},
        "spec": {
            "restartPolicy": "Never",
            "serviceAccountName": settings.scanner_service_account,
            "automountServiceAccountToken": False,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": spec.run_as_user or settings.run_as_user,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": containers,
            "volumes": volumes,
        },
    }


def _job_spec(spec, variant, target, env, settings, labels, annotations):
    return {
        "backoffLimit": 1,
        "activeDeadlineSeconds": settings.scan_deadline_seconds,
        "ttlSecondsAfterFinished": settings.ttl_seconds_after_finished,
        "template": build_pod_template(spec, variant, target, env, settings, labels, annotations),
    }


def _metadata(name, settings, labels, annotations, owner):
    metadata = {
        "name": name,
        "namespace": settings.namespace,
        "labels": dict(labels),
        "annotations": dict(annotations),
    }
    if owner:
        metadata["ownerReferences"] = [dict(owner)]
    return metadata


def build_job(spec, variant, target, env, settings, owner=None, scanner_name=None, extra_labels=None, samma_io_id=None):
    """A batch/v1 Job that runs the scanner once, now."""
    scanner_uid = owner.get("uid") if owner else None
    labels = base_labels(spec, variant, target, scanner_uid, extra_labels)
    annotations = {ANNOTATION_TARGET: target}
    if scanner_name:
        annotations[ANNOTATION_SCANNER_NAME] = scanner_name
    if samma_io_id not in (None, ""):
        annotations[ANNOTATION_SAMMA_IO_ID] = str(samma_io_id)
    name = object_name(spec.name, variant.name, target, samma_io_id)
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": _metadata(name, settings, labels, annotations, owner),
        "spec": _job_spec(spec, variant, target, env, settings, labels, annotations),
    }


def build_cronjob(spec, variant, target, env, settings, schedule, owner=None, scanner_name=None, extra_labels=None, samma_io_id=None):
    """A batch/v1 CronJob that runs the scanner on a schedule."""
    scanner_uid = owner.get("uid") if owner else None
    labels = base_labels(spec, variant, target, scanner_uid, extra_labels)
    annotations = {ANNOTATION_TARGET: target}
    if scanner_name:
        annotations[ANNOTATION_SCANNER_NAME] = scanner_name
    if samma_io_id not in (None, ""):
        annotations[ANNOTATION_SAMMA_IO_ID] = str(samma_io_id)
    name = object_name(spec.name, variant.name, target, samma_io_id)
    cron_spec = {
        "schedule": cron_schedule(schedule, target, settings.default_schedule),
        "concurrencyPolicy": "Forbid",
        "successfulJobsHistoryLimit": 1,
        "failedJobsHistoryLimit": 1,
        "startingDeadlineSeconds": 600,
        "jobTemplate": {
            "metadata": {"labels": dict(labels), "annotations": dict(annotations)},
            "spec": _job_spec(spec, variant, target, env, settings, labels, annotations),
        },
    }
    metadata = _metadata(name, settings, labels, annotations, owner)
    metadata["annotations"][ANNOTATION_SPEC_HASH] = spec_hash(cron_spec)
    return {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": metadata,
        "spec": cron_spec,
    }


def owner_reference(api_version, kind, name, uid, controller=True):
    """An ownerReference entry. blockOwnerDeletion stays false: setting it
    needs update rights on the owner's finalizers, and nothing here relies
    on foreground deletion."""
    return {
        "apiVersion": api_version,
        "kind": kind,
        "name": name,
        "uid": uid,
        "controller": bool(controller),
        "blockOwnerDeletion": False,
    }


def job_finished(status):
    """True when a Job status (a dict, camelCase or snake_case) says the Job
    completed or failed. A Job with no terminal condition counts as running,
    which includes one whose pod has not started yet."""
    status = status or {}
    for condition in status.get("conditions") or []:
        kind = condition.get("type")
        if kind in ("Complete", "Failed") and str(condition.get("status", "")).lower() == "true":
            return True
    return bool(status.get("completionTime") or status.get("completion_time"))
