"""The samma operator: kopf handlers for Scanner and Ingress resources.

A Scanner (samma.io/v1) names a target and the scanners to run against it.
For every scanner the operator creates one Job right away (through a bounded
queue, see scanqueue.py) and one CronJob on the Scanner's schedule. Both are
owned by the Scanner, so deleting the Scanner removes them through garbage
collection and no finalizers are needed.

An Ingress with the samma-io.alpha.kubernetes.io/enable annotation gets one
Scanner per scanner and host. Those Scanners carry labels naming the Ingress;
when the Ingress is in the operator's own namespace they are also owned by
it. Kubernetes does not allow an owner in another namespace, so for every
other Ingress the delete and update handlers remove stale Scanners by label.
Ingresses without the annotation are never touched: the handlers are
filtered on it and kopf's diff-base annotation is stored only on opted-in
Ingresses (ingress_optin.py).

Job and CronJob bodies are built in jobspec.py; nothing here renders YAML.
"""

import logging
import os
import threading

import kopf
import requests
import yaml
from kubernetes import client, config
from kubernetes.client.rest import ApiException

import ingress_optin
import jobspec
import scanreport
import target_policy
from profile_resolver import resolve_profiles
from scanqueue import ScanQueue, start_drainer

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

# Defaults handed to every scanner pod (Scanner.spec fields override them).
samma_io_id = os.getenv('SAMMA_IO_ID', '1234')
samma_io_tags = os.getenv('SAMMA_IO_TAGS', ["samma"])
samma_io_json = os.getenv('SAMMA_IO_JSON', '{"samma":"scanner"}')
samma_io_scanners = os.getenv('SAMMA_IO_SCANNER', "nmap")
write_to_file = os.getenv('WRITE_TO_FILE', 'true')
samma_io_api_url = os.getenv('SAMMA_IO_API_URL', 'https://www.samma.io')
samma_io_api_token = os.getenv('SAMMA_IO_API_TOKEN', '')
samma_io_profile_id = os.getenv('SAMMA_IO_PROFILE_ID', '')
nats_url = os.getenv('NATS_URL', 'nats://nats:4222')
nats_enabled = os.getenv('NATS_ENABLED', 'True')
nats_subject = os.getenv('NATS_SUBJECT', 'samma-io.scan')

SETTINGS = jobspec.Settings.from_env()
NAMESPACE = SETTINGS.namespace

ENV_DEFAULTS = {
    'SAMMA_IO_ID': samma_io_id,
    'SAMMA_IO_TAGS': samma_io_tags,
    'SAMMA_IO_JSON': samma_io_json,
    'WRITE_TO_FILE': write_to_file,
    'NATS_URL': nats_url,
    'NATS_ENABLED': nats_enabled,
    'NATS_SUBJECT': nats_subject,
}

GROUP, VERSION, PLURAL, KIND = 'samma.io', 'v1', 'scanner', 'Scanner'
API_VERSION = GROUP + '/' + VERSION

ANNOTATION_PREFIX = ingress_optin.ANNOTATION_PREFIX
ENABLE_ANNOTATION = ingress_optin.ENABLE_ANNOTATION
# The kopf filter on every Ingress handler: only opted-in Ingresses match.
OPTED_IN = {ENABLE_ANNOTATION: kopf.PRESENT}
# The namespaces whose Ingresses the handlers act on: the operator's own
# always, plus what SAMMA_INGRESS_NAMESPACES lists, comma-separated with
# '*' for all. The guard lives in the handlers rather than the RBAC, so the
# ClusterRole stays cluster-wide and the list can change with an env edit.
INGRESS_NAMESPACES = [entry.strip() for entry in os.getenv('SAMMA_INGRESS_NAMESPACES', '').split(',') if entry.strip()]
PROFILE_ANNOTATION = ANNOTATION_PREFIX + 'profile'
SCANNERS_ANNOTATION = ANNOTATION_PREFIX + 'scanners'
# The only annotation values that are copied into a Scanner's spec. Anything
# else under the prefix is ignored (the old operator copied every field).
COPIED_ANNOTATION_FIELDS = ('scheduler', 'samma_io_id', 'samma_io_tags', 'samma_io_json', 'write_to_file', 'elasticsearch')
FALSE_WORDS = ('0', 'false', 'no', 'off')

# A target that does not resolve is checked again every 5 minutes this many
# times before the operator gives up on it (DNS is often created after the
# Ingress, for example by external-dns).
MAX_RESOLVE_RETRIES = 12
RESOLVE_RETRY_DELAY = 300

config.load_incluster_config()
api = client.CoreV1Api()
batch1api = client.BatchV1Api()
k8sapi = client.CustomObjectsApi()
networking_api = client.NetworkingV1Api()

# The generated client picks a patch content type from the body's Python
# type, which is wrong for custom resources. A client whose default header
# is merge-patch (default headers win over the generated ones) patches both
# built-in and custom objects the same way.
_merge_client = client.ApiClient()
_merge_client.set_default_header('Content-Type', 'application/merge-patch+json')
merge_batch = client.BatchV1Api(_merge_client)
merge_custom = client.CustomObjectsApi(_merge_client)


# ---------------------------------------------------------------------------
# Startup: default ConfigMaps and the scan queue
# ---------------------------------------------------------------------------

def init_operator():
    """Create the ConfigMaps the scanners need when they are absent. The
    deployment can override them by creating its own before the operator
    starts; existing ConfigMaps are never changed. The filebeat and live
    ConfigMaps exist only for the legacy base scanner's sidecar and are
    created only with SAMMA_LEGACY_BASE_SCANNER=true; the detect scanners
    publish to NATS and need neither."""

    def have_configmap(name):
        try:
            api.read_namespaced_config_map(name, NAMESPACE)
            return True
        except ApiException as exc:
            if exc.status == 404:
                return False
            raise

    legacy = (('filebeat', 'scanners/core/config-filebeat.yaml'), ('live', 'scanners/core/config-live.yaml'))
    if not SETTINGS.legacy_base_scanner:
        legacy = ()
    for name, path in legacy:
        if have_configmap(name):
            continue
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), path), 'r') as handle:
            body = yaml.load(handle, Loader=Loader)
        body.setdefault('metadata', {})['namespace'] = NAMESPACE
        try:
            api.create_namespaced_config_map(namespace=NAMESPACE, body=body)
            logging.info("Created ConfigMap %s", name)
        except ApiException as exc:
            logging.warning("Could not create ConfigMap %s: %s", name, exc.reason)

    if not have_configmap('scanner-profiles'):
        profiles_cm = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name="scanner-profiles", namespace=NAMESPACE),
            data={
                "default": "http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http,port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls,dns-scanner,whois-scanner",
                "web":     "http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http",
                "network": "port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls",
                "dns":     "dns-scanner,whois-scanner",
                "detect":  "port-scanner,dns-scanner,http-headers-scanner,tls-scanner,traceroute-scanner,ssh-banner-scanner,whois-scanner,http-redirect-scanner",
                "classic": "nikto,nmap/port,nmap/http,nmap/tls,tsunami",
                "all":     "http-headers-scanner,http-redirect-scanner,tls-scanner,nikto,nmap/http,port-scanner,traceroute-scanner,ssh-banner-scanner,nmap/port,nmap/tls,dns-scanner,whois-scanner,tsunami",
                "full":    "nmap,nikto,tsunami,base",
            }
        )
        try:
            api.create_namespaced_config_map(namespace=NAMESPACE, body=profiles_cm)
            logging.info("Created scanner-profiles ConfigMap")
        except ApiException as exc:
            logging.warning("Could not create scanner-profiles ConfigMap: %s", exc.reason)


def count_running_scan_jobs():
    jobs = batch1api.list_namespaced_job(NAMESPACE, label_selector=jobspec.LABEL_SCANNER)
    running = 0
    for job in jobs.items:
        status = job.status.to_dict() if job.status is not None else {}
        if not jobspec.job_finished(status):
            running += 1
    return running


def create_job(body):
    """Create a Job; when one with that name exists already, make sure this
    Scanner is among its owners (two Scanners for the same target and
    scanner share one Job)."""
    try:
        batch1api.create_namespaced_job(NAMESPACE, body)
        logging.info("Created Job %s", body['metadata']['name'])
    except ApiException as exc:
        if exc.status != 409:
            raise
        add_owner(batch1api.read_namespaced_job, merge_batch.patch_namespaced_job, body)


def create_cronjob(body):
    try:
        batch1api.create_namespaced_cron_job(NAMESPACE, body)
        logging.info("Created CronJob %s", body['metadata']['name'])
    except ApiException as exc:
        if exc.status != 409:
            raise
        add_owner(batch1api.read_namespaced_cron_job, merge_batch.patch_namespaced_cron_job, body)


def add_owner(read, patch, body):
    """Append body's owner to an existing object's ownerReferences when it is
    not there yet. Garbage collection removes the object once every owner is
    gone, so a shared Job or CronJob outlives the first Scanner deleted."""
    owners = body['metadata'].get('ownerReferences') or []
    if not owners:
        return
    name = body['metadata']['name']
    existing = read(name, NAMESPACE)
    refs = existing.metadata.owner_references or []
    if any(ref.uid == owners[0]['uid'] for ref in refs):
        return
    merged = [
        {
            'apiVersion': ref.api_version,
            'kind': ref.kind,
            'name': ref.name,
            'uid': ref.uid,
            'controller': bool(ref.controller),
            'blockOwnerDeletion': bool(ref.block_owner_deletion),
        }
        for ref in refs
    ]
    # Only one owner may be the controller; the newcomer is a plain owner.
    extra = dict(owners[0])
    extra['controller'] = not any(ref.get('controller') for ref in merged)
    merged.append(extra)
    patch(name, NAMESPACE, {'metadata': {'ownerReferences': merged}})
    logging.info("%s %s exists already, added Scanner %s as an owner", existing.kind or 'Object', name, extra['name'])


def scanner_still_exists(key, body):
    owners = body['metadata'].get('ownerReferences') or []
    if not owners:
        return True
    try:
        current = k8sapi.get_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, owners[0]['name'])
    except ApiException as exc:
        if exc.status == 404:
            return False
        raise
    return current.get('metadata', {}).get('uid') == owners[0]['uid']


def mark_initial_scan(scanner_name, state):
    body = {'metadata': {'annotations': {jobspec.ANNOTATION_INITIAL_SCAN: state}}}
    try:
        merge_custom.patch_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, scanner_name, body)
    except ApiException as exc:
        if exc.status != 404:
            logging.warning("Could not annotate Scanner %s: %s", scanner_name, exc.reason)


def job_launched(key, body):
    uid = key.split('/', 1)[0]
    if not scan_queue.has_pending(uid + '/'):
        scanner_name = body['metadata'].get('annotations', {}).get(jobspec.ANNOTATION_SCANNER_NAME)
        if scanner_name:
            mark_initial_scan(scanner_name, jobspec.INITIAL_SCAN_LAUNCHED)


scan_queue = ScanQueue(
    SETTINGS.max_concurrent_scans,
    count_running=count_running_scan_jobs,
    launch=create_job,
    on_launched=job_launched,
    still_wanted=scanner_still_exists,
)
_drainer_stop = threading.Event()


# ---------------------------------------------------------------------------
# Failed scan Jobs -> ScanReport status.lastRun
# ---------------------------------------------------------------------------

def record_job_outcomes():
    """Runs on every queue tick. For each scan Job that failed (or hit its
    deadline) and whose scanner has a ScanReport, write the outcome into
    status.lastRun, creating the report with its spec when it is missing,
    then annotate the Job so this happens once. See scanreport.py."""
    jobs = batch1api.list_namespaced_job(NAMESPACE, label_selector=jobspec.LABEL_SCANNER).items
    for job in jobs:
        metadata = job.metadata.to_dict() if job.metadata is not None else {}
        if scanreport.outcome_recorded(metadata):
            continue
        identity = scanreport.job_identity(metadata)
        if identity is None:
            continue
        scanner, template, target = identity
        samma_id = scanreport.job_samma_io_id(metadata)
        if not scanreport.wants_report(scanner):
            continue
        status = job.status.to_dict() if job.status is not None else {}
        result = scanreport.job_outcome(status)
        if result is None:
            continue
        outcome, message, started_at, finished_at = result
        job_name = metadata['name']
        try:
            run_id = job_pod_name(job_name) or job_name
            write_failed_run(
                scanner, template, target, samma_id,
                owners=scanreport.scanner_owners(metadata),
                extra_labels=scanreport.ingress_labels(metadata),
                run_id=run_id, job_name=job_name, outcome=outcome, message=message,
                started_at=started_at, finished_at=finished_at,
            )
        except ApiException as exc:
            logging.warning("Could not record the outcome of Job %s: %s", job_name, exc.reason)
            continue
        try:
            merge_batch.patch_namespaced_job(job_name, NAMESPACE, {'metadata': {'annotations': {scanreport.ANNOTATION_OUTCOME_RECORDED: 'true'}}})
        except ApiException as exc:
            if exc.status != 404:
                logging.warning("Could not annotate Job %s: %s", job_name, exc.reason)
        logging.info("Recorded %s run of %s (%s) in ScanReport %s", outcome, scanner, target, scanreport.report_name(scanner, template, target, samma_id))


def job_pod_name(job_name):
    """The pod the Job ran last, which is the run id the scanner itself
    would have used (its hostname)."""
    pods = api.list_namespaced_pod(NAMESPACE, label_selector="job-name={0}".format(job_name)).items
    return scanreport.latest_pod_name([pod.metadata.to_dict() for pod in pods if pod.metadata is not None])


def write_failed_run(scanner, template, target, samma_id, owners, extra_labels, run_id, job_name, outcome, message, started_at, finished_at):
    """Create the ScanReport when it is missing, then replace its status
    with lastRun set, keeping findings and everything else. The replace
    carries the resourceVersion read just before, so a bridge write in
    between is a 409 and the loop reads again."""
    name = scanreport.report_name(scanner, template, target, samma_id)
    for attempt in range(3):
        try:
            existing = k8sapi.get_namespaced_custom_object(scanreport.GROUP, scanreport.VERSION, NAMESPACE, scanreport.PLURAL, name)
        except ApiException as exc:
            if exc.status != 404:
                raise
            body = scanreport.report_body(scanner, template, target, NAMESPACE, owners=owners, extra_labels=extra_labels, samma_io_id=samma_id)
            try:
                existing = k8sapi.create_namespaced_custom_object(scanreport.GROUP, scanreport.VERSION, NAMESPACE, scanreport.PLURAL, body)
                logging.info("Created ScanReport %s", name)
            except ApiException as exc:
                if exc.status != 409:
                    raise
                continue  # created by the bridge in the meantime; read it
        current = existing.get('status') or {}
        if scanreport.run_already_recorded(current, run_id):
            return
        existing['status'] = scanreport.failed_run_status(current, run_id, job_name, outcome, message, started_at, finished_at)
        try:
            k8sapi.replace_namespaced_custom_object_status(scanreport.GROUP, scanreport.VERSION, NAMESPACE, scanreport.PLURAL, name, existing)
            return
        except ApiException as exc:
            if exc.status != 409:
                raise
    raise ApiException(status=409, reason="ScanReport {0} kept changing while its status was written".format(name))


@kopf.on.startup()
def configure(settings, **_):
    global _drainer_stop
    # The operator serves only the resources that exist when it starts, so
    # it does not need to list or watch CustomResourceDefinitions.
    scanning = getattr(settings, 'scanning', None)
    if scanning is not None:
        scanning.disabled = True
    # kopf writes its diff base onto every watched object, handled or not;
    # this storage writes it on opted-in Ingresses only (ingress_optin.py).
    settings.persistence.diffbase_storage = ingress_optin.make_diffbase_storage()
    init_operator()
    _, _drainer_stop = start_drainer(scan_queue, SETTINGS.queue_interval_seconds, on_tick=record_job_outcomes)
    logging.info(
        "samma operator in namespace %s: max %d concurrent scans, deadline %ds, nmap raw sockets %s, "
        "NATS credentials %s, Ingress namespaces %s",
        NAMESPACE, SETTINGS.max_concurrent_scans, SETTINGS.scan_deadline_seconds, SETTINGS.nmap_raw_sockets,
        "from Secret {0}".format(SETTINGS.nats_secret) if SETTINGS.nats_secret else "none",
        ", ".join(INGRESS_NAMESPACES) if INGRESS_NAMESPACES else "own only ({0})".format(NAMESPACE),
    )


@kopf.on.cleanup()
def shutdown(**_):
    _drainer_stop.set()


def post_target_to_api(host):
    """POST a discovered domain to the external samma.io API if a token is configured."""
    if not samma_io_api_token:
        return
    url = "{0}/api/v1/targets".format(samma_io_api_url.rstrip('/'))
    payload = {"value": host, "type": "dns", "label": host}
    if samma_io_profile_id:
        payload["profileId"] = samma_io_profile_id
    headers = {
        "Authorization": "Bearer {0}".format(samma_io_api_token),
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        logging.info("Posted target %s to API: %s", host, resp.status_code)
    except Exception as exc:
        logging.warning("Failed to post target %s to API: %s", host, exc)


# ---------------------------------------------------------------------------
# Scanner handlers
# ---------------------------------------------------------------------------

def validate_scanner(body, retry):
    """Run the target policy and the name and schedule checks. Raises the
    kopf errors that stop the handler; returns the parsed pieces."""
    spec = body.get('spec') or {}
    target = spec.get('target')
    try:
        target_policy.check_target(target, networking_api=networking_api)
    except target_policy.TargetUnresolvable as exc:
        if retry >= MAX_RESOLVE_RETRIES:
            kopf.warn(body, reason='TargetRejected', message="{0}; giving up after {1} attempts".format(exc, retry + 1))
            raise kopf.PermanentError(str(exc))
        kopf.warn(body, reason='TargetUnresolvable', message=str(exc))
        raise kopf.TemporaryError("{0}; retrying in 5 minutes".format(exc), delay=RESOLVE_RETRY_DELAY)
    except target_policy.TargetRejected as exc:
        kopf.warn(body, reason='TargetRejected', message=str(exc))
        raise kopf.PermanentError(str(exc))

    scanners = spec.get('scanners') or [s.strip() for s in samma_io_scanners.split(',') if s.strip()]
    scheduler = spec.get('scheduler') or 'none'
    templates = spec.get('templates') or None
    try:
        for scanner in scanners:
            target_policy.validate_scanner_name(scanner)
        target_policy.validate_schedule(scheduler)
    except target_policy.TargetRejected as exc:
        kopf.warn(body, reason='ScannerRejected', message=str(exc))
        raise kopf.PermanentError(str(exc))

    runs, unknown = jobspec.resolve_runs(scanners, templates)
    for name in unknown:
        kopf.warn(body, reason='UnknownScanner', message="Scanner {0!r} is not known to this operator and was skipped".format(name))
    if not runs:
        raise kopf.PermanentError("none of the requested scanners {0} is known".format(scanners))
    if not SETTINGS.legacy_base_scanner and any(spec.name == 'base' for spec, _ in runs):
        kopf.warn(body, reason='LegacyScanner',
                  message="The base scanner mounts the filebeat and live ConfigMaps, which are created only with "
                          "SAMMA_LEGACY_BASE_SCANNER=true (chart: scanners.legacyBaseScanner); its pod will not start")
    return target, scheduler, runs


def scanner_links(body):
    """The ownerReference for objects of this Scanner and the labels that
    tie an Ingress-made Scanner back to its Ingress."""
    meta = body['metadata']
    owner = jobspec.owner_reference(API_VERSION, KIND, meta['name'], meta['uid'])
    labels = meta.get('labels') or {}
    extra = {}
    for key in (jobspec.LABEL_INGRESS_NAMESPACE, jobspec.LABEL_INGRESS_NAME):
        if key in labels:
            extra[key] = labels[key]
    return owner, extra


def build_scanner_objects(body, retry):
    target, scheduler, runs = validate_scanner(body, retry)
    env = jobspec.scanner_env(body.get('spec') or {}, ENV_DEFAULTS)
    owner, extra_labels = scanner_links(body)
    name = body['metadata']['name']
    # Keyed by tenant: a Job runs with one SAMMA_IO_ID, so two tenants
    # scanning the same host each need their own (operator#14).
    samma_id = (body.get('spec') or {}).get('samma_io_id')
    jobs = []
    cronjobs = []
    for spec, variant in runs:
        jobs.append(jobspec.build_job(spec, variant, target, env, SETTINGS, owner=owner, scanner_name=name, extra_labels=extra_labels, samma_io_id=samma_id))
        cronjobs.append(jobspec.build_cronjob(spec, variant, target, env, SETTINGS, scheduler, owner=owner, scanner_name=name, extra_labels=extra_labels, samma_io_id=samma_id))
    return jobs, cronjobs


def list_owned_cronjobs(uid):
    selector = "{0}={1}".format(jobspec.LABEL_SCANNER_UID, uid)
    return batch1api.list_namespaced_cron_job(NAMESPACE, label_selector=selector).items


def reconcile_cronjobs(body, cronjobs):
    """Create the CronJobs the Scanner needs and delete the ones it no
    longer needs or whose built spec changed."""
    uid = body['metadata']['uid']
    desired = {cj['metadata']['name']: cj for cj in cronjobs}
    for existing in list_owned_cronjobs(uid):
        name = existing.metadata.name
        annotations = existing.metadata.annotations or {}
        wanted = desired.get(name)
        if wanted is not None and annotations.get(jobspec.ANNOTATION_SPEC_HASH) == wanted['metadata']['annotations'][jobspec.ANNOTATION_SPEC_HASH]:
            desired.pop(name)
            continue
        owners = existing.metadata.owner_references or []
        if wanted is not None and len(owners) > 1:
            # Shared with another Scanner for the same target: keep the
            # schedule that is there instead of recreating it back and forth.
            kopf.info(body, reason='CronJobShared',
                      message="CronJob {0} is shared with another Scanner; its current schedule applies".format(name))
            desired.pop(name)
            continue
        try:
            batch1api.delete_namespaced_cron_job(name, NAMESPACE, propagation_policy='Background')
            logging.info("Deleted CronJob %s (stale)", name)
        except ApiException as exc:
            if exc.status != 404:
                raise
    for cronjob in desired.values():
        create_cronjob(cronjob)


def submit_jobs(body, jobs, patch):
    uid = body['metadata']['uid']
    queued = False
    for job in jobs:
        state = scan_queue.submit("{0}/{1}".format(uid, job['metadata']['name']), job)
        if state == 'failed':
            message = "Could not create Job {0}: {1}".format(job['metadata']['name'], scan_queue.error("{0}/{1}".format(uid, job['metadata']['name'])))
            kopf.warn(body, reason='JobCreateFailed', message=message)
            scan_queue.forget("{0}/{1}".format(uid, job['metadata']['name']))
            raise kopf.TemporaryError(message, delay=60)
        if state == 'queued':
            queued = True
    annotations = patch.setdefault('metadata', {}).setdefault('annotations', {})
    annotations[jobspec.ANNOTATION_INITIAL_SCAN] = jobspec.INITIAL_SCAN_QUEUED if queued else jobspec.INITIAL_SCAN_LAUNCHED
    if queued:
        kopf.info(body, reason='ScanQueued',
                  message="First scan waits for a free slot ({0} concurrent scans allowed)".format(SETTINGS.max_concurrent_scans))


@kopf.on.create(GROUP, VERSION, PLURAL)
def create_fn(body, retry, patch, **kwargs):
    jobs, cronjobs = build_scanner_objects(body, retry)
    reconcile_cronjobs(body, cronjobs)
    submit_jobs(body, jobs, patch)
    logging.info("Scanner %s: %d scanners against %s", body['metadata']['name'], len(jobs), body['spec'].get('target'))


@kopf.on.resume(GROUP, VERSION, PLURAL)
def resume_fn(body, retry, patch, **kwargs):
    """After a restart, re-queue the first Jobs of Scanners that were still
    waiting for a slot. Jobs that exist already are adopted, not repeated."""
    annotations = body['metadata'].get('annotations') or {}
    if annotations.get(jobspec.ANNOTATION_INITIAL_SCAN) != jobspec.INITIAL_SCAN_QUEUED:
        return
    jobs, _ = build_scanner_objects(body, retry)
    submit_jobs(body, jobs, patch)


@kopf.on.update(GROUP, VERSION, PLURAL, field='spec')
def update_fn(body, retry, **kwargs):
    """A changed spec recreates the CronJobs. The first Job is not run again."""
    uid = body['metadata']['uid']
    try:
        _, cronjobs = build_scanner_objects(body, retry)
    except kopf.PermanentError:
        # The new spec is rejected: nothing may keep running against it.
        for existing in list_owned_cronjobs(uid):
            try:
                batch1api.delete_namespaced_cron_job(existing.metadata.name, NAMESPACE, propagation_policy='Background')
            except ApiException as exc:
                if exc.status != 404:
                    raise
        raise
    reconcile_cronjobs(body, cronjobs)


@kopf.on.delete(GROUP, VERSION, PLURAL, optional=True)
def delete_fn(body, **kwargs):
    """Jobs and CronJobs are owned by the Scanner and go with it. This
    handler only forgets queued work and removes objects an older operator
    created under the pre-hash names. optional=True: no finalizer, so a
    Scanner can always be deleted, even with the operator gone."""
    meta = body['metadata']
    scan_queue.forget(meta['uid'] + '/')
    spec = body.get('spec') or {}
    target = spec.get('target') or ''
    scanners = spec.get('scanners') or [s.strip() for s in samma_io_scanners.split(',') if s.strip()]
    runs, _ = jobspec.resolve_runs(scanners, spec.get('templates') or None)
    for scanner_spec, variant in runs:
        for name in jobspec.legacy_names(scanner_spec.name, variant.name, target):
            for method in (batch1api.delete_namespaced_job, batch1api.delete_namespaced_cron_job):
                try:
                    method(name, NAMESPACE, propagation_policy='Background')
                    logging.info("Deleted legacy object %s", name)
                except ApiException as exc:
                    if exc.status != 404:
                        logging.warning("Could not delete legacy object %s: %s", name, exc.reason)
    logging.info("Scanner %s deleted", meta['name'])


# ---------------------------------------------------------------------------
# Ingress handlers
# ---------------------------------------------------------------------------

def ingress_enabled(annotations):
    if ENABLE_ANNOTATION not in annotations:
        return False
    return str(annotations.get(ENABLE_ANNOTATION) or '').strip().lower() not in FALSE_WORDS


def ingress_scanner_specs(annotations):
    profile_ann = annotations.get(PROFILE_ANNOTATION)
    scanners_ann = annotations.get(SCANNERS_ANNOTATION)
    if profile_ann:
        specs = resolve_profiles([p.strip() for p in profile_ann.split(',')], api, namespace=NAMESPACE)
    elif scanners_ann:
        specs = [jobspec.split_scanner_name(s) for s in scanners_ann.split(',') if s.strip()]
    else:
        specs = resolve_profiles(['default'], api, namespace=NAMESPACE)
    if not specs:
        logging.warning("No scanner specs resolved for Ingress, falling back to env default")
        specs = [jobspec.split_scanner_name(s) for s in samma_io_scanners.split(',') if s.strip()]
    return specs


def ingress_spec_fields(annotations):
    fields = {}
    for field in COPIED_ANNOTATION_FIELDS:
        value = annotations.get(ANNOTATION_PREFIX + field)
        if value is None:
            continue
        if field == 'samma_io_tags':
            fields[field] = [t.strip() for t in value.split(',') if t.strip()]
        else:
            fields[field] = value
    return fields


def ingress_hosts(body):
    """(hosts to scan, hosts that did not resolve yet). Wildcard and
    host-less rules are skipped and rejected hosts get an event."""
    hosts = []
    deferred = []
    for rule in (body.get('spec') or {}).get('rules') or []:
        host = rule.get('host')
        if not host:
            continue
        if target_policy.is_wildcard_host(host):
            kopf.info(body, reason='WildcardHostSkipped',
                      message="Skipped wildcard host {0}: scanners need a concrete hostname".format(host))
            continue
        try:
            # This Ingress serves the host, so the managed check is not
            # needed; the apiserver already checked the host's syntax.
            target_policy.check_target(host, allow_unmanaged=True)
        except target_policy.TargetUnresolvable as exc:
            logging.warning("%s", exc)
            deferred.append(host)
            continue
        except target_policy.TargetRejected as exc:
            logging.warning("%s", exc)
            kopf.warn(body, reason='TargetRejected', message=str(exc))
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts, deferred


def ingress_selector(namespace, name):
    return "{0}={1},{2}={3}".format(
        jobspec.LABEL_INGRESS_NAMESPACE, jobspec.label_value(namespace),
        jobspec.LABEL_INGRESS_NAME, jobspec.label_value(name),
    )


def list_ingress_scanners(namespace, name):
    result = k8sapi.list_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, label_selector=ingress_selector(namespace, name))
    return result.get('items', [])


def desired_scanners(body, hosts):
    """The Scanner bodies an Ingress should have, keyed by name."""
    meta = body['metadata']
    annotations = meta.get('annotations') or {}
    fields = ingress_spec_fields(annotations)
    wanted = {}
    for scanner, template in ingress_scanner_specs(annotations):
        for host in hosts:
            # The hash covers the Ingress too, so two Ingresses serving the
            # same host each get their own Scanner (their Jobs are shared).
            name = jobspec.object_name(scanner, template or scanner, "{0}/{1}/{2}".format(meta['namespace'], meta['name'], host))
            spec = dict(fields)
            spec['target'] = host
            spec['scanners'] = [scanner]
            if template:
                spec['templates'] = [template]
            scanner_body = {
                'apiVersion': API_VERSION,
                'kind': KIND,
                'metadata': {
                    'name': name,
                    'namespace': NAMESPACE,
                    'labels': {
                        jobspec.LABEL_MANAGED_BY: jobspec.MANAGED_BY,
                        jobspec.LABEL_INGRESS_NAMESPACE: jobspec.label_value(meta['namespace']),
                        jobspec.LABEL_INGRESS_NAME: jobspec.label_value(meta['name']),
                    },
                    'annotations': {
                        jobspec.ANNOTATION_INGRESS: "{0}/{1}".format(meta['namespace'], meta['name']),
                        jobspec.ANNOTATION_TARGET: host,
                    },
                },
                'spec': spec,
            }
            if meta['namespace'] == NAMESPACE and meta.get('uid'):
                # Same namespace: a real owner, so the Scanner is garbage
                # collected with the Ingress. Across namespaces Kubernetes
                # forbids owner references; the labels above and
                # ingress_delete do that job instead.
                scanner_body['metadata']['ownerReferences'] = [
                    jobspec.owner_reference('networking.k8s.io/v1', 'Ingress', meta['name'], meta['uid'])
                ]
            wanted[name] = scanner_body
    return wanted


def reconcile_ingress(body, retry):
    meta = body['metadata']
    annotations = meta.get('annotations') or {}
    existing = {item['metadata']['name']: item for item in list_ingress_scanners(meta['namespace'], meta['name'])}

    if not ingress_enabled(annotations):
        wanted = {}
        deferred = []
    else:
        hosts, deferred = ingress_hosts(body)
        wanted = desired_scanners(body, hosts)

    for name, item in existing.items():
        if name in wanted:
            continue
        host = (item.get('spec') or {}).get('target')
        if host in deferred:
            continue  # still scanned; the host just failed to resolve this time
        delete_scanner(name)

    posted = set()
    for name, scanner_body in wanted.items():
        current = existing.get(name)
        if current is None:
            try:
                k8sapi.create_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, scanner_body)
                logging.info("Created Scanner %s for Ingress %s/%s", name, meta['namespace'], meta['name'])
            except ApiException as exc:
                if exc.status == 409:
                    logging.info("Scanner %s exists already", name)
                else:
                    kopf.warn(body, reason='ScannerCreateFailed',
                              message="Could not create Scanner {0}: {1}".format(name, getattr(exc, 'reason', exc)))
                    continue
            host = scanner_body['spec']['target']
            if host not in posted:
                posted.add(host)
                post_target_to_api(host)
        elif managed_spec(current, scanner_body['spec']) != scanner_body['spec']:
            try:
                merge_custom.patch_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, name, {'spec': scanner_body['spec']})
                logging.info("Updated Scanner %s from Ingress %s/%s", name, meta['namespace'], meta['name'])
            except ApiException as exc:
                kopf.warn(body, reason='ScannerUpdateFailed',
                          message="Could not update Scanner {0}: {1}".format(name, getattr(exc, 'reason', exc)))

    if deferred:
        message = "Ingress hosts {0} did not resolve yet".format(", ".join(deferred))
        if retry >= MAX_RESOLVE_RETRIES:
            kopf.warn(body, reason='TargetUnresolvable', message="{0}; giving up after {1} attempts".format(message, retry + 1))
        else:
            raise kopf.TemporaryError("{0}; retrying in 5 minutes".format(message), delay=RESOLVE_RETRY_DELAY)


def managed_spec(current, wanted):
    """The part of an existing Scanner's spec that the Ingress controls, so
    fields an older operator copied from other annotations are left alone."""
    spec = current.get('spec') or {}
    return {key: spec.get(key) for key in wanted}


def delete_scanner(name):
    try:
        k8sapi.delete_namespaced_custom_object(GROUP, VERSION, NAMESPACE, PLURAL, name)
        logging.info("Deleted Scanner %s", name)
    except ApiException as exc:
        if exc.status != 404:
            logging.warning("Could not delete Scanner %s: %s", name, exc.reason)


# Every handler below is filtered on the enable annotation (OPTED_IN), so an
# Ingress that never carried it matches none of them; ingress_opted_out
# catches the one transition the filter cannot see, the annotation going
# away. Ingresses in namespaces outside SAMMA_INGRESS_NAMESPACES are skipped
# the same way, by the guard each handler calls first. Together with the
# diff-base storage set in configure(), the operator reads other Ingresses
# but never writes to them.

# One skip log line per Ingress, not one per event.
_namespace_skip_logged = set()


def ingress_namespace_blocked(meta):
    """True for an Ingress in a namespace this operator does not act on (its
    own plus SAMMA_INGRESS_NAMESPACES, '*' is all). The first event on a
    disallowed Ingress logs the skip, the rest are silent."""
    namespace = meta.get('namespace')
    if ingress_optin.ingress_namespace_allowed(namespace, NAMESPACE, INGRESS_NAMESPACES):
        return False
    key = "{0}/{1}".format(namespace, meta.get('name'))
    if key not in _namespace_skip_logged:
        _namespace_skip_logged.add(key)
        logging.info("Ingress %s: skipped, only Ingresses in %s and SAMMA_INGRESS_NAMESPACES (%s) are handled",
                     key, NAMESPACE, ", ".join(INGRESS_NAMESPACES) or "empty")
    return True


@kopf.on.create('networking.k8s.io', 'v1', 'ingresses', annotations=OPTED_IN)
def ingress_create_fn(body, retry, **kwargs):
    if ingress_namespace_blocked(body['metadata']):
        return
    reconcile_ingress(body, retry)


@kopf.on.update('networking.k8s.io', 'v1', 'ingresses', field='metadata.annotations', annotations=OPTED_IN)
def ingress_annotations_changed(body, retry, **kwargs):
    """A changed annotation under the prefix, or enable set to "false":
    reconcile_ingress then deletes the Scanners."""
    if ingress_namespace_blocked(body['metadata']):
        return
    reconcile_ingress(body, retry)


@kopf.on.update('networking.k8s.io', 'v1', 'ingresses', field='spec.rules', annotations=OPTED_IN)
def ingress_rules_changed(body, retry, **kwargs):
    if ingress_namespace_blocked(body['metadata']):
        return
    reconcile_ingress(body, retry)


@kopf.on.update('networking.k8s.io', 'v1', 'ingresses', field=ingress_optin.ENABLE_FIELD,
                old=kopf.PRESENT, new=kopf.ABSENT)
def ingress_opted_out(body, retry, **kwargs):
    """The enable annotation was removed: the Ingress no longer matches the
    filtered handlers, so this one removes its Scanners (ingress_enabled is
    false without the annotation, and reconcile_ingress wants none)."""
    if ingress_namespace_blocked(body['metadata']):
        return
    reconcile_ingress(body, retry)


@kopf.on.delete('networking.k8s.io', 'v1', 'ingresses', optional=True, annotations=OPTED_IN)
def ingress_delete(body, **kwargs):
    """Remove the Scanners this Ingress created, by label. Scanners in the
    operator's namespace are also garbage collected through their owner
    reference; the explicit delete covers every other namespace and the
    names an older operator used."""
    if ingress_namespace_blocked(body['metadata']):
        return
    meta = body['metadata']
    for item in list_ingress_scanners(meta['namespace'], meta['name']):
        delete_scanner(item['metadata']['name'])
    annotations = meta.get('annotations') or {}
    if not ingress_enabled(annotations):
        return
    hosts = [rule.get('host') for rule in (body.get('spec') or {}).get('rules') or []]
    hosts = [host for host in hosts if host and not target_policy.is_wildcard_host(host)]
    for scanner, template in ingress_scanner_specs(annotations):
        for host in hosts:
            delete_scanner(jobspec.legacy_ingress_scanner_name(scanner, template, host))
