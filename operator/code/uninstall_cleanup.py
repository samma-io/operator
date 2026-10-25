"""Remove every Scanner and every scanner Job and CronJob in the namespace.

The Helm chart runs this from a pre-delete hook Job (templates/
pre-delete-hook.yaml) using the operator image and the operator's
ServiceAccount, so that `helm uninstall` never leaves Scanners behind that
would block removal of the CRD or the namespace, and so that scan pods do
not keep running after the operator is gone. It can also be run by hand:

    kubectl -n samma-io run samma-cleanup --rm -it --restart=Never \
        --image <operator image> --overrides '{"spec":{"serviceAccountName":"samma-operator"}}' \
        -- python3 /code/uninstall_cleanup.py

The Jobs and CronJobs of current Scanners are owned by them and are removed
by garbage collection; the explicit delete covers objects an older operator
created without ownerReferences.
"""

import logging
import os
import sys
import time

from kubernetes import client, config
from kubernetes.client.rest import ApiException

GROUP, VERSION, PLURAL = "samma.io", "v1", "scanner"
MANAGED_SELECTOR = "app.kubernetes.io/managed-by=samma-operator"
LEGACY_SELECTOR = "samma.io/scanner"


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    namespace = os.environ.get("SAMMA_NAMESPACE", "samma-io")
    timeout = int(os.environ.get("SAMMA_CLEANUP_TIMEOUT_SECONDS", "120"))
    config.load_incluster_config()
    custom = client.CustomObjectsApi()
    batch = client.BatchV1Api()

    deleted = 0
    try:
        items = custom.list_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL).get("items", [])
    except ApiException as exc:
        if exc.status == 404:
            logging.info("Scanner CRD is not installed, nothing to remove")
            items = []
        else:
            raise
    for item in items:
        name = item["metadata"]["name"]
        try:
            custom.delete_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL, name)
            deleted += 1
        except ApiException as exc:
            if exc.status != 404:
                logging.warning("Could not delete Scanner %s: %s", name, exc.reason)
    logging.info("Deleted %d Scanners in %s", deleted, namespace)

    for selector in (MANAGED_SELECTOR, LEGACY_SELECTOR):
        for cronjob in batch.list_namespaced_cron_job(namespace, label_selector=selector).items:
            _delete(batch.delete_namespaced_cron_job, cronjob.metadata.name, namespace)
        for job in batch.list_namespaced_job(namespace, label_selector=selector).items:
            _delete(batch.delete_namespaced_job, job.metadata.name, namespace)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            remaining = custom.list_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL).get("items", [])
        except ApiException:
            remaining = []
        if not remaining:
            logging.info("All Scanners are gone")
            return 0
        logging.info("%d Scanners still present, waiting", len(remaining))
        time.sleep(5)
    logging.warning("Scanners still present after %d seconds", timeout)
    return 1


def _delete(method, name, namespace):
    try:
        method(name, namespace, propagation_policy="Background")
        logging.info("Deleted %s", name)
    except ApiException as exc:
        if exc.status != 404:
            logging.warning("Could not delete %s: %s", name, exc.reason)


if __name__ == "__main__":
    sys.exit(main())
