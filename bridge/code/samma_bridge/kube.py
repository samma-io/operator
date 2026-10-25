"""The kubernetes client behind reports.upsert and scanners.ScannerIndex.

Imported only by bridge.py; the kubernetes package is imported here, lazily,
so the rest of the package stays importable without it.
"""

from . import reports

SCANNER_GROUP, SCANNER_VERSION, SCANNER_PLURAL = "samma.io", "v1", "scanner"


class KubeStore(object):
    def __init__(self, namespace):
        from kubernetes import client, config
        from kubernetes.client.rest import ApiException

        config.load_incluster_config()
        self._ApiException = ApiException
        self.namespace = namespace
        self.api = client.CustomObjectsApi()
        # The generated client picks a patch content type from the body's
        # Python type; a client with merge-patch as its default header
        # patches custom objects the way the bridge needs.
        merge_client = client.ApiClient()
        merge_client.set_default_header("Content-Type", "application/merge-patch+json")
        self.merge_api = client.CustomObjectsApi(merge_client)

    # scanners.ScannerIndex lister
    def list_scanners(self):
        result = self.api.list_namespaced_custom_object(SCANNER_GROUP, SCANNER_VERSION, self.namespace, SCANNER_PLURAL)
        return result.get("items", [])

    # reports.upsert store
    def get(self, name):
        try:
            return self.api.get_namespaced_custom_object(reports.GROUP, reports.VERSION, self.namespace, reports.PLURAL, name)
        except self._ApiException as exc:
            if exc.status == 404:
                return None
            raise

    def create(self, body):
        try:
            return self.api.create_namespaced_custom_object(reports.GROUP, reports.VERSION, self.namespace, reports.PLURAL, body)
        except self._ApiException as exc:
            if exc.status == 409:
                raise reports.Conflict(str(exc.reason))
            raise

    def replace_status(self, name, body):
        try:
            return self.api.replace_namespaced_custom_object_status(reports.GROUP, reports.VERSION, self.namespace, reports.PLURAL, name, body)
        except self._ApiException as exc:
            if exc.status == 409:
                raise reports.Conflict(str(exc.reason))
            raise

    def patch_metadata(self, name, patch):
        return self.merge_api.patch_namespaced_custom_object(reports.GROUP, reports.VERSION, self.namespace, reports.PLURAL, name, patch)
