"""The opted-in Ingress hosts of this cluster.

The collector exports results only for hosts that an opted-in Ingress of its
own cluster serves, with the operator's rules: the
samma-io.alpha.kubernetes.io/enable annotation present and not "false", "0",
"no" or "off"; the Ingress in the operator's namespace or one listed in
SAMMA_INGRESS_NAMESPACES ('*' is all); wildcard and host-less rules skipped.

:func:`opted_in_hosts` is plain Python. :class:`InClusterIngresses` lists
Ingresses through the API server with the pod's ServiceAccount token, using
urllib only (the collector has no kubernetes client).
"""

import json
import ssl
import urllib.parse
import urllib.request

ENABLE_ANNOTATION = "samma-io.alpha.kubernetes.io/enable"
FALSE_WORDS = ("0", "false", "no", "off")

SERVICE_ACCOUNT_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class KubeError(Exception):
    pass


def ingress_enabled(annotations):
    if ENABLE_ANNOTATION not in annotations:
        return False
    return str(annotations.get(ENABLE_ANNOTATION) or "").strip().lower() not in FALSE_WORDS


def namespace_allowed(namespace, own_namespace, allowed):
    if namespace == own_namespace:
        return True
    return "*" in allowed or namespace in allowed


def opted_in_hosts(ingresses, own_namespace, allowed_namespaces):
    """The lower-cased hosts of the opted-in Ingresses in ``ingresses``
    (Ingress objects as dicts)."""
    hosts = set()
    for ingress in ingresses:
        meta = ingress.get("metadata") or {}
        if not namespace_allowed(meta.get("namespace"), own_namespace, allowed_namespaces):
            continue
        if not ingress_enabled(meta.get("annotations") or {}):
            continue
        for rule in (ingress.get("spec") or {}).get("rules") or []:
            host = (rule.get("host") or "").strip().lower().rstrip(".")
            if host and "*" not in host:
                hosts.add(host)
    return hosts


class InClusterIngresses(object):
    """Lists every Ingress in the cluster (the ClusterRole grants list)."""

    PAGE = 500

    def __init__(self, host, port, token_path=None, ca_path=None, timeout=15):
        self.base = "https://{0}:{1}".format("[{0}]".format(host) if ":" in host else host, port)
        self.token_path = token_path or SERVICE_ACCOUNT_DIR + "/token"
        self.context = ssl.create_default_context(cafile=ca_path or SERVICE_ACCOUNT_DIR + "/ca.crt")
        self.timeout = timeout

    @classmethod
    def from_env(cls, environ, timeout=15):
        host = environ.get("KUBERNETES_SERVICE_HOST")
        port = environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise KubeError("not running in a cluster (KUBERNETES_SERVICE_HOST unset); set COLLECTOR_HOSTS for a local run")
        return cls(host, port, timeout=timeout)

    def list(self):
        items = []
        token = ""
        while True:
            query = {"limit": str(self.PAGE)}
            if token:
                query["continue"] = token
            body = self._get("/apis/networking.k8s.io/v1/ingresses?" + urllib.parse.urlencode(query))
            items.extend(body.get("items") or [])
            token = (body.get("metadata") or {}).get("continue") or ""
            if not token:
                return items

    def _get(self, path):
        # The token is re-read on every call: the kubelet rotates it.
        with open(self.token_path) as handle:
            bearer = handle.read().strip()
        request = urllib.request.Request(self.base + path, headers={"Authorization": "Bearer " + bearer, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise KubeError("listing Ingresses failed: HTTP {0}".format(exc.code))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise KubeError("listing Ingresses failed: {0}".format(exc))
