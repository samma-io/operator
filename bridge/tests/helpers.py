"""Shared fixtures for the bridge tests: message builders and fakes.

Run the suite with

    python3 -m unittest discover -s bridge/tests -t bridge

Nothing here imports nats-py, asyncpg or the kubernetes client.
"""

import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(BRIDGE_DIR)
CODE_DIR = os.path.join(BRIDGE_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from samma_bridge import reports  # noqa: E402

TARGET = "api.example.com"
RUN_ID = "tls-scanner-d0c43d38-x7k2p"

FINDING = {
    "schema": "samma.io/scan/v2",
    "kind": "finding",
    "scanner": "tls-scanner",
    "scannerVersion": "1.4.0",
    "target": TARGET,
    "runId": RUN_ID,
    "emittedAt": "2026-10-15T02:00:10Z",
    "samma-io": {"scanner": "tls-scanner", "id": "1234", "tags": ["scanner"], "json": "{}"},
    "checkId": "SAMMA-TLS-PROTOCOL-DEPRECATED",
    "severity": "HIGH",
    "title": "Deprecated TLS protocol version negotiated",
    "endpoint": {"host": TARGET, "port": 443, "scheme": "https"},
    "evidence": "negotiated TLSv1",
    "remediation": "Disable TLS 1.0 and 1.1.",
    "references": ["https://datatracker.ietf.org/doc/html/rfc8996"],
    "cveIds": [],
    "compliance": ["pci-dss:4.2.1"],
    "raw": {"host": TARGET, "port": 443, "status": "open", "type": "tls", "body": "x" * 5000},
    "host": TARGET,
    "port": 443,
    "status": "open",
    "type": "tls",
}

RUN = {
    "schema": "samma.io/scan/v2",
    "kind": "run",
    "scanner": "tls-scanner",
    "scannerVersion": "1.4.0",
    "target": TARGET,
    "runId": RUN_ID,
    "emittedAt": "2026-10-15T02:00:21Z",
    "samma-io": {"scanner": "tls-scanner", "id": "1234", "tags": ["scanner"], "json": "{}"},
    "outcome": "succeeded",
    "message": "",
    "startedAt": "2026-10-15T02:00:04Z",
    "finishedAt": "2026-10-15T02:00:21Z",
    "findingCount": 1,
    "scan": "done",
}

LEGACY = {
    "host": TARGET,
    "port": 22,
    "status": "open",
    "type": "ssh-banner",
    "banner": "SSH-2.0-OpenSSH_9.6",
    "samma-io": {"scanner": "nmap", "id": "1234", "tags": ["scanner"], "json": "{}"},
}


def finding(**overrides):
    data = copy.deepcopy(FINDING)
    data.update(overrides)
    return data


def run(**overrides):
    data = copy.deepcopy(RUN)
    data.update(overrides)
    return data


def scanner_object(name="tls-scanner-api", target=TARGET, scanners=("tls-scanner",), uid="uid-1", labels=None):
    return {
        "apiVersion": "samma.io/v1",
        "kind": "Scanner",
        "metadata": {"name": name, "namespace": "samma-io", "uid": uid, "labels": dict(labels or {})},
        "spec": {"target": target, "scanners": list(scanners)},
    }


class FakeStore(object):
    """An in-memory stand-in for the kubernetes client adapter with the
    four methods reports.upsert needs, plus the Scanner lister."""

    def __init__(self, scanners=None, conflicts=0):
        self.objects = {}
        self.scanners = list(scanners or [])
        self.conflicts_left = conflicts
        self.calls = []
        self.version = 0

    def list_scanners(self):
        self.calls.append("list_scanners")
        return list(self.scanners)

    def get(self, name):
        self.calls.append(("get", name))
        obj = self.objects.get(name)
        return copy.deepcopy(obj) if obj is not None else None

    def create(self, body):
        self.calls.append(("create", body["metadata"]["name"]))
        name = body["metadata"]["name"]
        if name in self.objects:
            raise reports.Conflict("exists")
        stored = copy.deepcopy(body)
        stored["metadata"]["resourceVersion"] = str(self._bump())
        stored["metadata"]["uid"] = "report-uid-" + name
        self.objects[name] = stored
        return copy.deepcopy(stored)

    def replace_status(self, name, body):
        self.calls.append(("replace_status", name))
        current = self.objects[name]
        if self.conflicts_left > 0:
            self.conflicts_left -= 1
            raise reports.Conflict("resourceVersion mismatch")
        if body["metadata"].get("resourceVersion") != current["metadata"]["resourceVersion"]:
            raise reports.Conflict("resourceVersion mismatch")
        current["status"] = copy.deepcopy(body["status"])
        current["metadata"]["resourceVersion"] = str(self._bump())
        return copy.deepcopy(current)

    def patch_metadata(self, name, patch):
        self.calls.append(("patch_metadata", name))
        current = self.objects[name]
        for field, value in patch["metadata"].items():
            if isinstance(value, dict):
                current["metadata"].setdefault(field, {}).update(value)
            else:
                current["metadata"][field] = copy.deepcopy(value)
        current["metadata"]["resourceVersion"] = str(self._bump())

    def _bump(self):
        self.version += 1
        return self.version


class Clock(object):
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
        return self.now
