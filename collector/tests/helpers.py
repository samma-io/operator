"""Shared fakes for the collector tests.

Run the suite with

    python3 -m unittest discover -s collector/tests -t collector

No cluster and no network: samma.io is a FakeDashboard (or a local HTTP
server in test_dashboard), the Ingress listing a plain list.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(COLLECTOR_DIR)
CODE_DIR = os.path.join(COLLECTOR_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from samma_collector.dashboard import NotFound  # noqa: E402


def ingress(name, hosts, namespace="samma-io", enable="true"):
    annotations = {} if enable is None else {"samma-io.alpha.kubernetes.io/enable": enable}
    return {
        "metadata": {"name": name, "namespace": namespace, "annotations": annotations},
        "spec": {"rules": [{"host": h} if h else {} for h in hosts]},
    }


def run(scanner, run_id="r1", finished="2026-11-10T12:00:00.000Z", outcome="succeeded", **severity):
    body = {"targetId": "t", "scanner": scanner, "findingCount": sum(severity.values()), "severity": severity}
    if run_id:
        body["runId"] = run_id
        body["outcome"] = outcome
        body["finishedAt"] = finished
    body["lastSeenAt"] = finished
    return body


def finding(scanner, run_id="r1", severity="HIGH", check="TLS-OLD-PROTOCOL", **extra):
    body = {
        "time": "2026-11-10T12:00:00.000Z",
        "targetId": "t",
        "scanner": scanner,
        "runId": run_id,
        "checkId": check,
        "severity": severity,
        "title": "Old protocol",
        "host": "app.example.com",
        "port": "443",
        "evidence": "password=hunter2",
        "remediation": "Turn it off",
    }
    body.update(extra)
    return body


class FakeDashboard(object):
    def __init__(self, targets=None, results=None):
        self.target_list = targets or []
        self.result_map = results or {}
        self.calls = []
        self.fail = None

    def targets(self):
        self.calls.append("targets")
        if self.fail:
            raise self.fail
        return list(self.target_list)

    def results(self, target_id):
        self.calls.append(target_id)
        if target_id not in self.result_map:
            raise NotFound("gone")
        return self.result_map[target_id]
