"""Unit tests for what the ScanReport change added to jobspec: the scanner
role label, per-scanner NATS subjects, NATS credentials from a Secret and
the extra environment of the detect scanners."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(os.path.dirname(HERE), "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import jobspec  # noqa: E402

ENV = {"SAMMA_IO_ID": "12345", "NATS_URL": "nats://nats:4222", "NATS_ENABLED": "True", "NATS_SUBJECT": "samma-io.scan"}
OWNER = jobspec.owner_reference("samma.io/v1", "Scanner", "my-scanner", "0000-uid")


def run(scanner, template=None):
    runs, unknown = jobspec.resolve_runs([scanner if template is None else "{0}/{1}".format(scanner, template)])
    assert not unknown and len(runs) == 1
    return runs[0]


def build(scanner, template=None, **settings):
    spec, variant = run(scanner, template)
    return jobspec.build_job(spec, variant, "www.example.com", ENV, jobspec.Settings(**settings), owner=OWNER)


def env_list(job):
    return job["spec"]["template"]["spec"]["containers"][0]["env"]


def env_dict(job):
    return dict((item["name"], item.get("value")) for item in env_list(job))


class RoleLabelTests(unittest.TestCase):
    def test_every_object_carries_the_scanner_role(self):
        spec, variant = run("nmap", "port")
        job = jobspec.build_job(spec, variant, "www.example.com", ENV, jobspec.Settings(), owner=OWNER)
        cronjob = jobspec.build_cronjob(spec, variant, "www.example.com", ENV, jobspec.Settings(), "none", owner=OWNER)
        for labels in (job["metadata"]["labels"], job["spec"]["template"]["metadata"]["labels"],
                       cronjob["metadata"]["labels"], cronjob["spec"]["jobTemplate"]["spec"]["template"]["metadata"]["labels"]):
            self.assertEqual(labels[jobspec.LABEL_ROLE], jobspec.ROLE_SCANNER)
            self.assertEqual(labels[jobspec.LABEL_MANAGED_BY], jobspec.MANAGED_BY)

    def test_network_policy_selector_values(self):
        self.assertEqual(jobspec.LABEL_ROLE, "samma.io/role")
        self.assertEqual(jobspec.ROLE_SCANNER, "scanner")


class SubjectTests(unittest.TestCase):
    def test_scanner_subject(self):
        self.assertEqual(jobspec.scanner_subject("samma-io.scan", "tls-scanner"), "samma-io.scan.tls-scanner")
        self.assertEqual(jobspec.scanner_subject("scans.", "nmap"), "scans.nmap")
        self.assertEqual(jobspec.scanner_subject("", "nmap"), "samma-io.scan.nmap")
        self.assertEqual(jobspec.scanner_subject(None, "nmap"), "samma-io.scan.nmap")

    def test_every_scanner_pod_publishes_on_its_own_subject(self):
        for name in ("dns-scanner", "nmap", "nikto", "tsunami"):
            template = "http" if name == "nmap" else None
            job = build(name, template)
            with self.subTest(scanner=name):
                self.assertEqual(env_dict(job)["NATS_SUBJECT"], "samma-io.scan." + name)

    def test_cronjob_pods_too(self):
        spec, variant = run("tls-scanner")
        cronjob = jobspec.build_cronjob(spec, variant, "www.example.com", ENV, jobspec.Settings(), "none", owner=OWNER)
        env = dict((e["name"], e.get("value")) for e in cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["env"])
        self.assertEqual(env["NATS_SUBJECT"], "samma-io.scan.tls-scanner")


class CredentialTests(unittest.TestCase):
    def test_no_secret_means_no_credentials(self):
        job = build("tls-scanner")
        names = [e["name"] for e in env_list(job)]
        self.assertNotIn(jobspec.ENV_NATS_USER, names)
        self.assertNotIn(jobspec.ENV_NATS_PASSWORD, names)
        self.assertEqual(env_dict(job)["NATS_URL"], "nats://nats:4222")

    def test_secret_adds_user_password_and_rewrites_the_url(self):
        job = build("tls-scanner", nats_secret="samma-nats-auth", nats_scanner_user="scanner")
        items = env_list(job)
        names = [e["name"] for e in items]
        self.assertEqual(names[:4], ["TARGET", "SAMMA_IO_SCANNER", "NATS_USER", "NATS_PASSWORD"])
        self.assertLess(names.index("NATS_PASSWORD"), names.index("NATS_URL"), "the kubelet expands only variables defined earlier")
        by_name = dict((e["name"], e) for e in items)
        self.assertEqual(by_name["NATS_USER"]["value"], "scanner")
        self.assertEqual(by_name["NATS_PASSWORD"], {"name": "NATS_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "samma-nats-auth", "key": "scanner-password"}}})
        self.assertEqual(by_name["NATS_URL"]["value"], "nats://$(NATS_USER):$(NATS_PASSWORD)@nats:4222")
        self.assertEqual(jobspec.NATS_SECRET_SCANNER_KEY, "scanner-password")

    def test_url_rewrite(self):
        self.assertEqual(jobspec.nats_url_with_credentials("nats://nats:4222"), "nats://$(NATS_USER):$(NATS_PASSWORD)@nats:4222")
        self.assertEqual(jobspec.nats_url_with_credentials("tls://nats.samma-io.svc:4222/"), "tls://$(NATS_USER):$(NATS_PASSWORD)@nats.samma-io.svc:4222/")
        self.assertEqual(jobspec.nats_url_with_credentials("nats://u:p@nats:4222"), "nats://u:p@nats:4222")
        self.assertEqual(jobspec.nats_url_with_credentials("nats:4222"), "nats:4222")
        self.assertEqual(jobspec.nats_url_with_credentials(""), "")

    def test_settings_from_env(self):
        s = jobspec.Settings.from_env({"SAMMA_NATS_SECRET": " samma-nats-auth ", "SAMMA_NATS_SCANNER_USER": "pub"})
        self.assertEqual(s.nats_secret, "samma-nats-auth")
        self.assertEqual(s.nats_scanner_user, "pub")
        s = jobspec.Settings.from_env({})
        self.assertEqual(s.nats_secret, "")
        self.assertEqual(s.nats_scanner_user, "scanner")
        self.assertEqual(jobspec.Settings(nats_scanner_user="").nats_scanner_user, "scanner")


class DetectEnvTests(unittest.TestCase):
    def test_http_headers_scanner_gets_https(self):
        self.assertEqual(env_dict(build("http-headers-scanner"))["HTTPS"], "True")
        for name in ("tls-scanner", "dns-scanner", "nmap"):
            with self.subTest(scanner=name):
                self.assertNotIn("HTTPS", env_dict(build(name, "port" if name == "nmap" else None)))

    def test_reports_flag(self):
        for name in jobspec.DETECT_SCANNERS:
            self.assertTrue(jobspec.SCANNERS[name].reports, name)
        for name in ("nmap", "nikto", "tsunami", "base"):
            self.assertFalse(jobspec.SCANNERS[name].reports, name)


if __name__ == "__main__":
    unittest.main()
