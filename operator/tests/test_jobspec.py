"""Unit tests for operator/code/jobspec.py.

Run from anywhere:

    python3 -m unittest discover -s operator/tests -t operator

No cluster, no network and no kubernetes client: the builders return plain
dictionaries and the tests inspect those.
"""

import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
OPERATOR_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(OPERATOR_DIR)
CODE_DIR = os.path.join(OPERATOR_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import jobspec  # noqa: E402

DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
LABEL_VALUE = re.compile(r"^(([A-Za-z0-9][-A-Za-z0-9_.]{0,61})?[A-Za-z0-9])?$")

OWNER = jobspec.owner_reference("samma.io/v1", "Scanner", "my-scanner", "0000-uid")
ENV = {"SAMMA_IO_ID": "12345", "NATS_URL": "nats://nats:4222"}


def settings(**overrides):
    return jobspec.Settings(**overrides)


def run(scanner, template=None):
    runs, unknown = jobspec.resolve_runs([scanner if template is None else "{0}/{1}".format(scanner, template)])
    assert not unknown, unknown
    assert len(runs) == 1, runs
    return runs[0]


def container_of(job):
    return job["spec"]["template"]["spec"]["containers"][0]


def env_dict(container):
    return {item["name"]: item["value"] for item in container["env"]}


class SettingsTests(unittest.TestCase):
    def test_defaults(self):
        s = jobspec.Settings.from_env({})
        self.assertEqual(s.namespace, "samma-io")
        self.assertEqual(s.scanner_service_account, "samma-scanner")
        self.assertEqual(s.max_concurrent_scans, 2)
        self.assertEqual(s.scan_deadline_seconds, 900)
        self.assertEqual(s.ttl_seconds_after_finished, 3600)
        self.assertFalse(s.nmap_raw_sockets)
        self.assertEqual(s.run_as_user, 1000)
        self.assertEqual(s.image_prefix, "")
        self.assertEqual(s.image_overrides, {})
        self.assertEqual(s.resources, jobspec.DEFAULT_RESOURCES)
        self.assertEqual(s.default_schedule, "0 0 * * 0")
        self.assertFalse(s.legacy_base_scanner)

    def test_values_from_environment(self):
        s = jobspec.Settings.from_env({
            "SAMMA_NAMESPACE": "scans",
            "SAMMA_MAX_CONCURRENT_SCANS": "5",
            "SAMMA_SCAN_DEADLINE_SECONDS": "60",
            "SAMMA_JOB_TTL_SECONDS": "0",
            "SAMMA_NMAP_RAW_SOCKETS": "true",
            "SAMMA_SCANNER_RUN_AS_USER": "10001",
            "SAMMA_SCANNER_IMAGE_PREFIX": "registry.example/samma/",
            "SAMMA_SCANNER_IMAGE_TAG": "v1.2.3",
            "SAMMA_SCANNER_IMAGE_PULL_POLICY": "IfNotPresent",
            "SAMMA_SCANNER_IMAGE_NMAP": "registry.example/nmap:v9",
            "SAMMA_SCANNER_IMAGE_HTTP_HEADERS_SCANNER": "registry.example/hh:v9",
            "SAMMA_SCANNER_CPU_LIMIT": "2",
            "SAMMA_IO_WEEKLY_SCHEDULE": "0 3 * * 1",
            "SAMMA_LEGACY_BASE_SCANNER": "true",
        })
        self.assertEqual(s.namespace, "scans")
        self.assertEqual(s.max_concurrent_scans, 5)
        self.assertEqual(s.scan_deadline_seconds, 60)
        self.assertEqual(s.ttl_seconds_after_finished, 0)
        self.assertTrue(s.nmap_raw_sockets)
        self.assertEqual(s.run_as_user, 10001)
        self.assertEqual(s.image_prefix, "registry.example/samma")
        self.assertEqual(s.image_tag, "v1.2.3")
        self.assertEqual(s.image_pull_policy, "IfNotPresent")
        self.assertEqual(s.image_overrides, {"nmap": "registry.example/nmap:v9", "http-headers-scanner": "registry.example/hh:v9"})
        self.assertEqual(s.resources["limits"]["cpu"], "2")
        self.assertEqual(s.resources["requests"]["cpu"], "100m")
        self.assertEqual(s.default_schedule, "0 3 * * 1")
        self.assertTrue(s.legacy_base_scanner)

    def test_bad_numbers_and_words_fall_back(self):
        s = jobspec.Settings.from_env({
            "SAMMA_MAX_CONCURRENT_SCANS": "many",
            "SAMMA_SCAN_DEADLINE_SECONDS": "-5",
            "SAMMA_NMAP_RAW_SOCKETS": "maybe",
            "SAMMA_SCANNER_RUN_AS_USER": "0",
        })
        self.assertEqual(s.max_concurrent_scans, 2)
        self.assertEqual(s.scan_deadline_seconds, 1)
        self.assertFalse(s.nmap_raw_sockets)
        self.assertEqual(s.run_as_user, 1)


class ResolveRunsTests(unittest.TestCase):
    def test_nmap_has_three_variants(self):
        runs, unknown = jobspec.resolve_runs(["nmap"])
        self.assertEqual(unknown, [])
        self.assertEqual([v.name for _, v in runs], ["port", "http", "tls"])
        self.assertEqual([v.container for _, v in runs], ["nmap-portscanner", "nmap-httprecon", "nmap-tls"])

    def test_slash_selects_one_variant(self):
        runs, _ = jobspec.resolve_runs(["nmap/http"])
        self.assertEqual([(s.name, v.name) for s, v in runs], [("nmap", "http")])

    def test_templates_filter_every_scanner_by_variant_name(self):
        # The old operator filtered template files by stem for every scanner,
        # so nikto (stem "nikto") was skipped when templates named only nmap
        # variants. That behaviour is kept.
        runs, _ = jobspec.resolve_runs(["nmap", "nikto"], templates=["port", "nikto"])
        self.assertEqual([(s.name, v.name) for s, v in runs], [("nmap", "port"), ("nikto", "nikto")])
        runs, _ = jobspec.resolve_runs(["nmap", "nikto"], templates=["http"])
        self.assertEqual([(s.name, v.name) for s, v in runs], [("nmap", "http")])

    def test_unknown_scanners_are_reported_not_raised(self):
        runs, unknown = jobspec.resolve_runs(["nikto", "zap", "nope/x"])
        self.assertEqual([(s.name, v.name) for s, v in runs], [("nikto", "nikto")])
        self.assertEqual(unknown, ["zap", "nope/x"])

    def test_duplicates_collapse(self):
        runs, _ = jobspec.resolve_runs(["nmap/port", "nmap", "nikto", "nikto"])
        self.assertEqual(len(runs), 4)

    def test_every_table_entry_is_well_formed(self):
        for name, spec in jobspec.SCANNERS.items():
            with self.subTest(scanner=name):
                self.assertRegex(name, DNS_LABEL)
                self.assertIn(":", spec.image.rsplit("/", 1)[-1], "image needs a tag")
                for variant in spec.variants:
                    self.assertRegex(variant.name, DNS_LABEL)
                    self.assertRegex(variant.container, DNS_LABEL)


class NamingTests(unittest.TestCase):
    def test_names_are_short_valid_labels(self):
        long_host = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61
        for target in ("www.example.com", "2001:db8::1", "10.0.0.1", long_host):
            for scanner, variant in (("nmap", "port"), ("http-redirect-scanner", "http-redirect-scanner"), ("tsunami", "tsunami")):
                name = jobspec.object_name(scanner, variant, target)
                with self.subTest(target=target, name=name):
                    self.assertRegex(name, DNS_LABEL)
                    self.assertLessEqual(len(name), 63)

    def test_name_layout(self):
        digest = jobspec.target_hash("www.example.com")
        self.assertRegex(digest, r"^[0-9a-f]{8}$")
        self.assertEqual(jobspec.object_name("nmap", "port", "www.example.com"), "nmap-port-" + digest)
        self.assertEqual(jobspec.object_name("nikto", "nikto", "www.example.com"), "nikto-" + digest)
        self.assertEqual(jobspec.object_name("nikto", None, "www.example.com"), "nikto-" + digest)

    def test_tenants_get_their_own_names(self):
        """operator#14: two tenants on one host must not share a Job."""
        plain = jobspec.object_name("nmap", "port", "www.example.com")
        self.assertEqual(jobspec.object_name("nmap", "port", "www.example.com", None), plain)
        self.assertEqual(jobspec.object_name("nmap", "port", "www.example.com", ""), plain)
        a = jobspec.object_name("nmap", "port", "www.example.com", "tenant-a")
        b = jobspec.object_name("nmap", "port", "www.example.com", "tenant-b")
        self.assertNotEqual(a, plain)
        self.assertNotEqual(a, b)
        self.assertRegex(a, DNS_LABEL)
        self.assertEqual(a, jobspec.object_name("nmap", "port", "www.example.com", "tenant-a"))

    def test_hash_is_deterministic_and_distinguishes_targets(self):
        self.assertEqual(jobspec.target_hash("a.example"), jobspec.target_hash("a.example"))
        self.assertNotEqual(jobspec.target_hash("a.example"), jobspec.target_hash("b.example"))

    def test_legacy_names(self):
        self.assertEqual(jobspec.legacy_names("nmap", "http", "www.example.com"), ["nmap-www-example-com", "nmap-www-example-com-http"])
        self.assertEqual(jobspec.legacy_names("nikto", "nikto", "www.example.com"), ["nikto-www-example-com", "nikto-www-example-com-nikto"])
        self.assertEqual(jobspec.legacy_names("nikto", None, "www.example.com"), ["nikto-www-example-com", "nikto-www-example-com-nikto"])

    def test_legacy_ingress_scanner_name(self):
        self.assertEqual(jobspec.legacy_ingress_scanner_name("nmap", "http", "www.example.com"), "nmap-www-example-com-http")
        self.assertEqual(jobspec.legacy_ingress_scanner_name("nikto", None, "www.nikto"), "nikto-www-nikto")

    def test_label_value(self):
        self.assertEqual(jobspec.label_value("my-ingress"), "my-ingress")
        long_name = "ingress-" + "x" * 80
        short = jobspec.label_value(long_name)
        self.assertRegex(short, LABEL_VALUE)
        self.assertLessEqual(len(short), 63)
        self.assertNotEqual(short, jobspec.label_value(long_name + "y"))
        self.assertRegex(jobspec.label_value("ends-with-dash-" + "x" * 60), LABEL_VALUE)


class CronScheduleTests(unittest.TestCase):
    def test_default_schedule_gets_a_hashed_minute(self):
        for schedule in ("0 0 * * 0", "none", "", None):
            with self.subTest(schedule=schedule):
                result = jobspec.cron_schedule(schedule, "www.example.com")
                fields = result.split()
                self.assertEqual(len(fields), 5)
                self.assertEqual(fields[1:], ["0", "*", "*", "0"])
                self.assertTrue(0 <= int(fields[0]) <= 59)

    def test_offset_depends_on_target_and_is_stable(self):
        a = jobspec.cron_schedule("0 0 * * 0", "a.example.com")
        self.assertEqual(a, jobspec.cron_schedule("0 0 * * 0", "a.example.com"))
        minutes = {jobspec.cron_schedule("0 0 * * 0", "host{0}.example.com".format(i)).split()[0] for i in range(40)}
        self.assertGreater(len(minutes), 10)

    def test_user_schedule_is_kept(self):
        self.assertEqual(jobspec.cron_schedule("0 3 * * 1", "a.example.com"), "0 3 * * 1")
        self.assertEqual(jobspec.cron_schedule("@daily", "a.example.com"), "@daily")

    def test_custom_default_from_settings(self):
        result = jobspec.cron_schedule("none", "a.example.com", default_schedule="0 4 * * 6")
        self.assertEqual(result.split()[1:], ["4", "*", "*", "6"])
        # A default that is not five fields cannot be offset and is returned as is.
        self.assertEqual(jobspec.cron_schedule("none", "a.example.com", default_schedule="@weekly"), "@weekly")


class ScannerEnvTests(unittest.TestCase):
    DEFAULTS = {"SAMMA_IO_ID": "default-id", "SAMMA_IO_TAGS": "['samma']", "NATS_URL": "nats://nats:4222", "NATS_ENABLED": "True", "NATS_SUBJECT": "samma-io.scan"}

    def test_absent_field_sets_nothing_empty_field_uses_default(self):
        env = jobspec.scanner_env({"samma_io_id": "", "samma_io_tags": ["a", "b"]}, self.DEFAULTS)
        self.assertEqual(env["SAMMA_IO_ID"], "default-id")
        self.assertEqual(env["SAMMA_IO_TAGS"], "['a', 'b']")
        self.assertNotIn("SAMMA_IO_JSON", env)
        self.assertNotIn("WRITE_TO_FILE", env)

    def test_nats_is_always_present_and_values_are_strings(self):
        env = jobspec.scanner_env({}, self.DEFAULTS)
        self.assertEqual(env["NATS_URL"], "nats://nats:4222")
        self.assertEqual(env["NATS_ENABLED"], "True")
        self.assertTrue(all(isinstance(v, str) for v in env.values()))

    def test_nats_comes_from_the_operator_never_from_the_scanner(self):
        # operator#2: the NATS URL and subject are chart values. A Scanner
        # spec naming them (in any spelling) changes nothing.
        spec = {"NATS_URL": "nats://evil.example:4222", "nats_url": "nats://evil.example:4222",
                "NATS_SUBJECT": "other", "nats_subject": "other", "natsUrl": "nats://evil.example:4222"}
        env = jobspec.scanner_env(spec, dict(self.DEFAULTS, NATS_URL="nats://nats.external.example:4222"))
        self.assertEqual(env["NATS_URL"], "nats://nats.external.example:4222")
        self.assertEqual(env["NATS_SUBJECT"], "samma-io.scan")
        self.assertEqual(set(env), {"NATS_URL", "NATS_ENABLED", "NATS_SUBJECT"})

    def test_elasticsearch_default(self):
        self.assertEqual(jobspec.scanner_env({"elasticsearch": ""}, self.DEFAULTS)["ELASTICSEARCH"], "elasticsearch")
        self.assertEqual(jobspec.scanner_env({"elasticsearch": "es.example"}, self.DEFAULTS)["ELASTICSEARCH"], "es.example")


class ImageTests(unittest.TestCase):
    def test_default_override_and_prefix(self):
        nmap = jobspec.SCANNERS["nmap"]
        dns = jobspec.SCANNERS["dns-scanner"]
        self.assertEqual(jobspec.image_for(nmap, settings()), "sammascanner/nmap:v0.2")
        self.assertEqual(jobspec.image_for(nmap, settings(image_overrides={"nmap": "r.example/nmap:v9"})), "r.example/nmap:v9")
        self.assertEqual(jobspec.image_for(nmap, settings(image_prefix="ghcr.io/samma-io/")), "ghcr.io/samma-io/nmap:v0.2")
        self.assertEqual(jobspec.image_for(dns, settings(image_prefix="ghcr.io/mirror", image_tag="2026.10")), "ghcr.io/mirror/detect-dns-scanner:2026.10")
        self.assertEqual(jobspec.image_for(jobspec.SCANNERS["base"], settings(image_prefix="r.example")), "r.example/base:latest")

    def test_override_wins_over_prefix(self):
        nmap = jobspec.SCANNERS["nmap"]
        s = settings(image_prefix="ghcr.io/x", image_overrides={"nmap": "r.example/nmap:v9"})
        self.assertEqual(jobspec.image_for(nmap, s), "r.example/nmap:v9")


class TenantJobTests(unittest.TestCase):
    def test_job_and_cronjob_are_keyed_by_samma_io_id(self):
        spec, variant = run("dns-scanner")
        for build in (
            lambda sid: jobspec.build_job(spec, variant, "www.example.com", ENV, settings(), owner=OWNER, samma_io_id=sid),
            lambda sid: jobspec.build_cronjob(spec, variant, "www.example.com", ENV, settings(), "none", owner=OWNER, samma_io_id=sid),
        ):
            a, b, none = build("tenant-a"), build("tenant-b"), build(None)
            self.assertNotEqual(a["metadata"]["name"], b["metadata"]["name"])
            self.assertEqual(a["metadata"]["name"], jobspec.object_name("dns-scanner", variant.name, "www.example.com", "tenant-a"))
            self.assertEqual(a["metadata"]["annotations"][jobspec.ANNOTATION_SAMMA_IO_ID], "tenant-a")
            self.assertEqual(none["metadata"]["name"], jobspec.object_name("dns-scanner", variant.name, "www.example.com"))
            self.assertNotIn(jobspec.ANNOTATION_SAMMA_IO_ID, none["metadata"]["annotations"])


class BuildJobTests(unittest.TestCase):
    def setUp(self):
        self.settings = settings()
        spec, variant = run("dns-scanner")
        self.job = jobspec.build_job(spec, variant, "www.example.com", ENV, self.settings, owner=OWNER, scanner_name="my-scanner")

    def test_shape(self):
        job = self.job
        self.assertEqual(job["apiVersion"], "batch/v1")
        self.assertEqual(job["kind"], "Job")
        self.assertEqual(job["metadata"]["name"], "dns-scanner-" + jobspec.target_hash("www.example.com"))
        self.assertEqual(job["metadata"]["namespace"], "samma-io")
        self.assertEqual(job["metadata"]["ownerReferences"], [OWNER])
        self.assertEqual(job["metadata"]["annotations"][jobspec.ANNOTATION_TARGET], "www.example.com")
        self.assertEqual(job["metadata"]["annotations"][jobspec.ANNOTATION_SCANNER_NAME], "my-scanner")
        self.assertEqual(job["spec"]["backoffLimit"], 1)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 900)
        self.assertEqual(job["spec"]["ttlSecondsAfterFinished"], 3600)
        json.dumps(job)  # serialisable

    def test_labels(self):
        labels = self.job["metadata"]["labels"]
        self.assertEqual(labels[jobspec.LABEL_MANAGED_BY], "samma-operator")
        self.assertEqual(labels[jobspec.LABEL_SCANNER], "dns-scanner")
        self.assertEqual(labels[jobspec.LABEL_TEMPLATE], "dns-scanner")
        self.assertEqual(labels[jobspec.LABEL_TARGET_HASH], jobspec.target_hash("www.example.com"))
        self.assertEqual(labels[jobspec.LABEL_SCANNER_UID], "0000-uid")
        self.assertEqual(self.job["spec"]["template"]["metadata"]["labels"], labels)
        for value in labels.values():
            self.assertRegex(value, LABEL_VALUE)

    def test_pod_hygiene(self):
        pod = self.job["spec"]["template"]["spec"]
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertEqual(pod["serviceAccountName"], "samma-scanner")
        self.assertIs(pod["automountServiceAccountToken"], False)
        self.assertEqual(pod["securityContext"], {"runAsNonRoot": True, "runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}})
        self.assertEqual([v["name"] for v in pod["volumes"]], ["out", "tmp"])
        self.assertTrue(all("emptyDir" in v for v in pod["volumes"]))
        container = pod["containers"][0]
        self.assertEqual(container["securityContext"], {
            "allowPrivilegeEscalation": False,
            "privileged": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
        })
        self.assertEqual([m["mountPath"] for m in container["volumeMounts"]], ["/out", "/tmp"])
        self.assertEqual(container["resources"], jobspec.DEFAULT_RESOURCES)
        self.assertNotIn("imagePullPolicy", container)

    def test_container_env(self):
        container = container_of(self.job)
        self.assertEqual(container["name"], "dns-scanner")
        self.assertEqual(container["image"], "ghcr.io/samma-io/detect-dns-scanner:latest")
        self.assertEqual(container["env"][:2], [{"name": "TARGET", "value": "www.example.com"}, {"name": "SAMMA_IO_SCANNER", "value": "dns-scanner"}])
        self.assertEqual(env_dict(container)["SAMMA_IO_ID"], "12345")
        self.assertNotIn("command", container)
        self.assertNotIn("args", container)

    def test_http_headers_scanner_gets_https_and_its_port(self):
        # detect up to 2.0.1 let config.yaml's port 80 beat the HTTPS default
        # when only HTTPS was set, so the port is passed along with it.
        spec, variant = run("http-headers-scanner")
        job = jobspec.build_job(spec, variant, "www.example.com", ENV, self.settings, owner=OWNER)
        env = env_dict(container_of(job))
        self.assertEqual((env["HTTPS"], env["PORT"]), ("True", "443"))
        self.assertEqual(jobspec.DETECT_ENV, {"http-headers-scanner": {"HTTPS": "True", "PORT": "443"}},
                         "every other detect scanner runs on its image defaults")

    def test_settings_reach_the_job(self):
        s = settings(namespace="scans", scanner_service_account="runner", scan_deadline_seconds=60, ttl_seconds_after_finished=10, run_as_user=4242, image_pull_policy="IfNotPresent",
                     resources={"requests": {"cpu": "1m", "memory": "1Mi"}, "limits": {"cpu": "2", "memory": "2Gi"}})
        spec, variant = run("tls-scanner")
        job = jobspec.build_job(spec, variant, "www.example.com", ENV, s)
        self.assertEqual(job["metadata"]["namespace"], "scans")
        self.assertNotIn("ownerReferences", job["metadata"])
        pod = job["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "runner")
        self.assertEqual(pod["securityContext"]["runAsUser"], 4242)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 60)
        self.assertEqual(job["spec"]["ttlSecondsAfterFinished"], 10)
        self.assertEqual(pod["containers"][0]["resources"]["limits"]["memory"], "2Gi")
        self.assertEqual(pod["containers"][0]["imagePullPolicy"], "IfNotPresent")

    def test_ingress_labels_are_copied(self):
        spec, variant = run("nikto")
        extra = {jobspec.LABEL_INGRESS_NAMESPACE: "shop", jobspec.LABEL_INGRESS_NAME: "frontend-" + "x" * 70}
        job = jobspec.build_job(spec, variant, "shop.example.com", ENV, self.settings, owner=OWNER, extra_labels=extra)
        labels = job["metadata"]["labels"]
        self.assertEqual(labels[jobspec.LABEL_INGRESS_NAMESPACE], "shop")
        self.assertRegex(labels[jobspec.LABEL_INGRESS_NAME], LABEL_VALUE)
        self.assertLessEqual(len(labels[jobspec.LABEL_INGRESS_NAME]), 63)


class ClassicScannerTests(unittest.TestCase):
    def test_nmap_variants_have_their_commands_and_no_raw_sockets_by_default(self):
        runs, _ = jobspec.resolve_runs(["nmap"])
        for spec, variant in runs:
            job = jobspec.build_job(spec, variant, "www.example.com", ENV, settings(), owner=OWNER)
            container = container_of(job)
            with self.subTest(variant=variant.name):
                self.assertEqual(container["command"], ["python3", "/code/nmap_{0}.py".format({"port": "portscanner", "http": "httprecon", "tls": "tlscipher"}[variant.name])])
                self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
                self.assertEqual(env_dict(container)["NMAP_UNPRIVILEGED"], "1")
                self.assertNotIn("NMAP_PRIVILEGED", env_dict(container))
                self.assertEqual(env_dict(container)["SAMMA_IO_SCANNER"], "nmap")
                self.assertEqual(job["metadata"]["name"], "nmap-{0}-{1}".format(variant.name, jobspec.target_hash("www.example.com")))
                # sudo in the image: privilege escalation stays allowed for now.
                self.assertIs(container["securityContext"]["allowPrivilegeEscalation"], True)

    def test_nmap_raw_sockets_toggle(self):
        spec, variant = run("nmap", "port")
        job = jobspec.build_job(spec, variant, "www.example.com", ENV, settings(nmap_raw_sockets=True), owner=OWNER)
        container = container_of(job)
        self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"], "add": ["NET_RAW"]})
        self.assertEqual(env_dict(container)["NMAP_PRIVILEGED"], "1")
        self.assertNotIn("NMAP_UNPRIVILEGED", env_dict(container))
        # Only nmap gets the capability.
        spec, variant = run("port-scanner")
        other = container_of(jobspec.build_job(spec, variant, "www.example.com", ENV, settings(nmap_raw_sockets=True)))
        self.assertEqual(other["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertNotIn("NMAP_PRIVILEGED", env_dict(other))

    def test_tsunami_args_follow_the_target_kind(self):
        spec, variant = run("tsunami")
        expected_tail = ["--scan-results-local-output-format=JSON", "--scan-results-local-output-filename=/out/tsunami-output.json"]
        for target, flag in (("www.example.com", "--hostname-target=www.example.com"), ("203.0.113.9", "--ip-v4-target=203.0.113.9"), ("2001:db8::1", "--ip-v6-target=2001:db8::1")):
            with self.subTest(target=target):
                container = container_of(jobspec.build_job(spec, variant, target, ENV, settings()))
                self.assertEqual(container["args"], [flag] + expected_tail)
                self.assertIs(container["securityContext"]["allowPrivilegeEscalation"], False)

    def test_base_keeps_its_filebeat_sidecar(self):
        spec, variant = run("base")
        job = jobspec.build_job(spec, variant, "www.example.com", ENV, settings())
        pod = job["spec"]["template"]["spec"]
        self.assertEqual([c["name"] for c in pod["containers"]], ["base", "filebeat"])
        self.assertEqual(env_dict(pod["containers"][0])["PARSER"], "base")
        self.assertEqual([v["name"] for v in pod["volumes"]], ["out", "tmp", "filebeat", "liveness", "filebeat-data"])
        self.assertEqual(pod["volumes"][3]["configMap"], {"name": "live", "defaultMode": 0o777})
        self.assertIs(pod["containers"][1]["securityContext"]["readOnlyRootFilesystem"], True)
        json.dumps(job)

    def test_nikto_env_matches_the_old_template(self):
        spec, variant = run("nikto")
        container = container_of(jobspec.build_job(spec, variant, "www.example.com", {"SAMMA_IO_TAGS": "['a']", "NATS_URL": "x"}, settings()))
        self.assertEqual(container["name"], "nikto")
        self.assertEqual(container["image"], "sammascanner/nikto:v0.2")
        self.assertEqual([e["name"] for e in container["env"]], ["TARGET", "SAMMA_IO_SCANNER", "SAMMA_IO_TAGS", "NATS_URL"])


class BuildCronJobTests(unittest.TestCase):
    def setUp(self):
        self.spec, self.variant = run("tls-scanner")
        self.cron = jobspec.build_cronjob(self.spec, self.variant, "www.example.com", ENV, settings(), "none", owner=OWNER, scanner_name="my-scanner")

    def test_shape(self):
        cron = self.cron
        self.assertEqual(cron["apiVersion"], "batch/v1")
        self.assertEqual(cron["kind"], "CronJob")
        self.assertEqual(cron["metadata"]["name"], "tls-scanner-" + jobspec.target_hash("www.example.com"))
        self.assertEqual(cron["metadata"]["ownerReferences"], [OWNER])
        spec = cron["spec"]
        self.assertEqual(spec["concurrencyPolicy"], "Forbid")
        self.assertEqual(spec["successfulJobsHistoryLimit"], 1)
        self.assertEqual(spec["failedJobsHistoryLimit"], 1)
        self.assertEqual(spec["startingDeadlineSeconds"], 600)
        self.assertEqual(spec["schedule"], jobspec.cron_schedule("none", "www.example.com"))
        self.assertEqual(spec["jobTemplate"]["metadata"]["labels"], cron["metadata"]["labels"])
        self.assertEqual(spec["jobTemplate"]["spec"]["backoffLimit"], 1)
        self.assertEqual(spec["jobTemplate"]["spec"]["template"]["spec"]["containers"][0]["name"], "tls-scanner")
        json.dumps(cron)

    def test_spec_hash_tracks_changes(self):
        digest = self.cron["metadata"]["annotations"][jobspec.ANNOTATION_SPEC_HASH]
        self.assertRegex(digest, r"^[0-9a-f]{16}$")
        same = jobspec.build_cronjob(self.spec, self.variant, "www.example.com", ENV, settings(), "none", owner=OWNER, scanner_name="my-scanner")
        self.assertEqual(same["metadata"]["annotations"][jobspec.ANNOTATION_SPEC_HASH], digest)
        other_schedule = jobspec.build_cronjob(self.spec, self.variant, "www.example.com", ENV, settings(), "0 3 * * 1", owner=OWNER)
        self.assertNotEqual(other_schedule["metadata"]["annotations"][jobspec.ANNOTATION_SPEC_HASH], digest)
        other_env = jobspec.build_cronjob(self.spec, self.variant, "www.example.com", {"SAMMA_IO_ID": "2"}, settings(), "none", owner=OWNER)
        self.assertNotEqual(other_env["metadata"]["annotations"][jobspec.ANNOTATION_SPEC_HASH], digest)

    def test_user_schedule_is_kept(self):
        cron = jobspec.build_cronjob(self.spec, self.variant, "www.example.com", ENV, settings(), "0 3 * * 1")
        self.assertEqual(cron["spec"]["schedule"], "0 3 * * 1")


class HelperTests(unittest.TestCase):
    def test_owner_reference(self):
        ref = jobspec.owner_reference("samma.io/v1", "Scanner", "n", "u")
        self.assertEqual(ref, {"apiVersion": "samma.io/v1", "kind": "Scanner", "name": "n", "uid": "u", "controller": True, "blockOwnerDeletion": False})
        self.assertIs(jobspec.owner_reference("v1", "X", "n", "u", controller=False)["controller"], False)

    def test_job_finished(self):
        self.assertFalse(jobspec.job_finished(None))
        self.assertFalse(jobspec.job_finished({}))
        self.assertFalse(jobspec.job_finished({"active": 1, "conditions": None}))
        self.assertTrue(jobspec.job_finished({"conditions": [{"type": "Complete", "status": "True"}]}))
        self.assertTrue(jobspec.job_finished({"conditions": [{"type": "Failed", "status": "True"}]}))
        self.assertFalse(jobspec.job_finished({"conditions": [{"type": "Failed", "status": "False"}]}))
        self.assertTrue(jobspec.job_finished({"completion_time": "2026-10-24T00:00:00Z"}))
        self.assertTrue(jobspec.job_finished({"completionTime": "2026-10-24T00:00:00Z"}))

    def test_no_template_files_remain(self):
        scanners_dir = os.path.join(CODE_DIR, "scanners")
        self.assertEqual(sorted(os.listdir(scanners_dir)), ["core"])
        self.assertFalse(os.path.exists(os.path.join(CODE_DIR, "deployJob.py")))
        self.assertFalse(os.path.exists(os.path.join(CODE_DIR, "deploycron.py")))
        with open(os.path.join(OPERATOR_DIR, "requirements.txt")) as handle:
            self.assertNotIn("jinja", handle.read().lower())


if __name__ == "__main__":
    unittest.main()
