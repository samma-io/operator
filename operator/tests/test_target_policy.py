"""Unit tests for operator/code/target_policy.py.

Run from the repository root (or anywhere else):

    python3 -m unittest discover -s operator/tests -t operator

No network is used: DNS lookups are replaced by fakes, and the Kubernetes
client is replaced by a small stand-in with the one method the module calls.
"""

import ipaddress
import os
import socket
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
OPERATOR_DIR = os.path.dirname(HERE)
REPO_DIR = os.path.dirname(OPERATOR_DIR)
CODE_DIR = os.path.join(OPERATOR_DIR, "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import target_policy as tp  # noqa: E402

CRD_FILES = [
    os.path.join(REPO_DIR, "helm", "samma-operator", "crds", "scanner.samma.io.yaml"),
    os.path.join(REPO_DIR, "manifest", "samma-operator.yaml"),
]

LONGEST_HOSTNAME = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 61  # 253 chars
TOO_LONG_HOSTNAME = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 62  # 254 chars

ACCEPTED_TARGETS = [
    "example.com",
    "www.example.com",
    "a.b.c.example.co.uk",
    "localhost",
    "xn--bcher-kva.example",
    "my-host-1.example.org",
    "1.2.3.4",
    "203.0.113.9",
    "2001:db8::1",
    "2001:4860:4860::8888",
    "::1",
    "ff02::1",
    "a" * 63 + ".example",
    LONGEST_HOSTNAME,
]

REJECTED_TARGETS = [
    "",
    " ",
    "*.example.com",
    "*",
    "https://example.com",
    "http://example.com/",
    "example.com/path",
    "example.com:443",
    "example.com; id",
    "example.com && curl evil",
    "example.com|id",
    "$(id)",
    "`id`",
    "exa mple.com",
    "example.com\n",
    "example.com\t",
    "Example.com",
    "EXAMPLE.COM",
    "-bad.example.com",
    "bad-.example.com",
    ".example.com",
    "example.com.",
    "example..com",
    "a" * 64 + ".example",
    TOO_LONG_HOSTNAME,
    "exämple.com",
    "example.com\x00",
    "user@example.com",
    "example.com?x=1",
    '"example.com"',
    "'example.com'",
    'example.com"',
    "1.2.3.4 5.6.7.8",
    "1.2.3.256",
    "1.2.3",
    "1-2",
    "10.0.0.1-254",
    "192.168.0-255.1",
    "10.0.0.0/24",
    "2001:db8::zz",
    ":::",
    "1::2::3",
    "2001:db8:::1",
    "a:b:c",
    "[2001:db8::1]",
    "fe80::1%eth0",
    None,
    42,
    b"example.com",
    ["example.com"],
]

PUBLIC_ADDRESSES = [
    "8.8.8.8",
    "1.1.1.1",
    "9.9.9.9",
    "11.0.0.1",
    "93.184.216.34",
    "100.63.255.255",
    "100.128.0.1",
    "172.15.255.255",
    "172.32.0.1",
    "203.0.114.1",
    "2001:4860:4860::8888",
    "2606:4700::1111",
    "::ffff:8.8.8.8",
]

NON_PUBLIC_ADDRESSES = [
    "0.0.0.0",
    "0.1.2.3",
    "10.0.0.1",
    "10.255.255.255",
    "100.64.0.1",
    "100.127.255.254",
    "127.0.0.1",
    "127.255.255.255",
    "169.254.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.1",
    "192.0.2.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "239.255.255.255",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "2001:db8::1",
    "::ffff:10.0.0.1",
    "::ffff:127.0.0.1",
    "::ffff:192.168.0.1",
]


def fake_resolver(*addresses):
    """A socket.getaddrinfo stand-in answering with the given addresses."""
    calls = []

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        calls.append(host)
        results = []
        for text in addresses:
            address = ipaddress.ip_address(text.split("%", 1)[0])
            if address.version == 6:
                results.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (text, 0, 0, 0)))
            else:
                results.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (text, 0)))
        return results

    getaddrinfo.calls = calls
    return getaddrinfo


def failing_resolver(host, port, family=0, type=0, proto=0, flags=0):
    raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def forbidden_resolver(host, port, family=0, type=0, proto=0, flags=0):
    raise AssertionError("DNS must not be consulted for {0!r}".format(host))


class _Rule(object):
    def __init__(self, host):
        self.host = host


class _Spec(object):
    def __init__(self, rules):
        self.rules = rules


class _Ingress(object):
    def __init__(self, spec):
        self.spec = spec


class _IngressList(object):
    def __init__(self, items):
        self.items = items


class FakeNetworkingApi(object):
    """Stands in for kubernetes.client.NetworkingV1Api."""

    def __init__(self, hosts):
        self.calls = 0
        self._items = [
            _Ingress(None),
            _Ingress(_Spec(None)),
            _Ingress(_Spec([_Rule(None)])),
            _Ingress(_Spec([_Rule(host) for host in hosts])),
        ]

    def list_ingress_for_all_namespaces(self):
        self.calls += 1
        return _IngressList(self._items)


class ValidateTargetTests(unittest.TestCase):
    def test_accepts_hostnames_and_ip_literals(self):
        for target in ACCEPTED_TARGETS:
            with self.subTest(target=target):
                self.assertIsNone(tp.validate_target(target))

    def test_rejects_everything_else(self):
        for target in REJECTED_TARGETS:
            with self.subTest(target=target):
                with self.assertRaises(tp.TargetRejected):
                    tp.validate_target(target)

    def test_rejection_message_names_the_target(self):
        with self.assertRaises(tp.TargetRejected) as ctx:
            tp.validate_target("example.com; id")
        self.assertIn("example.com; id", str(ctx.exception))

    def test_pattern_uses_only_re2_constructs(self):
        # Kubernetes compiles CRD patterns with Go's regexp (RE2): no
        # lookarounds and no backreferences.
        for pattern in (tp.TARGET_PATTERN, tp.SCANNER_PATTERN, tp.SCHEDULE_PATTERN, tp.TAG_PATTERN, tp.ID_PATTERN):
            with self.subTest(pattern=pattern):
                self.assertNotIn("(?", pattern)
                self.assertTrue(pattern.startswith("^") and pattern.endswith("$"))


class WildcardTests(unittest.TestCase):
    def test_wildcards(self):
        self.assertTrue(tp.is_wildcard_host("*.example.com"))
        self.assertTrue(tp.is_wildcard_host("*"))
        self.assertFalse(tp.is_wildcard_host("www.example.com"))
        self.assertFalse(tp.is_wildcard_host(""))
        self.assertFalse(tp.is_wildcard_host(None))


class ScannerAndScheduleTests(unittest.TestCase):
    def test_scanner_names(self):
        for name in ("nmap", "nmap/http", "http-headers-scanner", "a1"):
            with self.subTest(name=name):
                tp.validate_scanner_name(name)
        for name in ("", "Nmap", "nmap/http/x", "../etc", "nmap;id", "nmap http", "/nmap", "nmap/", None):
            with self.subTest(name=name):
                with self.assertRaises(tp.TargetRejected):
                    tp.validate_scanner_name(name)

    def test_schedules(self):
        for schedule in ("0 0 * * 0", "*/15 * * * *", "2 19 * * *", "0 3 * * MON-FRI", " 0 0 * * 0 ", "none", "@daily", "@hourly"):
            with self.subTest(schedule=schedule):
                tp.validate_schedule(schedule)
        for schedule in ("", "0 0 * *", "0 0 * * * *", '0 0 * * 0", "x": "y', "0 0 * * 0; id", "@every 1h", "daily", None):
            with self.subTest(schedule=schedule):
                with self.assertRaises(tp.TargetRejected):
                    tp.validate_schedule(schedule)


class PublicAddressTests(unittest.TestCase):
    def test_public(self):
        for address in PUBLIC_ADDRESSES:
            with self.subTest(address=address):
                self.assertTrue(tp.is_public_address(address))
                self.assertTrue(tp.is_public_address(ipaddress.ip_address(address)))

    def test_non_public(self):
        for address in NON_PUBLIC_ADDRESSES:
            with self.subTest(address=address):
                self.assertFalse(tp.is_public_address(address))
                self.assertFalse(tp.is_public_address(ipaddress.ip_address(address)))

    def test_scope_id_is_ignored(self):
        self.assertFalse(tp.is_public_address("fe80::1%eth0"))


class ResolutionTests(unittest.TestCase):
    def test_public_name(self):
        resolver = fake_resolver("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")
        self.assertTrue(tp.resolves_to_public_address("example.com", getaddrinfo=resolver))
        self.assertEqual(resolver.calls, ["example.com"])

    def test_one_private_answer_is_enough_to_refuse(self):
        resolver = fake_resolver("93.184.216.34", "10.0.0.5")
        self.assertFalse(tp.resolves_to_public_address("split.example.com", getaddrinfo=resolver))

    def test_private_name(self):
        resolver = fake_resolver("192.168.1.10")
        self.assertFalse(tp.resolves_to_public_address("intranet.example.com", getaddrinfo=resolver))

    def test_ip_literal_skips_dns(self):
        self.assertTrue(tp.resolves_to_public_address("8.8.8.8", getaddrinfo=forbidden_resolver))
        self.assertFalse(tp.resolves_to_public_address("10.0.0.1", getaddrinfo=forbidden_resolver))
        self.assertFalse(tp.resolves_to_public_address("fe80::1", getaddrinfo=forbidden_resolver))
        self.assertTrue(tp.resolves_to_public_address("2001:4860:4860::8888", getaddrinfo=forbidden_resolver))

    def test_duplicate_answers_collapse(self):
        resolver = fake_resolver("8.8.8.8", "8.8.8.8")
        self.assertEqual(tp.resolve_target_addresses("dns.google", getaddrinfo=resolver), [ipaddress.ip_address("8.8.8.8")])

    def test_unresolvable_raises(self):
        with self.assertRaises(tp.TargetUnresolvable):
            tp.resolves_to_public_address("nope.invalid", getaddrinfo=failing_resolver)
        with self.assertRaises(tp.TargetUnresolvable):
            tp.resolves_to_public_address("empty.invalid", getaddrinfo=fake_resolver())


class IngressTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeNetworkingApi(["api.example.com", "Www.Example.com.", "*.wild.example.com"])

    def test_hosts_are_normalised(self):
        self.assertEqual(tp.ingress_hosts(self.api), {"api.example.com", "www.example.com", "*.wild.example.com"})

    def test_exact_match_only(self):
        self.assertTrue(tp.target_served_by_ingress("api.example.com", self.api))
        self.assertTrue(tp.target_served_by_ingress("www.example.com", self.api))
        self.assertFalse(tp.target_served_by_ingress("x.wild.example.com", self.api))
        self.assertFalse(tp.target_served_by_ingress("other.example.com", self.api))
        self.assertFalse(tp.target_served_by_ingress("example.com", self.api))

    def test_empty_cluster(self):
        self.assertFalse(tp.target_served_by_ingress("api.example.com", FakeNetworkingApi([])))


class EnvFlagTests(unittest.TestCase):
    def test_values(self):
        cases = {
            "true": True, "True": True, "TRUE": True, "1": True, "yes": True, "on": True, " true ": True,
            "false": False, "False": False, "0": False, "no": False, "off": False,
            "ture": False, "maybe": False,
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                with mock.patch.dict(os.environ, {"SAMMA_TEST_FLAG": raw}):
                    self.assertIs(tp.env_flag("SAMMA_TEST_FLAG", True), expected)
                    self.assertIs(tp.env_flag("SAMMA_TEST_FLAG", False), expected)

    def test_unset_and_empty_give_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIs(tp.env_flag("SAMMA_TEST_FLAG", True), True)
            self.assertIs(tp.env_flag("SAMMA_TEST_FLAG", False), False)
        with mock.patch.dict(os.environ, {"SAMMA_TEST_FLAG": "  "}):
            self.assertIs(tp.env_flag("SAMMA_TEST_FLAG", True), True)

    def test_defaults_of_the_operator_toggles(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertFalse(tp.allow_private_targets())
            self.assertTrue(tp.allow_unmanaged_targets())


class CheckTargetTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.api = FakeNetworkingApi(["api.example.com"])

    def test_defaults_accept_a_public_unmanaged_target(self):
        resolver = fake_resolver("93.184.216.34")
        self.assertIsNone(tp.check_target("other.example.com", networking_api=self.api, getaddrinfo=resolver))
        self.assertEqual(self.api.calls, 0)
        self.assertEqual(resolver.calls, ["other.example.com"])

    def test_defaults_reject_a_private_target(self):
        with self.assertRaises(tp.TargetRejected) as ctx:
            tp.check_target("intranet.example.com", networking_api=self.api, getaddrinfo=fake_resolver("10.1.2.3"))
        self.assertIn(tp.ENV_ALLOW_PRIVATE, str(ctx.exception))
        with self.assertRaises(tp.TargetRejected):
            tp.check_target("127.0.0.1", networking_api=self.api, getaddrinfo=forbidden_resolver)

    def test_private_targets_allowed_skips_dns(self):
        os.environ[tp.ENV_ALLOW_PRIVATE] = "true"
        self.assertIsNone(tp.check_target("intranet.example.com", networking_api=self.api, getaddrinfo=forbidden_resolver))
        self.assertIsNone(tp.check_target("10.0.0.1", networking_api=self.api, getaddrinfo=forbidden_resolver))

    def test_unmanaged_targets_refused_when_disabled(self):
        os.environ[tp.ENV_ALLOW_UNMANAGED] = "false"
        resolver = fake_resolver("93.184.216.34")
        self.assertIsNone(tp.check_target("api.example.com", networking_api=self.api, getaddrinfo=resolver))
        self.assertEqual(self.api.calls, 1)
        with self.assertRaises(tp.TargetRejected) as ctx:
            tp.check_target("other.example.com", networking_api=self.api, getaddrinfo=resolver)
        self.assertIn(tp.ENV_ALLOW_UNMANAGED, str(ctx.exception))
        # The managed check runs before DNS, so the refused host was never resolved.
        self.assertEqual(resolver.calls, ["api.example.com"])

    def test_unmanaged_check_needs_an_api_client(self):
        os.environ[tp.ENV_ALLOW_UNMANAGED] = "false"
        with self.assertRaises(tp.TargetRejected):
            tp.check_target("api.example.com", networking_api=None, getaddrinfo=forbidden_resolver)

    def test_unresolvable_propagates(self):
        with self.assertRaises(tp.TargetUnresolvable):
            tp.check_target("nope.invalid", networking_api=self.api, getaddrinfo=failing_resolver)

    def test_syntax_is_checked_first(self):
        os.environ[tp.ENV_ALLOW_PRIVATE] = "true"
        for target in ("*.example.com", "example.com; id", "https://example.com"):
            with self.subTest(target=target):
                with self.assertRaises(tp.TargetRejected):
                    tp.check_target(target, networking_api=self.api, getaddrinfo=forbidden_resolver)

    def test_arguments_override_the_environment(self):
        os.environ[tp.ENV_ALLOW_PRIVATE] = "true"
        os.environ[tp.ENV_ALLOW_UNMANAGED] = "true"
        with self.assertRaises(tp.TargetRejected):
            tp.check_target("intranet.example.com", networking_api=self.api, allow_private=False,
                            getaddrinfo=fake_resolver("10.1.2.3"))
        with self.assertRaises(tp.TargetRejected):
            tp.check_target("other.example.com", networking_api=self.api, allow_unmanaged=False,
                            getaddrinfo=forbidden_resolver)


class CrdSchemaTests(unittest.TestCase):
    """The CRD copies must carry exactly the patterns this module enforces."""

    def _read(self, path):
        with open(path, "r") as handle:
            return handle.read()

    def test_both_crd_copies_carry_the_patterns(self):
        for path in CRD_FILES:
            with self.subTest(path=os.path.relpath(path, REPO_DIR)):
                text = self._read(path)
                for pattern in (tp.TARGET_PATTERN, tp.SCANNER_PATTERN, tp.SCHEDULE_PATTERN, tp.TAG_PATTERN, tp.ID_PATTERN):
                    self.assertIn("pattern: '{0}'".format(pattern), text)
                self.assertIn("maxLength: {0}".format(tp.MAX_TARGET_LENGTH), text)

    def test_crd_copies_agree_on_the_schema(self):
        def schema_lines(text):
            lines = text.splitlines()
            start = next(i for i, line in enumerate(lines) if "openAPIV3Schema" in line)
            end = next(i for i, line in enumerate(lines) if line.strip().startswith("names:") and i > start)
            return [line.rstrip() for line in lines[start:end]]

        helm, manifest = (self._read(path) for path in CRD_FILES)
        self.assertEqual(schema_lines(helm), schema_lines(manifest))


if __name__ == "__main__":
    unittest.main()
