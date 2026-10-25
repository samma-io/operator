"""Target validation for the samma operator.

A Scanner target ends up as an argument to a scanner inside a Job pod and as
a value inside the rendered Job and CronJob YAML. This module decides what a
target may look like before the operator creates anything.

The module imports neither kopf nor the kubernetes client, so it can be unit
tested on its own. Callers pass a NetworkingV1Api instance where one is needed.

Three checks exist, applied in this order by check_target():

1. Syntax. The target must be a DNS-1123 hostname (lowercase labels, no
   wildcard, no scheme, no path, no whitespace) or an IPv4 or IPv6 literal.
   TARGET_PATTERN is the same regular expression the CRD schema carries.
2. Managed. Unless SAMMA_ALLOW_UNMANAGED_TARGETS is true (the default), the
   target must be the host of an Ingress rule somewhere in the cluster.
3. Public. Unless SAMMA_ALLOW_PRIVATE_TARGETS is true (default false), the
   target must resolve only to public addresses. Loopback, RFC 1918,
   link-local, multicast, unspecified, carrier-grade NAT and IPv6 unique local
   addresses are refused. An IP literal is checked without DNS.
"""

import ipaddress
import logging
import os
import re
import socket

# A DNS-1123 label: 1 to 63 characters, lowercase letters, digits and hyphens,
# starting and ending with a letter or a digit.
_LABEL = r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"
HOSTNAME_PATTERN = r"{label}(\.{label})*".format(label=_LABEL)

_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IPV4_PATTERN = r"({octet}\.){{3}}{octet}".format(octet=_OCTET)

# Hex groups and colons only, two to eight groups. This keeps every shell and
# YAML metacharacter out; validate_target() then asks the ipaddress module
# whether the string is a real IPv6 address.
IPV6_PATTERN = r"[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}"

# The one pattern shared with the CRD (spec.target). Keep the CRD copies in
# helm/samma-operator/templates/crd.yaml and manifest/samma-operator.yaml
# identical to this string; tests/test_target_policy.py checks that.
TARGET_PATTERN = "^({0}|{1}|{2})$".format(HOSTNAME_PATTERN, IPV4_PATTERN, IPV6_PATTERN)
MAX_TARGET_LENGTH = 253

# spec.scanners[] entries: a scanner directory name with an optional template
# after a slash, for example "nmap" or "nmap/http".
SCANNER_PATTERN = r"^[a-z0-9-]+(/[a-z0-9-]+)?$"

# spec.scheduler: five whitespace separated cron fields built from digits,
# letters and the usual cron punctuation, one of the @-macros CronJob accepts,
# or the literal "none" the operator has always treated as "use the default".
_CRON_FIELD = r"[A-Za-z0-9*/,?-]+"
SCHEDULE_PATTERN = (
    r"^\s*(none|@(yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    r"(" + _CRON_FIELD + r"\s+){4}" + _CRON_FIELD + r")\s*$"
)

# spec.samma_io_tags[] and spec.samma_io_id are rendered into scanner env
# values; keep them to plain identifier characters.
TAG_PATTERN = r"^[A-Za-z0-9_.-]{1,63}$"
ID_PATTERN = r"^[A-Za-z0-9_.-]{0,128}$"

_TARGET_RE = re.compile(TARGET_PATTERN)
# Digits, dots and hyphens only: legal DNS syntax, but nmap reads
# "10.0.0.1-254" as a range, so such a string must be one real address.
_NUMERIC_RE = re.compile(r"[0-9.-]+")
_SCANNER_RE = re.compile(SCANNER_PATTERN)
_SCHEDULE_RE = re.compile(SCHEDULE_PATTERN)

# Ranges the ipaddress module does not flag on every Python version, or flags
# under a property name that differs between versions. Checked explicitly so
# the result does not depend on the interpreter in the operator image.
_NON_PUBLIC_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),  # unique local
    ipaddress.ip_network("fe80::/10"),  # link local
    ipaddress.ip_network("ff00::/8"),  # multicast
]

ENV_ALLOW_PRIVATE = "SAMMA_ALLOW_PRIVATE_TARGETS"
ENV_ALLOW_UNMANAGED = "SAMMA_ALLOW_UNMANAGED_TARGETS"

_TRUE_WORDS = {"1", "true", "yes", "on"}
_FALSE_WORDS = {"0", "false", "no", "off"}


class TargetRejected(ValueError):
    """The target must not be scanned. The message says why."""


class TargetUnresolvable(RuntimeError):
    """The target name did not resolve, so its addresses could not be checked."""


def env_flag(name, default):
    """Read a boolean from the environment.

    Unset or empty gives the default. Anything that is not a recognised true
    or false word is logged and treated as false, so a typo never widens what
    the operator accepts.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    word = raw.strip().lower()
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    logging.warning("%s=%r is not a boolean, treating it as false", name, raw)
    return False


def allow_private_targets():
    return env_flag(ENV_ALLOW_PRIVATE, False)


def allow_unmanaged_targets():
    return env_flag(ENV_ALLOW_UNMANAGED, True)


def is_wildcard_host(host):
    """True for Ingress hosts such as "*.example.com". They are skipped: a
    wildcard is not a scannable endpoint."""
    return isinstance(host, str) and "*" in host


def validate_target(target):
    """Raise TargetRejected unless target is a hostname or IP literal that
    matches TARGET_PATTERN. Returns None."""
    if not isinstance(target, str):
        raise TargetRejected("target must be a string, got {0}".format(type(target).__name__))
    if target == "":
        raise TargetRejected("target is empty")
    if len(target) > MAX_TARGET_LENGTH:
        raise TargetRejected(
            "target is {0} characters long, the maximum is {1}".format(len(target), MAX_TARGET_LENGTH)
        )
    if is_wildcard_host(target):
        raise TargetRejected("target {0!r} is a wildcard; scan a concrete hostname instead".format(target))
    if _TARGET_RE.fullmatch(target) is None:
        raise TargetRejected(
            "target {0!r} is not a DNS hostname (lowercase labels, no scheme, no path) "
            "or an IPv4/IPv6 address".format(target)
        )
    if ":" in target:
        try:
            ipaddress.IPv6Address(target)
        except ValueError:
            raise TargetRejected("target {0!r} is not a valid IPv6 address".format(target))
    if _NUMERIC_RE.fullmatch(target) is not None and parse_ip_literal(target) is None:
        raise TargetRejected(
            "target {0!r} looks like an IPv4 address or range but is not one address".format(target)
        )


def validate_scanner_name(scanner):
    """Raise TargetRejected unless scanner matches SCANNER_PATTERN."""
    if not isinstance(scanner, str) or _SCANNER_RE.fullmatch(scanner) is None:
        raise TargetRejected(
            "scanner {0!r} is not a valid scanner name (letters, digits, hyphens, "
            "optionally /template)".format(scanner)
        )


def validate_schedule(schedule):
    """Raise TargetRejected unless schedule matches SCHEDULE_PATTERN."""
    if not isinstance(schedule, str) or _SCHEDULE_RE.fullmatch(schedule) is None:
        raise TargetRejected("scheduler {0!r} is not a five field cron expression".format(schedule))


def parse_ip_literal(target):
    """Return an IPv4Address or IPv6Address when target is an IP literal, else None."""
    try:
        return ipaddress.ip_address(target.split("%", 1)[0])
    except ValueError:
        return None


def is_public_address(address):
    """True when address (an ipaddress object or a string) is globally routable.

    IPv4-mapped IPv6 addresses are judged by the IPv4 address they carry.
    """
    if isinstance(address, str):
        address = ipaddress.ip_address(address.split("%", 1)[0])
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
        or address.is_reserved
    ):
        return False
    for network in _NON_PUBLIC_NETWORKS:
        if address.version == network.version and address in network:
            return False
    return True


def resolve_target_addresses(target, getaddrinfo=socket.getaddrinfo):
    """Return the list of addresses target resolves to.

    An IP literal is returned as is without a lookup. Raises
    TargetUnresolvable when the name has no A or AAAA records or the lookup
    fails.
    """
    literal = parse_ip_literal(target)
    if literal is not None:
        return [literal]
    try:
        results = getaddrinfo(target, None, 0, socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, UnicodeError, OSError) as exc:
        raise TargetUnresolvable("target {0!r} did not resolve: {1}".format(target, exc))
    addresses = []
    for entry in results:
        sockaddr = entry[4]
        try:
            address = ipaddress.ip_address(str(sockaddr[0]).split("%", 1)[0])
        except (ValueError, IndexError, TypeError):
            continue
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise TargetUnresolvable("target {0!r} has no A or AAAA record".format(target))
    return addresses


def resolves_to_public_address(target, getaddrinfo=socket.getaddrinfo):
    """True when every address the target resolves to is public.

    One private address among several is enough to return False: a scan of
    such a name could reach the private side. Raises TargetUnresolvable when
    the name does not resolve.
    """
    addresses = resolve_target_addresses(target, getaddrinfo=getaddrinfo)
    return all(is_public_address(address) for address in addresses)


def _normalise_host(host):
    return host.strip().lower().rstrip(".")


def ingress_hosts(networking_api):
    """The set of spec.rules[].host values across every Ingress in the cluster."""
    hosts = set()
    ingresses = networking_api.list_ingress_for_all_namespaces()
    for ingress in ingresses.items or []:
        spec = getattr(ingress, "spec", None)
        for rule in (getattr(spec, "rules", None) or []):
            host = getattr(rule, "host", None)
            if host:
                hosts.add(_normalise_host(host))
    return hosts


def target_served_by_ingress(target, networking_api):
    """True when some Ingress rule in the cluster names target exactly.

    A wildcard rule does not count as serving a concrete host.
    """
    return _normalise_host(target) in ingress_hosts(networking_api)


def check_target(
    target,
    networking_api=None,
    allow_private=None,
    allow_unmanaged=None,
    getaddrinfo=socket.getaddrinfo,
):
    """Run every check on target. Returns None when the target may be scanned.

    Raises TargetRejected with a human readable reason, or TargetUnresolvable
    when the public-address check could not run because the name did not
    resolve (the caller decides whether to retry).

    allow_private and allow_unmanaged default to the environment toggles.
    networking_api is only consulted when allow_unmanaged is false.
    """
    validate_target(target)
    if allow_private is None:
        allow_private = allow_private_targets()
    if allow_unmanaged is None:
        allow_unmanaged = allow_unmanaged_targets()

    if not allow_unmanaged:
        if networking_api is None:
            raise TargetRejected(
                "target {0!r} cannot be checked against the cluster's Ingresses "
                "and {1} is false".format(target, ENV_ALLOW_UNMANAGED)
            )
        if not target_served_by_ingress(target, networking_api):
            raise TargetRejected(
                "target {0!r} is not the host of any Ingress in this cluster and "
                "{1} is false".format(target, ENV_ALLOW_UNMANAGED)
            )

    if not allow_private:
        if not resolves_to_public_address(target, getaddrinfo=getaddrinfo):
            raise TargetRejected(
                "target {0!r} resolves to a private, loopback, link-local or other "
                "non-public address and {1} is false".format(target, ENV_ALLOW_PRIVATE)
            )
