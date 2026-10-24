"""The Scanners that exist right now, cached for a short time.

A message is only acted on when its target is the target of a current
Scanner in the bridge's namespace: anything else is dropped, so a pod
that can reach NATS cannot plant findings for a host nobody asked to
scan. The same list gives a report its owners (the Scanners with that
target and scanner) and the Ingress labels to copy.

The lister is injected (bridge.py passes the kubernetes client call) and
the list is refreshed at most every ttl seconds. When a refresh fails the
previous list stays in use; before the first successful list nothing
matches.
"""

import logging
import time

from . import reports


def scanner_names(scanner_object):
    """The base scanner names a Scanner runs ("nmap/http" -> "nmap"). An
    empty list means the operator's default, which this module cannot
    know, so such a Scanner matches every scanner for its target."""
    spec = scanner_object.get("spec") or {}
    names = []
    for raw in spec.get("scanners") or []:
        name = str(raw).strip().split("/", 1)[0]
        if name and name not in names:
            names.append(name)
    return names


class ScannerIndex(object):
    def __init__(self, lister, ttl_seconds=30, clock=None, logger=None):
        self.lister = lister
        self.ttl = float(ttl_seconds)
        self.clock = clock or time.monotonic
        self.log = logger or logging.getLogger("samma.bridge.scanners")
        self._by_target = {}
        self._loaded_at = None
        self.loaded = False

    def refresh(self, now=None, force=False):
        """Re-list when the cache is older than ttl. Returns True when the
        index is usable (a list succeeded at some point)."""
        now = self.clock() if now is None else now
        if not force and self._loaded_at is not None and now - self._loaded_at < self.ttl:
            return self.loaded
        try:
            items = list(self.lister())
        except Exception as exc:
            self.log.warning("Could not list Scanners, keeping the previous list: %s", exc)
            self._loaded_at = now  # do not hammer a failing API; try again after ttl
            return self.loaded
        by_target = {}
        for item in items:
            target = ((item.get("spec") or {}).get("target") or "").strip()
            if not target:
                continue
            by_target.setdefault(target, []).append(item)
        self._by_target = by_target
        self._loaded_at = now
        self.loaded = True
        return True

    def is_target(self, target):
        self.refresh()
        return target in self._by_target

    def matching(self, scanner, target):
        """The Scanners that have this target and run this scanner."""
        self.refresh()
        matches = []
        for item in self._by_target.get(target, []):
            names = scanner_names(item)
            if not names or scanner in names:
                matches.append(item)
        return matches

    def owners(self, scanner, target):
        return [reports.owner_reference(item) for item in self.matching(scanner, target)]

    def extra_labels(self, scanner, target):
        """Ingress labels of the first matching Scanner that has them."""
        for item in self.matching(scanner, target):
            labels = (item.get("metadata") or {}).get("labels") or {}
            extra = dict((key, labels[key]) for key in (reports.LABEL_INGRESS_NAMESPACE, reports.LABEL_INGRESS_NAME) if key in labels)
            if extra:
                return extra
        return {}
