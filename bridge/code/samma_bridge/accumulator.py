"""Collect the findings of one scan run until its run message arrives.

A run is (scanner, template, target, runId). Findings are kept in arrival
order; the run message ends the run. When the run message says it emitted
more findings than arrived here, the run stays open for straggler_wait
seconds in case the rest is still in flight, and is then finalised as
incomplete. A run whose run message never comes (the scanner died before
sending it) is dropped after idle_timeout; the operator records that
Job's failure in the ScanReport itself.

Pure Python: time comes from an injected clock so tests do not sleep.
"""

import time

from . import messages


class Finalized(object):
    """One run ready to be written."""

    def __init__(self, key, run, findings, received, run_received_at):
        self.key = key
        self.run = run
        self.findings = list(findings)
        self.received = received
        self.run_received_at = run_received_at

    @property
    def expected(self):
        return self.run.finding_count

    @property
    def complete(self):
        return self.received >= self.expected

    @property
    def scanner(self):
        return self.run.scanner

    @property
    def target(self):
        return self.run.target


class _Pending(object):
    def __init__(self, now):
        self.findings = []
        self.received = 0
        self.run = None
        self.run_received_at = None
        self.deadline = None
        self.last_seen = now


class Accumulator(object):
    def __init__(self, straggler_wait=30.0, idle_timeout=3600.0, clock=None):
        self.straggler_wait = float(straggler_wait)
        self.idle_timeout = float(idle_timeout)
        self.clock = clock or time.monotonic
        self._runs = {}

    def __len__(self):
        return len(self._runs)

    def add(self, message, now=None):
        """Record a Finding or Run. Returns the runs this message finished
        (at most one)."""
        now = self.clock() if now is None else now
        pending = self._runs.get(message.key)
        if pending is None:
            pending = self._runs[message.key] = _Pending(now)
        pending.last_seen = now
        if message.kind == messages.KIND_FINDING:
            pending.findings.append(message)
            pending.received += 1
            if pending.run is not None and pending.received >= pending.run.finding_count:
                return [self._finish(message.key)]
            return []
        if message.kind == messages.KIND_RUN:
            pending.run = message
            pending.run_received_at = now
            if pending.received >= message.finding_count or self.straggler_wait <= 0:
                return [self._finish(message.key)]
            pending.deadline = now + self.straggler_wait
            return []
        return []

    def due(self, now=None):
        """Finalise runs whose straggler wait is over. Call it regularly."""
        now = self.clock() if now is None else now
        done = []
        for key in list(self._runs):
            pending = self._runs[key]
            if pending.run is not None and pending.deadline is not None and now >= pending.deadline:
                done.append(self._finish(key))
        return done

    def expire(self, now=None):
        """Drop runs that have been silent for idle_timeout without a run
        message. Returns (key, findings received) pairs."""
        now = self.clock() if now is None else now
        dropped = []
        for key in list(self._runs):
            pending = self._runs[key]
            if pending.run is None and now - pending.last_seen >= self.idle_timeout:
                del self._runs[key]
                dropped.append((key, pending.received))
        return dropped

    def _finish(self, key):
        pending = self._runs.pop(key)
        return Finalized(key, pending.run, pending.findings, pending.received, pending.run_received_at)
