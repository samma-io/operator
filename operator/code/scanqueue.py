"""A bounded, first-in first-out queue for immediate scan Jobs.

A Scanner creates one Job per scanner right away. Without a limit, a burst of
Scanners (an Ingress with many hosts, a profile with twelve scanners) starts
every scan pod at once. ScanQueue holds the Job bodies and launches them in
order while the number of unfinished scan Jobs in the namespace stays under
max_concurrent. CronJob-born Jobs count towards the limit as running Jobs,
but they are started by the CronJob controller on their own schedule.

The class is pure Python: the caller supplies

    count_running()        -> number of unfinished scan Jobs right now
    launch(body)           -> creates the Job; raising marks the entry failed
    on_launched(key, body) -> optional, called after a successful launch
    still_wanted(key, body)-> optional, False drops an entry without launching

drain() is called after every submit() and by a background thread
(run_drainer) every few seconds, so a Job starts as soon as a slot is free.
"""

import collections
import logging
import threading
import time

QUEUED = "queued"
LAUNCHED = "launched"
FAILED = "failed"
DROPPED = "dropped"


class ScanQueue(object):
    def __init__(self, max_concurrent, count_running, launch, on_launched=None, still_wanted=None, logger=None):
        # 0 (or less) means no limit.
        self.max_concurrent = int(max_concurrent)
        self.count_running = count_running
        self.launch = launch
        self.on_launched = on_launched
        self.still_wanted = still_wanted
        self.log = logger or logging.getLogger("samma.scanqueue")
        self._lock = threading.Lock()
        self._pending = collections.deque()
        self._states = {}
        self._errors = {}

    def submit(self, key, body):
        """Queue a Job body under key and drain. Returns the entry's state
        afterwards: "launched" when it started right away, "queued" when it
        waits for a slot, "failed" when the launch raised."""
        with self._lock:
            state = self._states.get(key)
            if state == LAUNCHED:
                return LAUNCHED
            if state != QUEUED:
                self._pending.append((key, body))
                self._states[key] = QUEUED
                self._errors.pop(key, None)
        self.drain()
        return self.state(key)

    def state(self, key):
        with self._lock:
            return self._states.get(key)

    def error(self, key):
        with self._lock:
            return self._errors.get(key)

    def pending_keys(self):
        with self._lock:
            return [key for key, _ in self._pending]

    def has_pending(self, prefix):
        """True while any queued key starts with prefix (a Scanner uid)."""
        with self._lock:
            return any(key.startswith(prefix) for key, _ in self._pending)

    def forget(self, prefix):
        """Drop every entry whose key starts with prefix, queued or done."""
        with self._lock:
            self._pending = collections.deque((k, b) for k, b in self._pending if not k.startswith(prefix))
            for key in [k for k in self._states if k.startswith(prefix)]:
                self._states.pop(key, None)
                self._errors.pop(key, None)

    def __len__(self):
        with self._lock:
            return len(self._pending)

    def drain(self):
        """Launch queued Jobs while slots are free. Returns the launched keys."""
        launched = []
        with self._lock:
            if not self._pending:
                return launched
            if self.max_concurrent > 0:
                try:
                    running = int(self.count_running())
                except Exception as exc:  # the API call failed; try again next tick
                    self.log.warning("Could not count running scan Jobs, keeping %d queued: %s", len(self._pending), exc)
                    return launched
                free = self.max_concurrent - running
            else:
                free = len(self._pending)
            while free > 0 and self._pending:
                key, body = self._pending.popleft()
                if self.still_wanted is not None:
                    try:
                        wanted = self.still_wanted(key, body)
                    except Exception as exc:
                        self.log.warning("Could not check whether %s is still wanted, launching it anyway: %s", key, exc)
                        wanted = True
                    if not wanted:
                        self._states[key] = DROPPED
                        self.log.info("Dropped queued scan %s: its Scanner is gone", key)
                        continue
                try:
                    self.launch(body)
                except Exception as exc:
                    self._states[key] = FAILED
                    self._errors[key] = str(exc)
                    self.log.warning("Could not launch scan %s: %s", key, exc)
                    continue
                self._states[key] = LAUNCHED
                launched.append((key, body))
                free -= 1
            if self._pending:
                self.log.info("%d scan Jobs waiting for a free slot (limit %d)", len(self._pending), self.max_concurrent)
        if self.on_launched is not None:
            for key, body in launched:
                try:
                    self.on_launched(key, body)
                except Exception as exc:
                    self.log.warning("on_launched failed for %s: %s", key, exc)
        return [key for key, _ in launched]


def run_drainer(queue, interval_seconds, stop_event, sleep=None):
    """Call queue.drain() every interval_seconds until stop_event is set.
    Meant to run in a daemon thread started by the operator at startup."""
    wait = stop_event.wait if sleep is None else sleep
    while not stop_event.is_set():
        try:
            queue.drain()
        except Exception as exc:
            queue.log.warning("Scan queue drain failed: %s", exc)
        if wait(interval_seconds):
            break


def start_drainer(queue, interval_seconds):
    """Start run_drainer in a daemon thread. Returns (thread, stop_event)."""
    stop_event = threading.Event()
    thread = threading.Thread(
        target=run_drainer,
        args=(queue, interval_seconds, stop_event),
        name="samma-scan-queue",
        daemon=True,
    )
    thread.start()
    return thread, stop_event
