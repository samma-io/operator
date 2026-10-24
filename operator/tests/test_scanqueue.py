"""Unit tests for operator/code/scanqueue.py. Pure Python, fake API."""

import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CODE_DIR = os.path.join(os.path.dirname(HERE), "code")
if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

import scanqueue  # noqa: E402


class FakeCluster(object):
    """Counts the Jobs it was asked to create; finish() completes one."""

    def __init__(self, fail_names=()):
        self.running = []
        self.finished = []
        self.fail_names = set(fail_names)
        self.count_calls = 0

    def count_running(self):
        self.count_calls += 1
        return len(self.running)

    def launch(self, body):
        name = body["metadata"]["name"]
        if name in self.fail_names:
            raise RuntimeError("apiserver said no to " + name)
        self.running.append(name)

    def finish(self, count=1):
        for _ in range(count):
            self.finished.append(self.running.pop(0))


def job(name, scanner="s1"):
    return {"metadata": {"name": name, "ownerReferences": [{"name": scanner, "uid": scanner + "-uid"}]}}


def key(name, scanner="s1"):
    return "{0}-uid/{1}".format(scanner, name)


class ScanQueueTests(unittest.TestCase):
    def setUp(self):
        self.cluster = FakeCluster()
        self.launched = []
        self.queue = scanqueue.ScanQueue(
            2, self.cluster.count_running, self.cluster.launch,
            on_launched=lambda k, b: self.launched.append(k),
        )

    def test_launches_up_to_the_limit_then_queues_in_order(self):
        states = [self.queue.submit(key("j{0}".format(i)), job("j{0}".format(i))) for i in range(5)]
        self.assertEqual(states, ["launched", "launched", "queued", "queued", "queued"])
        self.assertEqual(self.cluster.running, ["j0", "j1"])
        self.assertEqual(self.queue.pending_keys(), [key("j2"), key("j3"), key("j4")])
        self.assertEqual(len(self.queue), 3)
        self.assertEqual(self.launched, [key("j0"), key("j1")])

        self.cluster.finish(1)
        self.assertEqual(self.queue.drain(), [key("j2")])
        self.assertEqual(self.cluster.running, ["j1", "j2"])

        self.cluster.finish(2)
        self.assertEqual(self.queue.drain(), [key("j3"), key("j4")])
        self.assertEqual(self.cluster.running, ["j3", "j4"])
        self.assertEqual(len(self.queue), 0)
        self.assertEqual(self.queue.drain(), [])
        self.assertEqual(self.queue.state(key("j4")), "launched")

    def test_running_jobs_from_elsewhere_count(self):
        self.cluster.running = ["cron-born-1", "cron-born-2"]
        self.assertEqual(self.queue.submit(key("j0"), job("j0")), "queued")
        self.cluster.finish(1)
        self.assertEqual(self.queue.drain(), [key("j0")])

    def test_resubmitting_a_launched_or_queued_key_is_a_no_op(self):
        self.assertEqual(self.queue.submit(key("j0"), job("j0")), "launched")
        self.assertEqual(self.queue.submit(key("j0"), job("j0")), "launched")
        self.assertEqual(self.cluster.running, ["j0"])
        self.cluster.running = ["a", "b"]
        self.assertEqual(self.queue.submit(key("j1"), job("j1")), "queued")
        self.assertEqual(self.queue.submit(key("j1"), job("j1")), "queued")
        self.assertEqual(len(self.queue), 1)

    def test_no_limit(self):
        queue = scanqueue.ScanQueue(0, self.cluster.count_running, self.cluster.launch)
        for i in range(6):
            self.assertEqual(queue.submit(key("j{0}".format(i)), job("j{0}".format(i))), "launched")
        self.assertEqual(len(self.cluster.running), 6)
        self.assertEqual(self.cluster.count_calls, 0)

    def test_failed_launch_is_recorded_and_frees_the_slot(self):
        cluster = FakeCluster(fail_names=["bad"])
        queue = scanqueue.ScanQueue(1, cluster.count_running, cluster.launch)
        self.assertEqual(queue.submit(key("bad"), job("bad")), "failed")
        self.assertIn("apiserver said no", queue.error(key("bad")))
        self.assertEqual(queue.submit(key("good"), job("good")), "launched")
        # A failed key can be submitted again after forget().
        queue.forget(key("bad"))
        self.assertIsNone(queue.state(key("bad")))

    def test_still_wanted_drops_entries(self):
        gone = {key("j1")}
        queue = scanqueue.ScanQueue(1, self.cluster.count_running, self.cluster.launch, still_wanted=lambda k, b: k not in gone)
        queue.submit(key("j0"), job("j0"))
        queue.submit(key("j1"), job("j1"))
        queue.submit(key("j2"), job("j2"))
        self.cluster.finish(1)
        self.assertEqual(queue.drain(), [key("j2")])
        self.assertEqual(queue.state(key("j1")), "dropped")
        self.assertEqual(self.cluster.running, ["j2"])

    def test_forget_by_prefix(self):
        self.cluster.running = ["a", "b"]
        self.queue.submit(key("j0", "s1"), job("j0", "s1"))
        self.queue.submit(key("j1", "s1"), job("j1", "s1"))
        self.queue.submit(key("j2", "s2"), job("j2", "s2"))
        self.assertTrue(self.queue.has_pending("s1-uid/"))
        self.queue.forget("s1-uid/")
        self.assertFalse(self.queue.has_pending("s1-uid/"))
        self.assertEqual(self.queue.pending_keys(), [key("j2", "s2")])
        self.assertIsNone(self.queue.state(key("j0", "s1")))
        self.cluster.running = []
        self.assertEqual(self.queue.drain(), [key("j2", "s2")])

    def test_count_failure_keeps_everything_queued(self):
        def broken():
            raise RuntimeError("503")

        queue = scanqueue.ScanQueue(2, broken, self.cluster.launch)
        self.assertEqual(queue.submit(key("j0"), job("j0")), "queued")
        self.assertEqual(queue.drain(), [])
        self.assertEqual(self.cluster.running, [])

    def test_on_launched_sees_key_and_body(self):
        seen = []
        queue = scanqueue.ScanQueue(5, self.cluster.count_running, self.cluster.launch, on_launched=lambda k, b: seen.append((k, b["metadata"]["name"])))
        queue.submit(key("j0"), job("j0"))
        self.assertEqual(seen, [(key("j0"), "j0")])

    def test_on_launched_errors_do_not_break_the_queue(self):
        def boom(k, b):
            raise RuntimeError("patch failed")

        queue = scanqueue.ScanQueue(5, self.cluster.count_running, self.cluster.launch, on_launched=boom)
        self.assertEqual(queue.submit(key("j0"), job("j0")), "launched")

    def test_concurrent_submits_respect_the_limit(self):
        barrier = threading.Barrier(8)
        results = []

        def worker(i):
            barrier.wait()
            results.append(self.queue.submit(key("j{0}".format(i)), job("j{0}".format(i))))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("launched"), 2)
        self.assertEqual(results.count("queued"), 6)
        self.assertEqual(len(self.cluster.running), 2)
        self.assertEqual(len(self.queue), 6)


class DrainerTests(unittest.TestCase):
    def test_run_drainer_drains_until_stopped(self):
        cluster = FakeCluster()
        queue = scanqueue.ScanQueue(1, cluster.count_running, cluster.launch)
        queue.submit(key("j0"), job("j0"))
        queue.submit(key("j1"), job("j1"))
        stop = threading.Event()
        ticks = []

        def fake_sleep(seconds):
            ticks.append(seconds)
            cluster.finish(1)
            if len(ticks) == 2:
                stop.set()
            return stop.is_set()

        scanqueue.run_drainer(queue, 7, stop, sleep=fake_sleep)
        self.assertEqual(ticks, [7, 7])
        self.assertEqual(cluster.finished + cluster.running, ["j0", "j1"])
        self.assertEqual(len(queue), 0)

    def test_start_drainer_thread_stops(self):
        cluster = FakeCluster()
        queue = scanqueue.ScanQueue(1, cluster.count_running, cluster.launch)
        thread, stop = scanqueue.start_drainer(queue, 0.01)
        self.assertTrue(thread.daemon)
        stop.set()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
