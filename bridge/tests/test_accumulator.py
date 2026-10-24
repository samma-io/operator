"""Findings are collected per run until the run message; stragglers wait."""

import json
import unittest

from .helpers import Clock, finding, run  # noqa: F401
from samma_bridge import messages
from samma_bridge.accumulator import Accumulator


def parse(data):
    return messages.parse(json.dumps(data))


class AccumulatorTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.acc = Accumulator(straggler_wait=30, idle_timeout=3600, clock=self.clock)

    def test_findings_then_run(self):
        self.assertEqual(self.acc.add(parse(finding(checkId="SAMMA-A-ONE"))), [])
        self.assertEqual(self.acc.add(parse(finding(checkId="SAMMA-A-TWO"))), [])
        self.assertEqual(len(self.acc), 1)
        done = self.acc.add(parse(run(findingCount=2)))
        self.assertEqual(len(done), 1)
        fin = done[0]
        self.assertTrue(fin.complete)
        self.assertEqual(fin.received, 2)
        self.assertEqual(fin.expected, 2)
        self.assertEqual([f.check_id for f in fin.findings], ["SAMMA-A-ONE", "SAMMA-A-TWO"])
        self.assertEqual(fin.run.outcome, "succeeded")
        self.assertEqual(fin.run_received_at, self.clock.now)
        self.assertEqual(len(self.acc), 0)

    def test_run_with_no_findings_finishes_at_once(self):
        done = self.acc.add(parse(run(findingCount=0)))
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0].findings, [])
        self.assertTrue(done[0].complete)

    def test_stragglers_after_the_run_message_complete_the_run(self):
        self.acc.add(parse(finding(checkId="SAMMA-A-ONE")))
        self.assertEqual(self.acc.add(parse(run(findingCount=3))), [])
        self.clock.advance(5)
        self.assertEqual(self.acc.due(), [])
        self.assertEqual(self.acc.add(parse(finding(checkId="SAMMA-A-TWO"))), [])
        done = self.acc.add(parse(finding(checkId="SAMMA-A-THREE")))
        self.assertEqual(len(done), 1)
        self.assertTrue(done[0].complete)
        self.assertEqual(done[0].received, 3)

    def test_incomplete_run_is_finalised_after_the_wait(self):
        self.acc.add(parse(finding()))
        self.acc.add(parse(run(findingCount=3)))
        self.clock.advance(29)
        self.assertEqual(self.acc.due(), [])
        self.clock.advance(1)
        done = self.acc.due()
        self.assertEqual(len(done), 1)
        self.assertFalse(done[0].complete)
        self.assertEqual((done[0].received, done[0].expected), (1, 3))
        self.assertEqual(len(self.acc), 0)

    def test_zero_wait_finalises_immediately(self):
        acc = Accumulator(straggler_wait=0, clock=self.clock)
        done = acc.add(parse(run(findingCount=5)))
        self.assertEqual(len(done), 1)
        self.assertFalse(done[0].complete)

    def test_runs_do_not_mix(self):
        self.acc.add(parse(finding(runId="run-a", checkId="SAMMA-A-ONE")))
        self.acc.add(parse(finding(runId="run-b", checkId="SAMMA-B-ONE")))
        self.acc.add(parse(finding(runId="run-a", scanner="dns-scanner", checkId="SAMMA-DNS-ONE")))
        self.assertEqual(len(self.acc), 3)
        done = self.acc.add(parse(run(runId="run-a", findingCount=1)))
        self.assertEqual([f.check_id for f in done[0].findings], ["SAMMA-A-ONE"])
        self.assertEqual(len(self.acc), 2)

    def test_runs_without_a_run_message_expire(self):
        self.acc.add(parse(finding(runId="lost")))
        self.acc.add(parse(finding(runId="lost", checkId="SAMMA-A-TWO")))
        self.acc.add(parse(finding(runId="fresh")))
        self.clock.advance(3599)
        self.assertEqual(self.acc.expire(), [])
        self.clock.advance(1)
        self.acc.add(parse(finding(runId="fresh", checkId="SAMMA-A-TWO")))  # keeps "fresh" alive
        dropped = self.acc.expire()
        self.assertEqual(dropped, [(("tls-scanner", None, "api.example.com", "lost"), 2)])
        self.assertEqual(len(self.acc), 1)

    def test_a_run_waiting_for_stragglers_is_not_expired(self):
        self.acc.add(parse(run(findingCount=1)))
        self.clock.advance(3600)
        self.assertEqual(self.acc.expire(), [])
        self.assertEqual(len(self.acc.due()), 1)

    def test_findings_after_finalisation_start_a_new_pending_run(self):
        self.acc.add(parse(run(findingCount=0)))
        self.assertEqual(self.acc.add(parse(finding())), [])
        self.assertEqual(len(self.acc), 1)


if __name__ == "__main__":
    unittest.main()
