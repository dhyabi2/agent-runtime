"""Laws for the shared model daemon's failure response.

modeld is shared by every agent on the box, so its backoff is a decision about all ten of them. One
slow call must not stop the swarm; no credit must stop it at once.
"""
import os, sys, time, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runtime"))
import modeld


class OneSlowCallIsNotAnOutage(unittest.TestCase):
    def setUp(self):
        modeld._state.update({"down_until": 0.0, "errors": 0, "consecutive": 0})

    def tearDown(self):
        modeld._state.update({"down_until": 0.0, "errors": 0, "consecutive": 0})

    def test_a_single_soft_failure_does_not_take_the_provider_down(self):
        """The defect: one TimeoutError set a 300s backoff for every agent on the box."""
        modeld._note_failure(hard=False)
        self.assertLessEqual(modeld._state["down_until"], time.time(),
                             "one slow call stopped the whole swarm")

    def test_it_takes_a_run_of_failures_to_declare_an_outage(self):
        for _ in range(modeld.FAIL_THRESHOLD - 1):
            modeld._note_failure(hard=False)
        self.assertLessEqual(modeld._state["down_until"], time.time())
        modeld._note_failure(hard=False)
        self.assertGreater(modeld._state["down_until"], time.time(), "a real run of failures must back off")

    def test_no_credit_is_believed_immediately(self):
        """HTTP 402 will not fix itself; retrying it is just spending time to be told no again."""
        modeld._note_failure(hard=True)
        self.assertGreater(modeld._state["down_until"], time.time() + modeld.BACKOFF_S - 5)

    def test_the_wait_grows_with_the_run_rather_than_starting_at_the_maximum(self):
        waits = []
        for _ in range(modeld.FAIL_THRESHOLD + 3):
            modeld._note_failure(hard=False)
            waits.append(modeld._state["down_until"] - time.time())
        backing_off = [w for w in waits if w > 0]
        self.assertGreater(len(backing_off), 1)
        self.assertLess(backing_off[0], modeld.BACKOFF_S, "the first backoff must not be the maximum")
        self.assertGreaterEqual(backing_off[-1], backing_off[0], "the wait must grow with the run")

    def test_a_success_ends_the_run(self):
        for _ in range(modeld.FAIL_THRESHOLD - 1):
            modeld._note_failure(hard=False)
        modeld._state["consecutive"] = 0          # what a successful call does
        modeld._note_failure(hard=False)
        self.assertLessEqual(modeld._state["down_until"], time.time(),
                             "failures either side of a success are not a run")

    def test_the_backoff_never_exceeds_the_configured_maximum(self):
        for _ in range(60):
            modeld._note_failure(hard=False)
        self.assertLessEqual(modeld._state["down_until"] - time.time(), modeld.BACKOFF_S + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
