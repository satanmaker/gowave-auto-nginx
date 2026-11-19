#!/usr/bin/env python3
"""Suite nonroot: the ACME refusal table is read from three copies of one function.

`ACME-REJECT-ARB` claims that an arbitrary ACME directory is refused by the
Master and by the Worker, outside and inside the test-only opt-in, and that the
pinned fixture endpoint plus the Let's Encrypt allowlist are the only values
accepted. These tests hold the case on the shipped tree and then damage the
inputs it reads — the copies of the function, one refusal sentence, the
allowlist — so a case that stopped listening to the product fails here.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import acme_mode  # noqa: E402


class TestAcmeMode(unittest.TestCase):
    """The refusal table the case proves, and the branches that prove it."""

    def test_the_case_holds_on_the_shipped_product(self):
        evidence = acme_mode.case_arbitrary_directory_is_refused(None, None)
        self.assertEqual(evidence["function_copies"], 3)
        self.assertEqual(evidence["worker_copies_identical"], "True")
        self.assertEqual(evidence["pinned_endpoint"], acme_mode.FIXTURE)
        self.assertIn(acme_mode.ARBITRARY, evidence["arbitrary_inside_sentence"])
        self.assertIn("test-only ACME mode", evidence["arbitrary_inside_sentence"])
        self.assertIn("digest mismatch", evidence["unpinned_ca_sentence"])
        self.assertIn("GOWAVE_ACME_TEST_MODE=1", evidence["fixture_without_optin_sentence"])
        self.assertIn("refused_inputs", evidence)
        self.assertIn("arbitrary_outside", evidence["refused_inputs"])
        self.assertIn("fixture_pinned", evidence["accepted_inputs"])

    def test_the_three_copies_are_one_body(self):
        copies = acme_mode._copies()
        self.assertEqual([name for name, _body in copies], ["nginx.sh", "gowave-node-auto.sh",
                                                           "gowave-node-auto.sh"])
        self.assertEqual(len({body for _name, body in copies}), 1)

    # --- damage ------------------------------------------------------------

    def test_a_worker_copy_that_diverged_is_refused(self):
        body = acme_mode.FUNCTION.search(acme_mode.MASTER.read_text(encoding="utf-8")).group(0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            master = root / "nginx.sh"
            worker = root / "gowave-node-auto.sh"
            master.write_text(body, encoding="utf-8")
            worker.write_text(body + "\n" + body.replace("local server", "local value"),
                              encoding="utf-8")
            with mock.patch.object(acme_mode, "MASTER", master), \
                    mock.patch.object(acme_mode, "WORKER", worker):
                with self.assertRaises(AssertionError) as caught:
                    acme_mode.case_arbitrary_directory_is_refused(None, None)
        self.assertIn("no longer validate the ACME directory with the same function",
                      str(caught.exception))

    def test_a_worker_that_lost_a_copy_is_refused(self):
        body = acme_mode.FUNCTION.search(acme_mode.MASTER.read_text(encoding="utf-8")).group(0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            master = root / "nginx.sh"
            worker = root / "gowave-node-auto.sh"
            master.write_text(body, encoding="utf-8")
            worker.write_text(body, encoding="utf-8")
            with mock.patch.object(acme_mode, "MASTER", master), \
                    mock.patch.object(acme_mode, "WORKER", worker):
                with self.assertRaises(AssertionError) as caught:
                    acme_mode.case_arbitrary_directory_is_refused(None, None)
        self.assertIn("bod(ies)", str(caught.exception))

    def test_a_rewording_of_the_allowlist_sentence_is_refused(self):
        with mock.patch.object(acme_mode, "MASTER_SENTENCE", "an allowlist nobody printed"):
            with self.assertRaises(AssertionError) as caught:
                acme_mode.case_arbitrary_directory_is_refused(None, None)
        self.assertIn("does not name the two Let's Encrypt directories", str(caught.exception))

    def test_an_allowlist_that_stopped_accepting_staging_is_refused(self):
        with mock.patch.object(acme_mode, "STAGING", acme_mode.ARBITRARY):
            with self.assertRaises(AssertionError) as caught:
                acme_mode.case_arbitrary_directory_is_refused(None, None)
        self.assertIn("staging was refused", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
