#!/usr/bin/env python3
"""Suite nonroot: every Xray TLS outbound carries the fixture CA, and it is load-bearing.

`TLS-VERIFY-ANCHORS` claims three things at once — the anchor is present and
embedded in every TLS outbound, REALITY is left alone, and removing the anchor
is what makes the chain fail. These tests hold the case on the shipped helper
and then damage the three inputs it reads: the anchoring call, the two
authorities `openssl` is asked about, and the failure classifier. A case that
merely restated "the anchors are there" would pass with all three damaged.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import client_trust  # noqa: E402
from tools.podman_e2e import tls_anchors  # noqa: E402

EXPECTED_KEYS = (
    "anchor_usage",
    "anchored_tags",
    "anchors_embedded",
    "anchors_named_by_path",
    "chain_error_accepted",
    "container_ca_file",
    "fixture_ca_trusts_leaf",
    "input_unchanged",
    "non_chain_failure_refused",
    "reality_untouched",
    "unanchored_tags",
    "unrelated_ca_rejects_leaf",
    "verify_anchors_per_outbound",
    "without_anchor_error",
)


class TestTlsAnchors(unittest.TestCase):
    """The anchor the case proves, and the three ways it could be vacuous."""

    def test_the_case_holds_on_the_shipped_helper(self):
        evidence = tls_anchors.case_every_tls_outbound_carries_the_fixture_ca(None, None)
        self.assertEqual(tuple(sorted(evidence)), EXPECTED_KEYS)
        self.assertEqual(evidence["anchored_tags"], "trojan-tls,vmess-tls")
        self.assertEqual(evidence["unanchored_tags"], "trojan-tls,vmess-tls")
        self.assertEqual(evidence["anchor_usage"], "verify,verify")
        self.assertEqual(evidence["verify_anchors_per_outbound"], "1,1")
        self.assertEqual(evidence["anchors_named_by_path"], "0")
        self.assertEqual(evidence["anchors_embedded"], "True")
        self.assertEqual(evidence["reality_untouched"], "True")
        self.assertEqual(evidence["input_unchanged"], "True")
        self.assertEqual(evidence["fixture_ca_trusts_leaf"], "True")
        self.assertEqual(evidence["unrelated_ca_rejects_leaf"], "False")
        self.assertEqual(evidence["chain_error_accepted"], "True")
        self.assertEqual(evidence["non_chain_failure_refused"], "True")
        self.assertEqual(evidence["container_ca_file"], client_trust.CONTAINER_CA_FILE)

    def test_the_helper_leaves_the_unanchored_config_alone(self):
        original = tls_anchors._config()
        self.assertEqual(sorted(client_trust.unanchored_tls_outbounds(original)),
                         sorted(tls_anchors.TLS_TAGS))

    # --- damage ------------------------------------------------------------

    def test_an_outbound_that_lost_its_anchor_is_refused(self):
        real = client_trust.apply_xray_trust_anchors

        def drop_the_second(config, ca_path):
            anchored = real(config, ca_path)
            second = client_trust.tls_outbounds(anchored)[1]
            ((second.get("streamSettings") or {}).get("tlsSettings") or {}).pop(
                "certificates", None)
            return anchored

        with mock.patch.object(client_trust, "apply_xray_trust_anchors", drop_the_second):
            with self.assertRaises(AssertionError) as caught:
                tls_anchors.case_every_tls_outbound_carries_the_fixture_ca(None, None)
        self.assertIn("carries 0 certificate entr(ies)", str(caught.exception))

    def test_two_authorities_that_are_one_are_refused(self):
        real = tls_anchors._mint_chain

        def aliased(directory):
            ca, leaf, _unrelated = real(directory)
            return ca, leaf, ca

        with mock.patch.object(tls_anchors, "_mint_chain", aliased):
            with self.assertRaises(AssertionError) as caught:
                tls_anchors.case_every_tls_outbound_carries_the_fixture_ca(None, None)
        self.assertIn("a CA that never saw the leaf reported it as trusted",
                      str(caught.exception))

    def test_a_classifier_that_accepts_any_failure_is_refused(self):
        with mock.patch.object(client_trust, "verify_chain_failure", return_value=None):
            with self.assertRaises(AssertionError) as caught:
                tls_anchors.case_every_tls_outbound_carries_the_fixture_ca(None, None)
        self.assertIn("a closed port was accepted as an untrusted-anchor result",
                      str(caught.exception))


if __name__ == "__main__":
    unittest.main()
