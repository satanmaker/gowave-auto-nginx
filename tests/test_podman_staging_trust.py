#!/usr/bin/env python3
"""Suite nonroot: the pinned Staging roots, the anchors they become, and the bundle.

``DP-09``, ``DP-10`` and ``DP-11`` decide what a Staging run trusts. The vendored
roots and their manifest, the product's own ``verify_staging_roots``,
``build_runtime_ca_bundle``, ``create_ssl_context``,
``apply_xray_trust_anchors`` and ``apply_mihomo_trust_anchors`` are real, and
``openssl`` makes the trust decision these cases read.

Each clause is then damaged on its own: a pinned set that resolves fewer roots, a
manifest that describes less than the directory holds, a digest that no longer
matches, a refusal that stopped naming the digest or the issuer, an outbound
whose anchors are missing or not ``verify``, a REALITY outbound rewritten, a
bundle that names no Staging root, a context that stopped verifying, and a build
that touched the machine's own trust store or environment.
"""
import os
import shutil
import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.live_vps import tls as live_tls  # noqa: E402
from tools.live_vps import traffic as live_traffic  # noqa: E402
from tools.podman_e2e import catalog, staging_trust  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASES = {
    staging_trust.DP11_CASE_ID: staging_trust.case_staging_roots_are_pinned,
    staging_trust.DP10_CASE_ID: staging_trust.case_xray_outbounds_carry_anchors,
    staging_trust.DP09_CASE_ID: staging_trust.case_staging_and_public_chains_are_trusted,
}

#: What each damage is meant to make its case say, so a probe that went red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    ("DP-11", "roots-missing"): "resolves 3 roots",
    ("DP-11", "manifest-gap"): "so the manifest is not the whole pinned set",
    ("DP-11", "digest-drift"): "do not hash to the digest pins.json records",
    ("DP-11", "digest-refusal-silent"): "which does not name the digest it compared",
    ("DP-11", "issuer-refusal-silent"): "so an intermediate could be pinned as a root",
    ("DP-10", "anchor-not-injected"): "certificate entries for",
    ("DP-10", "anchor-usage-loose"): "an entry that is not 'verify' is not a trust anchor",
    ("DP-10", "anchor-mutates-input"):
        "modified the outbound it was handed instead of returning an anchored copy",
    ("DP-10", "reality-rewritten"): "a REALITY outbound was rewritten",
    ("DP-09", "bundle-without-staging"): "names no pinned Staging root",
    ("DP-09", "context-not-verifying"): "the context built from the Staging bundle verifies mode",
    ("DP-09", "environment-touched"): "the trust environment changed from",
    ("DP-09", "system-bundle-rewritten"): "changed while the Staging bundle was built",
}

_REAL_ROOTS = live_tls.verify_staging_roots
_REAL_ANCHORS = live_traffic.apply_xray_trust_anchors
_REAL_BUNDLE = live_tls.build_runtime_ca_bundle
_REAL_FIND_BUNDLE = live_tls.find_system_ca_bundle
_REAL_CONTEXT = live_tls.create_ssl_context


def _roots_missing_one(*_args, **_kwargs):
    return list(_REAL_ROOTS())[:3]


def _digest_that_drifted(_pem):
    return "0" * 64


def _verify_that_refuses_with(message):
    """A reader that answers a directory with ``message`` and the real set otherwise."""
    def verify(directory=None):
        if directory is None:
            return _REAL_ROOTS()
        raise ValueError(message)
    return verify


def _anchors_not_injected(outbound, mode):
    anchored = _REAL_ANCHORS(outbound, mode)
    if anchored is outbound:
        return anchored
    settings = (anchored.get("streamSettings") or {}).get("tlsSettings") or {}
    settings.pop("certificates", None)
    return anchored


def _anchors_with_a_loose_usage(outbound, mode):
    anchored = _REAL_ANCHORS(outbound, mode)
    settings = (anchored.get("streamSettings") or {}).get("tlsSettings") or {}
    for entry in settings.get("certificates") or []:
        entry["usage"] = "trusted"
    return anchored


def _anchors_that_mutate_the_input(outbound, mode):
    anchored = _REAL_ANCHORS(outbound, mode)
    settings = (outbound.get("streamSettings") or {}).get("tlsSettings") or {}
    source = (anchored.get("streamSettings") or {}).get("tlsSettings") or {}
    settings["certificates"] = source.get("certificates") or []
    return outbound


def _anchors_every_outbound(outbound, mode):
    anchored = _REAL_ANCHORS(outbound, mode)
    if anchored is outbound and mode == "staging":
        anchored = {**outbound}
        anchored["streamSettings"] = {
            **(outbound.get("streamSettings") or {}),
            "tlsSettings": {
                "certificates": [
                    {"usage": "verify", "certificateFile": str(path)}
                    for path, _meta in _REAL_ROOTS()
                ],
            },
        }
    return anchored


def _real_bundle(mode, output_path, staging_dir):
    """The product's builder, called the way the caller called it."""
    if staging_dir is None:
        return _REAL_BUNDLE(mode, output_path=output_path)
    return _REAL_BUNDLE(mode, output_path=output_path, staging_dir=staging_dir)


def _bundle_without_the_staging_roots(mode, output_path=None, staging_dir=None):
    del mode, staging_dir
    target = Path(output_path)
    target.write_bytes(_REAL_FIND_BUNDLE().read_bytes())
    return target


def _bundle_that_touches_the_environment(mode, output_path=None, staging_dir=None):
    target = _real_bundle(mode, output_path, staging_dir)
    os.environ["SSL_CERT_FILE"] = str(target)
    return target


def _system_bundle_rewritten(workdir):
    """A build that appends to the store it was handed, on a copy of it."""
    copy = Path(workdir) / "system-store.pem"
    copy.write_bytes(_REAL_FIND_BUNDLE().read_bytes())

    def build(mode, output_path=None, staging_dir=None):
        target = _real_bundle(mode, output_path, staging_dir)
        with copy.open("ab") as handle:
            handle.write(b"\n# rewritten by the damaged build\n")
        return target

    return [
        mock.patch.object(live_tls, "find_system_ca_bundle", lambda: copy),
        mock.patch.object(live_tls, "build_runtime_ca_bundle", build),
    ]


def _context_that_trusts_anything(bundle):
    del bundle
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _damages(workdir):
    return {
        "roots-missing": [
            mock.patch.object(live_tls, "verify_staging_roots", _roots_missing_one),
        ],
        "manifest-gap": [
            mock.patch.object(staging_trust, "STAGING_DIR", _directory_with_an_extra_pem(workdir)),
        ],
        "digest-drift": [
            mock.patch.object(staging_trust, "_der_sha256", _digest_that_drifted),
        ],
        "digest-refusal-silent": [
            mock.patch.object(
                live_tls, "verify_staging_roots",
                _verify_that_refuses_with("the pinned set does not match the vendored files")),
        ],
        "issuer-refusal-silent": [
            mock.patch.object(
                live_tls, "verify_staging_roots",
                _verify_that_refuses_with(
                    "Digest mismatch on a pinned root; the vendored file was refused")),
        ],
        "anchor-not-injected": [
            mock.patch.object(
                live_traffic, "apply_xray_trust_anchors", _anchors_not_injected),
        ],
        "anchor-usage-loose": [
            mock.patch.object(
                live_traffic, "apply_xray_trust_anchors", _anchors_with_a_loose_usage),
        ],
        "anchor-mutates-input": [
            mock.patch.object(
                live_traffic, "apply_xray_trust_anchors", _anchors_that_mutate_the_input),
        ],
        "reality-rewritten": [
            mock.patch.object(
                live_traffic, "apply_xray_trust_anchors", _anchors_every_outbound),
        ],
        "bundle-without-staging": [
            mock.patch.object(
                live_tls, "build_runtime_ca_bundle", _bundle_without_the_staging_roots),
        ],
        "context-not-verifying": [
            mock.patch.object(live_tls, "create_ssl_context", _context_that_trusts_anything),
        ],
        "environment-touched": [
            mock.patch.object(
                live_tls, "build_runtime_ca_bundle", _bundle_that_touches_the_environment),
        ],
        "system-bundle-rewritten": _system_bundle_rewritten(workdir),
    }


def _directory_with_an_extra_pem(workdir):
    """A copy of the vendored set holding one certificate its manifest does not name."""
    target = Path(workdir) / "manifest-gap"
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for item in staging_trust.STAGING_DIR.iterdir():
        (target / item.name).write_bytes(item.read_bytes())
    pinned = sorted(path.name for path in target.glob("*.pem"))
    (target / "an-extra-intermediate.pem").write_bytes((target / pinned[0]).read_bytes())
    return target


def run_case(case_id, damage=None, workdir=None):
    """Run one case, optionally with one damaged behaviour; return (facts, refusal)."""
    patchers = _damages(workdir)[damage] if damage else []
    for patcher in patchers:
        patcher.start()
    try:
        return CASES[case_id](object(), SimpleNamespace(topology="aio")), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class TestStagingTrustRegistration(unittest.TestCase):
    """Each id is registered on both contours with its own callable."""

    def test_every_id_is_registered_on_both_contours(self):
        registry = catalog.driver_registry()
        for case_id, function in CASES.items():
            with self.subTest(case=case_id):
                self.assertIn(case_id, registry)
                self.assertEqual(set(registry[case_id]), set(TOPOLOGIES))
                for topology in TOPOLOGIES:
                    self.assertEqual(
                        registry[case_id][topology]["driver"],
                        f"staging_trust:{function.__name__}",
                    )

    def test_every_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])


class TestStagingTrustCases(unittest.TestCase):
    """Every case holds on its contour, and its evidence is what the catalog records."""

    def test_every_case_holds_on_both_contours(self):
        for case_id in CASES:
            for topology in TOPOLOGIES:
                with self.subTest(case=case_id, topology=topology):
                    facts = CASES[case_id](object(), SimpleNamespace(topology=topology))
                    self.assertTrue(facts)

    def test_every_evidence_set_is_what_the_catalog_records(self):
        registry = catalog.driver_registry()
        for case_id in CASES:
            with self.subTest(case=case_id):
                facts, refusal = run_case(case_id)
                self.assertIsNone(refusal)
                self.assertEqual(sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_the_four_pinned_roots_are_reproducible_and_read_from_disk(self):
        facts, refusal = run_case(staging_trust.DP11_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["pinned_roots"], 4)
        self.assertEqual(facts["digests_recomputed"], 4)
        self.assertTrue(facts["manifest_matches_directory"])
        self.assertEqual(facts["bundle_builder_network_imports"], "")
        self.assertEqual(facts["pins_record_provenance"], 4)
        for key in ("missing_file_refusal", "extra_pem_refusal", "tampered_digest_refusal",
                    "short_manifest_refusal", "not_self_signed_refusal"):
            self.assertTrue(facts[key], key)

    def test_a_tls_outbound_carries_one_verify_anchor_per_root_and_only_there(self):
        facts, refusal = run_case(staging_trust.DP10_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["pinned_roots"], 4)
        self.assertEqual(facts["anchors_injected"], 4)
        self.assertEqual(facts["anchor_usage"], "verify,verify,verify,verify")
        self.assertTrue(facts["input_outbound_unchanged"])
        self.assertTrue(facts["reality_untouched"])
        self.assertTrue(facts["production_injects_none"])
        self.assertTrue(facts["existing_anchor_preserved"])
        self.assertTrue(facts["anchors_are_files"])
        self.assertTrue(facts["allow_insecure_absent"])

    def test_the_staging_bundle_trusts_both_chains_and_nothing_global_changed(self):
        facts, refusal = run_case(staging_trust.DP09_CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["staging_root_trusted"])
        self.assertTrue(facts["public_root_trusted"])
        self.assertFalse(facts["untrusted_authority_trusted"])
        self.assertEqual(facts["verify_mode"], "CERT_REQUIRED")
        self.assertTrue(facts["check_hostname"])
        self.assertTrue(facts["system_bundle_unchanged"])
        self.assertTrue(facts["trust_environment_unchanged"])
        self.assertEqual(facts["bypass_directives"], 0)
        self.assertGreater(facts["staging_bytes"], facts["public_bytes"])


class TestStagingTrustDamage(unittest.TestCase):
    """Each clause is damaged on its own and its case refuses for that reason."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-staging-test-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def assert_refused(self, damage, case_id=None):
        case_id = case_id or next(
            key for key in CASES if (key, damage) in EXPECTED_REFUSALS)
        _, refusal = run_case(case_id, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make {case_id} refuse")
        self.assertIn(EXPECTED_REFUSALS[(case_id, damage)], refusal)

    def test_a_pinned_set_that_lost_a_root_is_refused(self):
        self.assert_refused("roots-missing")

    def test_a_manifest_that_describes_less_than_the_directory_holds_is_refused(self):
        self.assert_refused("manifest-gap")

    def test_a_vendored_root_that_no_longer_matches_its_digest_is_refused(self):
        self.assert_refused("digest-drift")

    def test_a_digest_refusal_that_names_no_digest_is_refused(self):
        self.assert_refused("digest-refusal-silent")

    def test_an_issuer_refusal_that_names_no_issuer_is_refused(self):
        self.assert_refused("issuer-refusal-silent")

    def test_an_outbound_without_anchors_is_refused(self):
        self.assert_refused("anchor-not-injected")

    def test_an_anchor_that_is_not_a_verify_entry_is_refused(self):
        self.assert_refused("anchor-usage-loose")

    def test_an_anchor_call_that_mutates_its_input_is_refused(self):
        self.assert_refused("anchor-mutates-input")

    def test_a_reality_outbound_that_was_rewritten_is_refused(self):
        self.assert_refused("reality-rewritten")

    def test_a_bundle_without_a_staging_root_is_refused(self):
        self.assert_refused("bundle-without-staging")

    def test_a_context_that_stopped_verifying_is_refused(self):
        self.assert_refused("context-not-verifying")

    def test_a_build_that_touched_the_trust_environment_is_refused(self):
        self.addCleanup(os.environ.pop, "SSL_CERT_FILE", None)
        self.assert_refused("environment-touched")

    def test_a_build_that_rewrote_the_system_store_is_refused(self):
        self.assert_refused("system-bundle-rewritten")


if __name__ == "__main__":
    unittest.main()
