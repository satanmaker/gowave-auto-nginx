#!/usr/bin/env python3
"""Suite nonroot: the mode-specific CA bundle, and what each mode trusts.

``DP-12`` is a harness-side sentence about files, so it runs here whole: the
production half is this machine's own bundle, the Staging half is the four
vendored roots, and ``openssl`` decides every trust question. Nothing about it
needs a container, which is why the case can be driven directly instead of
through a run.

Each clause is then damaged on its own — a system bundle that already carries a
Staging root, a pinned name that collides with a public one, a verifier that
trusts everything, a context that verifies nothing, a builder that accepts any
mode — so each assertion is seen to fail for the reason it protects.
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.live_vps import tls  # noqa: E402
from tools.podman_e2e import catalog, trust_bundle  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASE = trust_bundle.case_production_bundle_excludes_staging

#: What each damage is meant to make the case say, so a probe that goes red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "system-bundle-carries-staging":
        "the production bundle carries a Let's Encrypt Staging marker",
    "staging-cn-collides":
        "so a pinned Staging root is a trust anchor in production mode",
    "staging-trusted-in-production": "is trusted by the production bundle",
    "context-does-not-verify": "the context built from the production bundle verifies mode",
    "unknown-mode-accepted": "an unknown ACME mode was answered with",
    "bundle-mode-too-loose": "not 0600",
}

_REAL_BUILD = trust_bundle.build_runtime_ca_bundle
_REAL_VERIFY = trust_bundle.verify_staging_roots


def _pinned_names_colliding():
    """The four pinned roots, one of them renamed to a public root's name."""
    colliding = []
    for index, (path, meta) in enumerate(_REAL_VERIFY()):
        if index == 0:
            meta = dict(meta, subject_cn=trust_bundle.PUBLIC_ROOT_NAME)
        colliding.append((path, meta))
    return colliding


def _verifier_that_trusts_everything(_bundle, _certificate):
    return True, "ok"


def _context_that_verifies_nothing(_bundle):
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _builder_that_accepts_any_mode(acme_mode, output_path=None, **_kwargs):
    """An unknown mode is answered with the production bundle instead of refused."""
    mode = acme_mode if acme_mode in ("production", "staging") else "production"
    return _REAL_BUILD(mode, output_path=output_path)


def _bundle_with_a_loose_mode(acme_mode, output_path=None, **_kwargs):
    """A production bundle every local user can read."""
    real = _REAL_BUILD(acme_mode, output_path=output_path)
    if acme_mode == "production":
        real.chmod(0o644)
    return real


def _damages(workdir):
    """The patches each damage installs; one of them needs a file on disk."""
    built = {}

    def bundle_that_carries_staging(acme_mode, output_path=None, **_kwargs):
        """A production bundle that is the staging one, and the system bundle beside it."""
        if acme_mode != "production":
            return _REAL_BUILD(acme_mode, output_path=output_path)
        target = Path(output_path) if output_path else workdir / "production.pem"
        target.write_bytes(
            _REAL_BUILD("staging", output_path=workdir / "staging-src.pem").read_bytes())
        target.chmod(0o600)
        built["production"] = target
        return target

    return {
        "system-bundle-carries-staging": [
            mock.patch.object(trust_bundle, "build_runtime_ca_bundle", bundle_that_carries_staging),
            mock.patch.object(trust_bundle, "find_system_ca_bundle", lambda: built["production"]),
        ],
        "staging-cn-collides": [
            mock.patch.object(trust_bundle, "verify_staging_roots", _pinned_names_colliding),
        ],
        "staging-trusted-in-production": [
            mock.patch.object(trust_bundle, "_openssl_verify", _verifier_that_trusts_everything),
        ],
        "context-does-not-verify": [
            mock.patch.object(trust_bundle, "create_ssl_context", _context_that_verifies_nothing),
        ],
        "unknown-mode-accepted": [
            mock.patch.object(trust_bundle, "build_runtime_ca_bundle", _builder_that_accepts_any_mode),
        ],
        "bundle-mode-too-loose": [
            mock.patch.object(trust_bundle, "build_runtime_ca_bundle", _bundle_with_a_loose_mode),
        ],
    }


def run_case(topology="aio", damage=None, workdir=None, extra_patches=()):
    """Run the case, optionally with one damaged behaviour; return (facts, refusal)."""
    patchers = list(_damages(workdir)[damage]) if damage else []
    patchers.extend(extra_patches)
    for patcher in patchers:
        patcher.start()
    try:
        return CASE(object(), SimpleNamespace(topology=topology)), None
    except AssertionError as error:
        return None, str(error)
    finally:
        for patcher in reversed(patchers):
            patcher.stop()


class TestTrustBundleRegistration(unittest.TestCase):
    """The case is registered on both contours and mapped to its requirement."""

    def test_the_id_is_registered_on_both_contours_with_its_own_callable(self):
        registry = catalog.driver_registry()
        self.assertIn(trust_bundle.DP12_CASE_ID, registry)
        self.assertEqual(set(registry[trust_bundle.DP12_CASE_ID]), set(TOPOLOGIES))
        for topology in TOPOLOGIES:
            self.assertEqual(
                registry[trust_bundle.DP12_CASE_ID][topology]["driver"],
                f"trust_bundle:{CASE.__name__}",
            )

    def test_the_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        entry = entries[trust_bundle.DP12_CASE_ID]
        self.assertEqual(entry["driver_status"], "implemented")
        self.assertEqual(entry["drivers"], registry[trust_bundle.DP12_CASE_ID])


class TestProductionBundleCase(unittest.TestCase):
    """The case holds here, and its evidence is what the catalog records."""

    def test_the_case_holds_on_both_contours(self):
        for topology in TOPOLOGIES:
            with self.subTest(topology=topology):
                facts, refusal = run_case(topology)
                self.assertIsNone(refusal)
                self.assertTrue(facts)

    def test_the_evidence_is_exactly_what_the_catalog_records(self):
        facts, _ = run_case()
        registry = catalog.driver_registry()
        self.assertEqual(
            sorted(facts), registry[trust_bundle.DP12_CASE_ID]["aio"]["evidence"])

    def test_the_facts_are_the_verdict_the_sentence_names(self):
        facts, _ = run_case()
        self.assertEqual(
            facts["production_bytes"], os.path.getsize(trust_bundle.find_system_ca_bundle()))
        self.assertFalse(facts["staging_marker_in_production"])
        self.assertEqual(facts["pinned_roots"], 4)
        self.assertTrue(facts["staging_root_trusted_by_staging"])
        self.assertFalse(facts["staging_root_trusted_by_production"])
        self.assertTrue(facts["public_root_trusted"])
        self.assertEqual(facts["verify_mode"], "CERT_REQUIRED")
        self.assertTrue(facts["check_hostname"])
        self.assertIn("staging-and-production", facts["unknown_mode_refusal"])
        self.assertGreater(facts["staging_bytes"], facts["production_bytes"])


class TestTrustBundleDamage(unittest.TestCase):
    """Each clause is damaged on its own and the case refuses for that reason."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-dp12-test-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def assert_refused(self, damage):
        _, refusal = run_case(damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make the case refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_system_bundle_that_carries_a_staging_root_is_refused(self):
        self.assert_refused("system-bundle-carries-staging")

    def test_a_pinned_name_that_collides_with_a_public_root_is_refused(self):
        self.assert_refused("staging-cn-collides")

    def test_the_collision_is_read_from_the_certificates_not_the_bundle_text(self):
        """A Debian/Ubuntu bundle is plain PEM, with no ``# <name>`` line per certificate.

        Arch's bundle prepends those comments, Debian's and Ubuntu's do not, so a
        check that searches the file's text for a subject name sees the collision
        on one distribution and not the other. The names have to come out of the
        certificates, and the collision must then be refused on both shapes.
        """
        real = trust_bundle.find_system_ca_bundle().read_bytes()
        plain = self.workdir / "plain-ca-bundle.pem"
        plain.write_bytes(
            b"\n".join(line for line in real.splitlines() if not line.startswith(b"#")) + b"\n")
        self.assertNotIn(b"ISRG Root X1", plain.read_bytes(),
                         "the stripped bundle still names the root in its text")
        _, refusal = run_case(
            damage="staging-cn-collides",
            workdir=self.workdir,
            extra_patches=[
                mock.patch.object(trust_bundle, "find_system_ca_bundle", lambda: plain),
                mock.patch.object(tls, "find_system_ca_bundle", lambda: plain),
            ],
        )
        self.assertIsNotNone(refusal, "a comment-less bundle hid the collision")
        self.assertIn(EXPECTED_REFUSALS["staging-cn-collides"], refusal)

    def test_a_verifier_that_trusts_the_staging_root_in_production_is_refused(self):
        self.assert_refused("staging-trusted-in-production")

    def test_a_context_that_verifies_nothing_is_refused(self):
        self.assert_refused("context-does-not-verify")

    def test_a_builder_that_accepts_any_mode_is_refused(self):
        self.assert_refused("unknown-mode-accepted")

    def test_a_bundle_any_local_user_can_read_is_refused(self):
        self.assert_refused("bundle-mode-too-loose")


if __name__ == "__main__":
    unittest.main()
