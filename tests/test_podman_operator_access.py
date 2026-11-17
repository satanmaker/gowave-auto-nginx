#!/usr/bin/env python3
"""Suite nonroot: the operator's input gate, its password and the access it installs.

``OP-01``, ``OP-02``, ``SSHID-01``, ``SSHID-02``, ``TSSH-01`` and ``TSSH-02`` are
Control-Machine sentences: they are decided by ``tools/live_vps/operator.py``
rather than by a running pair, so the cases are driven here whole instead of
quoted. The transport, the SFTP channel and ``ssh-keygen`` are the seams; the
remote is a model whose filesystem, modes, systemd answers and clock the case
reads back.

Each clause is then damaged on its own — a parser that accepts everything, a
controller that parses after it dials, a password that reaches a log line or an
environment variable, a known_hosts file left world-readable, a password read
before the host was confirmed, a temporary entry that replaces the provider's,
a one-minute expiry, and a cleanup reported as verified — so each assertion is
seen to fail for the reason it protects.
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

from tools.live_vps import operator  # noqa: E402
from tools.podman_e2e import catalog, operator_access  # noqa: E402

TOPOLOGIES = ("aio", "multi-node")

CASES = {
    operator_access.OP_CASE_ID: operator_access.case_domain_input_is_validated_before_network,
    operator_access.PASSWORD_CASE_ID: operator_access.case_password_is_hidden_and_unpersisted,
    operator_access.SSHID_CONFIRMED_CASE_ID: operator_access.case_confirmed_host_key_is_pinned,
    operator_access.SSHID_DECLINED_CASE_ID: operator_access.case_unconfirmed_host_key_aborts,
    operator_access.BOUNDED_CASE_ID: operator_access.case_temporary_key_is_bounded,
    operator_access.FALLBACK_CASE_ID: operator_access.case_failed_bootstrap_falls_back_to_timer,
}

#: What each damage is meant to make its case say, so a probe that went red on an
#: unrelated assertion is not read as a held clause.
EXPECTED_REFUSALS = {
    "parser-bypassed": "the controller contacted a host for invalid-ip",
    "validation-after-dial": "reaches its first bootstrap before it parses",
    "password-printed": "the password was printed to the controller's own output",
    "password-in-environment": "the password appeared in the environment",
    "known-hosts-mode-loosened": "the temporary known_hosts file is mode",
    "password-before-confirmation": "read a password",
    "existing-entry-replaced": "not the provider's entry beside exactly one temporary one",
    "expiry-shortened": "not a persistent two-hour bound",
    "cleanup-reported-verified": "does not name the timer as the remaining bound",
}

_REAL_BOOTSTRAP = operator._bootstrap_one
_REAL_SFTP_WRITE = operator._sftp_write
_REAL_CHMOD = os.chmod
_REAL_REMOTE = operator_access._Remote


def _source_with_the_parser_moved(workdir):
    """A controller that dials first and parses afterwards."""
    body = operator_access.OPERATOR.read_text(encoding="utf-8")
    line = "            validation_config = load_config(validation_path)\n"
    assert body.count(line) == 1
    moved = body.replace(line, "")
    target = workdir / "operator_moved.py"
    target.write_text(moved + "\n# moved\n" + line, encoding="utf-8")
    return target


def _bootstrap_that_prints_the_password(*args, **kwargs):
    print(operator_access._PROBE_PASSWORD)
    return _REAL_BOOTSTRAP(*args, **kwargs)


def _bootstrap_that_exports_the_password(*args, **kwargs):
    os.environ["GOWAVE_PROBE_PASSWORD"] = operator_access._PROBE_PASSWORD
    return _REAL_BOOTSTRAP(*args, **kwargs)


def _bootstrap_that_reads_the_password_first(*args, **kwargs):
    operator.getpass.getpass("probe: ")
    return _REAL_BOOTSTRAP(*args, **kwargs)


def _chmod_except_known_hosts(path, mode):
    if str(path).endswith("master_known_hosts"):
        return None
    return _REAL_CHMOD(path, mode)


def _sftp_write_that_replaces(sftp, path, content, mode):
    if path.endswith(".tmp"):
        content = content.rstrip("\n").splitlines()[-1] + "\n"
    return _REAL_SFTP_WRITE(sftp, path, content, mode)


class _VerifiedCleanup(_REAL_REMOTE):
    """A host whose rollback succeeds, so the fallback sentence is not exercised."""

    def _rollback(self):
        return 0, "", ""


def _damages(workdir):
    return {
        "parser-bypassed": [
            mock.patch.object(operator, "load_config", lambda path: object()),
        ],
        "validation-after-dial": [
            mock.patch.object(
                operator_access, "OPERATOR", _source_with_the_parser_moved(workdir)),
        ],
        "password-printed": [
            mock.patch.object(operator, "_bootstrap_one",
                              side_effect=_bootstrap_that_prints_the_password),
        ],
        "password-in-environment": [
            mock.patch.dict(os.environ, {}, clear=False),
            mock.patch.object(operator, "_bootstrap_one",
                              side_effect=_bootstrap_that_exports_the_password),
        ],
        "known-hosts-mode-loosened": [
            mock.patch.object(operator.os, "chmod", side_effect=_chmod_except_known_hosts),
        ],
        "password-before-confirmation": [
            mock.patch.object(operator, "_bootstrap_one",
                              side_effect=_bootstrap_that_reads_the_password_first),
        ],
        "existing-entry-replaced": [
            mock.patch.object(operator, "_sftp_write", side_effect=_sftp_write_that_replaces),
        ],
        "expiry-shortened": [
            mock.patch.object(operator, "TEMP_ACCESS_TTL_HOURS", 0.1),
        ],
        "cleanup-reported-verified": [
            mock.patch.object(operator_access, "_Remote", _VerifiedCleanup),
        ],
    }


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


class TestOperatorAccessRegistration(unittest.TestCase):
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
                        f"operator_access:{function.__name__}",
                    )

    def test_every_catalog_entry_is_what_the_registry_derives(self):
        registry = catalog.driver_registry()
        entries = {entry["id"]: entry for entry in catalog.load_catalog()["cases"]}
        for case_id in CASES:
            with self.subTest(case=case_id):
                entry = entries[case_id]
                self.assertEqual(entry["driver_status"], "implemented")
                self.assertEqual(entry["drivers"], registry[case_id])
                self.assertEqual(sorted(entry["topology"]), sorted(TOPOLOGIES))


class TestOperatorAccessCases(unittest.TestCase):
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
                self.assertEqual(
                    sorted(facts), registry[case_id]["aio"]["evidence"])

    def test_the_input_gate_refuses_every_class_without_dialling(self):
        facts, refusal = run_case(operator_access.OP_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["rejected_classes"].split(","),
                         ["invalid-ip", "duplicate-domain", "invalid-fqdn", "non-root-account"])
        self.assertEqual(facts["connections_before_validation"], 0)
        self.assertEqual(facts["valid_input_bootstraps"], 1)
        self.assertTrue(facts["validation_precedes_bootstrap"])
        self.assertEqual(facts["invalid_exit_code"], 1)

    def test_the_password_exists_in_one_call_and_no_document(self):
        facts, refusal = run_case(operator_access.PASSWORD_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["password_reads"], 1)
        self.assertTrue(facts["prompt_names_hidden"])
        for key in ("argv_mentions", "environment_mentions", "runtime_files_mentioning",
                    "stdout_mentions"):
            self.assertEqual(facts[key], 0, key)
        self.assertTrue(facts["authenticated"])
        self.assertTrue(facts["key_installed"])
        self.assertEqual(facts["ephemeral_key_mode"], "0o600")
        self.assertTrue(facts["password_cleared_after_auth"])

    def test_the_confirmed_host_key_is_the_key_that_was_pinned(self):
        facts, refusal = run_case(operator_access.SSHID_CONFIRMED_CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["known_hosts_matches_observed_key"])
        self.assertEqual(facts["known_hosts_mode"], "0o600")
        self.assertEqual(facts["known_hosts_lines"], 1)
        self.assertTrue(facts["password_authentication_proceeded"])
        self.assertEqual(facts["timer_state_at_bootstrap"], "active")

    def test_an_unconfirmed_host_key_stops_before_the_password(self):
        facts, refusal = run_case(operator_access.SSHID_DECLINED_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["password_reads"], 0)
        self.assertEqual(facts["remote_writes"], 0)
        self.assertEqual(facts["remote_commands"], 0)
        self.assertEqual(facts["timers_armed"], 0)
        self.assertFalse(facts["known_hosts_written"])
        self.assertTrue(facts["authorized_keys_unchanged"])

    def test_the_temporary_key_sits_beside_the_existing_one_under_its_timer(self):
        facts, refusal = run_case(operator_access.BOUNDED_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["authorized_keys_lines"], 2)
        self.assertTrue(facts["existing_entry_preserved"])
        self.assertEqual(facts["temporary_entries"], 1)
        self.assertTrue(facts["temporary_entry_restricted"])
        self.assertTrue(facts["timer_armed_before_key"])
        self.assertEqual(facts["timer_on_active_sec"], "2h")
        self.assertTrue(facts["timer_persistent"])
        self.assertEqual(facts["timer_state_at_bootstrap"], "active")

    def test_a_failed_bootstrap_leaves_the_timer_as_the_bound(self):
        facts, refusal = run_case(operator_access.FALLBACK_CASE_ID)
        self.assertIsNone(refusal)
        self.assertTrue(facts["failure"])
        self.assertEqual(facts["cleanup_attempts"], 1)
        self.assertFalse(facts["cleanup_verified"])
        self.assertTrue(facts["warning_names_the_timer"])
        self.assertEqual(facts["timers_still_armed"], 1)
        self.assertEqual(facts["timer_state"], "active")
        self.assertFalse(facts["key_installed"])
        self.assertTrue(facts["existing_entry_preserved"])


class TestOperatorAccessDamage(unittest.TestCase):
    """Each clause is damaged on its own and its case refuses for that reason."""

    def setUp(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="gowave-op-test-"))
        self.addCleanup(shutil.rmtree, self.workdir, True)

    def assert_refused(self, case_id, damage):
        _, refusal = run_case(case_id, damage=damage, workdir=self.workdir)
        self.assertIsNotNone(refusal, f"{damage} did not make {case_id} refuse")
        self.assertIn(EXPECTED_REFUSALS[damage], refusal)

    def test_a_parser_that_accepts_everything_is_refused(self):
        self.assert_refused(operator_access.OP_CASE_ID, "parser-bypassed")

    def test_a_controller_that_parses_after_dialling_is_refused(self):
        self.assert_refused(operator_access.OP_CASE_ID, "validation-after-dial")

    def test_a_password_that_reaches_a_log_line_is_refused(self):
        self.assert_refused(operator_access.PASSWORD_CASE_ID, "password-printed")

    def test_a_password_that_reaches_the_environment_is_refused(self):
        self.assert_refused(operator_access.PASSWORD_CASE_ID, "password-in-environment")

    def test_a_known_hosts_file_left_readable_is_refused(self):
        self.assert_refused(operator_access.SSHID_CONFIRMED_CASE_ID,
                            "known-hosts-mode-loosened")

    def test_a_password_read_before_confirmation_is_refused(self):
        self.assert_refused(operator_access.SSHID_DECLINED_CASE_ID,
                            "password-before-confirmation")

    def test_a_temporary_entry_that_replaces_the_providers_is_refused(self):
        self.assert_refused(operator_access.BOUNDED_CASE_ID, "existing-entry-replaced")

    def test_a_one_minute_expiry_is_refused(self):
        self.assert_refused(operator_access.BOUNDED_CASE_ID, "expiry-shortened")

    def test_a_cleanup_reported_as_verified_is_refused(self):
        self.assert_refused(operator_access.FALLBACK_CASE_ID, "cleanup-reported-verified")


if __name__ == "__main__":
    unittest.main()
