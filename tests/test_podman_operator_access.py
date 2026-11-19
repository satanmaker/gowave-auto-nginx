#!/usr/bin/env python3
"""Suite nonroot: the operator's input gate, its password and the access it installs.

``OP-01``, ``OP-02``, ``SSHID-01``, ``SSHID-02``, ``TSSH-01``, ``TSSH-02`` and
``BOOT-02`` are Control-Machine sentences: they are decided by
``tools/live_vps/operator.py`` rather than by a running pair, so the cases are
driven here whole instead of quoted. The transport, the SFTP channel and
``ssh-keygen`` are the seams; the remote is a model whose filesystem, modes,
systemd answers and clock the case reads back.

Each clause is then damaged on its own — a parser that accepts everything, a
controller that parses after it dials, a password that reaches a log line or an
environment variable, a known_hosts file left world-readable, a password read
before the host was confirmed, a temporary entry that replaces the provider's,
a one-minute expiry, a cleanup reported as verified, a revocation that drops a
host or gives up after one it cannot reach, one that reports a pass without
running the script, one that removes the provider's own entry, one that leaves
the timer files behind, and one whose record hides what survived — so each
assertion is seen to fail for the reason it protects.
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
    operator_access.REVOKED_CASE_ID: operator_access.case_temporary_access_is_revoked,
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
    "revocation-skips-a-host": "a finished pair was not revoked on both hosts",
    "revocation-unverified": "revocation reported ['INCOMPLETE', 'INCOMPLETE']",
    "revocation-reuses-one-connection": "not one per host",
    "revocation-passes-without-running-the-script": "a temporary key survived revocation",
    "revocation-removes-the-provider-entry":
        "revocation removed the provider's own authorized_keys entry",
    "revocation-leaves-the-timer-files":
        "revocation left expiry files",
    "revocation-forgets-the-script-presence": "does not say the revocation script was present",
    "revocation-record-claims-residue": "the record still reports residue after revocation",
    "revocation-accepts-an-inert-cleanup":
        "a pass can be claimed without the key being gone",
    "revocation-hides-what-survived": "the incomplete record hides what survived",
    "revocation-names-nothing": "does not name what the operator has to remove by hand",
    "revocation-passes-an-unreachable-host": "an unreachable host was reported",
    "revocation-gives-up-after-a-failure":
        "stopped the revocation of the host behind it",
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


# --------------------------------------------------------------------------- #
# BOOT-02 — the damages. Each one changes the revocation product or the host it
# answers for, never the case; the seam is the same ``SSHClient`` the case uses.
# --------------------------------------------------------------------------- #
_REAL_CLEANUP_ACCESS = operator._cleanup_access
_REAL_REVOKE_ALL = operator._revoke_all
_REAL_FAKE_CLIENT = operator_access._FakeSSHClient


class _AlwaysCleanRemote(_REAL_REMOTE):
    """A host that runs its revocation script even when the case asked it not to."""

    def _cleanup_script(self):
        ignored, self.cleanup_ignored = self.cleanup_ignored, False
        try:
            return super()._cleanup_script()
        finally:
            self.cleanup_ignored = ignored


class _ProviderWipingCleanup(_REAL_REMOTE):
    """A revocation script that clears the file instead of removing one line."""

    def _cleanup_script(self):
        self.files["/root/.ssh/authorized_keys"] = ""
        self.timers.clear()
        for path in [p for p in list(self.files) if "gowave-e2e-key-expiry" in p]:
            self.files.pop(path, None)
        return 0, "", ""


class _TimerFileLeavingCleanup(_REAL_REMOTE):
    """A revocation script that stops the timer but leaves its unit files behind."""

    def _cleanup_script(self):
        marker = self.marker
        if marker:
            lines = self.files.get("/root/.ssh/authorized_keys", "").splitlines(True)
            self.files["/root/.ssh/authorized_keys"] = "".join(
                line for line in lines if marker not in line)
        self.timers.clear()
        return 0, "", ""


class _InertCleanup(_REAL_REMOTE):
    """A host whose revocation script answers success and changes nothing."""

    def _cleanup_script(self):
        return 0, "", ""


def _one_connection_for_both_hosts():
    """``SSHClient`` faked as one multiplexed master reported for every host."""

    opened = []

    class _Reused(_REAL_FAKE_CLIENT):
        def __init__(self, remotes, **kwargs):
            super().__init__(remotes, **kwargs)
            recorded = kwargs.get("constructed")
            if recorded:
                if not opened:
                    opened.append(self.host)
                recorded[-1] = opened[0]

    return _Reused


def _revocation_that_skips_a_host(targets):
    """``_revoke_all`` cut down to one host, as a loop that loses its last target."""
    results, ok = _REAL_REVOKE_ALL(targets[:-1])
    return results, ok


def _revocation_that_reports_an_unreachable_host_as_a_pass(targets):
    """``_revoke_all`` that turns a transport failure into a pass."""
    results = {}
    for target in reversed(targets):
        try:
            ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
        except Exception:  # noqa: BLE001 - the damage is this broad catch
            ok, message, evidence = True, "temporary SSH key removed", {}
        entry = {"status": "PASS" if ok else "INCOMPLETE", "message": message}
        entry.update(evidence)
        results[f"{target['user']}@{target['host']}"] = entry
    return results, all(item["status"] == "PASS" for item in results.values())


def _revocation_that_gives_up_after_a_failure(targets):
    """``_revoke_all`` that walks the list forward and stops at the first failure."""
    results = {}
    given_up = False
    for target in targets:
        key = f"{target['user']}@{target['host']}"
        if given_up:
            results[key] = {
                "status": "INCOMPLETE",
                "message": "not attempted after an earlier host failed",
            }
            continue
        try:
            ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
        except Exception:  # noqa: BLE001 - the damage is this broad catch
            given_up = True
            results[key] = {"status": "INCOMPLETE", "message": "host unreachable"}
            continue
        entry = {"status": "PASS" if ok else "INCOMPLETE", "message": message}
        entry.update(evidence)
        results[key] = entry
        given_up = not ok
    return results, all(item["status"] == "PASS" for item in results.values())


def _cleanup_that_never_verifies(target):
    ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
    return False, message, evidence


def _revocation_that_aggregates_a_pass(targets):
    """``_revoke_all`` whose aggregate says PASS while a target's record says otherwise."""
    results, _ = _REAL_REVOKE_ALL(targets)
    return results, True


def _cleanup_that_calls_an_inert_host_a_pass(target):
    ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
    return True, message, evidence


def _cleanup_that_forgets_the_script_presence(target):
    ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
    evidence = {key: value for key, value in evidence.items()
                if key != "revocation_script_present"}
    return ok, message, evidence


def _cleanup_that_records_residue_as_a_pass(target):
    ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
    return True, message, dict(evidence, key_present=True)


def _cleanup_that_hides_what_survived(target):
    ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
    if not ok:
        evidence = {key: value for key, value in evidence.items()
                    if key not in ("key_present", "timer_active")}
    return ok, message, evidence


def _cleanup_that_names_nothing(target):
    ok, message, evidence = _REAL_CLEANUP_ACCESS(target)
    if not ok:
        message = "temporary SSH access cleanup could not be verified"
    return ok, message, evidence


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
        "revocation-skips-a-host": [
            mock.patch.object(operator, "_revoke_all",
                              side_effect=_revocation_that_skips_a_host),
        ],
        "revocation-unverified": [
            mock.patch.object(operator, "_cleanup_access",
                              side_effect=_cleanup_that_never_verifies),
            mock.patch.object(operator, "_revoke_all",
                              side_effect=_revocation_that_aggregates_a_pass),
        ],
        "revocation-reuses-one-connection": [
            mock.patch.object(operator_access, "_FakeSSHClient",
                              _one_connection_for_both_hosts()),
        ],
        "revocation-passes-without-running-the-script": [
            mock.patch.object(operator_access, "_Remote", _InertCleanup),
            mock.patch.object(operator, "_cleanup_access",
                              side_effect=_cleanup_that_calls_an_inert_host_a_pass),
        ],
        "revocation-removes-the-provider-entry": [
            mock.patch.object(operator_access, "_Remote", _ProviderWipingCleanup),
        ],
        "revocation-leaves-the-timer-files": [
            mock.patch.object(operator_access, "_Remote", _TimerFileLeavingCleanup),
        ],
        "revocation-forgets-the-script-presence": [
            mock.patch.object(operator, "_cleanup_access",
                              side_effect=_cleanup_that_forgets_the_script_presence),
        ],
        "revocation-record-claims-residue": [
            mock.patch.object(operator, "_cleanup_access",
                              side_effect=_cleanup_that_records_residue_as_a_pass),
        ],
        "revocation-accepts-an-inert-cleanup": [
            mock.patch.object(operator_access, "_Remote", _AlwaysCleanRemote),
        ],
        "revocation-hides-what-survived": [
            mock.patch.object(operator, "_cleanup_access",
                              side_effect=_cleanup_that_hides_what_survived),
        ],
        "revocation-names-nothing": [
            mock.patch.object(operator, "_cleanup_access",
                              side_effect=_cleanup_that_names_nothing),
        ],
        "revocation-passes-an-unreachable-host": [
            mock.patch.object(
                operator, "_revoke_all",
                side_effect=_revocation_that_reports_an_unreachable_host_as_a_pass),
        ],
        "revocation-gives-up-after-a-failure": [
            mock.patch.object(operator, "_revoke_all",
                              side_effect=_revocation_that_gives_up_after_a_failure),
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

    def test_the_access_a_finished_run_installed_is_revoked(self):
        facts, refusal = run_case(operator_access.REVOKED_CASE_ID)
        self.assertIsNone(refusal)
        self.assertEqual(facts["targets_revoked"], 2)
        self.assertEqual(facts["revocation_statuses"], "PASS,PASS")
        self.assertEqual(facts["revocation_clients"], 2)
        self.assertTrue(facts["revocation_script_present"])
        self.assertFalse(facts["key_present_after"])
        self.assertFalse(facts["timer_active_after"])
        self.assertTrue(facts["provider_entry_preserved"])
        self.assertEqual(facts["timer_files_remaining"], 0)
        self.assertEqual(facts["inert_cleanup_status"], "INCOMPLETE")
        self.assertTrue(facts["inert_key_present"])
        self.assertTrue(facts["inert_message_names_residue"])
        self.assertEqual(facts["unreachable_status"], "INCOMPLETE")
        self.assertTrue(facts["reachable_host_revoked_despite_failure"])


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

    def test_a_revocation_that_drops_a_host_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID, "revocation-skips-a-host")

    def test_a_revocation_that_verifies_nothing_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID, "revocation-unverified")

    def test_a_revocation_that_reports_one_connection_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-reuses-one-connection")

    def test_a_revocation_that_runs_no_script_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-passes-without-running-the-script")

    def test_a_revocation_that_removes_the_providers_entry_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-removes-the-provider-entry")

    def test_a_revocation_that_leaves_the_timer_files_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-leaves-the-timer-files")

    def test_a_revocation_that_forgets_the_script_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-forgets-the-script-presence")

    def test_a_record_that_claims_residue_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-record-claims-residue")

    def test_a_revocation_that_accepts_an_inert_script_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-accepts-an-inert-cleanup")

    def test_a_record_that_hides_what_survived_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-hides-what-survived")

    def test_a_record_that_names_nothing_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID, "revocation-names-nothing")

    def test_an_unreachable_host_reported_as_a_pass_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-passes-an-unreachable-host")

    def test_a_revocation_that_gives_up_after_a_failure_is_refused(self):
        self.assert_refused(operator_access.REVOKED_CASE_ID,
                            "revocation-gives-up-after-a-failure")


if __name__ == "__main__":
    unittest.main()
