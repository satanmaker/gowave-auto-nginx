"""Temporary access is revoked, or the run is not PASS.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Local-only live VPS
credential handling and §Transactional Updates say the run's temporary SSH access
is gone when the cleanup phase reports PASS, and that a cleanup which cannot be
verified turns an otherwise PASS run into INCOMPLETE.

Both are decided by ``tools/live_vps/operator.py``, so the two cases drive
``_cleanup_access``, ``_revoke_all``, ``_cleanup_summary_message``,
``_write_operator_only_report`` and ``_refresh_report`` against a model of the SSH
client: every command the controller sends is recorded, and the host answers the
four probes the cleanup makes. The private key on the control machine carries a
sentinel body, so "the key never leaves the control machine" is a search over
what was sent rather than a promise.

Not claimed: no SSH server answers here. The transport is a seam and the host is
a model; what the cases decide is the controller's own logic, its commands, the
evidence it records and the report it writes.
"""
from __future__ import annotations

import shutil
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest import mock

from tools.live_vps import operator
from tools.test_live_vps import load_run_state, save_run_state

REV_01 = "REV-01"
REV_02 = "REV-02"

_SENTINEL = "control-machine-only-sentinel"
_KEY_BODY = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{_SENTINEL}\n"
_MARKER = "gowave-e2e-revocation"


class _Host:
    """A host that answers the four cleanup probes and records what it was asked."""

    def __init__(self, script_present: bool = True, key_present: bool = False,
                 timer_active: bool = False, fail_on: str = "") -> None:
        self.script_present = script_present
        self.key_present = key_present
        self.timer_active = timer_active
        self.fail_on = fail_on
        self.commands: List[str] = []

    def run(self, command: str, timeout: int = 30) -> SimpleNamespace:
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            return SimpleNamespace(returncode=255, stdout="", stderr="connection closed")
        if command.startswith("test -x"):
            return SimpleNamespace(returncode=0 if self.script_present else 1,
                                   stdout="", stderr="")
        if command.startswith("/bin/sh"):
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if command.startswith("grep -Fq"):
            return SimpleNamespace(returncode=0 if self.key_present else 1,
                                   stdout="", stderr="")
        if command.startswith("systemctl is-active"):
            return SimpleNamespace(returncode=0 if self.timer_active else 3,
                                   stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    def close(self) -> None:
        return None


class _Client:
    """The ``SSHClient`` the cleanup builds, replaced by a recording model."""

    constructed: List[Dict[str, Any]] = []
    hosts: Dict[str, _Host] = {}

    def __init__(self, host: str, port: int, user: str, key_path: str,
                 known_hosts: str) -> None:
        _Client.constructed.append({
            "host": host, "port": port, "user": user,
            "key_path": key_path, "known_hosts": known_hosts,
        })
        self.host = _Client.hosts[host]

    def run(self, command: str, timeout: int = 30) -> SimpleNamespace:
        return self.host.run(command, timeout)

    def close(self) -> None:
        self.host.close()


def _target(host: str, key_path: Path) -> Dict[str, Any]:
    return {
        "host": host, "port": 22, "user": "root",
        "key_path": str(key_path), "known_hosts": str(key_path.parent / "known_hosts"),
        "timer": f"gowave-e2e-key-expiry-{host.replace('.', '-')}",
        "marker": _MARKER,
        "expiry_deadline_utc": "2026-11-17T14:00:00Z",
        "timer_state_at_bootstrap": "active",
    }


def _patched(hosts: Dict[str, _Host]):
    _Client.constructed = []
    _Client.hosts = hosts
    return mock.patch.object(operator, "SSHClient", _Client)


def _key_file(workdir: Path) -> Path:
    key_path = workdir / "id_ed25519"
    key_path.write_text(_KEY_BODY, encoding="utf-8")
    key_path.chmod(0o600)
    return key_path


def case_revocation_succeeds(
    context: Any, run: Any
) -> Dict[str, Any]:
    """A host with neither the marker nor the timer is a passing cleanup."""
    workdir = Path(tempfile.mkdtemp(prefix="gowave-rev-01-"))
    try:
        key_path = _key_file(workdir)
        target = _target("192.0.2.10", key_path)
        host = _Host(script_present=True, key_present=False, timer_active=False)

        with _patched({target["host"]: host}):
            ok, message, recorded = operator._cleanup_access(target)

        sent = list(host.commands)
        artifact_dir = workdir / "artifacts" / "run-rev-01"
        operator._write_operator_only_report(artifact_dir, {
            "status": "PASS" if ok else "INCOMPLETE",
            "targets": {target["user"] + "@" + target["host"]:
                        dict(recorded, message=message)},
        })
        report = artifact_dir / "operator-access.json"
        report_text = report.read_text(encoding="utf-8")
        script = f"/usr/local/sbin/{target['timer']}.sh"
        client = _Client.constructed[0] if _Client.constructed else {}

        evidence = {
            "cleanup_reported_pass": ok,
            "cleanup_message": message,
            "revoke_script_named": any(script in command for command in sent),
            "revoke_script_ran": any(
                command.startswith("/bin/sh") and script in command for command in sent),
            "marker_probed": any(_MARKER in command and "authorized_keys" in command
                                 for command in sent),
            "timer_probed": any(
                f"systemctl is-active --quiet '{target['timer']}.timer'" == command
                for command in sent),
            "key_recorded_absent": recorded.get("key_present") is False,
            "timer_recorded_inactive": recorded.get("timer_active") is False,
            "key_material_left_the_control_machine": any(
                _SENTINEL in command for command in sent),
            "client_keyed_on_the_control_machine_file": client.get("key_path") == str(key_path),
            "client_pinned_the_known_hosts_file":
                client.get("known_hosts") == target["known_hosts"],
            "report_records_the_cleanup": "operator_access_cleanup" in report_text,
            "report_mode": oct(stat.S_IMODE(report.stat().st_mode)),
            "report_directory_mode": oct(stat.S_IMODE(artifact_dir.stat().st_mode)),
            "report_carries_key_material": _SENTINEL in report_text,
        }
        refused = []
        if not evidence["cleanup_reported_pass"]:
            refused.append(f"a host that answered clean reported {message!r}")
        if evidence["cleanup_message"] != "temporary SSH key removed and expiry timer disabled":
            refused.append(f"the passing sentence reads {evidence['cleanup_message']!r}")
        if not evidence["revoke_script_named"]:
            refused.append("the cleanup never named the remote revoke script")
        if not evidence["revoke_script_ran"]:
            refused.append("the cleanup never ran the remote revoke script")
        if not evidence["marker_probed"]:
            refused.append("the cleanup never probed authorized_keys for its marker")
        if not evidence["timer_probed"]:
            refused.append("the cleanup never probed the expiry timer's state")
        if not evidence["key_recorded_absent"]:
            refused.append("the evidence does not record the marker as absent")
        if not evidence["timer_recorded_inactive"]:
            refused.append("the evidence does not record the timer as inactive")
        if evidence["key_material_left_the_control_machine"]:
            refused.append("the private key was sent to the host")
        if not evidence["client_keyed_on_the_control_machine_file"]:
            refused.append("the client was not built from the control-machine key")
        if not evidence["client_pinned_the_known_hosts_file"]:
            refused.append("the client did not use the pinned known_hosts file")
        if not evidence["report_records_the_cleanup"]:
            refused.append("the report does not carry the cleanup record")
        if evidence["report_mode"] != "0o600":
            refused.append(f"the operator report is mode {evidence['report_mode']}")
        if evidence["report_directory_mode"] != "0o700":
            refused.append(f"the report directory is mode {evidence['report_directory_mode']}")
        if evidence["report_carries_key_material"]:
            refused.append("the operator report carries the private key")
        if refused:
            raise AssertionError("REV-01: " + "; ".join(refused))
        return evidence
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def case_revocation_cannot_be_verified(
    context: Any, run: Any
) -> Dict[str, Any]:
    """Every way the cleanup can fail ends in INCOMPLETE, never in a PASS."""
    workdir = Path(tempfile.mkdtemp(prefix="gowave-rev-02-"))
    try:
        key_path = _key_file(workdir)
        gone = _target("192.0.2.10", key_path)
        stuck = _target("198.51.100.20", key_path)

        with _patched({gone["host"]: _Host(True, False, False)}):
            gone_ok, _, gone_recorded = operator._cleanup_access(gone)
        with _patched({stuck["host"]: _Host(True, True, True)}):
            stuck_ok, stuck_message, stuck_recorded = operator._cleanup_access(stuck)
        with _patched({gone["host"]: _Host(True, True, False)}):
            key_only_ok, key_only_message, _ = operator._cleanup_access(gone)
        with _patched({gone["host"]: _Host(True, False, True)}):
            timer_only_ok, timer_only_message, _ = operator._cleanup_access(gone)
        with _patched({gone["host"]: _Host(False, True, False)}):
            absent_ok, _, absent_recorded = operator._cleanup_access(gone)

        # A verification that never completed is raised, not reported clean.
        with _patched({gone["host"]: _Host(True, False, False, fail_on="grep -Fq")}):
            try:
                operator._cleanup_access(gone)
                unverified_raised = False
            except RuntimeError as error:
                unverified_raised = "connection failed" in str(error)

        # Both targets at once: the stuck one fails the run and is still recorded.
        with _patched({
            gone["host"]: _Host(True, False, False),
            stuck["host"]: _Host(True, True, True),
        }):
            results, overall = operator._revoke_all([gone, stuck])
        labels = [gone["user"] + "@" + gone["host"], stuck["user"] + "@" + stuck["host"]]
        summary_fail = operator._cleanup_summary_message({"status": "INCOMPLETE",
                                                          "targets": results})
        summary_pass = operator._cleanup_summary_message({
            "status": "PASS",
            "targets": {labels[0]: {"status": "PASS"}},
        })

        failing = {"status": "INCOMPLETE", "targets": results}
        passing = {"status": "PASS", "targets": {labels[0]: {"status": "PASS"}}}
        with mock.patch.object(operator, "REPO_ROOT", workdir):
            failed_run = workdir / "artifacts" / "live-vps" / "run-rev-02-failed"
            save_run_state(failed_run, {
                "run_id": "run-rev-02-failed", "overall": "PASS",
                "results": {"install": {"status": "PASS"}},
            })
            operator._refresh_report("run-rev-02-failed", failing)
            failed_state = load_run_state(failed_run)
            passed_run = workdir / "artifacts" / "live-vps" / "run-rev-02-passed"
            save_run_state(passed_run, {
                "run_id": "run-rev-02-passed", "overall": "PASS",
                "results": {"install": {"status": "PASS"}},
            })
            operator._refresh_report("run-rev-02-passed", passing)
            passed_state = load_run_state(passed_run)

        evidence = {
            "clean_host_reported_pass": gone_ok,
            "clean_host_key_recorded_absent": gone_recorded.get("key_present") is False,
            "key_only_reported_failure": not key_only_ok,
            "key_only_names_the_timer_fallback":
                "timer remains the fallback" in key_only_message,
            "timer_only_reported_failure": not timer_only_ok,
            "timer_only_names_the_removed_key":
                "was removed" in timer_only_message,
            "both_present_reported_failure": not stuck_ok,
            "both_present_names_both": "still present" in stuck_message
            and "still active" in stuck_message,
            "timer_still_armed_recorded": stuck_recorded.get("timer_active") is True,
            "absent_script_recorded": absent_recorded.get("revocation_script_present") is False,
            "absent_script_reported_failure": not absent_ok,
            "unverifiable_connection_raised": unverified_raised,
            "revoke_all_overall": overall,
            "revoke_all_walks_targets_in_reverse": list(results) == [labels[1], labels[0]],
            "revoke_all_reports_every_target": sorted(results) == sorted(labels),
            "failed_target_status": results[labels[1]]["status"],
            "summary_names_the_stuck_host": stuck["host"] in summary_fail,
            "summary_without_a_failure_claims_removal":
                "temporary SSH access removed on every target" in summary_pass,
            "overall_with_failed_cleanup": failed_state.get("overall"),
            "overall_with_passed_cleanup": passed_state.get("overall"),
            "failed_run_records_the_cleanup": failed_state.get("results", {})
            .get("operator_access_cleanup", {}).get("status"),
        }
        refused = []
        if not evidence["clean_host_reported_pass"]:
            refused.append("a host with neither the marker nor the timer did not pass")
        if not evidence["clean_host_key_recorded_absent"]:
            refused.append("the passing evidence does not record the marker as absent")
        if not evidence["key_only_reported_failure"]:
            refused.append("a host still holding the marker was reported as clean")
        if not evidence["key_only_names_the_timer_fallback"]:
            refused.append("the marker-only refusal does not name the timer as the fallback")
        if not evidence["timer_only_reported_failure"]:
            refused.append("a host with an active expiry timer was reported as clean")
        if not evidence["timer_only_names_the_removed_key"]:
            refused.append("the timer-only refusal does not record the marker's removal")
        if not evidence["both_present_reported_failure"]:
            refused.append("a host keeping the marker and the timer was reported as clean")
        if not evidence["both_present_names_both"]:
            refused.append("the refusal does not name both what remains")
        if not evidence["timer_still_armed_recorded"]:
            refused.append("the failed cleanup does not record the expiry timer as still armed")
        if not evidence["absent_script_recorded"]:
            refused.append("a host without the revoke script is not recorded as such")
        if not evidence["absent_script_reported_failure"]:
            refused.append("a host whose revoke script is missing was reported as clean")
        if not evidence["unverifiable_connection_raised"]:
            refused.append("a lost connection was answered instead of raised")
        if evidence["revoke_all_overall"]:
            refused.append("a run with one stuck host reported overall success")
        if not evidence["revoke_all_walks_targets_in_reverse"]:
            refused.append("the revoke pass did not walk the targets in reverse order")
        if not evidence["revoke_all_reports_every_target"]:
            refused.append("the revoke pass did not report every target")
        if evidence["failed_target_status"] != "INCOMPLETE":
            refused.append(f"the stuck target is recorded as {evidence['failed_target_status']!r}")
        if not evidence["summary_names_the_stuck_host"]:
            refused.append("a failing summary does not name the host that failed")
        if not evidence["summary_without_a_failure_claims_removal"]:
            refused.append("a passing summary does not say the access was removed")
        if evidence["overall_with_failed_cleanup"] != "INCOMPLETE":
            refused.append("an otherwise PASS run kept "
                           f"{evidence['overall_with_failed_cleanup']!r} after a failed cleanup")
        if not evidence["failed_run_records_the_cleanup"]:
            refused.append("the run state does not record the failed cleanup")
        if evidence["overall_with_passed_cleanup"] != "PASS":
            refused.append("a passing cleanup did not leave the run at PASS")
        if refused:
            raise AssertionError("REV-02: " + "; ".join(refused))
        return evidence
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
