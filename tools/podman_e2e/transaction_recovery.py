"""An interrupted mutation leaves a validated journal and is recovered first.

``openspec/specs/podman-e2e/spec.md`` §Transactional
Updates says an operator killed mid-switch leaves a validated journal naming the
snapshot it took, that the boot-time recovery runs before the next mutation, and
that a recovery which cannot roll back refuses instead of reporting success.

The journal half is ``modules/recovery.py`` driven directly: the journal is
written by the product's own atomic writer, validated by its validator and read
back. The boot half is ``recover_boot_files`` from ``modules/recovery.sh``,
sourced in a temporary tree with the mutation lock and the file rollback replaced
by stubs — so the verdict, the state the journal is left in and the snapshot path
it names are the product's own, and no host is touched.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from modules import recovery

CASE_ID = "TXN-02"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

#: The tree whose ``modules/recovery.sh`` and ``modules/recovery.py`` are driven.
SCRIPT_ROOT = REPO_ROOT

_STUB = (
    "acquire_mutation_lock() { return 0; }\n"
    "execute_file_rollback() { echo \"rollback-delegate:$1\"; return 0; }\n"
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _journal(root: Path, **overrides: Any) -> Dict[str, Any]:
    data = {
        "op": "channel_switch",
        "state": "APPLYING",
        "timestamp": _timestamp(),
        "snapshot_dir": str(root / "snap-tx-1"),
    }
    data.update(overrides)
    return data


def _boot_recovery(root: Path, journal_path: Path) -> subprocess.CompletedProcess:
    script = (
        _STUB
        + f'JOURNAL_FILE="{journal_path}"\n'
        + "recover_boot_files\n"
    )
    return subprocess.run(
        ["bash", "-c", f'source "{SCRIPT_ROOT / "modules" / "recovery.sh"}" && {script}'],
        capture_output=True, text=True, timeout=120,
        env={**os.environ, "SCRIPT_DIR": str(SCRIPT_ROOT), "RECOVERY_DIR": str(root)},
    )


def _state(journal_path: Path) -> str:
    try:
        return json.loads(journal_path.read_text(encoding="utf-8")).get("state", "")
    except (OSError, ValueError):
        return ""


def case_interrupted_mutation_leaves_a_validated_journal(
    context: Any, run: Any
) -> Dict[str, Any]:
    """The journal, the boot recovery and its refusals, all in one temporary root."""
    workdir = Path(tempfile.mkdtemp(prefix="gowave-txn-02-"))
    try:
        root = workdir / "recovery"
        snapshot = root / "snap-tx-1"
        snapshot.mkdir(parents=True)
        (snapshot / "gowave-auto.sh").write_text("#!/bin/sh\n", encoding="utf-8")

        journal_path = workdir / "journal.json"
        mid_switch = _journal(root)
        validated, refusal = True, ""
        try:
            recovery.validate_journal(mid_switch)
        except recovery.JournalValidationError as error:  # pragma: no cover - defensive
            validated, refusal = False, str(error)
        recovery.write_journal_atomically(journal_path, mid_switch)
        journal_mode = oct(stat.S_IMODE(journal_path.stat().st_mode))
        no_temp_left = not (workdir / "journal.json.tmp").exists()
        reloaded = recovery.load_journal_file(journal_path)

        recovered = _boot_recovery(root, journal_path)
        recovered_state = _state(journal_path)

        # A snapshot the journal names but the disk does not hold.
        missing_root = workdir / "recovery-missing"
        missing_root.mkdir()
        missing_journal = workdir / "journal-missing.json"
        recovery.write_journal_atomically(missing_journal, _journal(missing_root))
        missing = _boot_recovery(missing_root, missing_journal)
        missing_state = _state(missing_journal)

        # A snapshot outside the recovery root.
        outside_root = workdir / "recovery-outside"
        outside_root.mkdir()
        (workdir / "elsewhere").mkdir()
        outside_journal = workdir / "journal-outside.json"
        recovery.write_journal_atomically(
            outside_journal, _journal(outside_root, snapshot_dir=str(workdir / "elsewhere")))
        outside = _boot_recovery(outside_root, outside_journal)
        outside_state = _state(outside_journal)

        # A journal whose state does not belong to its operation.
        invalid_root = workdir / "recovery-invalid"
        invalid_root.mkdir()
        invalid_journal = workdir / "journal-invalid.json"
        invalid_data = _journal(invalid_root, state="PROVISION_APPLYING")
        invalid_journal.write_text(json.dumps(invalid_data, indent=2), encoding="utf-8")
        os.chmod(invalid_journal, 0o600)
        invalid = _boot_recovery(invalid_root, invalid_journal)
        invalid_state = _state(invalid_journal)

        # No journal at all: nothing to recover, and nothing written.
        absent_root = workdir / "recovery-absent"
        absent_root.mkdir()
        absent_journal = workdir / "journal-absent.json"
        absent = _boot_recovery(absent_root, absent_journal)

        body = (SCRIPT_ROOT / "modules" / "recovery.sh").read_text(encoding="utf-8")
        start = body.index("recover_boot_files() {")
        function_body = body[start:body.index("\nrecover_boot_provision() {", start)]
        lock_at = function_body.find("acquire_mutation_lock")
        validation_at = function_body.find("--validate-journal")
        journal_read_at = function_body.find("snapshot_dir")

        evidence = {
            "mid_switch_journal_validated": validated,
            "validation_refusal": refusal,
            "journal_names_the_snapshot": reloaded.get("snapshot_dir") == str(snapshot),
            "journal_mode": journal_mode,
            "journal_write_leaves_no_temp": no_temp_left,
            "recovery_exit": recovered.returncode,
            "recovered_state": recovered_state,
            "recovery_names_the_state_it_found": "Detected interrupted update/restore in state APPLYING"
            in recovered.stdout,
            "rollback_delegate_called": f"rollback-delegate:{snapshot}" in recovered.stdout,
            "missing_snapshot_refused": missing.returncode != 0,
            "missing_snapshot_names_the_risk": "refusing to report successful recovery"
            in missing.stderr,
            "missing_snapshot_left_state": missing_state,
            "outside_root_refused": outside.returncode != 0,
            "outside_root_names_the_root": "snapshot path is outside RECOVERY_DIR" in outside.stderr,
            "outside_root_left_state": outside_state,
            "invalid_journal_refused": invalid.returncode != 0,
            "invalid_journal_names_validation": "journal.json validation failed" in invalid.stderr,
            "invalid_journal_left_state": invalid_state,
            "absent_journal_exit": absent.returncode,
            "recovery_takes_the_mutation_lock": -1 < lock_at < journal_read_at,
            "lock_precedes_validation": -1 < lock_at < validation_at,
        }
        refused = []
        if not evidence["mid_switch_journal_validated"]:
            refused.append(f"a mid-switch journal was rejected: {refusal}")
        if not evidence["journal_names_the_snapshot"]:
            refused.append("the journal does not name the snapshot it took")
        if evidence["journal_mode"] != "0o600":
            refused.append(f"the journal is mode {evidence['journal_mode']}")
        if not evidence["journal_write_leaves_no_temp"]:
            refused.append("the atomic write left a temporary file behind")
        if evidence["recovery_exit"] != 0:
            refused.append(
                f"the boot recovery exited {evidence['recovery_exit']} on a recoverable journal")
        if evidence["recovered_state"] != "ROLLED_BACK":
            refused.append(
                f"the recovered journal is left in {evidence['recovered_state']!r}")
        if not evidence["recovery_names_the_state_it_found"]:
            refused.append("the recovery did not say which state it found")
        if not evidence["rollback_delegate_called"]:
            refused.append("the recovery did not reach the file rollback for the named snapshot")
        if not evidence["missing_snapshot_refused"]:
            refused.append("a journal naming an absent snapshot was reported as recovered")
        if not evidence["missing_snapshot_names_the_risk"]:
            refused.append("the missing-snapshot refusal does not name what it refuses to claim")
        if evidence["missing_snapshot_left_state"] != "APPLYING":
            refused.append("the refused recovery rewrote the journal")
        if not evidence["outside_root_refused"]:
            refused.append("a snapshot outside the recovery root was rolled back")
        if not evidence["outside_root_names_the_root"]:
            refused.append("the outside-root refusal does not name the root")
        if evidence["outside_root_left_state"] != "APPLYING":
            refused.append("the outside-root refusal rewrote the journal")
        if not evidence["invalid_journal_refused"]:
            refused.append("an invalid journal was accepted for automated rollback")
        if not evidence["invalid_journal_names_validation"]:
            refused.append("the invalid-journal refusal does not name validation")
        if evidence["invalid_journal_left_state"] != "PROVISION_APPLYING":
            refused.append("the invalid-journal refusal rewrote the journal")
        if evidence["absent_journal_exit"] != 0:
            refused.append("a host with no journal did not report nothing to recover")
        if not evidence["recovery_takes_the_mutation_lock"]:
            refused.append("the recovery reads the journal before it takes the mutation lock")
        if not evidence["lock_precedes_validation"]:
            refused.append("the recovery validates without holding the mutation lock")
        if refused:
            raise AssertionError("TXN-02: " + "; ".join(refused))
        return evidence
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
