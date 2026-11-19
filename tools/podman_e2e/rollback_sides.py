"""A failed node add is INCOMPLETE until both its sides are verified.

``openspec/specs/podman-e2e/spec.md`` §Signal-Safe and
Verifiable Transaction Compensation: when the Worker compensation succeeds and
the Panel API rollback fails, or the other way round, Master retains both
recovery records, reports the overall operation as INCOMPLETE, and does not mark
the transaction rolled back or committed until both sides are verified.

The Master answers that with ``finalize_failed_node_add``: it asks the Worker
host to compensate, asks ``modules.api_client.rollback_provisioning`` to undo the
Panel entities, and then hands both verdicts to
``modules.recovery.record_rollback_sides``, which is the only writer allowed to
finalize the journal. The order matters, because the API rollback is itself a
writer: it finalizes a clean rollback as ``NODE_ADD_ROLLED_BACK``, so a Worker
failure discovered afterwards would otherwise leave the transaction recorded as
rolled back over a host that was never put back.

The case drives that function as the shipped bytes. The Worker side is a stub
script at ``$SCRIPT_DIR/gowave-node-auto.sh`` that records the transaction it was
given and exits with the scenario's status — the seam the product already has,
since the Worker rollback is a separate process on another host. The API side is
the product's own ``rollback_provisioning`` reading a journal this case wrote with
the product's own atomic writer: a ``NODE_ADD_PREPARED`` journal with no entities
is a verified API side without a network call, and a ``NODE_ADD_APPLYING`` journal
without a durable action ledger is a refusal the same function prints and records.
Three runs decide the sentence: each side failing while the other succeeds, and
both verified. The Worker's own record retention is the remote compensator's
(TXN-01); this case decides what the Master records and reports.
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
from typing import Any, Dict, Tuple

from modules import recovery
from tools.podman_e2e.mutation_baseline import _function_body
from tools.podman_e2e.runner import require

CASE_ID = "TXN-03"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

#: The tree whose ``gowave-auto.sh`` and ``modules/`` are driven.
SCRIPT_ROOT = REPO_ROOT
AUTO_SCRIPT = SCRIPT_ROOT / "gowave-auto.sh"

_FUNCTION_SIGNATURE = "finalize_failed_node_add() {"

#: The refusal ``rollback_provisioning`` records when a transaction entered
#: APPLYING without a durable action ledger.
LEDGER_REFUSAL = "without a durable action ledger"

#: scenario, the journal state this case writes, and the Worker stub's exit code.
SCENARIOS: Tuple[Tuple[str, str, int], ...] = (
    ("api-verified", "NODE_ADD_PREPARED", 1),
    ("worker-verified", "NODE_ADD_APPLYING", 0),
    ("both-verified", "NODE_ADD_PREPARED", 0),
)

#: What each run must record: the Worker verdict, then the Panel API verdict.
EXPECTED_SIDES = {
    "api-verified": {"worker": "INCOMPLETE", "api": "ROLLED_BACK"},
    "worker-verified": {"worker": "ROLLED_BACK", "api": "INCOMPLETE"},
    "both-verified": {"worker": "ROLLED_BACK", "api": "ROLLED_BACK"},
}

_SENTENCES = {
    "worker_side_attempted":
        "the Worker host was not asked to compensate, so one side of the transaction was "
        "never attempted",
    "worker_attempted_with_the_transaction":
        "the Worker rollback was asked to compensate a different transaction than the one "
        "the journal records",
    "both_sides_are_recorded":
        "the journal does not record both compensation sides",
    "api_verified_worker_incomplete_is_incomplete":
        "a verified Panel API rollback over a failed Worker restore was not left INCOMPLETE",
    "worker_verified_api_incomplete_is_incomplete":
        "a verified Worker restore over a failed Panel API rollback was not left INCOMPLETE",
    "both_verified_is_rolled_back":
        "two verified sides did not finalize the transaction as rolled back",
    "incomplete_is_reported":
        "the operation was not reported INCOMPLETE naming both sides",
    "complete_is_reported":
        "a transaction whose two sides verified was not reported as rolled back",
    "records_retained_on_incomplete":
        "the recovery record of the incomplete transaction was not retained",
    "api_refusal_survives_the_record":
        "the Panel API's own refusal was dropped when the outcome was recorded",
    "rollback_refusal_retained":
        "the aggregate refusal an operator reads was not reported, or was reported over a "
        "transaction that completed",
}

EVIDENCE = tuple(sorted(_SENTENCES))

_DRIVER = r"""set -Eeuo pipefail
work="$1"
source "$work/lib.sh"

panel_ip="10.89.0.10"
panel_ipv6=""
node_port="3002"
vision_domain=""
known_hosts="$work/known_hosts"
export GOWAVE_WORKER_LEASE_TOKEN=""
: > "$known_hosts"

run() {
    local name="$1"
    local dir="$work/$name"
    export SCRIPT_DIR="$work/bin/$name"
    export JOURNAL_FILE="$dir/journal.json"
    export STATE_FILE="$dir/state.json"
    export CREDENTIALS_FILE="$dir/credentials.txt"
    export WORKER_STUB_LOG="$dir/worker.log"
    local rc=0
    finalize_failed_node_add "worker-$name" "10.89.0.11" "22" \
        "worker.testbed.internal" "worker-reality.testbed.internal" "root" \
        "worker_install_$name" \
        >"$dir/stdout" 2>"$dir/stderr" || rc=$?
    printf '%s\n' "$rc" >"$dir/exit"
}

run api-verified
run worker-verified
run both-verified
"""

_STUB = """#!/bin/sh
printf 'call=%s acme=%s\\n' "$1" "${ACME_TX_ID:-}" >> "$WORKER_STUB_LOG"
exit __CODE__
"""


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def function_body(path: Path = None) -> str:
    """The shipped finalizer, sliced out of the script that calls it."""
    return _function_body(path or AUTO_SCRIPT, _FUNCTION_SIGNATURE)


def driver_script(path: Path = None) -> str:
    """The shipped finalizer, sourced from the scratch tree, and its three runs."""
    body = function_body(path)
    if body.count(_FUNCTION_SIGNATURE) != 1:
        raise AssertionError(
            f"{_FUNCTION_SIGNATURE!r} occurs {body.count(_FUNCTION_SIGNATURE)} times")
    return _DRIVER


def _write_scenario(workdir: Path, name: str, state: str, worker_exit: int) -> None:
    directory = workdir / name
    directory.mkdir(parents=True)
    recovery.write_journal_atomically(directory / "journal.json", {
        "transaction_id": f"node_add_worker-{name}",
        "op": "node_add",
        "state": state,
        "node_name": f"worker-{name}",
        "timestamp": _timestamp(),
        "entities": [],
    })
    (directory / "state.json").write_text(
        json.dumps({"schemaVersion": 2, "nodes": []}), encoding="utf-8")
    (directory / "credentials.txt").write_text(
        "ADMIN_PASSWORD=not-used-in-this-case\n", encoding="utf-8")
    (directory / "worker.log").write_text("", encoding="utf-8")
    stub = workdir / "bin" / name / "gowave-node-auto.sh"
    stub.parent.mkdir(parents=True)
    stub.write_text(_STUB.replace("__CODE__", str(worker_exit)), encoding="utf-8")
    stub.chmod(0o755)


def _journal(directory: Path) -> Dict[str, Any]:
    try:
        return json.loads((directory / "journal.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _read(directory: Path, name: str) -> str:
    try:
        return (directory / name).read_text(encoding="utf-8")
    except OSError:
        return ""


def _facts(workdir: Path) -> Dict[str, Dict[str, Any]]:
    facts: Dict[str, Dict[str, Any]] = {}
    for name, _state, _worker_exit in SCENARIOS:
        directory = workdir / name
        journal = _journal(directory)
        try:
            mode = oct(stat.S_IMODE((directory / "journal.json").stat().st_mode))
        except OSError:
            mode = "missing"
        facts[name] = {
            "exit": _read(directory, "exit").strip(),
            "stderr": _read(directory, "stderr"),
            "worker_calls": [line for line in _read(directory, "worker.log").splitlines() if line],
            "state": journal.get("state", ""),
            "sides": journal.get("rollback_sides") or {},
            "transaction_id": journal.get("transaction_id", ""),
            "rollback_error": journal.get("rollback_error", ""),
            "mode": mode,
        }
    return facts


def _incomplete_sentence(name: str, worker: str, api: str) -> str:
    return (f"CRITICAL: Node add 'worker-{name}' is INCOMPLETE: Worker {worker}, "
            f"Panel API {api};")


def _aggregate_sentence(name: str) -> str:
    return f"CRITICAL: Rollback failed for Worker 'worker-{name}'; recovery journal retained."


def _evidence(facts: Dict[str, Dict[str, Any]]) -> Dict[str, bool]:
    api_verified = facts["api-verified"]
    worker_verified = facts["worker-verified"]
    both = facts["both-verified"]

    evidence = {
        # Neither side is skipped when the other fails: the Worker stub is asked
        # once per run, and the API verdict is what the journal records.
        "worker_side_attempted": all(
            len(item["worker_calls"]) == 1 for item in facts.values()),
        "worker_attempted_with_the_transaction": all(
            item["worker_calls"][:1] == [f"call=remote_rollback acme=worker_install_{name}"]
            for name, item in facts.items()),
        "both_sides_are_recorded": all(
            item["sides"] == EXPECTED_SIDES[name] for name, item in facts.items()),
        # The API rollback finalizes a clean rollback as NODE_ADD_ROLLED_BACK
        # before the Worker verdict exists; the later record must undo that.
        "api_verified_worker_incomplete_is_incomplete":
            api_verified["exit"] == "1"
            and api_verified["state"] == "NODE_ADD_ROLLBACK_REQUIRED",
        "worker_verified_api_incomplete_is_incomplete":
            worker_verified["exit"] == "1"
            and worker_verified["state"] == "NODE_ADD_ROLLBACK_REQUIRED",
        "both_verified_is_rolled_back":
            both["exit"] == "0" and both["state"] == "NODE_ADD_ROLLED_BACK",
        "incomplete_is_reported":
            _incomplete_sentence("api-verified", "INCOMPLETE", "ROLLED_BACK")
            in api_verified["stderr"]
            and _incomplete_sentence("worker-verified", "ROLLED_BACK", "INCOMPLETE")
            in worker_verified["stderr"]
            and "is INCOMPLETE:" not in both["stderr"],
        "complete_is_reported":
            "Node add 'worker-both-verified' rolled back: Worker and Panel API both verified."
            in both["stderr"]
            and "rolled back:" not in api_verified["stderr"]
            and "rolled back:" not in worker_verified["stderr"],
        "records_retained_on_incomplete": all(
            item["mode"] == "0o600"
            and item["transaction_id"] == f"node_add_worker-{name}"
            for name, item in (("api-verified", api_verified),
                               ("worker-verified", worker_verified))),
        "api_refusal_survives_the_record":
            LEDGER_REFUSAL in worker_verified["rollback_error"],
        "rollback_refusal_retained":
            _aggregate_sentence("api-verified") in api_verified["stderr"]
            and _aggregate_sentence("worker-verified") in worker_verified["stderr"]
            and _aggregate_sentence("both-verified") not in both["stderr"],
    }
    refused = [_SENTENCES[key] for key in EVIDENCE if not evidence.get(key)]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))
    return evidence


def _run(workdir: Path, path: Path = None) -> subprocess.CompletedProcess:
    (workdir / "lib.sh").write_text(function_body(path), encoding="utf-8")
    return subprocess.run(
        ["bash", "-s", str(workdir)],
        input=_DRIVER, capture_output=True, text=True, timeout=300,
        # The scratch tree is the working directory so the product's imports come
        # from PYTHONPATH — the stub bin directory and, behind it, the tree under
        # test — rather than from whichever tree the harness happens to run in.
        cwd=str(workdir),
        env={
            **os.environ,
            "PYTHONPATH": str(SCRIPT_ROOT),
        },
    )


def case_worker_and_api_rollback_are_both_required(
    product: Any, run: Any
) -> Dict[str, Any]:
    """Both compensation sides are recorded, and only both verified is a rollback."""
    workdir = Path(tempfile.mkdtemp(prefix="gowave-txn-03-"))
    try:
        for name, state, worker_exit in SCENARIOS:
            _write_scenario(workdir, name, state, worker_exit)
        result = _run(workdir)
        require(CASE_ID, result.returncode == 0,
                f"the rollback-sides probe exited {result.returncode}: "
                f"{(result.stderr or '').strip()[-400:]}")
        facts = _facts(workdir)
        for name, item in facts.items():
            require(CASE_ID, item["exit"] in ("0", "1"),
                    f"the {name} run did not report an exit status")
        evidence = _evidence(facts)
        return evidence
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
