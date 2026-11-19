#!/usr/bin/env python3
"""A run killed mid-install is reconciled before the next one writes anything.

``openspec/specs/podman-e2e/spec.md`` §Global Certbot
Deploy Hook Ownership: a Worker deployment terminated by SIGKILL, a kernel panic
or power loss after it wrote its transaction journal is discovered by the next
authenticated entrypoint, which reconciles it before accepting a new mutation;
when the recovery cannot be verified the new operation is refused, the journal is
retained and the outcome is reported incomplete.

The Worker payload answers that with a journal beside the ACME snapshot and the
two before-images: ``record_worker_transaction_journal`` writes ``started`` after
the before-image exists and before the first mutation, the verified end of the
install marks it ``installed``, and ``reconcile_worker_transaction_journals``
reads every journal under the recovery root, restores a ``started`` transaction
from its own before-images and releases its directory. A transaction that already
installed but was never finalized, one whose before-image cannot be restored, and
one whose journal cannot be read back all keep their directory and make the new
operation fail — so a half-written host is never built upon.

The case drives the shipped functions over a scratch root: the same bash, the
same functions and a real directory tree, on whichever host each contour
installs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.mutation_baseline import _function_body
from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "HOOK-03"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "journal_is_per_transaction":
        "the transaction journal was not written in the transaction's own recovery directory",
    "journal_names_the_transaction":
        "the journal does not name the transaction that wrote it, or the state it started in",
    "journal_mode_is_private": "the transaction journal is readable by every user",
    "mark_records_installed": "the verified end of the install did not mark the journal installed",
    "reopen_is_refused": "a new install reopened a transaction that had already installed",
    "installed_journal_retained":
        "a journal that installed but was never finalized was released, or its install was undone",
    "pre_existing_path_restored":
        "the reconcile did not put back the bytes the interrupted transaction found",
    "journal_released_after_reconcile":
        "a reconciled transaction left its journal behind",
    "second_reconcile_is_a_no_op": "a second reconcile of the same tree failed",
    "nothing_written_is_reconciled":
        "a journal with nothing written under it was not released",
    "unprovable_created_path_retained":
        "the reconcile removed a path no record proves the interrupted transaction wrote",
    "cleanup_reported_incomplete":
        "the reconcile did not report that it retained a transaction it could not verify",
    "unreadable_journal_refused": "an unreadable journal was ignored instead of refusing the new install",
    "failed_restore_retains_the_journal":
        "a transaction whose before-image could not be restored was released anyway",
    "firewall_image_is_consulted":
        "a firewall before-image that cannot be restored was ignored",
    "own_transaction_skipped":
        "the rollback entrypoint reconciled the transaction it was invoked for",
}

_FUNCTION_SIGNATURES = (
    "worker_mutation_targets() {",
    "worker_ownership_record() {",
    "worker_targets_before_image() {",
    "worker_targets_image() {",
    "record_worker_targets_before_image() {",
    "restore_worker_targets_before_image() {",
    "record_worker_mutation_targets() {",
    "firewall_before_image() {",
    "firewall_image() {",
    "restore_firewall_before_image() {",
    "worker_transaction_journal() {",
    "worker_journal_action() {",
    "record_worker_transaction_journal() {",
    "mark_worker_transaction_state() {",
    "reconcile_worker_transaction_journals() {",
)

_SCENARIOS = r"""\
report() { printf '%s=%s\n' "$1" "$2"; }
digest() { sha256sum "$1" | cut -d' ' -f1; }

export FAKE_ROOT="$work/root"
mkdir -p "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/nginx/conf.d"
# The host the interrupted run found: an Xray binary with bytes of its own. Every
# other inventoried path is absent, so the before-image records them as absent.
printf '#!/bin/sh\necho old\n' > "$FAKE_ROOT/usr/local/bin/xray"
chmod 0750 "$FAKE_ROOT/usr/local/bin/xray"
xray_before=$(digest "$FAKE_ROOT/usr/local/bin/xray")
state_root="$FAKE_ROOT/var/lib/gowave-auto-nginx"

# 1. The journal belongs to the transaction, names it, and is private.
tx="worker_install_casetx"
journal=$(worker_transaction_journal "$state_root" "$tx")
report journal_is_per_transaction "$(case "$journal" in "$state_root"/recovery/worker_install_casetx/transaction-journal.json) echo 1;; *) echo 0;; esac)"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>"$work/write.err"
report journal_names_the_transaction "$(python3 - "$journal" "$tx" <<'FACT'
import json
import sys

journal, tx = sys.argv[1:3]
with open(journal, "r", encoding="utf-8") as stream:
    data = json.load(stream)
print(1 if data.get("schema") == 1 and data.get("transaction") == tx and data.get("state") == "started" else 0)
FACT
)"
report journal_mode_is_private "$([[ "$(stat -c '%a' "$journal")" == "600" ]] && echo 1 || echo 0)"

# 2. The verified end of an install closes the journal, and a later run cannot
# reopen it: an installed transaction is one to finalize, never one to undo.
mark_worker_transaction_state installed "$tx" "$state_root" >/dev/null 2>&1
report mark_records_installed "$([[ "$(worker_journal_action state "$journal" "$tx" 2>/dev/null)" == "installed" ]] && echo 1 || echo 0)"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>"$work/reopen.err"
reopen_rc=$?
report reopen_is_refused "$([[ "$reopen_rc" -ne 0 && "$(worker_journal_action state "$journal" "$tx" 2>/dev/null)" == "installed" ]] && echo 1 || echo 0)"

# 3. An installed journal is retained and its install is left alone: the
# controller never finalized it, so it is not this entrypoint's to release.
printf '#!/bin/sh\necho new\n' > "$FAKE_ROOT/usr/local/bin/xray"
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >"$work/installed.out" 2>"$work/installed.err"
installed_rc=$?
report installed_journal_retained "$([[ "$installed_rc" -ne 0 && -d "$state_root/recovery/$tx" ]] && grep -q new "$FAKE_ROOT/usr/local/bin/xray" && echo 1 || echo 0)"
rm -rf "$state_root/recovery/$tx"

# 4. A transaction killed after its before-image but before it was installed is
# restored from that image, and its directory is released.
printf '#!/bin/sh\necho old\n' > "$FAKE_ROOT/usr/local/bin/xray"
tx="worker_install_recover"
image=$(worker_targets_before_image "$state_root" "$tx")
record_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/capture.err"
printf '#!/bin/sh\necho half-installed\n' > "$FAKE_ROOT/usr/local/bin/xray"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>&1
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >"$work/recover.out" 2>"$work/recover.err"
recovered_rc=$?
report pre_existing_path_restored "$([[ "$recovered_rc" -eq 0 && "$(digest "$FAKE_ROOT/usr/local/bin/xray")" == "$xray_before" ]] && echo 1 || echo 0)"
report journal_released_after_reconcile "$([[ "$recovered_rc" -eq 0 && ! -e "$state_root/recovery/$tx" ]] && echo 1 || echo 0)"
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >/dev/null 2>&1
report second_reconcile_is_a_no_op "$([[ $? -eq 0 ]] && echo 1 || echo 0)"

# 5. A journal whose run wrote nothing has nothing to restore, so it is released.
tx="worker_install_empty"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>&1
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >/dev/null 2>&1
empty_rc=$?
report nothing_written_is_reconciled "$([[ "$empty_rc" -eq 0 && ! -e "$state_root/recovery/$tx" ]] && echo 1 || echo 0)"

# 6. A path the interrupted run created, with no ownership record to prove it,
# is preserved and the transaction is retained: the recovery is not verified.
tx="worker_install_halfwritten"
image=$(worker_targets_before_image "$state_root" "$tx")
record_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>&1
printf 'server {}\n' > "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>&1
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >"$work/half.out" 2>"$work/half.err"
half_rc=$?
report unprovable_created_path_retained "$([[ "$half_rc" -ne 0 && -f "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf" && -d "$state_root/recovery/$tx" ]] && echo 1 || echo 0)"
report cleanup_reported_incomplete "$(grep -q 'retaining' "$work/half.err" && echo 1 || echo 0)"
rm -rf "$state_root/recovery/$tx" "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf"

# 7. A journal that cannot be read back is not guessed at.
tx="worker_install_corrupt"
mkdir -p "$state_root/recovery/$tx"
printf 'not json\n' > "$state_root/recovery/$tx/transaction-journal.json"
chmod 0600 "$state_root/recovery/$tx/transaction-journal.json"
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >/dev/null 2>"$work/corrupt.err"
corrupt_rc=$?
report unreadable_journal_refused "$([[ "$corrupt_rc" -ne 0 && -f "$state_root/recovery/$tx/transaction-journal.json" ]] && echo 1 || echo 0)"
rm -rf "$state_root/recovery/$tx"

# 8. A before-image that changed after it was taken cannot be restored, so the
# transaction keeps its journal instead of being reported as reconciled.
tx="worker_install_tampered"
image=$(worker_targets_before_image "$state_root" "$tx")
record_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>&1
copy=$(python3 - "$image/manifest.json" <<'FACT'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    data = json.load(stream)
print((data.get("targets") or {}).get("/usr/local/bin/xray", {}).get("copy") or "")
FACT
)
printf 'tampered\n' > "$image/$copy"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>&1
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >/dev/null 2>"$work/tampered.err"
tampered_rc=$?
report failed_restore_retains_the_journal "$([[ "$tampered_rc" -ne 0 && -d "$state_root/recovery/$tx" ]] && echo 1 || echo 0)"
rm -rf "$state_root/recovery/$tx"

# 9. The firewall before-image is consulted too: one that cannot be restored
# fails the reconcile rather than being passed over.
tx="worker_install_firewall"
mkdir -p "$state_root/recovery/$tx/firewall-before-image"
printf '{}\n' > "$state_root/recovery/$tx/firewall-before-image/manifest.json"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>&1
reconcile_worker_transaction_journals "" "$state_root" "$FAKE_ROOT" >/dev/null 2>"$work/firewall.err"
firewall_rc=$?
report firewall_image_is_consulted "$([[ "$firewall_rc" -ne 0 && -d "$state_root/recovery/$tx" ]] && echo 1 || echo 0)"
rm -rf "$state_root/recovery/$tx"

# 10. The rollback entrypoint reconciles every other transaction, never the one
# it was invoked for: that one is its own work.
tx="worker_install_current"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>&1
reconcile_worker_transaction_journals "$tx" "$state_root" "$FAKE_ROOT" >/dev/null 2>&1
skip_rc=$?
report own_transaction_skipped "$([[ "$skip_rc" -eq 0 && -d "$state_root/recovery/$tx" ]] && echo 1 || echo 0)"

exit 0
"""


def guard_functions(path: Path = None) -> str:
    """The shipped functions the case drives, in the order they appear."""
    source = path or WORKER_INSTALLER
    return "".join(_function_body(source, signature) for signature in _FUNCTION_SIGNATURES)


def journal_block_body(path: Path = None) -> str:
    """The one heredoc the three copies of the journal must agree on."""
    source = (path or WORKER_INSTALLER).read_text(encoding="utf-8")
    start = source.index("<<'JOURNAL_PY'\n") + len("<<'JOURNAL_PY'\n")
    end = source.index("\nJOURNAL_PY\n", start)
    return source[start:end]


def driver_script(path: Path = None) -> str:
    """A scratch host, the shipped journal functions, and the states they decide."""
    return (
        "set -u\n"
        "work=$(mktemp -d)\n"
        "trap 'rm -rf \"$work\"' EXIT\n\n"
        + guard_functions(path)
        + "\n"
        + _SCENARIOS
    )


def _facts(result: Any, keys: List[str]) -> Dict[str, bool]:
    """The probe's ``key=1`` lines, read back as the facts the case asserts."""
    require(CASE_ID, result.returncode == 0,
            f"the transaction-journal probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    missing = [key for key in keys if key not in values]
    require(CASE_ID, not missing,
            f"the transaction-journal probe reported nothing for {', '.join(missing)}")
    return {key: values[key] == "1" for key in keys}


def _refuse(evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))


EVIDENCE = (
    "journal_is_per_transaction",
    "journal_names_the_transaction",
    "journal_mode_is_private",
    "mark_records_installed",
    "reopen_is_refused",
    "installed_journal_retained",
    "pre_existing_path_restored",
    "journal_released_after_reconcile",
    "second_reconcile_is_a_no_op",
    "nothing_written_is_reconciled",
    "unprovable_created_path_retained",
    "cleanup_reported_incomplete",
    "unreadable_journal_refused",
    "failed_restore_retains_the_journal",
    "firewall_image_is_consulted",
    "own_transaction_skipped",
)


def case_panel_journal_is_reconciled(product: Any, run: Any) -> Dict[str, Any]:
    """HOOK-03 on the AIO contour: the journal functions run on the host they installed."""
    host_script = getattr(product, "host_script", None)
    if host_script is None:
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the container the run installed, and this "
            "product exposes no way to run a script on it"
        )
    result = host_script(driver_script(), timeout=300)
    facts = _facts(result, list(EVIDENCE))
    evidence = {
        "journal_is_per_transaction": facts["journal_is_per_transaction"],
        "journal_names_the_transaction": facts["journal_names_the_transaction"],
        "journal_mode_is_private": facts["journal_mode_is_private"],
        "mark_records_installed": facts["mark_records_installed"],
        "reopen_is_refused": facts["reopen_is_refused"],
        "installed_journal_retained": facts["installed_journal_retained"],
        "pre_existing_path_restored": facts["pre_existing_path_restored"],
        "journal_released_after_reconcile": facts["journal_released_after_reconcile"],
        "second_reconcile_is_a_no_op": facts["second_reconcile_is_a_no_op"],
        "nothing_written_is_reconciled": facts["nothing_written_is_reconciled"],
        "unprovable_created_path_retained": facts["unprovable_created_path_retained"],
        "cleanup_reported_incomplete": facts["cleanup_reported_incomplete"],
        "unreadable_journal_refused": facts["unreadable_journal_refused"],
        "failed_restore_retains_the_journal": facts["failed_restore_retains_the_journal"],
        "firewall_image_is_consulted": facts["firewall_image_is_consulted"],
        "own_transaction_skipped": facts["own_transaction_skipped"],
    }
    _refuse(evidence)
    return evidence


def case_worker_journal_is_reconciled(product: Any, run: Any) -> Dict[str, Any]:
    """HOOK-03 on the multi-node contour: the journal functions run on the Worker."""
    host = getattr(product, "topology", None)
    if host is None or not getattr(host, "worker_name", ""):
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the worker container the run created, and no "
            "topology with a worker exists yet"
        )
    result = product.podman.exec_bash(host.worker_name, driver_script(), check=False, timeout=300)
    facts = _facts(result, list(EVIDENCE))
    evidence = {
        "journal_is_per_transaction": facts["journal_is_per_transaction"],
        "journal_names_the_transaction": facts["journal_names_the_transaction"],
        "journal_mode_is_private": facts["journal_mode_is_private"],
        "mark_records_installed": facts["mark_records_installed"],
        "reopen_is_refused": facts["reopen_is_refused"],
        "installed_journal_retained": facts["installed_journal_retained"],
        "pre_existing_path_restored": facts["pre_existing_path_restored"],
        "journal_released_after_reconcile": facts["journal_released_after_reconcile"],
        "second_reconcile_is_a_no_op": facts["second_reconcile_is_a_no_op"],
        "nothing_written_is_reconciled": facts["nothing_written_is_reconciled"],
        "unprovable_created_path_retained": facts["unprovable_created_path_retained"],
        "cleanup_reported_incomplete": facts["cleanup_reported_incomplete"],
        "unreadable_journal_refused": facts["unreadable_journal_refused"],
        "failed_restore_retains_the_journal": facts["failed_restore_retains_the_journal"],
        "firewall_image_is_consulted": facts["firewall_image_is_consulted"],
        "own_transaction_skipped": facts["own_transaction_skipped"],
    }
    _refuse(evidence)
    return evidence
