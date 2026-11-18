#!/usr/bin/env python3
"""A preserved host carries the packages the run installed, and says so.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Global Certbot
Deploy Hook Ownership: when the installation transaction has installed or
upgraded OS packages and their post-install scripts have created service
defaults, and compensation or teardown then completes under
``TEST_TEARDOWN_POLICY=PRESERVE``, the report records the package changes as
retained residual state and distinguishes transaction compensation from
restoration of the original OS baseline — and the host is not eligible for
another clean-baseline run until it is re-imaged or restored through the
verified snapshot procedure.

Two halves answer it. The Worker payload records what its package manager
changed while the transaction still knows it: ``record_worker_package_baseline``
captures the inventory into the transaction's own recovery directory before the
first package mutation, and ``record_worker_package_changes`` diffs it against
the host afterwards into ``package-changes.tsv``, atomically and mode 0600. The
teardown report reads that record: ``read_package_changes`` parses it, and
``execute_teardown`` under PRESERVE reports the packages as residual state,
``restored_baseline: false``, ``clean_baseline_eligible: false`` and a message
naming the remedy — a host whose package change was never recorded reports
``inventory: unrecorded`` rather than "no changes".

The case drives the shipped functions over a scratch root with a stub package
manager, and hands the record the bytes it wrote to the shipped reader and to
the shipped teardown, so what it decides is the record's shape and the report's
verdict.
"""
from __future__ import annotations

import base64
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.mutation_baseline import _function_body
from tools.podman_e2e.runner import CaseBlocked, require
from tools.live_vps import teardown as live_teardown

CASE_ID = "HOOK-04"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "baseline_is_recorded": "the package baseline the transaction starts from was not written",
    "baseline_mode_is_private": "the package baseline is readable by every user",
    "changes_are_recorded": "the package changes the transaction caused were not recorded",
    "changes_mode_is_private": "the package change record is readable by every user",
    "installed_package_recorded": "a package the transaction installed is missing from the record",
    "upgraded_package_recorded":
        "a package the transaction upgraded is recorded without the version it came from",
    "removed_package_recorded": "a package the transaction removed is missing from the record",
    "unavailable_inventory_is_stated":
        "a package manager that could not answer was recorded as no package change",
    "baseline_refuses_outside_a_journal":
        "a package baseline was written for a transaction with no journal directory",
    "changes_refuse_without_a_baseline":
        "package changes were claimed for a transaction that recorded no baseline",
    "record_is_released_with_the_transaction":
        "releasing a transaction left its package record behind",
    "preserve_reports_residual_packages":
        "PRESERVE did not report the packages the transaction installed as retained state",
    "preserve_denies_baseline_restoration":
        "PRESERVE claimed to have restored an OS baseline it never touched",
    "preserve_reports_ineligibility":
        "PRESERVE left the host eligible for another clean-baseline run",
    "preserve_without_a_record_says_unrecorded":
        "a teardown handed no package record claimed to know the package change",
    "malformed_record_is_refused":
        "a package record that does not match the documented shape was parsed anyway",
}

_FUNCTION_SIGNATURES = (
    "worker_transaction_journal() {",
    "worker_journal_action() {",
    "record_worker_transaction_journal() {",
    "worker_package_record_dir() {",
    "worker_package_inventory() {",
    "record_worker_package_baseline() {",
    "record_worker_package_changes() {",
)

_SCENARIOS = r"""\
report() { printf '%s=%s\n' "$1" "$2"; }
emit() { base64 -w0 "$1" 2>/dev/null || true; }

state_root="$work/state"
tx="worker_install_packages"
record_worker_transaction_journal "$tx" "$state_root" >/dev/null 2>"$work/journal.err"
record_dir="$state_root/recovery/$tx"
baseline="$record_dir/packages-before.txt"
changes="$record_dir/package-changes.tsv"

mkdir -p "$work/bin"
cat > "$work/bin/dpkg-query" <<'STUB'
#!/bin/sh
printf 'alpha\t1.0\nbeta\t2.0\ngamma\t3.0\n'
STUB
chmod 0755 "$work/bin/dpkg-query"
PATH="$work/bin:$PATH"
export PATH

# 1. The inventory this transaction starts from, written inside its own journal
# directory and private to it.
record_worker_package_baseline "$tx" "$state_root" >/dev/null 2>"$work/baseline.err"
baseline_rc=$?
report baseline_is_recorded "$([[ "$baseline_rc" -eq 0 && -f "$baseline" ]] && echo 1 || echo 0)"
report baseline_mode_is_private "$([[ "$(stat -c '%a' "$baseline" 2>/dev/null)" == "600" ]] && echo 1 || echo 0)"
report baseline_record "$(emit "$baseline")"

# 2. The package manager then installs one package, upgrades another and removes
# a third; the record states all three, sorted, with the versions on both sides.
cat > "$work/bin/dpkg-query" <<'STUB'
#!/bin/sh
printf 'alpha\t1.0\nbeta\t2.1\ndelta\t4.0\n'
STUB
chmod 0755 "$work/bin/dpkg-query"
record_worker_package_changes "$tx" "$state_root" >/dev/null 2>"$work/changes.err"
changes_rc=$?
report changes_are_recorded "$([[ "$changes_rc" -eq 0 && -f "$changes" ]] && echo 1 || echo 0)"
report changes_mode_is_private "$([[ "$(stat -c '%a' "$changes" 2>/dev/null)" == "600" ]] && echo 1 || echo 0)"
report changes_record "$(emit "$changes")"
report installed_package_recorded "$(awk -F'\t' '$1=="installed" && $2=="delta" && $3=="4.0" {found=1} END {print found?1:0}' "$changes" 2>/dev/null)"
report upgraded_package_recorded "$(awk -F'\t' '$1=="upgraded" && $2=="beta" && $3=="2.0" && $4=="2.1" {found=1} END {print found?1:0}' "$changes" 2>/dev/null)"
report removed_package_recorded "$(awk -F'\t' '$1=="removed" && $2=="gamma" && $3=="3.0" {found=1} END {print found?1:0}' "$changes" 2>/dev/null)"

# 3. A package manager that cannot answer is a fact about the record, not a
# clean host: both files say so instead of claiming nothing changed.
tx_unavailable="worker_install_nopkg"
record_worker_transaction_journal "$tx_unavailable" "$state_root" >/dev/null 2>&1
cat > "$work/bin/dpkg-query" <<'STUB'
#!/bin/sh
exit 1
STUB
chmod 0755 "$work/bin/dpkg-query"
record_worker_package_baseline "$tx_unavailable" "$state_root" >/dev/null 2>&1
record_worker_package_changes "$tx_unavailable" "$state_root" >/dev/null 2>&1
unavailable_dir="$state_root/recovery/$tx_unavailable"
report unavailable_inventory_is_stated "$([[ "$(head -n 1 "$unavailable_dir/packages-before.txt" 2>/dev/null)" == "#unavailable" && "$(head -n 2 "$unavailable_dir/package-changes.tsv" 2>/dev/null | tail -n 1)" == "#unavailable" ]] && echo 1 || echo 0)"
report unavailable_record "$(emit "$unavailable_dir/package-changes.tsv")"
rm -rf "$unavailable_dir"

# 4. Two refusals: a baseline outside a journal directory, and a change record
# for a transaction that never wrote a baseline.
record_worker_package_baseline "$tx" "$work/absent-root" >/dev/null 2>"$work/outside.err"
outside_rc=$?
report baseline_refuses_outside_a_journal "$([[ "$outside_rc" -ne 0 && ! -e "$work/absent-root/recovery/$tx/packages-before.txt" ]] && echo 1 || echo 0)"
tx_nobaseline="worker_install_nobase"
mkdir -p "$state_root/recovery/$tx_nobaseline"
record_worker_package_changes "$tx_nobaseline" "$state_root" >/dev/null 2>"$work/nobase.err"
nobase_rc=$?
report changes_refuse_without_a_baseline "$([[ "$nobase_rc" -ne 0 && ! -e "$state_root/recovery/$tx_nobaseline/package-changes.tsv" ]] && echo 1 || echo 0)"
rm -rf "$state_root/recovery/$tx_nobaseline"

# 5. The record is the transaction's, so releasing the transaction releases it.
worker_journal_action remove "$(worker_transaction_journal "$state_root" "$tx")" "$tx" >/dev/null 2>"$work/remove.err"
remove_rc=$?
report record_is_released_with_the_transaction "$([[ "$remove_rc" -eq 0 && ! -e "$record_dir" ]] && echo 1 || echo 0)"

exit 0
"""


BLOCK_BANNER = "# --- package change record ---"


def guard_functions(path: Path = None) -> str:
    """The shipped functions the case drives, in the order they appear."""
    source = path or WORKER_INSTALLER
    return "".join(_function_body(source, signature) for signature in _FUNCTION_SIGNATURES)


def record_block_body(path: Path = None) -> str:
    """The one block the three copies of the record must agree on."""
    source = (path or WORKER_INSTALLER).read_text(encoding="utf-8")
    start = source.index(BLOCK_BANNER)
    end = source.index("restore_worker_targets_before_image() {", start)
    return source[start:end]


def driver_script(path: Path = None) -> str:
    """A scratch host, a stub package manager, and the record the installer writes."""
    return (
        "set -u\n"
        "work=$(mktemp -d)\n"
        "trap 'rm -rf \"$work\"' EXIT\n\n"
        + guard_functions(path)
        + "\n"
        + _SCENARIOS
    )


def _reported(result: Any) -> Dict[str, str]:
    require(CASE_ID, result.returncode == 0,
            f"the package-record probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _decoded(values: Dict[str, str], key: str, directory: str, name: str) -> Path:
    payload = values.get(key, "")
    require(CASE_ID, payload, f"the package-record probe reported no {key}")
    path = Path(directory) / name
    path.write_bytes(base64.b64decode(payload))
    return path


def _malformed_is_refused(directory: str) -> bool:
    """Every shape the reader documents as wrong is refused, not guessed at."""
    broken = {
        "no-header.tsv": "installed\tdelta\t4.0\n",
        "unknown-kind.tsv": "#gowave-package-changes/v1\nreinstalled\tdelta\t4.0\n",
        "short-row.tsv": "#gowave-package-changes/v1\ninstalled\tdelta\n",
        "long-row.tsv": "#gowave-package-changes/v1\nremoved\tdelta\t4.0\t5.0\n",
        "unsafe-field.tsv": "#gowave-package-changes/v1\ninstalled\tdel ta\t4.0\n",
        "both-and-neither.tsv": (
            "#gowave-package-changes/v1\n#unavailable\ninstalled\tdelta\t4.0\n"),
    }
    for name, text in broken.items():
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        try:
            live_teardown.read_package_changes(str(path))
        except ValueError:
            continue
        return False
    return True


def _preserve(record: Dict[str, Any] = None) -> Dict[str, Any]:
    return live_teardown.execute_teardown(
        type("Config", (), {"test_teardown_policy": "PRESERVE"})(),
        "run-hook-04", package_changes=record,
    )


def _evidence(values: Dict[str, str], directory: str) -> Dict[str, bool]:
    baseline = _decoded(values, "baseline_record", directory, "packages-before.txt")
    changes = _decoded(values, "changes_record", directory, "package-changes.tsv")
    unavailable = _decoded(values, "unavailable_record", directory, "unavailable.tsv")
    recorded = live_teardown.read_package_changes(str(changes))
    reported = live_teardown.read_package_changes(str(unavailable))
    preserve = _preserve(recorded)
    preserved = preserve.get("residual_state", {}).get("packages", {})
    bare = _preserve().get("residual_state", {}).get("packages", {})
    return {
        "baseline_is_recorded": values.get("baseline_is_recorded") == "1",
        "baseline_mode_is_private": values.get("baseline_mode_is_private") == "1",
        "changes_are_recorded": values.get("changes_are_recorded") == "1",
        "changes_mode_is_private": values.get("changes_mode_is_private") == "1",
        "installed_package_recorded": values.get("installed_package_recorded") == "1",
        "upgraded_package_recorded": values.get("upgraded_package_recorded") == "1",
        "removed_package_recorded": values.get("removed_package_recorded") == "1",
        "unavailable_inventory_is_stated": (
            values.get("unavailable_inventory_is_stated") == "1"
            and reported.get("inventory") == "unavailable"
        ),
        "baseline_refuses_outside_a_journal":
            values.get("baseline_refuses_outside_a_journal") == "1",
        "changes_refuse_without_a_baseline":
            values.get("changes_refuse_without_a_baseline") == "1",
        "record_is_released_with_the_transaction":
            values.get("record_is_released_with_the_transaction") == "1",
        "preserve_reports_residual_packages": (
            preserved.get("installed") == recorded["installed"]
            and preserved.get("upgraded") == recorded["upgraded"]
            and preserved.get("removed") == recorded["removed"]
            and preserve.get("residual_state", {}).get("retained") is True
        ),
        "preserve_denies_baseline_restoration": (
            preserve.get("restored_baseline") is False
            and "not a restoration of the original OS baseline" in preserve.get("message", "")
        ),
        "preserve_reports_ineligibility": (
            preserve.get("clean_baseline_eligible") is False
            and "not eligible for another clean-baseline run" in preserve.get("message", "")
        ),
        "preserve_without_a_record_says_unrecorded": bare.get("inventory") == "unrecorded",
        "malformed_record_is_refused": _malformed_is_refused(directory),
    }


def _refuse(evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))


EVIDENCE = (
    "baseline_is_recorded",
    "baseline_mode_is_private",
    "changes_are_recorded",
    "changes_mode_is_private",
    "installed_package_recorded",
    "upgraded_package_recorded",
    "removed_package_recorded",
    "unavailable_inventory_is_stated",
    "baseline_refuses_outside_a_journal",
    "changes_refuse_without_a_baseline",
    "record_is_released_with_the_transaction",
    "preserve_reports_residual_packages",
    "preserve_denies_baseline_restoration",
    "preserve_reports_ineligibility",
    "preserve_without_a_record_says_unrecorded",
    "malformed_record_is_refused",
)


def _run(result: Any) -> Dict[str, bool]:
    values = _reported(result)
    with tempfile.TemporaryDirectory(prefix="gowave-package-residual-") as directory:
        evidence = _evidence(values, directory)
    _refuse(evidence)
    return evidence


def case_panel_package_residuals(product: Any, run: Any) -> Dict[str, Any]:
    """HOOK-04 on the AIO contour: the package record and the report on the host it installed."""
    host_script = getattr(product, "host_script", None)
    if host_script is None:
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the container the run installed, and this "
            "product exposes no way to run a script on it"
        )
    facts = _run(host_script(driver_script(), timeout=300))
    return {
        "baseline_is_recorded": facts["baseline_is_recorded"],
        "baseline_mode_is_private": facts["baseline_mode_is_private"],
        "changes_are_recorded": facts["changes_are_recorded"],
        "changes_mode_is_private": facts["changes_mode_is_private"],
        "installed_package_recorded": facts["installed_package_recorded"],
        "upgraded_package_recorded": facts["upgraded_package_recorded"],
        "removed_package_recorded": facts["removed_package_recorded"],
        "unavailable_inventory_is_stated": facts["unavailable_inventory_is_stated"],
        "baseline_refuses_outside_a_journal": facts["baseline_refuses_outside_a_journal"],
        "changes_refuse_without_a_baseline": facts["changes_refuse_without_a_baseline"],
        "record_is_released_with_the_transaction": facts["record_is_released_with_the_transaction"],
        "preserve_reports_residual_packages": facts["preserve_reports_residual_packages"],
        "preserve_denies_baseline_restoration": facts["preserve_denies_baseline_restoration"],
        "preserve_reports_ineligibility": facts["preserve_reports_ineligibility"],
        "preserve_without_a_record_says_unrecorded":
            facts["preserve_without_a_record_says_unrecorded"],
        "malformed_record_is_refused": facts["malformed_record_is_refused"],
    }


def case_worker_package_residuals(product: Any, run: Any) -> Dict[str, Any]:
    """HOOK-04 on the multi-node contour: the package record and the report on the Worker."""
    host = getattr(product, "topology", None)
    if host is None or not getattr(host, "worker_name", ""):
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the worker container the run created, and no "
            "topology with a worker exists yet"
        )
    facts = _run(product.podman.exec_bash(host.worker_name, driver_script(), check=False, timeout=300))
    return {
        "baseline_is_recorded": facts["baseline_is_recorded"],
        "baseline_mode_is_private": facts["baseline_mode_is_private"],
        "changes_are_recorded": facts["changes_are_recorded"],
        "changes_mode_is_private": facts["changes_mode_is_private"],
        "installed_package_recorded": facts["installed_package_recorded"],
        "upgraded_package_recorded": facts["upgraded_package_recorded"],
        "removed_package_recorded": facts["removed_package_recorded"],
        "unavailable_inventory_is_stated": facts["unavailable_inventory_is_stated"],
        "baseline_refuses_outside_a_journal": facts["baseline_refuses_outside_a_journal"],
        "changes_refuse_without_a_baseline": facts["changes_refuse_without_a_baseline"],
        "record_is_released_with_the_transaction": facts["record_is_released_with_the_transaction"],
        "preserve_reports_residual_packages": facts["preserve_reports_residual_packages"],
        "preserve_denies_baseline_restoration": facts["preserve_denies_baseline_restoration"],
        "preserve_reports_ineligibility": facts["preserve_reports_ineligibility"],
        "preserve_without_a_record_says_unrecorded":
            facts["preserve_without_a_record_says_unrecorded"],
        "malformed_record_is_refused": facts["malformed_record_is_refused"],
    }
