#!/usr/bin/env python3
"""A Worker install interrupted by a signal compensates once and says so.

``openspec/specs/podman-e2e/spec.md`` §Signal-Safe and
Verifiable Transaction Compensation: a remote Worker deployment that has mutated
at least one resource and has not committed, on HUP, INT or TERM, stops starting
new mutations, persists interruption state, executes compensation exactly once,
verifies the result and exits nonzero — secret and temp-file cleanup alone is not
sufficient.

The payload answers that with the trap block its remote shell installs before the
first mutation: ``handle_signal`` for the three signals, ``handle_error`` for a
failing step, ``compensate_once`` in front of both, and the EXIT trap for the temp
files and the unset secrets. Compensation is ``compensate_remote_worker``: it
records the package residue, restores the inventoried paths from the transaction's
own before-image, verifies every restored file against the digest it recorded, and
reports the cleanup incomplete when it cannot.

The case runs that block as the shipped bytes — the handlers and the traps are
sliced out of ``gowave-node-auto.sh`` unchanged, and the compensator is the
shipped function with its signature renamed so a wrapper can count the calls the
shipped traps make. The deployment it interrupts is a real transaction: the
before-image and the journal are written by the shipped functions over a scratch
host root, one inventoried binary is mutated and its mode changed, and the signal
arrives while the run is between mutations. Four runs decide the sentence: TERM,
HUP and INT against a restorable before-image, and TERM against one whose copy was
altered after it was written, so the verification clause is decided in both
directions. The service manager is stubbed, because a rollback that stopped
``gowave-node.service`` would take down the host the suite installed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.mutation_baseline import _function_body
from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "TXN-01"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "term_handler_runs_compensation":
        "the TERM handler did not run the compensator exactly once",
    "hup_handler_runs_compensation":
        "the HUP handler did not run the compensator exactly once",
    "int_handler_runs_compensation":
        "the INT handler did not run the compensator exactly once",
    "compensation_runs_exactly_once":
        "the compensator ran more than once for one interruption",
    "no_mutation_after_the_signal":
        "the interrupted run started another mutation after the signal",
    "interruption_state_is_persisted":
        "the interrupted transaction left no journal naming the state it never committed",
    "compensation_restored_the_before_image":
        "the compensation left the mutated path as the interrupted run wrote it",
    "compensation_restored_the_mode":
        "the compensation put the content back without the mode it recorded",
    "restored_state_is_verified":
        "the compensation preserved a path its restore could have put back, so the "
        "restore was not verified",
    "failed_restore_is_reported_incomplete":
        "the compensation claimed a restore it could not verify",
    "signal_exit_is_nonzero":
        "the interrupted run did not exit nonzero, or was still running after the signal",
    "temp_files_are_cleaned":
        "the payload's temp file survived the interruption",
    "journal_survives_every_signal":
        "a signal other than TERM did not leave the transaction's journal in place",
}

_FUNCTION_SIGNATURES = (
    "worker_mutation_targets() {",
    "worker_ownership_record() {",
    "worker_targets_before_image() {",
    "record_worker_targets_before_image() {",
    "restore_worker_targets_before_image() {",
    "worker_targets_image() {",
    "worker_transaction_journal() {",
    "worker_journal_action() {",
    "record_worker_transaction_journal() {",
    "mark_worker_transaction_state() {",
    "worker_package_record_dir() {",
    "worker_package_inventory() {",
    "record_worker_package_changes() {",
    "restore_acme_lineage() {",
    "compensate_remote_worker() {",
)

_PREAMBLE_START = "    _COMPENSATED=0\n"
_PREAMBLE_END = "    trap 'cleanup_temp_and_secrets' EXIT\n"

#: The scenarios the driver runs: name, signal, and whether the before-image copy
#: is altered after it is written so the restore cannot be verified.
SCENARIOS = (
    ("term", "TERM", "0"),
    ("hup", "HUP", "0"),
    ("int", "INT", "0"),
    ("tampered", "TERM", "1"),
)

_CHILD = r"""set -Eeuo pipefail
scenario="$1"
signal="$2"
tamper="$3"
work="$4"
source "$work/lib.sh"

# The calls the shipped traps make, counted where the probe can read them. The
# compensator itself is the product's, renamed only so this wrapper can stand in
# front of it.
compensate_remote_worker() {
    printf 'call\n' >> "$work/compensation-$scenario.log"
    shipped_compensate_remote_worker "$@"
}

__PREAMBLE__

facts="$work/facts-$scenario"
: > "$facts"
report() { printf '%s=%s\n' "$1" "$2" >> "$facts"; }

# A scratch host the transaction describes, and the state root its records live
# under: the two roots the compensator takes, pointed at a tree this case owns.
export WORKER_HOST_ROOT="$work/root-$scenario"
export WORKER_STATE_ROOT="$WORKER_HOST_ROOT/var/lib/gowave-auto-nginx"
host_root="$WORKER_HOST_ROOT"
state_root="$WORKER_STATE_ROOT"
mkdir -p "$host_root/usr/local/bin"

tx="worker_install_case_$scenario"
case "$tx" in
    worker_install_case_*) ;;
    *) exit 1 ;;
esac
tx_dir="$state_root/recovery/$tx"
mkdir -p "$tx_dir"
chmod 0700 "$tx_dir"

# The inventoried binary this run mutates and the compensation has to put back.
target="$host_root/usr/local/bin/xray"
printf '#!/bin/sh\necho old\n' > "$target"
chmod 0750 "$target"
report target_present 1
report target_path "$target"
report target_before "$(sha256sum "$target" | cut -d' ' -f1)"
report target_mode_before "$(stat -c '%a' "$target")"

# The lineage manifests the compensator reads: two domains this transaction did
# not create, so its restore removes a renewal, a live and an archive path that
# never existed rather than touching a certificate.
for domain in case-worker.invalid case-reality.invalid; do
    mkdir -p "$tx_dir/acme/$domain"
    printf '{"domain": "%s", "existed_before": false, "serial": "", "fingerprint": ""}\n' \
        "$domain" > "$tx_dir/acme/$domain/lineage-manifest.json"
done

_ACME_TX_ID="$tx"
WORKER_DOMAIN="case-worker.invalid"
REALITY_DOMAIN="case-reality.invalid"
VISION_DOMAIN=""
_NODE_SERVICE_CONFIGURED=0
_NGINX_CONFIGS_CREATED=0
_NGINX_BOOTSTRAP_CREATED=0
_STREAM_INCLUDE_ADDED=0
_COVER_UNPACKED=0
_UFW_RULES_CONFIGURED=0
_UFW_WAS_ACTIVE=0
_SWAP_CREATED_BY_US=0
_SYSCTL_CREATED_BY_US=0
_DOT_CREATED_BY_US=0
_ROLLBACK_IN_PROGRESS=0

record_worker_targets_before_image \
    "$host_root" "$(worker_targets_before_image "$state_root" "$tx")" ||
    { report capture_ok 0; exit 0; }
report capture_ok 1
record_worker_transaction_journal "$tx" "$state_root" || { report journal_ok 0; exit 0; }
report journal_ok 1

if [[ "$tamper" == "1" ]]; then
    image=$(worker_targets_before_image "$state_root" "$tx")
    copy=$(python3 - "$image/manifest.json" "$target" "$host_root" <<'FACT'
import json
import sys

manifest, target, host_root = sys.argv[1:4]
with open(manifest, "r", encoding="utf-8") as stream:
    data = json.load(stream)
print((data.get("targets") or {}).get(target[len(host_root):], {}).get("copy") or "")
FACT
)
    if [[ -z "$copy" ]]; then
        report tamper_armed 0
        exit 0
    fi
    printf 'tampered\n' > "$image/$copy"
    report tamper_armed 1
else
    report tamper_armed 0
fi

# The mutation the interruption catches mid-flight, and the one it must never
# start: the sentinel after the wait is written only by a run that survived.
printf '#!/bin/sh\necho half-installed\n' > "$target"
chmod 0644 "$target"
report target_mutated "$(sha256sum "$target" | cut -d' ' -f1)"

printf 'stale\n' > /tmp/gowave-node-install-case.sh
: > "$work/armed-$scenario"
# The step the signal interrupts. Errexit is off around it, so a run that returns
# from its handler instead of exiting is not saved by the shell's disposition and
# reaches the mutation below; the ERR trap on the interrupted `wait` is the second
# thing that has to be gone for that to happen, which is what `signal-stops-nothing`
# removes. The sentinel is written only by a run that survived the signal.
set +e
sleep 30 & wait $!
set -e
printf 'mutation' > "$work/next-$scenario"
"""

_DRIVER_HEAD = r"""set -u
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/systemctl" <<'GOWAVE_PROBE_SYSTEMCTL'
#!/bin/sh
# The unit manager the case must not reach: the compensation's service step would
# stop the product this run installed, so it answers "no such unit" and the step
# is skipped while every other step is the real one.
exit 0
GOWAVE_PROBE_SYSTEMCTL
chmod 0755 "$work/bin/systemctl"
export PATH="$work/bin:$PATH"

ca_pem=/run/gowave-acme-test-ca.pem
ca_backup=""
if [[ -f "$ca_pem" && -r "$ca_pem" ]]; then
    cp -p "$ca_pem" "$work/ca.pem.original" 2>/dev/null && ca_backup="$work/ca.pem.original"
fi

cat > "$work/lib.sh" <<'GOWAVE_PROBE_LIB'
__LIB__
GOWAVE_PROBE_LIB

cat > "$work/child.sh" <<'GOWAVE_PROBE_CHILD'
__CHILD__
GOWAVE_PROBE_CHILD

source "$work/lib.sh"

run_scenario() {
    local name="$1" sig="$2" tamper="$3"
    local pid i rc alive journal facts state_root target before after
    rm -f "$work/armed-$name" "$work/next-$name"
    : > "$work/compensation-$name.log"

    # Job control, so the child is not started with SIGINT ignored: a signal
    # ignored on entry cannot be trapped, and the INT run would then be decided
    # by the shell's disposition rather than by the product's handler.
    set -m
    bash "$work/child.sh" "$name" "$sig" "$tamper" "$work" \
        >"$work/out-$name" 2>"$work/err-$name" &
    pid=$!
    set +m

    for i in $(seq 1 200); do
        [[ -e "$work/armed-$name" ]] && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    facts="$work/facts-$name"
    if [[ ! -e "$work/armed-$name" ]]; then
        printf 'armed=0\n' >> "$facts"
        kill -9 "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        return 0
    fi
    printf 'armed=1\n' >> "$facts"

    kill -"$sig" "$pid" 2>/dev/null || true
    for i in $(seq 1 200); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    alive=0
    if kill -0 "$pid" 2>/dev/null; then
        alive=1
        kill -9 "$pid" 2>/dev/null || true
    fi
    rc=0
    wait "$pid" 2>/dev/null || rc=$?

    printf 'handler_alive=%s\n' "$alive" >> "$facts"
    printf 'exit_code=%s\n' "$rc" >> "$facts"
    printf 'compensation_calls=%s\n' "$(wc -l < "$work/compensation-$name.log")" >> "$facts"
    printf 'mutation_after_signal=%s\n' "$([[ -e "$work/next-$name" ]] && echo 1 || echo 0)" >> "$facts"
    printf 'temp_file_left=%s\n' "$([[ -e /tmp/gowave-node-install-case.sh ]] && echo 1 || echo 0)" >> "$facts"
    printf 'signal_named=%s\n' "$(grep -q "Received signal $sig" "$work/err-$name" && echo 1 || echo 0)" >> "$facts"
    # The restore states its own verdict, and only in its own sentences: it names
    # every path it preserved and refuses to call that cleanup complete.
    printf 'restore_preserved_path=%s\n' \
        "$(grep -q 'Worker path(s) preserved' "$work/err-$name" && echo 1 || echo 0)" >> "$facts"

    target=$(sed -n 's/^target_path=//p' "$facts")
    before=$(sed -n 's/^target_before=//p' "$facts")
    [[ -n "$target" ]] || target="$work/root-$name/usr/local/bin/xray"
    printf 'restore_preserved_target=%s\n' \
        "$(grep -qF "Preserving $target:" "$work/err-$name" && echo 1 || echo 0)" >> "$facts"
    after=$(sha256sum "$target" 2>/dev/null | cut -d' ' -f1)
    printf 'target_after=%s\n' "$after" >> "$facts"
    printf 'target_mode_after=%s\n' "$(stat -c '%a' "$target" 2>/dev/null || echo missing)" >> "$facts"

    state_root="$work/root-$name/var/lib/gowave-auto-nginx"
    journal="$state_root/recovery/worker_install_case_$name/transaction-journal.json"
    printf 'journal_retained=%s\n' "$([[ -f "$journal" ]] && echo 1 || echo 0)" >> "$facts"
    printf 'journal_mode=%s\n' "$(stat -c '%a' "$journal" 2>/dev/null || echo missing)" >> "$facts"
    printf 'journal_state=%s\n' \
        "$(worker_journal_action state "$journal" "worker_install_case_$name" 2>/dev/null || echo unreadable)" \
        >> "$facts"
    rm -f /tmp/gowave-node-install-case.sh
}

"""

_DRIVER_TAIL = r"""run_scenario term TERM 0
run_scenario hup HUP 0
run_scenario int INT 0
run_scenario tampered TERM 1

if [[ -n "$ca_backup" && -f "$ca_backup" && ! -e "$ca_pem" ]]; then
    cp -p "$ca_backup" "$ca_pem" 2>/dev/null || true
fi

for file in "$work"/facts-*; do
    name=${file##*/facts-}
    while IFS= read -r line; do
        printf '%s.%s\n' "$name" "$line"
    done < "$file"
done
exit 0
"""


def guard_functions(path: Path = None) -> str:
    """The shipped functions the case drives, in the order they appear."""
    source = path or WORKER_INSTALLER
    return "".join(_function_body(source, signature) for signature in _FUNCTION_SIGNATURES)


def compensation_body(path: Path = None) -> str:
    """The shipped compensator, renamed so the probe can count its callers."""
    body = _function_body(path or WORKER_INSTALLER, "compensate_remote_worker() {")
    signature = "compensate_remote_worker() {"
    if body.count(signature) != 1:
        raise AssertionError(f"{signature!r} occurs {body.count(signature)} times in its own body")
    return body.replace(signature, "shipped_compensate_remote_worker() {", 1)


def signal_preamble(path: Path = None) -> str:
    """The handlers and traps the remote shell installs, as the payload writes them."""
    source = (path or WORKER_INSTALLER).read_text(encoding="utf-8")
    if source.count(_PREAMBLE_START) != 1:
        raise AssertionError(
            f"{_PREAMBLE_START!r} occurs {source.count(_PREAMBLE_START)} times")
    if source.count(_PREAMBLE_END) != 1:
        raise AssertionError(f"{_PREAMBLE_END!r} occurs {source.count(_PREAMBLE_END)} times")
    start = source.index(_PREAMBLE_START)
    end = source.index(_PREAMBLE_END, start) + len(_PREAMBLE_END)
    block = source[start:end]
    lines = []
    for line in block.splitlines(keepends=True):
        if line.strip():
            if not line.startswith("    "):
                raise AssertionError(f"the signal preamble is not uniformly indented: {line!r}")
            lines.append(line[4:])
        else:
            lines.append(line)
    return "".join(lines)


def library(path: Path = None) -> str:
    """The functions the child runs, with the compensator under its counted name."""
    body = guard_functions(path)
    shipped = "compensate_remote_worker() {"
    if body.count(shipped) != 1:
        raise AssertionError(f"{shipped!r} occurs {body.count(shipped)} times in the library")
    renamed = compensation_body(path).splitlines(keepends=True)[0].rstrip("\n")
    return body.replace(shipped, renamed, 1)


def child_script(path: Path = None) -> str:
    """The interrupted deployment: shipped handlers, one mutated resource, a wait."""
    return _CHILD.replace("__PREAMBLE__", signal_preamble(path).rstrip("\n"))


def driver_script(path: Path = None) -> str:
    """A scratch host, the shipped signal block, and the four runs that decide the case."""
    lib = library(path)
    child = child_script(path)
    for delimiter, text in (("GOWAVE_PROBE_LIB", lib), ("GOWAVE_PROBE_CHILD", child)):
        if any(line == delimiter for line in text.splitlines()):
            raise AssertionError(f"the {delimiter} heredoc would be closed by the shipped text")
    return _DRIVER_HEAD.replace("__LIB__", lib).replace("__CHILD__", child) + _DRIVER_TAIL


def _values(result: Any) -> Dict[str, str]:
    require(CASE_ID, result.returncode == 0,
            f"the signal-compensation probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _flag(values: Dict[str, str], key: str) -> bool:
    return values.get(key) == "1"


def _refuse(evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))


EVIDENCE = (
    "term_handler_runs_compensation",
    "hup_handler_runs_compensation",
    "int_handler_runs_compensation",
    "compensation_runs_exactly_once",
    "no_mutation_after_the_signal",
    "interruption_state_is_persisted",
    "compensation_restored_the_before_image",
    "compensation_restored_the_mode",
    "restored_state_is_verified",
    "failed_restore_is_reported_incomplete",
    "signal_exit_is_nonzero",
    "temp_files_are_cleaned",
    "journal_survives_every_signal",
)

_NAMES = tuple(name for name, _signal, _tamper in SCENARIOS)

_REQUIRED = tuple(
    [f"{name}.{key}" for name in _NAMES for key in (
        "armed", "capture_ok", "journal_ok", "journal_retained", "compensation_calls",
        "signal_named", "exit_code", "handler_alive", "mutation_after_signal",
        "restore_preserved_path", "restore_preserved_target",
        "target_before", "target_after",
    )]
    + ["term.target_mode_before", "term.target_mode_after", "term.target_mutated",
       "term.journal_mode", "term.journal_state", "term.temp_file_left",
       "tampered.tamper_armed"]
)


def _evidence(values: Dict[str, str]) -> Dict[str, bool]:
    """The probe's ``scenario.key=value`` lines, read back as the case's clauses."""
    missing = [key for key in _REQUIRED if key not in values]
    require(CASE_ID, not missing,
            f"the signal-compensation probe reported nothing for {', '.join(missing)}")
    for name in _NAMES:
        require(CASE_ID, _flag(values, f"{name}.armed"),
                f"the {name} run never reached its waiting window, so no signal was delivered")
        require(CASE_ID, _flag(values, f"{name}.capture_ok"),
                f"the {name} run could not capture the transaction's before-image")
        require(CASE_ID, _flag(values, f"{name}.journal_ok"),
                f"the {name} run could not record the transaction's journal")
    require(CASE_ID, _flag(values, "tampered.tamper_armed"),
            "the altered before-image copy was never written, so the verification clause "
            "was not decided in the failing direction")
    require(CASE_ID, values["term.target_mutated"] != values["term.target_before"],
            "the mutation did not change the inventoried binary, so nothing was interrupted")

    exit_codes = {name: values[f"{name}.exit_code"] for name in _NAMES}
    evidence = {
        "term_handler_runs_compensation":
            _flag(values, "term.signal_named") and values["term.compensation_calls"] == "1",
        "hup_handler_runs_compensation":
            _flag(values, "hup.signal_named") and values["hup.compensation_calls"] == "1",
        "int_handler_runs_compensation":
            _flag(values, "int.signal_named") and values["int.compensation_calls"] == "1",
        "compensation_runs_exactly_once":
            all(values[f"{name}.compensation_calls"] == "1" for name in _NAMES),
        "no_mutation_after_the_signal":
            not any(_flag(values, f"{name}.mutation_after_signal") for name in _NAMES),
        "interruption_state_is_persisted":
            _flag(values, "term.journal_retained")
            and values["term.journal_state"] == "started"
            and values["term.journal_mode"] == "600",
        "compensation_restored_the_before_image":
            values["term.target_after"] == values["term.target_before"],
        "compensation_restored_the_mode":
            values["term.target_mode_after"] == values["term.target_mode_before"]
            and values["term.target_mode_before"] != "644",
        # The restore verifies every file it writes against the digest it
        # recorded, and a path it cannot verify is preserved and named. Nothing
        # named across the three restorable runs is that verdict read back.
        "restored_state_is_verified":
            not any(_flag(values, f"{name}.restore_preserved_path")
                    for name in ("term", "hup", "int")),
        "failed_restore_is_reported_incomplete":
            _flag(values, "tampered.restore_preserved_path")
            and _flag(values, "tampered.restore_preserved_target")
            and values["tampered.target_after"] != values["tampered.target_before"],
        "signal_exit_is_nonzero":
            all(code == "128" for code in exit_codes.values())
            and not any(_flag(values, f"{name}.handler_alive") for name in _NAMES),
        "temp_files_are_cleaned": not _flag(values, "term.temp_file_left"),
        "journal_survives_every_signal":
            all(_flag(values, f"{name}.journal_retained") for name in ("term", "hup", "int")),
    }
    _refuse(evidence)
    return evidence


def case_panel_signal_is_compensated_once(product: Any, run: Any) -> Dict[str, Any]:
    """TXN-01 on the AIO contour: the payload's traps, on the host they installed."""
    host_script = getattr(product, "host_script", None)
    if host_script is None:
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the container the run installed, and this "
            "product exposes no way to run a script on it"
        )
    evidence = _evidence(_values(host_script(driver_script(), timeout=300)))
    return evidence


def case_worker_signal_is_compensated_once(product: Any, run: Any) -> Dict[str, Any]:
    """TXN-01 on the multi-node contour: the same traps on the Worker."""
    host = getattr(product, "topology", None)
    if host is None or not getattr(host, "worker_name", ""):
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the worker container the run created, and no "
            "topology with a worker exists yet"
        )
    result = product.podman.exec_bash(host.worker_name, driver_script(), check=False, timeout=300)
    evidence = _evidence(_values(result))
    return evidence
