#!/usr/bin/env python3
"""A Worker path this install did not write is not a rollback target.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Complete
Mutation-Target Baseline and Resource Ownership says the runner rejects a
pre-existing systemd unit, drop-in, binary or managed webroot unless a complete
ownership record proves the object belongs to this run. The Worker payload now
carries that guard: ``verify_worker_mutation_targets_preflight`` reads
``/var/lib/gowave-auto-nginx/worker-install-ownership.json`` (written by
``record_worker_mutation_targets`` after a verified install) and refuses any
managed path that is not absent, not recorded, or no longer has the digest —
or, for a link the upstream installer writes, the target — the record holds.
It runs before the first managed path is touched, so a refusal leaves the host
as it was.

The case drives the shipped functions, sliced out of ``gowave-node-auto.sh``,
on the host each contour installs: the AIO container and the Worker container.
Each run builds a scratch root, so what it decides is the verdict and the bytes
left behind, not a real ``/etc/systemd/system``.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "OWN-02"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "foreign_refused": "a pre-existing unit file was adopted instead of refused",
    "refusal_names_the_path": "the refusal does not name the path it refused",
    "foreign_bytes_intact": "the refusal rewrote the unmanaged file",
    "foreign_mode_intact": "the refusal changed the mode of the unmanaged file",
    "foreign_dir_refused": "a pre-existing directory was adopted instead of refused",
    "symlink_refused": "a symlink at a managed path was adopted as the file",
    "symlink_intact": "the refusal replaced the symlink it refused",
    "nothing_created_before_refusal":
        "the refusal created the ownership record before it refused",
    "record_adopts_own_paths":
        "the record this install wrote does not adopt its own file",
    "record_names_the_file": "the record does not name the file it adopts",
    "record_mode_is_private": "the ownership record is readable by every user",
    "changed_digest_refused":
        "a recorded file whose bytes changed was adopted anyway",
    "changed_digest_named": "the refusal of a changed file does not name it",
    "unclaimed_record_refused":
        "a record that does not claim this product created anything was trusted",
    "empty_root_accepted": "a host with none of the managed paths was refused",
    "recorded_symlink_adopted":
        "a symlink this install wrote was refused as a foreign object",
    "recorded_symlink_kept": "adopting the recorded symlink moved it",
    "repointed_symlink_refused":
        "a recorded symlink re-pointed elsewhere was adopted",
    "repointed_symlink_named":
        "the refusal of a re-pointed symlink does not name it",
}

_FUNCTION_SIGNATURES = (
    "worker_mutation_targets() {",
    "worker_ownership_record() {",
    "verify_worker_mutation_targets_preflight() {",
    "record_worker_mutation_targets() {",
)

_SCENARIOS = r"""\
report() { printf '%s=%s\n' "$1" "$2"; }
digest() { sha256sum "$1" | cut -d' ' -f1; }
mode() { stat -c '%a' "$1"; }

# 1. A unit file this install did not write: refused, named, and left byte for
# byte and mode for mode. The guard writes no record on its way out.
root="$work/foreign"
mkdir -p "$root/etc/systemd/system"
printf '%s\n' '[Service]' 'ExecStart=/opt/vendor/daemon' > "$root/etc/systemd/system/gowave-node.service"
chmod 0640 "$root/etc/systemd/system/gowave-node.service"
foreign_digest=$(digest "$root/etc/systemd/system/gowave-node.service")
foreign_mode=$(mode "$root/etc/systemd/system/gowave-node.service")
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>"$work/foreign.err"
foreign_rc=$?
refusal=$(cat "$work/foreign.err")
report foreign_refused "$([[ "$foreign_rc" -ne 0 ]] && echo 1 || echo 0)"
report refusal_names_the_path "$(case "$refusal" in *gowave-node.service*) echo 1;; *) echo 0;; esac)"
report foreign_bytes_intact "$([[ "$(digest "$root/etc/systemd/system/gowave-node.service")" == "$foreign_digest" ]] && echo 1 || echo 0)"
report foreign_mode_intact "$([[ "$(mode "$root/etc/systemd/system/gowave-node.service")" == "$foreign_mode" ]] && echo 1 || echo 0)"
report nothing_created_before_refusal "$([[ ! -e "$root/var/lib/ownership.json" ]] && echo 1 || echo 0)"

# 2. A directory at a managed binary path belongs to whoever put it there.
root="$work/directory"
mkdir -p "$root/opt/gowave-node/bin"
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>&1
report foreign_dir_refused "$([[ "$?" -ne 0 ]] && echo 1 || echo 0)"

# 3. A symlink is not the file a transaction wrote, even when its target holds
# the very bytes the record names: the link is refused and stays a link.
root="$work/link"
mkdir -p "$root/usr/local/bin"
printf '%s\n' 'xray' > "$root/usr/local/bin/xray"
record_worker_mutation_targets "$root" "$root/var/lib/ownership.json"
mv "$root/usr/local/bin/xray" "$work/xray-recorded"
ln -s "$work/xray-recorded" "$root/usr/local/bin/xray"
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>&1
report symlink_refused "$([[ "$?" -ne 0 ]] && echo 1 || echo 0)"
report symlink_intact "$([[ -L "$root/usr/local/bin/xray" ]] && echo 1 || echo 0)"

# 4. What this install wrote is recorded, and the record adopts it by digest.
root="$work/own"
mkdir -p "$root/usr/local/bin" "$root/opt/gowave-node"
printf '%s\n' 'gowave-node' > "$root/usr/local/bin/gowave-node"
printf '%s\n' 'xray' > "$root/usr/local/bin/xray"
record_worker_mutation_targets "$root" "$root/var/lib/ownership.json"
record_rc=$?
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>&1
adopt_rc=$?
report record_adopts_own_paths "$([[ "$record_rc" -eq 0 && "$adopt_rc" -eq 0 ]] && echo 1 || echo 0)"
report record_names_the_file "$(grep -qF '"/usr/local/bin/xray"' "$root/var/lib/ownership.json" 2>/dev/null && echo 1 || echo 0)"
report record_mode_is_private "$([[ "$(mode "$root/var/lib/ownership.json")" == "600" ]] && echo 1 || echo 0)"

# 5. A recorded file whose bytes changed is no longer the file the record names.
printf '%s\n' 'tampered' >> "$root/usr/local/bin/xray"
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>"$work/changed.err"
report changed_digest_refused "$([[ "$?" -ne 0 ]] && echo 1 || echo 0)"
report changed_digest_named "$(case "$(cat "$work/changed.err")" in *usr/local/bin/xray*) echo 1;; *) echo 0;; esac)"

# 6. A record that does not claim this product created anything proves nothing.
root="$work/unclaimed"
mkdir -p "$root/opt/gowave-node"
printf '%s\n' '{"created_by_tx": false, "targets": {"/opt/gowave-node": {"kind": "directory"}}}' > "$work/unclaimed.json"
verify_worker_mutation_targets_preflight "$root" "$work/unclaimed.json" >/dev/null 2>&1
report unclaimed_record_refused "$([[ "$?" -ne 0 ]] && echo 1 || echo 0)"

# 7. A host that carries none of the managed paths is the clean case.
root="$work/empty"
mkdir -p "$root"
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>&1
report empty_root_accepted "$([[ "$?" -eq 0 ]] && echo 1 || echo 0)"

# 8. The upstream installer links the Worker binary into /usr/local/bin, so a
# link this install wrote is adopted by the target the record names — and a
# link re-pointed after the record was written is not.
root="$work/own-link"
mkdir -p "$root/usr/local/bin" "$root/opt/gowave-node"
printf '%s\n' 'gowave-node' > "$root/opt/gowave-node/gowave-node"
ln -s /opt/gowave-node/gowave-node "$root/usr/local/bin/gowave-node"
record_worker_mutation_targets "$root" "$root/var/lib/ownership.json"
link_record_rc=$?
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>&1
link_adopt_rc=$?
report recorded_symlink_adopted "$([[ "$link_record_rc" -eq 0 && "$link_adopt_rc" -eq 0 ]] && echo 1 || echo 0)"
report recorded_symlink_kept "$([[ -L "$root/usr/local/bin/gowave-node" && "$(readlink "$root/usr/local/bin/gowave-node")" == "/opt/gowave-node/gowave-node" ]] && echo 1 || echo 0)"
ln -sfn /opt/remnanode/other "$root/usr/local/bin/gowave-node"
verify_worker_mutation_targets_preflight "$root" "$root/var/lib/ownership.json" >/dev/null 2>"$work/link-changed.err"
report repointed_symlink_refused "$([[ "$?" -ne 0 ]] && echo 1 || echo 0)"
report repointed_symlink_named "$(case "$(cat "$work/link-changed.err")" in *usr/local/bin/gowave-node*) echo 1;; *) echo 0;; esac)"

exit 0
"""


def _function_body(path: Path, signature: str) -> str:
    """The function as the product ships it, sliced out of its own file."""
    text = path.read_text(encoding="utf-8")
    start = text.index(signature)
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def guard_functions(path: Path = None) -> str:
    """The four shipped functions the case drives, in the order they appear."""
    source = path or WORKER_INSTALLER
    return "".join(_function_body(source, signature) for signature in _FUNCTION_SIGNATURES)


def driver_script(path: Path = None) -> str:
    """A scratch host, the shipped guard, and the eight states it decides."""
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
            f"the guard probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    missing = [key for key in keys if key not in values]
    require(CASE_ID, not missing,
            f"the guard probe reported nothing for {', '.join(missing)}")
    return {key: values[key] == "1" for key in keys}


def _refuse(evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))


EVIDENCE = (
    "foreign_refused",
    "refusal_names_the_path",
    "foreign_bytes_intact",
    "foreign_mode_intact",
    "foreign_dir_refused",
    "symlink_refused",
    "symlink_intact",
    "nothing_created_before_refusal",
    "record_adopts_own_paths",
    "record_names_the_file",
    "record_mode_is_private",
    "changed_digest_refused",
    "changed_digest_named",
    "unclaimed_record_refused",
    "empty_root_accepted",
    "recorded_symlink_adopted",
    "recorded_symlink_kept",
    "repointed_symlink_refused",
    "repointed_symlink_named",
)


def case_panel_mutation_targets_are_not_adopted(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-02 on the AIO contour: the guard run on the host it installed."""
    host_script = getattr(product, "host_script", None)
    if host_script is None:
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the container the run installed, and this "
            "product exposes no way to run a script on it"
        )
    result = host_script(driver_script(), timeout=300)
    facts = _facts(result, list(EVIDENCE))
    evidence = {
        "foreign_refused": facts["foreign_refused"],
        "refusal_names_the_path": facts["refusal_names_the_path"],
        "foreign_bytes_intact": facts["foreign_bytes_intact"],
        "foreign_mode_intact": facts["foreign_mode_intact"],
        "foreign_dir_refused": facts["foreign_dir_refused"],
        "symlink_refused": facts["symlink_refused"],
        "symlink_intact": facts["symlink_intact"],
        "nothing_created_before_refusal": facts["nothing_created_before_refusal"],
        "record_adopts_own_paths": facts["record_adopts_own_paths"],
        "record_names_the_file": facts["record_names_the_file"],
        "record_mode_is_private": facts["record_mode_is_private"],
        "changed_digest_refused": facts["changed_digest_refused"],
        "changed_digest_named": facts["changed_digest_named"],
        "unclaimed_record_refused": facts["unclaimed_record_refused"],
        "empty_root_accepted": facts["empty_root_accepted"],
        "recorded_symlink_adopted": facts["recorded_symlink_adopted"],
        "recorded_symlink_kept": facts["recorded_symlink_kept"],
        "repointed_symlink_refused": facts["repointed_symlink_refused"],
        "repointed_symlink_named": facts["repointed_symlink_named"],
    }
    _refuse(evidence)
    return evidence


def case_worker_mutation_targets_are_not_adopted(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-02 on the multi-node contour: the guard run on the Worker."""
    host = getattr(product, "topology", None)
    if host is None or not getattr(host, "worker_name", ""):
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the worker container the run created, and no "
            "topology with a worker exists yet"
        )
    result = product.podman.exec_bash(host.worker_name, driver_script(), check=False, timeout=300)
    facts = _facts(result, list(EVIDENCE))
    evidence = {
        "foreign_refused": facts["foreign_refused"],
        "refusal_names_the_path": facts["refusal_names_the_path"],
        "foreign_bytes_intact": facts["foreign_bytes_intact"],
        "foreign_mode_intact": facts["foreign_mode_intact"],
        "foreign_dir_refused": facts["foreign_dir_refused"],
        "symlink_refused": facts["symlink_refused"],
        "symlink_intact": facts["symlink_intact"],
        "nothing_created_before_refusal": facts["nothing_created_before_refusal"],
        "record_adopts_own_paths": facts["record_adopts_own_paths"],
        "record_names_the_file": facts["record_names_the_file"],
        "record_mode_is_private": facts["record_mode_is_private"],
        "changed_digest_refused": facts["changed_digest_refused"],
        "changed_digest_named": facts["changed_digest_named"],
        "unclaimed_record_refused": facts["unclaimed_record_refused"],
        "empty_root_accepted": facts["empty_root_accepted"],
        "recorded_symlink_adopted": facts["recorded_symlink_adopted"],
        "recorded_symlink_kept": facts["recorded_symlink_kept"],
        "repointed_symlink_refused": facts["repointed_symlink_refused"],
        "repointed_symlink_named": facts["repointed_symlink_named"],
    }
    _refuse(evidence)
    return evidence
