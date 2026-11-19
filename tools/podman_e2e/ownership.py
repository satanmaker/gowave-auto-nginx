#!/usr/bin/env python3
"""An install owns only what it created: the sysctl file each role writes.

``openspec/specs/podman-e2e/spec.md`` §Complete
Mutation-Target Baseline and Resource Ownership says a host configuration file
the install did not write is never truncated and then treated as
transaction-created. Two writers can truncate such a file: the panel's
``configure_bbr_and_mtu`` in ``modules/security.sh``, which owns
``/etc/sysctl.d/99-gowave.conf``, and the worker's ``configure_host_security``
in the payload ``gowave-node-auto.sh`` streams to the host, which owns
``/etc/sysctl.d/99-gowave-node.conf``.

Both are driven here as the product runs them, on the host that carries them:
the AIO contour sources the panel module in the container it installed, and the
multi-node contour runs the worker's writer on the worker container. Each writer
is handed a path and asked about five states — a file another tool wrote, an
empty file, a symlink to the product's own lines, a file of nothing but the
product's own lines, and no file at all — and the case reads back the exit
status, the bytes, the mode and the ``_SYSCTL_CREATED_BY_US`` verdict the
function itself leaves behind.

What is real is the function body the product ships, executed by bash on the
host an install would execute it on, and the file it reads and writes. What is
not is the kernel: ``sysctl``, ``modprobe``, ``systemctl`` and ``swapon`` are
answered by shims, because this case is about which bytes on disk survive a
refusal, not about what the kernel does with them.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "OWN-01"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PANEL_SECURITY = REPO_ROOT / "modules" / "security.sh"
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "foreign_refused": "a file another tool wrote was adopted instead of refused",
    "foreign_bytes_intact": "the refusal rewrote the unmanaged file",
    "foreign_mode_intact": "the refusal changed the mode of the unmanaged file",
    "refusal_names_the_path": "the refusal does not name the file it refused",
    "empty_refused": "an empty file was adopted on the strength of being empty",
    "symlink_refused": "a symlink at the managed path was adopted as the file",
    "symlink_still_a_symlink": "the refusal replaced the symlink it refused",
    "symlink_target_intact": "the refusal wrote through the symlink it refused",
    "own_lines_adopted": "the product's own file was refused",
    "own_lines_keep_the_marker":
        "the product's own file lost the marker that identifies it",
    "absent_created": "the product did not create its own file where none existed",
    "absent_has_the_marker":
        "the file the product created does not carry its marker",
    "foreign_not_marked_created":
        "the unmanaged file was recorded as created by this run",
    "own_lines_not_marked_created":
        "the product's own earlier file was recorded as created by this run",
    "absent_marked_created": "the product did not record the file it created",
}

#: ``set -u`` and a scratch directory; the four commands that would touch the
#: kernel answer instead of acting, and the swap branch is never entered.
_PREAMBLE = """\
set -u
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

sysctl() {
    printf 'sysctl %s\\n' "$*" >> "$work/shim.log"
    if [[ "${1:-}" == "-n" ]]; then printf 'cubic bbr\\n'; fi
    return 0
}
modprobe() { printf 'modprobe %s\\n' "$*" >> "$work/shim.log"; return 0; }
systemctl() { printf 'systemctl %s\\n' "$*" >> "$work/shim.log"; return 0; }
swapon() { printf '/dev/sdz\\n'; }
log_warn() { printf '[WARN] %s\\n' "$*" >&2; }
log_err() { printf '[ERR] %s\\n' "$*" >&2; }

report() { printf '%s=%s\\n' "$1" "$2"; }
digest() { sha256sum "$1" | cut -d' ' -f1; }

"""

_SCENARIOS = """\
# 1. A file another tool owns: refused, and left byte for byte and mode for mode.
# The refusal is read from a file rather than from ``$(call ...)``, because a
# command substitution is a subshell: the ``_SYSCTL_CREATED_BY_US`` the function
# sets inside it would never reach this shell, and the fact below would be read
# from a variable the call never touched.
foreign="$work/foreign.conf"
printf '%s\\n' '# vendor policy' 'vm.swappiness = 10' > "$foreign"
chmod 0644 "$foreign"
foreign_digest=$(digest "$foreign")
foreign_mode=$(stat -c '%a' "$foreign")
_SYSCTL_CREATED_BY_US=0
call "$foreign" >/dev/null 2>"$work/foreign.err"; foreign_rc=$?
refusal=$(cat "$work/foreign.err")
report foreign_refused "$([[ "$foreign_rc" -ne 0 ]] && echo 1 || echo 0)"
report foreign_bytes_intact "$([[ "$(digest "$foreign")" == "$foreign_digest" ]] && echo 1 || echo 0)"
report foreign_mode_intact "$([[ "$(stat -c '%a' "$foreign")" == "$foreign_mode" ]] && echo 1 || echo 0)"
report foreign_not_marked_created "$([[ "${_SYSCTL_CREATED_BY_US:-0}" -eq 0 ]] && echo 1 || echo 0)"
report refusal_names_the_path "$(case "$refusal" in *"$foreign"*) echo 1;; *) echo 0;; esac)"

# 2. An empty file proves nothing about who wrote it, so it is not adopted either.
empty="$work/empty.conf"
: > "$empty"
_SYSCTL_CREATED_BY_US=0
call "$empty" >/dev/null 2>&1; empty_rc=$?
report empty_refused "$([[ "$empty_rc" -ne 0 ]] && echo 1 || echo 0)"

# 3. A symlink is not the file a transaction wrote, even when its target holds
# the product's own lines: the link is refused and the target keeps its bytes.
ours_target="$work/ours-target.conf"
printf '%s\\n' '# Managed by GoWave Auto NGINX' 'net.ipv4.tcp_mtu_probing = 1' > "$ours_target"
target_digest=$(digest "$ours_target")
link="$work/link.conf"
ln -s "$ours_target" "$link"
_SYSCTL_CREATED_BY_US=0
call "$link" >/dev/null 2>&1; link_rc=$?
report symlink_refused "$([[ "$link_rc" -ne 0 ]] && echo 1 || echo 0)"
report symlink_still_a_symlink "$([[ -L "$link" ]] && echo 1 || echo 0)"
report symlink_target_intact "$([[ "$(digest "$ours_target")" == "$target_digest" ]] && echo 1 || echo 0)"

# 4. The product's own earlier file is adopted and rewritten, and this run did
# not create it, so a rollback leaves it in place.
own="$work/own.conf"
printf '%s\\n' '# Managed by GoWave Auto NGINX' 'net.ipv4.tcp_mtu_probing = 1' > "$own"
_SYSCTL_CREATED_BY_US=0
call "$own" >/dev/null 2>&1; own_rc=$?
report own_lines_adopted "$([[ "$own_rc" -eq 0 ]] && echo 1 || echo 0)"
report own_lines_not_marked_created "$([[ "${_SYSCTL_CREATED_BY_US:-0}" -eq 0 ]] && echo 1 || echo 0)"
report own_lines_keep_the_marker "$([[ "$(grep -cxF '# Managed by GoWave Auto NGINX' "$own")" == "1" ]] && echo 1 || echo 0)"

# 5. No file at all: the product creates its own, says so, and a rollback may
# remove it.
absent="$work/fresh/absent.conf"
mkdir -p "$(dirname "$absent")"
_SYSCTL_CREATED_BY_US=0
call "$absent" >/dev/null 2>&1; absent_rc=$?
report absent_created "$([[ "$absent_rc" -eq 0 && -f "$absent" ]] && echo 1 || echo 0)"
report absent_marked_created "$([[ "${_SYSCTL_CREATED_BY_US:-0}" -eq 1 ]] && echo 1 || echo 0)"
report absent_has_the_marker "$([[ -f "$absent" ]] && head -n 1 "$absent" | grep -qxF '# Managed by GoWave Auto NGINX' && echo 1 || echo 0)"

exit 0
"""


def _function_body(path: Path, signature: str) -> str:
    """The function as the product ships it, sliced out of its own file."""
    text = path.read_text(encoding="utf-8")
    start = text.index(signature)
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def worker_writer() -> str:
    """The two functions the worker payload runs, in the order it defines them.

    ``configure_host_security`` ends by calling ``configure_worker_dot``, so the
    slice carries that function too rather than stubbing the product's own tail.
    """
    return (
        _function_body(WORKER_INSTALLER, "configure_worker_dot() {")
        + "\n"
        + _function_body(WORKER_INSTALLER, "configure_host_security() {")
    )


def panel_script(repo: str) -> str:
    """The panel writer driven against a path in a temporary directory.

    The module is sourced rather than sliced: its own ``BASH_SOURCE`` decides
    where ``modules.api_client`` is imported from, and a sliced copy would name
    a directory that holds no package.
    """
    header = f'source "{repo}/modules/security.sh"\nset +e\n'
    # A module that failed to load leaves every writer call undefined, and an
    # undefined call exits non-zero: every "refused" fact would then be green
    # for the wrong reason. Refuse to report anything if the writer is missing.
    probe = (
        'command -v configure_bbr_and_mtu >/dev/null || '
        '{ printf \'the panel module did not define configure_bbr_and_mtu\\n\' >&2; exit 3; }\n'
    )
    call = 'call() { configure_bbr_and_mtu "$work/state.json" "$1" "$work/bbr-load.service"; }\n\n'
    return header + probe + _PREAMBLE + call + _SCENARIOS


def worker_script() -> str:
    """The worker writer driven against the path it is handed."""
    call = 'call() { configure_host_security "$1"; }\n\n'
    return _PREAMBLE + call + worker_writer() + "\n" + _SCENARIOS


def _facts(result: Any, keys: List[str]) -> Dict[str, bool]:
    """The probe's ``key=1`` lines, read back as the facts the case asserts."""
    require(CASE_ID, result.returncode == 0,
            f"the writer probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    missing = [key for key in keys if key not in values]
    require(CASE_ID, not missing,
            f"the writer probe reported nothing for {', '.join(missing)}")
    return {key: values[key] == "1" for key in keys}


def _refuse(case_id: str, evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{case_id}: " + "; ".join(refused))


_SHARED_PROBES = (
    "foreign_refused",
    "foreign_bytes_intact",
    "foreign_mode_intact",
    "refusal_names_the_path",
    "empty_refused",
    "symlink_refused",
    "symlink_still_a_symlink",
    "symlink_target_intact",
    "own_lines_adopted",
    "own_lines_keep_the_marker",
    "absent_created",
    "absent_has_the_marker",
)


def run_locally(case_id: str, script: str, timeout: int = 300) -> Any:
    """The same script the container runs, driven by bash on this machine."""
    return subprocess.run(
        ["bash", "-s"], input=script, capture_output=True, text=True, timeout=timeout,
    )


def case_panel_sysctl_is_not_adopted(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-01 on the AIO contour: the panel's own sysctl file.

    The panel has no rollback step that removes its sysctl file, so
    ``_SYSCTL_CREATED_BY_US`` is not one of the facts this half decides.
    """
    from tools.podman_e2e import topology

    host_script = getattr(product, "host_script", None)
    if host_script is None:
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the container the run installed, and this "
            "product exposes no way to run a script on it"
        )
    result = host_script(panel_script(topology.REPO_IN_CONTAINER), timeout=300)
    facts = _facts(result, list(_SHARED_PROBES))
    evidence = {
        "foreign_refused": facts["foreign_refused"],
        "foreign_bytes_intact": facts["foreign_bytes_intact"],
        "foreign_mode_intact": facts["foreign_mode_intact"],
        "refusal_names_the_path": facts["refusal_names_the_path"],
        "empty_refused": facts["empty_refused"],
        "symlink_refused": facts["symlink_refused"],
        "symlink_still_a_symlink": facts["symlink_still_a_symlink"],
        "symlink_target_intact": facts["symlink_target_intact"],
        "own_lines_adopted": facts["own_lines_adopted"],
        "own_lines_keep_the_marker": facts["own_lines_keep_the_marker"],
        "absent_created": facts["absent_created"],
        "absent_has_the_marker": facts["absent_has_the_marker"],
    }
    _refuse(CASE_ID, evidence)
    return evidence


def case_worker_sysctl_is_not_adopted(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-01 on the multi-node contour: the worker's own sysctl file."""
    host = getattr(product, "topology", None)
    if host is None or not getattr(host, "worker_name", ""):
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the worker container the run created, and no "
            "topology with a worker exists yet"
        )
    result = product.podman.exec_bash(host.worker_name, worker_script(), check=False, timeout=300)
    facts = _facts(result, list(_SHARED_PROBES) + [
        "foreign_not_marked_created",
        "own_lines_not_marked_created",
        "absent_marked_created",
    ])
    evidence = {
        "foreign_refused": facts["foreign_refused"],
        "foreign_bytes_intact": facts["foreign_bytes_intact"],
        "foreign_mode_intact": facts["foreign_mode_intact"],
        "foreign_not_marked_created": facts["foreign_not_marked_created"],
        "refusal_names_the_path": facts["refusal_names_the_path"],
        "empty_refused": facts["empty_refused"],
        "symlink_refused": facts["symlink_refused"],
        "symlink_still_a_symlink": facts["symlink_still_a_symlink"],
        "symlink_target_intact": facts["symlink_target_intact"],
        "own_lines_adopted": facts["own_lines_adopted"],
        "own_lines_not_marked_created": facts["own_lines_not_marked_created"],
        "own_lines_keep_the_marker": facts["own_lines_keep_the_marker"],
        "absent_created": facts["absent_created"],
        "absent_marked_created": facts["absent_marked_created"],
        "absent_has_the_marker": facts["absent_has_the_marker"],
    }
    _refuse(CASE_ID, evidence)
    return evidence
