#!/usr/bin/env python3
"""The pre-push acceptance gate: both full suites, and the hook that runs them.

The pull request is not the first place a regression may be caught. This
entrypoint runs the same two suites the acceptance jobs run — the pinned target
images and client artifacts of ``tests/cases/images.lock.yaml`` and
``tests/cases/matrix.yaml``, with no live host, no live credential and no public
DNS name — and ``--install-hook`` writes the ``pre-push`` hook that runs it
before ``git push`` sends anything.

    sudo python3 -m tools.pre_push_e2e
    python3 -m tools.pre_push_e2e --install-hook

Which topologies the gate runs is read from the manifest's own ``gate:`` list, so
a topology the matrix puts behind ``pre-push`` is run without this file being
edited, and a topology it does not gate is never silently skipped into a
shorter green. A failing topology stops the gate and the rest are printed as
not run: a later green suite would not change the verdict, and claiming it was
checked when it was not is the one thing a gate must not do.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

MATRIX_PATH = REPO_ROOT / "tests" / "cases" / "matrix.yaml"
SUITE_MODULE = "tools.run_podman_e2e"
GATE_MODULE = "tools.pre_push_e2e"
HOOK_MARKER = "# gowave pre-push acceptance gate"

HOOK_BODY = f"""#!/usr/bin/env bash
{HOOK_MARKER} — installed by `python3 -m {GATE_MODULE} --install-hook`.
# Both acceptance suites run before the push leaves the machine. The suites
# provision their own containers, so they run as root and sudo may prompt.
# `git push --no-verify` bypasses this hook; the pull request gate then judges
# the change, which is where the required checks live.
set -Eeuo pipefail
exec sudo python3 -m {GATE_MODULE}
"""


def load_matrix(path: Path = MATRIX_PATH) -> Dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def pre_push_topologies(matrix: Dict[str, Any]) -> List[str]:
    """The topologies the manifest puts behind ``pre-push``, in its own order."""
    return [
        str(name)
        for name, topology in (matrix.get("topologies") or {}).items()
        if "pre-push" in ((topology or {}).get("gate") or [])
    ]


def suite_command(topology: str) -> List[str]:
    """The full-suite invocation; the acceptance jobs run the same module.

    The suite pins its own fixtures from the matrix — image digests, client
    release checksums, the resolver and ACME directory — so nothing here passes
    a version, a host or a credential that could make the gate prove a different
    combination than CI does.
    """
    return [sys.executable, "-m", SUITE_MODULE, "--topology", topology]


def _git(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *arguments],
        capture_output=True, text=True, check=False,
    )


def repository_state() -> Tuple[str, str]:
    """The commit and tree the run belongs to, as its artifact will record them.

    A gate that does not say which commit it judged leaves the evidence
    unattributable, and a dirty tree is how a suite can pass on code nobody is
    pushing.
    """
    commit = _git("rev-parse", "HEAD").stdout.strip() or "unknown"
    dirty = bool(_git("status", "--porcelain").stdout.strip())
    return commit, "dirty" if dirty else "clean"


def hooks_directory() -> Path:
    """This checkout's hooks directory, including from a linked worktree."""
    result = _git("rev-parse", "--git-path", "hooks")
    location = result.stdout.strip()
    if result.returncode != 0 or not location:
        raise RuntimeError("not inside a git working tree, so there is no hook to install")
    path = Path(location)
    return path if path.is_absolute() else REPO_ROOT / path


def install_hook(directory: Optional[Path] = None) -> Path:
    """Write the pre-push hook, refusing to replace one this gate did not write.

    A hook is the contributor's own file: overwriting one that already exists
    would hide whatever it did, so the installer owns only the file carrying its
    marker and stops on anything else.
    """
    hooks = Path(directory) if directory is not None else hooks_directory()
    target = hooks / "pre-push"
    if target.exists():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in existing:
            raise FileExistsError(
                f"{target} already exists and was not written by this gate; "
                "move it aside before installing the hook"
            )
    hooks.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(HOOK_BODY, encoding="utf-8")
    temporary.chmod(0o755)
    os.replace(temporary, target)
    return target


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--install-hook", action="store_true",
        help="write the pre-push hook for this checkout and exit",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="print the suite commands this gate would run and exit",
    )
    args = parser.parse_args(argv)

    topologies = pre_push_topologies(load_matrix())
    if not topologies:
        print(
            "pre-push: the manifest puts no topology behind pre-push",
            file=sys.stderr,
        )
        return 2
    if args.list:
        for topology in topologies:
            print(" ".join(suite_command(topology)))
        return 0
    if args.install_hook:
        try:
            target = install_hook()
        except (RuntimeError, FileExistsError) as error:
            print(f"pre-push: {error}", file=sys.stderr)
            return 2
        print(f"pre-push: installed {target}")
        print(
            "pre-push: `git push` now runs both suites; "
            "`git push --no-verify` bypasses the gate."
        )
        return 0

    if os.geteuid() != 0:
        print(
            "pre-push: the suites provision privileged systemd containers, so the gate "
            "runs as root:",
            file=sys.stderr,
        )
        print("pre-push:   sudo python3 -m tools.pre_push_e2e", file=sys.stderr)
        return 2

    commit, tree = repository_state()
    print(f"pre-push: judging {commit} (tree: {tree}) with {', '.join(topologies)}")
    for index, topology in enumerate(topologies):
        command = suite_command(topology)
        print(f"pre-push: {topology}: {' '.join(command)}", flush=True)
        status = subprocess.run(command, cwd=str(REPO_ROOT), check=False).returncode
        if status != 0:
            print(
                f"pre-push: {topology} FAILED (exit {status}); the push is blocked",
                file=sys.stderr,
            )
            remaining = topologies[index + 1:]
            if remaining:
                print("pre-push: not run: " + ", ".join(remaining), file=sys.stderr)
            return 1
        print(f"pre-push: {topology} passed")
    print("pre-push: every gated suite passed; the push may continue")
    return 0


if __name__ == "__main__":
    sys.exit(main())
