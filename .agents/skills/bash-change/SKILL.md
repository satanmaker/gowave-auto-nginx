---
name: bash-change
description: Change Bash code here in the order that catches breakage cheapest first — locate the code and any payload-heredoc copies, edit atomically, then run bash -n, ShellCheck (or report it as not run), and the targeted lint unittest before any full suite. Use when the user asks for a правка bash-модуля, to change gowave-auto.sh, gowave-node-auto.sh, assets/backup/gowave-backup.sh, a modules/*.sh submodule or a tests/*.sh case, or says "edit shell script", "fix the installer script", "правка скрипта".
---

Apply one shell change to this repository and report only the checks that actually ran.

## When to use

- Editing `gowave-auto.sh`, `gowave-node-auto.sh`, `assets/backup/gowave-backup.sh`, `modules/*.sh`, `tests/*.sh`, or any `assets/**/*.sh`.
- A request to change, fix, or refactor installer, module, worker-payload, or backup shell logic.
- Not for OpenSpec artifacts, Python harness cases alone, or NGINX template edits.

## Procedure

1. **Locate the code, including heredoc copies.** Read the file around the target. In
   `gowave-node-auto.sh` most of the file is text inside heredocs streamed over SSH by
   `remote_payload`, and the same function bodies appear in several copies. If the edit is
   mechanical (`sed -i`, `perl -pi`) or reaches a streamed payload, count occurrences first
   and require exactly the number the change is about:
   `grep -c '^func_name()' gowave-node-auto.sh`. A pattern unique in one copy silently
   rewrites its siblings; a count that differs from the expected one means stop and
   re-anchor, never widen the pattern until something matches.
2. **Edit with the failure paths intact.** Every script and every SSH payload keeps
   `set -Eeuo pipefail` as its first line — `-E` is what makes the rollback trap fire inside
   a function. Register each `mktemp -d` with `track_temp_dir` (`modules/tempdir.sh`) and
   remove it early with `release_temp_dir`; never rely on a `RETURN` trap for cleanup.
   Before `rm -rf` on a path assembled from a name, resolve it with `realpath -m` and require
   it strictly below an owned directory (`require_tree_under` in `gowave-node-auto.sh`).
   Quote every expansion and redirect `< /dev/null` where a loop or streamed command must not
   steal stdin.
3. **Syntax check the edited file(s).** One `bash -n <file>` per script touched is enough for
   a targeted edit.
4. **ShellCheck, or say it did not run.** Probe availability first with
   `command -v shellcheck`. If it is absent, report "ShellCheck not run on this host"
   explicitly and never present it as passing — CI installs it via apt and is where it runs.
   When it is present, run the exact CI command from the repository root; `.shellcheckrc`
   sets `external-sources=true` and `source-path=SCRIPTDIR`, so a different working directory
   invents SC1090/SC1091 noise.
5. **Targeted unittest.** `python3 -m unittest -v tests.test_nonroot_lint.TestNonrootLint`
   re-runs `bash -n` over the canonical script list, `py_compile` over Python, and the
   strict-mode, temp-dir and tree-guard assertions.
6. **Optional broader runs.** Run `python3 tests/run_ci.py --suite nonroot` (requires
   `EUID != 0`, slower) when the change touches shared modules or generated NGINX config.
   Run `python3 tests/run_ci.py --check-completeness` when the change adds or renames a test
   class; it fails fast and is unrelated to shell logic but cheap.

## Commands

```bash
# from the repository root
grep -c '^func_name()' gowave-node-auto.sh      # anchor count before a bulk rewrite
bash -n <file>
command -v shellcheck
shellcheck --severity=error gowave-auto.sh gowave-node-auto.sh assets/backup/gowave-backup.sh modules/*.sh tests/*.sh
python3 -m unittest -v tests.test_nonroot_lint.TestNonrootLint
python3 tests/run_ci.py --suite nonroot
python3 tests/run_ci.py --check-completeness
```

## Reporting

State which commands ran and which did not, with the reason: a missing `shellcheck` is
"not run", never a pass. A green `bash -n` proves the file parses, not that the behaviour
works — say what remains unverified (worker payload on a remote host, live ports, generated
config) instead of implying coverage. Name the file and the function changed, and if a bulk
rewrite was involved, the match count it required.
