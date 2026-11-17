"""The managed deploy hook is removed only while the journal owns it.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Host Ownership
Inventory says a transaction-created Certbot deploy hook is cleaned up only while
the journal proves the transaction created it, that a hook the installation did
not write blocks the install before mutation, and that ``PRESERVE`` reports what
it leaves behind without claiming a restored baseline.

All three are shell decisions, so the functions are driven rather than quoted:
``modules/nginx.sh`` is sourced in a temporary tree and
``verify_deploy_hook_preflight``, ``install_managed_deploy_hook`` and
``rollback_managed_deploy_hook`` answer with the real ownership record, manifest
and digest they write. The teardown half is ``tools/live_vps/teardown.py``: the
``PRESERVE`` answer is read as it is returned, and the snapshot path is driven
with a real executable hook and two matching baselines so the ``INCOMPLETE``
verdict is the one the product produces rather than one this case repeats.

Nothing here starts a container or touches a host: the hook directory, the
recovery root and the restore hook are all inside one temporary directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest import mock

from tools.live_vps import teardown

CASE_ID = "HOOK-02"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NGINX_MODULE = REPO_ROOT / "modules" / "nginx.sh"

_HOOK_BODY = (
    "#!/bin/sh\n"
    "# Managed by GoWave Auto NGINX: Automated ACME Reload Hook\n"
    "if nginx -t -q; then\n"
    "    systemctl reload nginx\n"
    "fi\n"
)
_BASELINE = {
    "os_kernel": "6.1.0-fixture",
    "running_services": ["nginx.service", "gowave-panel.service"],
    "tcp_listeners_raw": ["443", "2096"],
    "listening_ports": [443, 2096],
    "existing_gowave_dirs": ["/opt/gowave"],
    "firewall_status": "Status: active",
    "swap_info": "swap 2G",
    "key_packages": ["nginx", "sqlite3"],
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _shell(script: str, module: Path | None = None) -> subprocess.CompletedProcess:
    # The default is resolved per call, so a damage that swaps NGINX_MODULE is
    # the module the functions are sourced from.
    source = module or NGINX_MODULE
    return subprocess.run(
        ["bash", "-c", f'source "{source}" && {script}'],
        capture_output=True, text=True, timeout=120,
    )


def _call(function: str, *args: Any, module: Path | None = None) -> subprocess.CompletedProcess:
    quoted = " ".join(f"'{argument}'" for argument in args)
    return _shell(f"{function} {quoted}", module=module)


def _restore_hook(directory: Path) -> SimpleNamespace:
    """An executable restore hook that answers the documented protocol."""
    path = directory / "restore-hook.sh"
    path.write_text(
        "#!/bin/sh\n"
        "cat >/dev/null\n"
        "cat <<'JSON'\n"
        '{"schema_version": 1, "status": "RESTORED", '
        '"master": {"snapshot_id": "snap-master", "restored": true}, '
        '"worker": {"snapshot_id": "snap-worker", "restored": true}}\n'
        "JSON\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o700)
    return SimpleNamespace(
        test_teardown_policy="RESTORE_SNAPSHOT",
        master_snapshot_id="snap-master",
        worker_snapshot_id="snap-worker",
        restore_hook_path=str(path),
        restore_hook_sha256=_sha256(path),
        restore_timeout=30,
        master_ip="45.13.20.10",
        worker_ip="91.203.40.20",
    )


def case_hook_is_removed_only_while_the_journal_owns_it(
    context: Any, run: Any
) -> Dict[str, Any]:
    """The three clauses of the sentence, each read from what decides it."""
    workdir = Path(tempfile.mkdtemp(prefix="gowave-hook-02-"))
    try:
        hook = workdir / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
        hook.parent.mkdir(parents=True)
        recovery = workdir / "recovery"

        # A hook the installation did not write blocks it before any mutation.
        hook.write_text("#!/bin/sh\necho provider-owned\n", encoding="utf-8")
        foreign_digest = _sha256(hook)
        preflight = _call(
            "verify_deploy_hook_preflight", str(hook), "tx-1", str(recovery))
        install_over_foreign = _call(
            "install_managed_deploy_hook", "tx-1", str(hook), str(recovery))
        unowned_unchanged = _sha256(hook) == foreign_digest
        manifests_before = len(list(recovery.rglob("deploy-hook-manifest.json")))

        # Its own hook is installed, recorded, and recognised on a repeated run.
        hook.unlink()
        install = _call(
            "install_managed_deploy_hook", "tx-2", str(hook), str(recovery))
        installed_bytes = hook.read_bytes()
        installed_digest = _sha256(hook)
        manifest = recovery / "tx-2" / "deploy-hook-manifest.json"
        ownership_record = recovery / "deploy-hook-ownership.json"
        manifest_data = json.loads(manifest.read_text()) if manifest.exists() else {}
        repeat = _call(
            "install_managed_deploy_hook", "tx-3", str(hook), str(recovery))
        record_published = ownership_record.exists()

        # A hook edited after installation is preserved and the rollback refuses.
        hook.write_text(installed_bytes.decode() + "# edited after install\n",
                        encoding="utf-8")
        edited_digest = _sha256(hook)
        rollback_edited = _call(
            "rollback_managed_deploy_hook", "tx-2", str(hook), str(recovery))
        edited_preserved = hook.exists() and _sha256(hook) == edited_digest

        # The untouched hook is removed and the ownership record with it.
        hook.write_bytes(installed_bytes)
        rollback_owned = _call(
            "rollback_managed_deploy_hook", "tx-2", str(hook), str(recovery))
        owned_removed = not hook.exists()
        record_cleared = not ownership_record.exists()

        # PRESERVE keeps the host and claims no baseline it did not compare.
        preserve = teardown.execute_teardown(
            SimpleNamespace(test_teardown_policy="PRESERVE"), run_id="run-hook-02")

        # The snapshot path compares baselines and still refuses to say PASS.
        with mock.patch.object(teardown, "collect_remote_baseline", lambda _ssh: dict(_BASELINE)), \
                mock.patch.object(teardown, "check_disposable_gate", lambda _baseline: (True, [])), \
                mock.patch.object(teardown.time, "sleep", lambda _seconds: None):
            snapshot = teardown.execute_teardown(
                _restore_hook(workdir), run_id="run-hook-02",
                master_ssh=object(), worker_ssh=object(),
                pre_baseline_master=dict(_BASELINE),
                pre_baseline_worker=dict(_BASELINE),
            )

        evidence = {
            "unowned_hook_refused": preflight.returncode != 0 and install_over_foreign.returncode != 0,
            "refusal_names_the_unmanaged_resource": "overwrite unmanaged host resource" in (
                preflight.stderr + install_over_foreign.stderr),
            "unowned_hook_unchanged": unowned_unchanged,
            "manifests_before_any_install": manifests_before,
            "install_exit": install.returncode,
            "manifest_created_by_tx": manifest_data.get("created_by_tx") is True,
            "manifest_names_the_hook": manifest_data.get("path") == str(hook),
            "manifest_digest_matches_the_hook": manifest_data.get("sha256") == installed_digest,
            "ownership_record_present": record_published,
            "repeat_install_exit": repeat.returncode,
            "edited_hook_preserved": edited_preserved,
            "rollback_of_edited_hook_refused": rollback_edited.returncode != 0,
            "owned_hook_removed": owned_removed,
            "ownership_record_cleared": record_cleared,
            "preserve_status": preserve.get("status"),
            "preserve_fields": ",".join(sorted(preserve)),
            "preserve_claims_restored_baseline": any(
                "baseline" in str(value).lower() or "restored" in str(value).lower()
                for key, value in preserve.items() if key != "policy"),
            "preserve_message": preserve.get("message"),
            "snapshot_status": snapshot.get("status"),
            "snapshot_hook_status": snapshot.get("hook_status"),
            "snapshot_baseline_comparison": snapshot.get("captured_baseline_comparison"),
            "snapshot_pair_lock_reacquisition": snapshot.get("pair_lock_reacquisition"),
            "snapshot_ownership_comparison": snapshot.get("complete_resource_ownership_comparison"),
        }
        refused: List[str] = []
        if not evidence["unowned_hook_refused"]:
            refused.append("an unowned hook was overwritten")
        if not evidence["refusal_names_the_unmanaged_resource"]:
            refused.append("the refusal does not name the unmanaged resource")
        if not evidence["unowned_hook_unchanged"]:
            refused.append("the unowned hook did not survive the refusal")
        if evidence["manifests_before_any_install"]:
            refused.append("a manifest was written before the install was allowed")
        if evidence["install_exit"] != 0:
            refused.append("the install of a clean hook directory failed")
        if not evidence["manifest_created_by_tx"]:
            refused.append("the manifest does not record the transaction as the creator")
        if not evidence["manifest_names_the_hook"]:
            refused.append("the manifest does not name the hook path")
        if not evidence["manifest_digest_matches_the_hook"]:
            refused.append("the manifest records a digest the hook does not have")
        if not evidence["ownership_record_present"]:
            refused.append("no ownership record was published")
        if evidence["repeat_install_exit"] != 0:
            refused.append("a repeated install did not recognise its own hook")
        if not evidence["edited_hook_preserved"]:
            refused.append("a hook edited after installation was not preserved")
        if not evidence["rollback_of_edited_hook_refused"]:
            refused.append("the rollback claimed success over an edited hook")
        if not evidence["owned_hook_removed"]:
            refused.append("the transaction-owned hook was not removed")
        if not evidence["ownership_record_cleared"]:
            refused.append("the ownership record outlived the hook it named")
        if evidence["preserve_status"] != "PASS":
            refused.append("PRESERVE did not report a preserved host")
        if evidence["preserve_fields"] != "message,policy,status":
            refused.append(
                f"PRESERVE answered with {evidence['preserve_fields']} rather than "
                "the message, policy and status it owns")
        if evidence["preserve_claims_restored_baseline"]:
            refused.append("PRESERVE claimed a baseline it never compared")
        if evidence["snapshot_status"] != "INCOMPLETE":
            refused.append(
                f"a matched snapshot baseline reported {evidence['snapshot_status']!r} "
                "instead of INCOMPLETE")
        if evidence["snapshot_hook_status"] != "RESTORED":
            refused.append("the restore hook's own answer is not recorded")
        if evidence["snapshot_baseline_comparison"] != "MATCHED":
            refused.append("the captured baseline comparison is not recorded as matched")
        if evidence["snapshot_pair_lock_reacquisition"] != "NOT_IMPLEMENTED":
            refused.append("the unimplemented pair-lock reacquisition is not named")
        if evidence["snapshot_ownership_comparison"] != "NOT_IMPLEMENTED":
            refused.append("the unimplemented ownership comparison is not named")
        if refused:
            raise AssertionError("HOOK-02: " + "; ".join(refused))
        return evidence
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
