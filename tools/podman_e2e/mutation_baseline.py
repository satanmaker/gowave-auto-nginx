#!/usr/bin/env python3
"""Compensation restores every transaction-owned resource, not a blanket subset.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Complete
Mutation-Target Baseline and Resource Ownership: after a later deployment step
fails, every path the transaction created is removed only while it is still what
the install wrote, every path that was here before is put back with its recorded
content and metadata, and anything changed afterwards — or that no record can
prove — is preserved with the cleanup reported as incomplete.

The Worker payload answers that with a before-image taken before the first
mutation: ``worker_targets_image capture`` records, for each inventoried path,
whether it was absent, a file (with its bytes copied into the image, its mode,
owner and digest), a symlink (with its target) or a directory. ``record`` writes
the ownership record of what the transaction has written so far, once after the
local steps and once after the upstream installer; ``restore`` walks the same
list, removes a created path only while it still matches that record, puts a
pre-existing path back from the image, and keeps anything it cannot prove — then
reports the cleanup incomplete and exits non-zero, so a rollback never claims a
success it did not earn.

The case drives the shipped functions over a scratch root: the same bash, the
same functions, and a real directory tree — so it decides the functions' verdict
and the bytes they leave behind, on whichever host each contour installs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "OWN-04"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "image_is_per_transaction":
        "the before-image was not written in the transaction's own recovery directory",
    "capture_mutates_nothing": "taking the before-image changed the paths it records",
    "image_names_every_target": "the before-image does not name every inventoried path",
    "image_calls_no_present_path_absent": "a path that was here is recorded as absent",
    "image_keeps_pre_existing_bytes": "the before-image does not hold the bytes it restores",
    "image_keeps_pre_existing_metadata":
        "the before-image does not record the mode and owner it restores",
    "image_keeps_pre_existing_link":
        "the before-image does not record where the link it restores pointed",
    "image_keeps_pre_existing_directory":
        "the before-image does not record a directory it restores",
    "image_mode_is_private": "the Worker targets before-image is readable by every user",
    "existing_image_refused": "a second capture overwrote the state the first one holds",
    "created_paths_removed": "the restore left a path this install created",
    "changed_created_path_preserved":
        "the restore removed a path that changed after this install wrote it",
    "unrecorded_paths_preserved":
        "the restore removed a path no record proves this install wrote",
    "pre_existing_file_restored": "the restore did not put back the bytes that were here",
    "pre_existing_metadata_restored":
        "the restore did not put back the mode and owner that were here",
    "pre_existing_link_restored": "the restore did not put back the link that was here",
    "missing_image_preserves_everything":
        "a rollback with no before-image removed the paths this install wrote",
    "corrupted_copy_preserved":
        "the restore wrote a before-image copy that changed after it was taken",
    "incomplete_is_reported": "the restore reported success while it preserved a path",
}

_FUNCTION_SIGNATURES = (
    "worker_mutation_targets() {",
    "worker_ownership_record() {",
    "worker_targets_before_image() {",
    "worker_targets_image() {",
    "record_worker_targets_before_image() {",
    "restore_worker_targets_before_image() {",
    "record_worker_mutation_targets() {",
)

_SCENARIOS = r"""\
report() { printf '%s=%s\n' "$1" "$2"; }
digest() { sha256sum "$1" | cut -d' ' -f1; }

export FAKE_ROOT="$work/root"
mkdir -p "$FAKE_ROOT"
# The host this install finds: a Worker root, an Xray binary and the symlink the
# payload replaces. Everything else the inventory names is absent.
mkdir -p "$FAKE_ROOT/opt/remnanode" "$FAKE_ROOT/usr/local/bin" "$FAKE_ROOT/etc/systemd/system"
printf '#!/bin/sh\necho old\n' > "$FAKE_ROOT/usr/local/bin/xray"
chmod 0750 "$FAKE_ROOT/usr/local/bin/xray"
ln -s /opt/remnanode/gowave-node "$FAKE_ROOT/usr/local/bin/gowave-node"
xray_before=$(digest "$FAKE_ROOT/usr/local/bin/xray")
xray_mode=$(stat -c '%a' "$FAKE_ROOT/usr/local/bin/xray")
targets=$(worker_mutation_targets)
expected=$(printf '%s\n' "$targets" | grep -c .)

# 1. The image belongs to the transaction, and taking it changes nothing.
ACME_TX_ID="worker_install_casetx"
image=$(worker_targets_before_image "$FAKE_ROOT/var/lib/gowave-auto-nginx")
report image_is_per_transaction "$(case "$image" in */var/lib/gowave-auto-nginx/recovery/worker_install_casetx/worker-targets-before-image) echo 1;; *) echo 0;; esac)"
record_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/capture.err"
capture_rc=$?
report capture_mutates_nothing "$([[ "$capture_rc" -eq 0 && "$(digest "$FAKE_ROOT/usr/local/bin/xray")" == "$xray_before" && "$(stat -c '%a' "$FAKE_ROOT/usr/local/bin/xray")" == "$xray_mode" && ! -e "$FAKE_ROOT/opt/gowave-node" ]] && echo 1 || echo 0)"

# 2. What the image holds, read from the image itself.
manifest="$image/manifest.json"
while IFS='=' read -r key value; do report "$key" "$value"; done < <(
    python3 - "$manifest" "$image" "$FAKE_ROOT" "$expected" <<'MANIFEST_FACTS'
import hashlib
import json
import os
import sys

manifest, image, root, expected = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


try:
    with open(manifest, "r", encoding="utf-8") as stream:
        data = json.load(stream)
except Exception:
    data = {}
targets = data.get("targets") if isinstance(data.get("targets"), dict) else {}
xray = targets.get("/usr/local/bin/xray") or {}
link = targets.get("/usr/local/bin/gowave-node") or {}
remnanode = targets.get("/opt/remnanode") or {}

print("image_names_every_target=%d" % (1 if len(targets) == expected else 0))
wrong = [name for name, entry in targets.items()
         if isinstance(entry, dict) and entry.get("state") == "absent"
         and os.path.lexists(under(name))]
print("image_calls_no_present_path_absent=%d" % (1 if not wrong else 0))

copy = os.path.join(image, str(xray.get("copy") or ""))
kept = (xray.get("state") == "file" and os.path.isfile(copy) and not os.path.islink(copy)
        and digest(copy) == xray.get("sha256"))
print("image_keeps_pre_existing_bytes=%d" % (1 if kept else 0))

state = os.stat(under("/usr/local/bin/xray"))
recorded = (xray.get("mode") == (state.st_mode & 0o7777)
            and xray.get("owner") == [state.st_uid, state.st_gid])
print("image_keeps_pre_existing_metadata=%d" % (1 if recorded else 0))

print("image_keeps_pre_existing_link=%d" % (
    1 if link.get("state") == "symlink" and link.get("target") == "/opt/remnanode/gowave-node" else 0))
print("image_keeps_pre_existing_directory=%d" % (
    1 if remnanode.get("state") == "directory" else 0))
MANIFEST_FACTS
)
report image_mode_is_private "$([[ "$(stat -c '%a' "$manifest" 2>/dev/null)" == "600" ]] && echo 1 || echo 0)"

# 3. A second capture must not overwrite a restorable image.
record_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/repeat.err"
report existing_image_refused "$([[ "$?" -ne 0 ]] && grep -q 'already exists' "$work/repeat.err" && echo 1 || echo 0)"

# 4. The install writes what it owns, replaces the Xray binary and the symlink,
# records the result, and then a later step fails. One of the paths it wrote is
# touched afterwards — by an operator or another process — and must survive.
mkdir -p "$FAKE_ROOT/etc/systemd/system/gowave-node.service.d" \
         "$FAKE_ROOT/opt/gowave-node" "$FAKE_ROOT/run/gowave-node" \
         "$FAKE_ROOT/etc/nginx/conf.d" "$FAKE_ROOT/var/www/gowave-acme"
printf 'unit\n' > "$FAKE_ROOT/etc/systemd/system/gowave-node.service"
printf '#!/bin/sh\necho new\n' > "$FAKE_ROOT/usr/local/bin/xray"
chmod 0755 "$FAKE_ROOT/usr/local/bin/xray"
ln -sfn /opt/gowave-node/gowave-node "$FAKE_ROOT/usr/local/bin/gowave-node"
printf 'server { listen 443; }\n' > "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf"
record_worker_mutation_targets "$FAKE_ROOT" >/dev/null 2>"$work/record.err"
printf 'server { listen 443; server_name later; }\n' > "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf"
touched=$(digest "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf")

restore_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/restore.err"
restore_rc=$?
report created_paths_removed "$([[ ! -e "$FAKE_ROOT/etc/systemd/system/gowave-node.service" && ! -e "$FAKE_ROOT/etc/systemd/system/gowave-node.service.d" && ! -e "$FAKE_ROOT/opt/gowave-node" && ! -e "$FAKE_ROOT/run/gowave-node" && ! -e "$FAKE_ROOT/var/www/gowave-acme" ]] && echo 1 || echo 0)"
report changed_created_path_preserved "$([[ -f "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf" && "$(digest "$FAKE_ROOT/etc/nginx/conf.d/gowave-worker-https.conf")" == "$touched" ]] && echo 1 || echo 0)"
report pre_existing_file_restored "$([[ "$(digest "$FAKE_ROOT/usr/local/bin/xray")" == "$xray_before" ]] && echo 1 || echo 0)"
report pre_existing_metadata_restored "$([[ "$(stat -c '%a' "$FAKE_ROOT/usr/local/bin/xray")" == "$xray_mode" ]] && echo 1 || echo 0)"
report pre_existing_link_restored "$([[ -L "$FAKE_ROOT/usr/local/bin/gowave-node" && "$(readlink "$FAKE_ROOT/usr/local/bin/gowave-node")" == /opt/remnanode/gowave-node ]] && echo 1 || echo 0)"
report incomplete_is_reported "$([[ "$restore_rc" -ne 0 ]] && grep -q 'path(s) preserved, so the cleanup is incomplete' "$work/restore.err" && echo 1 || echo 0)"

# 5. Without the ownership record the restore cannot prove it wrote anything,
# so every created path stays where it is and the cleanup says so.
record="$(worker_ownership_record "$FAKE_ROOT")"
mv "$record" "$work/record.away"
mkdir -p "$FAKE_ROOT/opt/gowave-node"
restore_worker_targets_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/unrecorded.err"
unrecorded_rc=$?
report unrecorded_paths_preserved "$([[ -d "$FAKE_ROOT/opt/gowave-node" && "$unrecorded_rc" -ne 0 ]] && grep -q 'no ownership record proves this transaction wrote it' "$work/unrecorded.err" && echo 1 || echo 0)"
mv "$work/record.away" "$record"
rmdir "$FAKE_ROOT/opt/gowave-node"

# 6. No image at all is a refusal, and a refusal removes nothing.
mkdir -p "$FAKE_ROOT/run/gowave-node"
restore_worker_targets_before_image "$FAKE_ROOT" "$work/no-such-image" >/dev/null 2>"$work/missing.err"
missing_rc=$?
report missing_image_preserves_everything "$([[ "$missing_rc" -ne 0 && -d "$FAKE_ROOT/run/gowave-node" ]] && grep -q 'No Worker targets before-image at' "$work/missing.err" && echo 1 || echo 0)"
rmdir "$FAKE_ROOT/run/gowave-node"

# 7. A before-image copy that changed after it was taken is not written back:
# the path it would restore keeps what is there and the cleanup says so.
image_second="$work/image-second"
record_worker_targets_before_image "$FAKE_ROOT" "$image_second" >/dev/null 2>&1
printf '#!/bin/sh\necho replaced\n' > "$FAKE_ROOT/usr/local/bin/xray"
replaced=$(digest "$FAKE_ROOT/usr/local/bin/xray")
copy=$(python3 - "$image_second/manifest.json" <<'COPY_OF'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    data = json.load(stream)
print((data.get("targets") or {}).get("/usr/local/bin/xray", {}).get("copy") or "")
COPY_OF
)
printf 'tampered\n' > "$image_second/$copy"
restore_worker_targets_before_image "$FAKE_ROOT" "$image_second" >/dev/null 2>"$work/corrupt.err"
corrupt_rc=$?
report corrupted_copy_preserved "$([[ "$corrupt_rc" -ne 0 && "$(digest "$FAKE_ROOT/usr/local/bin/xray")" == "$replaced" ]] && echo 1 || echo 0)"

exit 0
"""


def _function_body(path: Path, signature: str) -> str:
    """The function as the product ships it, sliced out of its own file."""
    text = path.read_text(encoding="utf-8")
    start = text.index(signature)
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def guard_functions(path: Path = None) -> str:
    """The shipped functions the case drives, in the order they appear."""
    source = path or WORKER_INSTALLER
    return "".join(_function_body(source, signature) for signature in _FUNCTION_SIGNATURES)


def block_body(path: Path = None) -> str:
    """The one heredoc the payload and the rollback script must agree on."""
    source = (path or WORKER_INSTALLER).read_text(encoding="utf-8")
    start = source.index("<<'WORKER_TARGETS_PY'\n") + len("<<'WORKER_TARGETS_PY'\n")
    end = source.index("\nWORKER_TARGETS_PY\n", start)
    return source[start:end]


def driver_script(path: Path = None) -> str:
    """A scratch host, the shipped inventory functions, and the states they decide."""
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
            f"the mutation-targets probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    missing = [key for key in keys if key not in values]
    require(CASE_ID, not missing,
            f"the mutation-targets probe reported nothing for {', '.join(missing)}")
    return {key: values[key] == "1" for key in keys}


def _refuse(evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))


EVIDENCE = (
    "image_is_per_transaction",
    "capture_mutates_nothing",
    "image_names_every_target",
    "image_calls_no_present_path_absent",
    "image_keeps_pre_existing_bytes",
    "image_keeps_pre_existing_metadata",
    "image_keeps_pre_existing_link",
    "image_keeps_pre_existing_directory",
    "image_mode_is_private",
    "existing_image_refused",
    "created_paths_removed",
    "changed_created_path_preserved",
    "unrecorded_paths_preserved",
    "pre_existing_file_restored",
    "pre_existing_metadata_restored",
    "pre_existing_link_restored",
    "missing_image_preserves_everything",
    "corrupted_copy_preserved",
    "incomplete_is_reported",
)


def case_panel_mutation_targets_are_restored(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-04 on the AIO contour: the inventory functions run on the host they installed."""
    host_script = getattr(product, "host_script", None)
    if host_script is None:
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the container the run installed, and this "
            "product exposes no way to run a script on it"
        )
    result = host_script(driver_script(), timeout=300)
    facts = _facts(result, list(EVIDENCE))
    evidence = {
        "image_is_per_transaction": facts["image_is_per_transaction"],
        "capture_mutates_nothing": facts["capture_mutates_nothing"],
        "image_names_every_target": facts["image_names_every_target"],
        "image_calls_no_present_path_absent": facts["image_calls_no_present_path_absent"],
        "image_keeps_pre_existing_bytes": facts["image_keeps_pre_existing_bytes"],
        "image_keeps_pre_existing_metadata": facts["image_keeps_pre_existing_metadata"],
        "image_keeps_pre_existing_link": facts["image_keeps_pre_existing_link"],
        "image_keeps_pre_existing_directory": facts["image_keeps_pre_existing_directory"],
        "image_mode_is_private": facts["image_mode_is_private"],
        "existing_image_refused": facts["existing_image_refused"],
        "created_paths_removed": facts["created_paths_removed"],
        "changed_created_path_preserved": facts["changed_created_path_preserved"],
        "unrecorded_paths_preserved": facts["unrecorded_paths_preserved"],
        "pre_existing_file_restored": facts["pre_existing_file_restored"],
        "pre_existing_metadata_restored": facts["pre_existing_metadata_restored"],
        "pre_existing_link_restored": facts["pre_existing_link_restored"],
        "missing_image_preserves_everything": facts["missing_image_preserves_everything"],
        "corrupted_copy_preserved": facts["corrupted_copy_preserved"],
        "incomplete_is_reported": facts["incomplete_is_reported"],
    }
    _refuse(evidence)
    return evidence


def case_worker_mutation_targets_are_restored(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-04 on the multi-node contour: the inventory functions run on the Worker."""
    host = getattr(product, "topology", None)
    if host is None or not getattr(host, "worker_name", ""):
        raise CaseBlocked(
            f"{CASE_ID}: this case needs the worker container the run created, and no "
            "topology with a worker exists yet"
        )
    result = product.podman.exec_bash(host.worker_name, driver_script(), check=False, timeout=300)
    facts = _facts(result, list(EVIDENCE))
    evidence = {
        "image_is_per_transaction": facts["image_is_per_transaction"],
        "capture_mutates_nothing": facts["capture_mutates_nothing"],
        "image_names_every_target": facts["image_names_every_target"],
        "image_calls_no_present_path_absent": facts["image_calls_no_present_path_absent"],
        "image_keeps_pre_existing_bytes": facts["image_keeps_pre_existing_bytes"],
        "image_keeps_pre_existing_metadata": facts["image_keeps_pre_existing_metadata"],
        "image_keeps_pre_existing_link": facts["image_keeps_pre_existing_link"],
        "image_keeps_pre_existing_directory": facts["image_keeps_pre_existing_directory"],
        "image_mode_is_private": facts["image_mode_is_private"],
        "existing_image_refused": facts["existing_image_refused"],
        "created_paths_removed": facts["created_paths_removed"],
        "changed_created_path_preserved": facts["changed_created_path_preserved"],
        "unrecorded_paths_preserved": facts["unrecorded_paths_preserved"],
        "pre_existing_file_restored": facts["pre_existing_file_restored"],
        "pre_existing_metadata_restored": facts["pre_existing_metadata_restored"],
        "pre_existing_link_restored": facts["pre_existing_link_restored"],
        "missing_image_preserves_everything": facts["missing_image_preserves_everything"],
        "corrupted_copy_preserved": facts["corrupted_copy_preserved"],
        "incomplete_is_reported": facts["incomplete_is_reported"],
    }
    _refuse(evidence)
    return evidence
