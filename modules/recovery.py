#!/usr/bin/env python3
"""Crash recovery journal manager, SQLite online backup staging, and snapshot lifecycle.
Adheres to Decision 5 of design.md and Section 9 tasks.
"""
import json
import os
from datetime import datetime
import math
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import tempfile

VALID_OPS = {"provision", "node_add", "update", "channel_switch", "restore"}
OP_ALLOWED_STATES = {
    "provision": {
        "PROVISION_PREPARED", "PROVISION_APPLYING", "PROVISION_VERIFYING",
        "PROVISION_COMMITTED", "PROVISION_ROLLBACK_REQUIRED", "PROVISION_ROLLED_BACK",
    },
    "node_add": {
        "NODE_ADD_PREPARED", "NODE_ADD_APPLYING", "NODE_ADD_VERIFYING",
        "NODE_ADD_COMMITTED", "NODE_ADD_ROLLBACK_REQUIRED", "NODE_ADD_ROLLED_BACK",
    },
    "update": {"PREPARED", "APPLYING", "VERIFYING", "COMMITTED", "ROLLBACK_REQUIRED", "ROLLED_BACK"},
    "restore": {"PREPARED", "APPLYING", "VERIFYING", "COMMITTED", "ROLLBACK_REQUIRED", "ROLLED_BACK"},
    "channel_switch": {"PREPARED", "APPLYING", "VERIFYING", "COMMITTED", "ROLLBACK_REQUIRED", "ROLLED_BACK"},
}
VALID_STATES = {st for states in OP_ALLOWED_STATES.values() for st in states}


class JournalValidationError(Exception):
    pass


def validate_journal(journal_data):
    """Strict JSON schema validation for journal.json before any recovery action."""
    if not isinstance(journal_data, dict):
        raise JournalValidationError("journal.json root must be a JSON object")

    for field in ("op", "state", "timestamp"):
        if field not in journal_data:
            raise JournalValidationError(f"Missing required journal field: {field}")

    op = journal_data["op"]
    state = journal_data["state"]
    if not isinstance(op, str) or not isinstance(state, str):
        raise JournalValidationError("Journal op and state must be strings")
    if op not in OP_ALLOWED_STATES:
        raise JournalValidationError(f"Invalid operation in journal: {op}")
    if state not in OP_ALLOWED_STATES[op]:
        raise JournalValidationError(f"Invalid state '{state}' for operation '{op}'")

    ts = journal_data["timestamp"]
    if isinstance(ts, str):
        try:
            parsed_ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if parsed_ts.tzinfo is None:
                raise ValueError("timestamp must include a timezone")
        except ValueError as exc:
            raise JournalValidationError(f"Invalid ISO-8601 timestamp in journal: {ts}") from exc
    elif isinstance(ts, (int, float)) and not isinstance(ts, bool):
        if not math.isfinite(ts) or ts <= 0:
            raise JournalValidationError(f"Invalid numeric timestamp in journal: {ts}")
    else:
        raise JournalValidationError(f"Invalid timestamp in journal: {ts}")

    if op in ("provision", "node_add") and "entities" in journal_data:
        entities = journal_data["entities"]
        if not isinstance(entities, (dict, list)):
            raise JournalValidationError("Provisioning entities must be a list or a legacy object")
        if isinstance(entities, list):
            for index, item in enumerate(entities):
                if not isinstance(item, dict):
                    raise JournalValidationError(f"Invalid entity entry at index {index}")
                if item.get("type") not in {"profile", "node", "squad", "host", "user", "token"}:
                    raise JournalValidationError(f"Unsupported entity type at index {index}")
                if item.get("action") not in {"created", "updated", "adopted", "pending_create"}:
                    raise JournalValidationError(f"Unsupported entity action at index {index}")
                if item["action"] == "pending_create":
                    if set(item) != {"type", "action"}:
                        raise JournalValidationError(f"Pending create entry has unexpected fields at index {index}")
                    continue
                if not isinstance(item.get("uuid"), str) or not item["uuid"].strip():
                    raise JournalValidationError(f"Missing entity UUID at index {index}")
                if item["action"] == "updated":
                    before = item.get("before")
                    if not isinstance(before, dict) or not before:
                        raise JournalValidationError(f"Missing rollback snapshot for updated entity at index {index}")
                    required_before = {
                        "profile": {"name", "config"},
                        "node": {"name", "address", "port", "configProfile"},
                        "squad": {"name", "inbounds"},
                        "host": {
                            "inbound", "nodes", "remark", "address", "port", "sni",
                            "path", "host", "alpn", "fingerprint", "securityLayer",
                            "internalSquads", "isDisabled",
                        },
                    }.get(item["type"])
                    if required_before is None or not required_before.issubset(before):
                        raise JournalValidationError(f"Incomplete rollback before-image for {item['type']} at index {index}")

    if op in ("update", "restore", "channel_switch") and state in {
        "APPLYING", "VERIFYING", "ROLLBACK_REQUIRED"
    }:
        snapshot_dir = journal_data.get("snapshot_dir")
        if not isinstance(snapshot_dir, str) or not snapshot_dir.startswith("/"):
            raise JournalValidationError(f"Missing absolute recovery snapshot path for state {state}")

    if "transaction_id" in journal_data:
        tid = journal_data["transaction_id"]
        if not isinstance(tid, str) or not tid.strip():
            raise JournalValidationError(f"Invalid transaction_id in journal: {tid}")

    return True


def write_journal_atomically(journal_path, journal_data):
    validate_journal(journal_data)
    path = Path(journal_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{path.name}.tmp"

    # The journal contains rollback before-images (including private config
    # material); create it as 0600 before writing and never follow a pre-planted
    # temporary symlink.
    fd = os.open(
        str(tmp_path),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(journal_data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, path)

    dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def prune_snapshots(recovery_dir, max_snapshots=3, max_bytes=5 * 1024 * 1024 * 1024):
    """Enforce retention: keep last 3 snapshots and enforce a 5 GB storage ceiling."""
    rdir = Path(recovery_dir)
    if not rdir.exists():
        return

    # Find snapshot directories (e.g. update-*, restore-*, pre-channel-switch-*)
    snapshots = []
    for item in rdir.iterdir():
        if item.is_dir() and (item.name.startswith("update-") or item.name.startswith("restore-") or item.name.startswith("pre-channel-")):
            try:
                # Calculate size
                size = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
                snapshots.append((item.stat().st_mtime, size, item))
            except Exception:
                pass

    # Sort newest first
    snapshots.sort(key=lambda x: x[0], reverse=True)

    # 1. Retain at most max_snapshots
    to_delete = snapshots[max_snapshots:]
    retained = snapshots[:max_snapshots]

    # 2. Check total size ceiling
    current_size = sum(x[1] for x in retained)
    while current_size > max_bytes and len(retained) > 1:
        oldest = retained.pop()
        to_delete.append(oldest)
        current_size -= oldest[1]

    for _, _, item in to_delete:
        try:
            shutil.rmtree(item)
        except Exception as e:
            print(f"Warning: Failed to prune snapshot {item}: {e}", file=sys.stderr)


def sqlite_online_backup(db_path, backup_dest, gowave_user="gowave"):
    """Preflight integrity check, WAL checkpoint, and staged SQLite Online Backup."""
    db_file = Path(db_path)
    dest_file = Path(backup_dest)
    dest_file.parent.mkdir(parents=True, exist_ok=True)

    if not db_file.exists():
        raise FileNotFoundError(f"Database {db_path} not found")

    # Connect to verify integrity and perform WAL checkpoint
    conn = sqlite3.connect(str(db_file), timeout=5.0)
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA busy_timeout = 5000;")
        integrity = cur.execute("PRAGMA integrity_check;").fetchall()
        if not integrity or integrity[0][0] != "ok":
            raise ValueError(f"SQLite preflight integrity check failed: {integrity}")

        # Checkpoint WAL
        cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    finally:
        conn.close()

    # Staged backup into pre-created file
    # Use a unique staging file; timestamp-only names collide for concurrent backups.
    fd, staged_name = tempfile.mkstemp(prefix=".backup-", suffix=".db", dir=str(db_file.parent))
    os.close(fd)
    staged_file = Path(staged_name)

    is_root = os.geteuid() == 0
    try:
        if is_root:
            # The service user performs the SQLite Online Backup, but all paths
            # are passed as argv rather than interpolated into a shell command.
            subprocess.run(["chown", f"{gowave_user}:{gowave_user}", str(staged_file)], check=True)
            os.chmod(str(staged_file), 0o640)
            backup_script = (
                "import sqlite3, sys\n"
                "source = sqlite3.connect(sys.argv[1], timeout=5.0)\n"
                "destination = sqlite3.connect(sys.argv[2], timeout=5.0)\n"
                "try:\n"
                "    source.backup(destination)\n"
                "finally:\n"
                "    destination.close()\n"
                "    source.close()\n"
            )
            subprocess.run(
                ["runuser", "-u", gowave_user, "--", "python3", "-c",
                 backup_script, str(db_file), str(staged_file)],
                check=True,
            )
        else:
            # Non-root fallback (for testing/unprivileged execution).
            bconn = sqlite3.connect(str(staged_file))
            try:
                src_conn = sqlite3.connect(str(db_file))
                try:
                    src_conn.backup(bconn)
                finally:
                    src_conn.close()
            finally:
                bconn.close()

        shutil.move(str(staged_file), str(dest_file))
        os.chmod(str(dest_file), 0o600)
    finally:
        try:
            staged_file.unlink()
        except FileNotFoundError:
            pass

    # Verify integrity of destination copy
    dest_conn = sqlite3.connect(str(dest_file))
    try:
        dest_check = dest_conn.execute("PRAGMA integrity_check;").fetchall()
        if not dest_check or dest_check[0][0] != "ok":
            raise ValueError(f"Backup copy integrity check failed: {dest_check}")
    finally:
        dest_conn.close()

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--validate-journal":
        with open(sys.argv[2]) as f:
            data = json.load(f)
        validate_journal(data)
        print("Journal valid.")
    else:
        print("Recovery module loaded.")
