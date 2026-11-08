#!/usr/bin/env python3
"""Crash recovery journal manager, SQLite online backup staging, and snapshot lifecycle.
Adheres to Decision 5 of design.md and Section 9 tasks.
"""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

VALID_OPS = {"provision", "node_add", "update", "channel_switch", "restore"}
VALID_STATES = {
    # Update / Restore / Channel switch
    "PREPARED", "APPLYING", "VERIFYING", "COMMITTED", "ROLLBACK_REQUIRED", "ROLLED_BACK",
    # Initial Provision
    "PROVISION_PREPARED", "PROVISION_APPLYING", "PROVISION_VERIFYING", "PROVISION_COMMITTED", "PROVISION_ROLLBACK_REQUIRED", "PROVISION_ROLLED_BACK",
    # Node Add
    "NODE_ADD_PREPARED", "NODE_ADD_APPLYING", "NODE_ADD_VERIFYING", "NODE_ADD_COMMITTED", "NODE_ADD_ROLLBACK_REQUIRED", "NODE_ADD_ROLLED_BACK",
}


class JournalValidationError(Exception):
    pass


def validate_journal(journal_data):
    """Strict JSON schema validation for journal.json before any recovery action."""
    if not isinstance(journal_data, dict):
        raise JournalValidationError("journal.json root must be a JSON object")

    for field in ("op", "state", "timestamp"):
        if field not in journal_data:
            raise JournalValidationError(f"Missing required journal field: {field}")

    if journal_data["op"] not in VALID_OPS:
        raise JournalValidationError(f"Invalid operation in journal: {journal_data['op']}")

    if journal_data["state"] not in VALID_STATES:
        raise JournalValidationError(f"Invalid state in journal: {journal_data['state']}")

    return True


def write_journal_atomically(journal_path, journal_data):
    validate_journal(journal_data)
    path = Path(journal_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f"{path.name}.tmp"

    with open(tmp_path, "w") as f:
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
    staged_file = db_file.parent / f".backup-{int(time.time())}.db"

    is_root = os.geteuid() == 0
    if is_root:
        # Pre-create with 0640 ownership gowave:gowave
        subprocess.run(["install", "-o", gowave_user, "-g", gowave_user, "-m", "0640", "/dev/null", str(staged_file)], check=True)
        # Execute backup under service user privileges
        backup_cmd = f"sqlite3 '{db_file}' '.backup {staged_file}'"
        subprocess.run(["runuser", "-u", gowave_user, "--", "bash", "-c", backup_cmd], check=True)
        # Move into private recovery storage
        shutil.move(str(staged_file), str(dest_file))
        os.chmod(str(dest_file), 0o600)
    else:
        # Non-root fallback (for testing/unprivileged execution)
        bconn = sqlite3.connect(str(dest_file))
        try:
            src_conn = sqlite3.connect(str(db_file))
            src_conn.backup(bconn)
            src_conn.close()
        finally:
            bconn.close()
        os.chmod(str(dest_file), 0o600)

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
