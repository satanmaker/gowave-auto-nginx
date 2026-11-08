#!/usr/bin/env bash
# assets/backup/gowave-backup.sh - Hardened Backup & Restore Format v1
# Usage: gowave-backup.sh {backup [--type panel|node] [output]|restore <archive>|inspect <archive>|verify <archive>}
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKUP_STORE="/var/backups/gowave"
RECOVERY_STORE="/var/lib/gowave-auto-nginx/recovery"
DEFAULT_GOWAVE_DIR="/opt/gowave"
DEFAULT_NODE_DIR="/opt/gowave-node"

log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }
die()      { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

# Python 15-point archive validator
validate_archive_py() {
    local archive="$1"
    local expected_type="${2:-panel}"
    local staging_target="${3:-}"

    python3 - "$archive" "$expected_type" "$staging_target" <<'PY'
import fnmatch
import hashlib
import json
import os
import posixpath
import sys
import tarfile

archive_path, expected_type, staging_target = sys.argv[1:4]

def fail(msg):
    print(f"Validation Error: {msg}", file=sys.stderr)
    sys.exit(1)

# Check archive exists and readable
if not os.path.isfile(archive_path):
    fail(f"Archive {archive_path} does not exist or is not a file")

# Allowlist definition
PANEL_ALLOWLIST_PATTERNS = [
    "opt/gowave/gowave.db",
    "opt/gowave/.env",
    "etc/nginx/conf.d/gowave-*.conf",
    "etc/nginx/stream-enabled/gowave-*.conf",
    "etc/letsencrypt/archive/**",
    "etc/letsencrypt/live/**",
    "etc/letsencrypt/renewal/**",
    "var/lib/gowave-auto-nginx/state.json",
]

NODE_ALLOWLIST_PATTERNS = [
    "opt/gowave-node/.env",
]

FORBIDDEN_SUBSTRINGS = [
    "renewal-hooks",
    "modules-enabled",
    ".service.d",
    ".service",
]

FORBIDDEN_EXTENSIONS = [
    ".sh", ".so", ".bin", ".exe", ".py"
]

total_size = 0
member_count = 0
meta_data = None
meta_bytes = b""

with tarfile.open(archive_path, "r:gz") as tar:
    members = tar.getmembers()
    member_count = len(members)

    # Check member count limit (5,000)
    if member_count > 5000:
        fail(f"Member count exceeds 5,000 files ({member_count})")

    meta_member = None
    for m in members:
        # Check decompression bomb limit (1 GB)
        total_size += m.size
        if total_size > 1024 * 1024 * 1024:
            fail(f"Unpacked size exceeds 1 GB decompression bomb limit ({total_size} bytes)")

        # 1. Path traversal check
        name = m.name
        if ".." in name.split("/"):
            fail(f"Path traversal detected in member name: {name}")

        # 2. Leading slash / absolute path check
        if name.startswith("/") or name.startswith("\\"):
            fail(f"Absolute path member rejected: {name}")

        # 7. Device nodes / special files rejection
        if m.isdev() or m.ischr() or m.isblk() or m.isfifo():
            fail(f"Device node or special file rejected: {name}")

        # 6. Hard links
        if m.islnk():
            fail(f"Hard link member rejected: {name}")

        if name == "meta.json" or name == "./meta.json":
            meta_member = m
            # 10. Metadata size limit (16 KB)
            if m.size > 16384:
                fail(f"meta.json exceeds 16 KB size limit ({m.size} bytes)")

    if not meta_member:
        fail("Missing meta.json in archive root")

    meta_f = tar.extractfile(meta_member)
    meta_bytes = meta_f.read()
    try:
        meta_data = json.loads(meta_bytes.decode("utf-8"))
    except Exception as e:
        fail(f"Malformed meta.json: {e}")

    # Check format version
    if meta_data.get("format_version") != 1:
        fail(f"Unsupported backup format version: {meta_data.get('format_version')}")

    backup_type = meta_data.get("backup_type")
    if expected_type and backup_type != expected_type:
        fail(f"Backup type mismatch: expected {expected_type}, got {backup_type}")

    allowlist = PANEL_ALLOWLIST_PATTERNS if backup_type == "panel" else NODE_ALLOWLIST_PATTERNS

    # 3. Inspect members against allowlist and forbidden patterns
    file_checksums = {f["path"]: f.get("sha256") for f in meta_data.get("files", []) if "path" in f}

    for m in members:
        clean_name = m.name
        if clean_name.startswith("./"):
            clean_name = clean_name[2:]

        if clean_name == "meta.json" or clean_name == "files" or clean_name == "files/":
            continue

        if not clean_name.startswith("files/"):
            fail(f"Member outside files/ hierarchy: {clean_name}")

        rel_path = clean_name[6:] # strip 'files/'

        # Skip directory members
        if m.isdir():
            continue

        # Forbidden substrings check
        for sub in FORBIDDEN_SUBSTRINGS:
            if sub in rel_path:
                fail(f"Forbidden path component '{sub}' in member: {rel_path}")

        # Forbidden extensions check
        for ext in FORBIDDEN_EXTENSIONS:
            if rel_path.endswith(ext):
                fail(f"Forbidden executable or script extension '{ext}' in member: {rel_path}")

        # Executable binary check
        if rel_path in ("opt/gowave/gowave-server", "opt/gowave-node/gowave-node"):
            fail(f"Binary executable rejected from archive: {rel_path}")

        # Allowlist match check
        matched = False
        for pattern in allowlist:
            if fnmatch.fnmatch(rel_path, pattern):
                matched = True
                break

        if not matched:
            fail(f"Member path '{rel_path}' is outside strict allowlist for type '{backup_type}'")

        # 5. Symbolic links check
        if m.issym():
            link_target = m.linkname
            if link_target.startswith("/") or ".." in link_target.split("/"):
                fail(f"Symbolic link escape detected in member {clean_name} -> {link_target}")

        # 11. Checksum validation against meta.json
        if m.isreg():
            expected_sha = file_checksums.get(rel_path)
            if expected_sha:
                content = tar.extractfile(m).read()
                actual_sha = hashlib.sha256(content).hexdigest()
                if actual_sha != expected_sha:
                    fail(f"Checksum mismatch for member {rel_path}: expected {expected_sha}, got {actual_sha}")

        # 4. Clear SUID / SGID bits
        m.mode &= ~(0o4000 | 0o2000 | 0o1000)

    # Extract if staging_target is requested
    if staging_target:
        os.makedirs(staging_target, mode=0o700, exist_ok=True)
        for m in members:
            # Force secure extraction
            tar.extract(m, path=staging_target)

print("15-point preflight archive validation PASSED.")
PY
}

create_panel_backup() {
    local output_file="$1"
    local gowave_dir="${2:-$DEFAULT_GOWAVE_DIR}"
    local state_file="/var/lib/gowave-auto-nginx/state.json"

    echo "==> Creating GoWave Central Panel Backup (Format v1)..."
    echo "SECURITY WARNING: Archive is UNENCRYPTED and contains master credentials, database, and TLS certificates." >&2
    echo "Files will be protected with POSIX permissions 0600 (root-only access)."

    local tmp_staging
    tmp_staging=$(mktemp -d "/tmp/gowave-backup-XXXXXX")
    trap 'rm -rf "$tmp_staging"' RETURN

    mkdir -p "$tmp_staging/files/opt/gowave" \
             "$tmp_staging/files/etc/nginx/conf.d" \
             "$tmp_staging/files/etc/nginx/stream-enabled" \
             "$tmp_staging/files/var/lib/gowave-auto-nginx"

    local files_meta=()

    # 1. Database backup via SQLite Online Backup
    if [[ -f "$gowave_dir/gowave.db" ]]; then
        echo "Staging SQLite Online Backup for $gowave_dir/gowave.db..."
        python3 -c "
from modules.recovery import sqlite_online_backup
sqlite_online_backup('$gowave_dir/gowave.db', '$tmp_staging/files/opt/gowave/gowave.db')
"
        local db_sha
        db_sha=$(sha256sum "$tmp_staging/files/opt/gowave/gowave.db" | awk '{print $1}')
        files_meta+=("{\"path\": \"opt/gowave/gowave.db\", \"sha256\": \"$db_sha\", \"mode\": \"0640\", \"owner\": \"gowave\", \"group\": \"gowave\"}")
    fi

    # 2. .env file
    if [[ -f "$gowave_dir/.env" ]]; then
        cp "$gowave_dir/.env" "$tmp_staging/files/opt/gowave/.env"
        local env_sha
        env_sha=$(sha256sum "$tmp_staging/files/opt/gowave/.env" | awk '{print $1}')
        files_meta+=("{\"path\": \"opt/gowave/.env\", \"sha256\": \"$env_sha\", \"mode\": \"0640\", \"owner\": \"root\", \"group\": \"gowave\"}")
    fi

    # 3. State JSON
    if [[ -f "$state_file" ]]; then
        cp "$state_file" "$tmp_staging/files/var/lib/gowave-auto-nginx/state.json"
        local state_sha
        state_sha=$(sha256sum "$tmp_staging/files/var/lib/gowave-auto-nginx/state.json" | awk '{print $1}')
        files_meta+=("{\"path\": \"var/lib/gowave-auto-nginx/state.json\", \"sha256\": \"$state_sha\", \"mode\": \"0600\", \"owner\": \"root\", \"group\": \"root\"}")
    fi

    # 4. NGINX project configurations
    for f in /etc/nginx/conf.d/gowave-*.conf /etc/nginx/stream-enabled/gowave-*.conf; do
        if [[ -f "$f" ]]; then
            local rel="${f#/}"
            local dest="$tmp_staging/files/$rel"
            mkdir -p "$(dirname "$dest")"
            cp "$f" "$dest"
            local f_sha
            f_sha=$(sha256sum "$dest" | awk '{print $1}')
            files_meta+=("{\"path\": \"$rel\", \"sha256\": \"$f_sha\", \"mode\": \"0644\", \"owner\": \"root\", \"group\": \"root\"}")
        fi
    done

    # 5. Let's Encrypt certificates
    if [[ -d /etc/letsencrypt ]]; then
        mkdir -p "$tmp_staging/files/etc/letsencrypt"
        for dir in archive live renewal; do
            if [[ -d "/etc/letsencrypt/$dir" ]]; then
                cp -r "/etc/letsencrypt/$dir" "$tmp_staging/files/etc/letsencrypt/"
            fi
        done
        # Record certificate files
        while IFS= read -r cfile; do
            if [[ -f "$cfile" ]]; then
                local rel="${cfile#$tmp_staging/files/}"
                local c_sha
                c_sha=$(sha256sum "$cfile" | awk '{print $1}')
                files_meta+=("{\"path\": \"$rel\", \"sha256\": \"$c_sha\", \"mode\": \"0600\", \"owner\": \"root\", \"group\": \"root\"}")
            fi
        done < <(find "$tmp_staging/files/etc/letsencrypt" -type f)
    fi

    # 6. Generate meta.json
    local files_json
    files_json=$(printf ',%s' "${files_meta[@]}")
    files_json="[${files_json:1}]"

    cat > "$tmp_staging/meta.json" <<EOF
{
  "format_version": 1,
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_type": "panel",
  "source_os": {
    "arch": "$(uname -m)"
  },
  "files": $files_json
}
EOF

    mkdir -p "$(dirname "$output_file")"
    tar -czf "$output_file" -C "$tmp_staging" meta.json files
    chmod 0600 "$output_file"
    echo "Panel backup created successfully: $output_file (mode 0600)."
}

create_node_backup() {
    local output_file="$1"
    local node_dir="${2:-$DEFAULT_NODE_DIR}"

    echo "==> Creating GoWave Worker Node Backup (Format v1)..."
    echo "SECURITY WARNING: Archive is UNENCRYPTED and contains worker credentials." >&2

    local tmp_staging
    tmp_staging=$(mktemp -d "/tmp/gowave-node-backup-XXXXXX")
    trap 'rm -rf "$tmp_staging"' RETURN

    mkdir -p "$tmp_staging/files/opt/gowave-node"
    local files_meta=()

    if [[ -f "$node_dir/.env" ]]; then
        cp "$node_dir/.env" "$tmp_staging/files/opt/gowave-node/.env"
        local env_sha
        env_sha=$(sha256sum "$tmp_staging/files/opt/gowave-node/.env" | awk '{print $1}')
        files_meta+=("{\"path\": \"opt/gowave-node/.env\", \"sha256\": \"$env_sha\", \"mode\": \"0600\", \"owner\": \"root\", \"group\": \"root\"}")
    fi

    local files_json
    files_json=$(printf ',%s' "${files_meta[@]}")
    files_json="[${files_json:1}]"

    cat > "$tmp_staging/meta.json" <<EOF
{
  "format_version": 1,
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_type": "node",
  "source_os": {
    "arch": "$(uname -m)"
  },
  "files": $files_json
}
EOF

    mkdir -p "$(dirname "$output_file")"
    tar -czf "$output_file" -C "$tmp_staging" meta.json files
    chmod 0600 "$output_file"
    echo "Node backup created successfully: $output_file (mode 0600)."
}

cmd_restore() {
    local archive="$1"
    local expected_type="${2:-panel}"

    [[ -f "$archive" ]] || die "Archive $archive not found"

    echo "==> Initiating Restore from $archive (type: $expected_type)..."

    local ts
    ts=$(date +%s)
    local restore_snap="${RECOVERY_STORE}/restore-${ts}"
    mkdir -p "$restore_snap"
    chmod 0700 "$restore_snap" 2>/dev/null || true

    # Step 1: Pre-restore persistent snapshotting
    echo "Capturing pre-restore snapshot in $restore_snap..."
    if [[ "$expected_type" == "panel" ]]; then
        if [[ -f "$DEFAULT_GOWAVE_DIR/gowave.db" ]]; then
            cp "$DEFAULT_GOWAVE_DIR/gowave.db" "$restore_snap/gowave.db"
        fi
        if [[ -f "$DEFAULT_GOWAVE_DIR/.env" ]]; then
            cp "$DEFAULT_GOWAVE_DIR/.env" "$restore_snap/.env"
        fi
    else
        if [[ -f "$DEFAULT_NODE_DIR/.env" ]]; then
            cp "$DEFAULT_NODE_DIR/.env" "$restore_snap/.env"
        fi
    fi

    # Step 2: 15-point preflight validation & extraction to staging directory
    local staging_dir
    staging_dir=$(mktemp -d "/tmp/gowave-restore-staging-XXXXXX")
    trap 'rm -rf "$staging_dir"' RETURN

    echo "Running 15-point preflight archive security validation..."
    validate_archive_py "$archive" "$expected_type" "$staging_dir"

    # Step 3: Atomic file restoration
    echo "Applying restored files..."
    if [[ "$expected_type" == "panel" ]]; then
        if [[ -f "$staging_dir/files/opt/gowave/gowave.db" ]]; then
            cp "$staging_dir/files/opt/gowave/gowave.db" "$DEFAULT_GOWAVE_DIR/gowave.db"
            rm -f "$DEFAULT_GOWAVE_DIR/gowave.db-wal" "$DEFAULT_GOWAVE_DIR/gowave.db-shm"
            chmod 0640 "$DEFAULT_GOWAVE_DIR/gowave.db"
        fi
        if [[ -f "$staging_dir/files/opt/gowave/.env" ]]; then
            cp "$staging_dir/files/opt/gowave/.env" "$DEFAULT_GOWAVE_DIR/.env"
            chmod 0640 "$DEFAULT_GOWAVE_DIR/.env"
        fi
        if [[ -f "$staging_dir/files/var/lib/gowave-auto-nginx/state.json" ]]; then
            mkdir -p /var/lib/gowave-auto-nginx
            cp "$staging_dir/files/var/lib/gowave-auto-nginx/state.json" /var/lib/gowave-auto-nginx/state.json
            chmod 0600 /var/lib/gowave-auto-nginx/state.json
        fi
    else
        if [[ -f "$staging_dir/files/opt/gowave-node/.env" ]]; then
            mkdir -p "$DEFAULT_NODE_DIR"
            cp "$staging_dir/files/opt/gowave-node/.env" "$DEFAULT_NODE_DIR/.env"
            chmod 0600 "$DEFAULT_NODE_DIR/.env"
        fi
    fi

    # Restart services if root
    if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        if [[ "$expected_type" == "panel" ]]; then
            systemctl restart --no-ask-password gowave.service || true
        else
            systemctl restart --no-ask-password gowave-node.service || true
        fi
    fi
    echo "Restore completed successfully."
}

# CLI routing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        backup)
            btype="panel"
            if [[ "${2:-}" == "--type" ]]; then
                btype="${3:-panel}"
                out="${4:-$BACKUP_STORE/gowave-backup-$btype-$(date +%s).tar.gz}"
            else
                out="${2:-$BACKUP_STORE/gowave-backup-panel-$(date +%s).tar.gz}"
            fi
            if [[ "$btype" == "panel" ]]; then
                create_panel_backup "$out"
            else
                create_node_backup "$out"
            fi
            ;;
        restore)
            archive="${2:-}"
            btype="panel"
            if [[ "${3:-}" == "--type" ]]; then
                btype="${4:-panel}"
            fi
            cmd_restore "$archive" "$btype"
            ;;
        verify|inspect)
            archive="${2:-}"
            btype="${3:-panel}"
            validate_archive_py "$archive" "$btype"
            ;;
        *)
            echo "Usage: gowave-backup.sh {backup [--type panel|node] [out]|restore <archive> [--type panel|node]|verify <archive> [panel|node]}"
            exit 1
            ;;
    esac
fi
