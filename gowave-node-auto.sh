#!/usr/bin/env bash
# gowave-node-auto.sh - Distributed Edge Worker Deployment and Hardening Orchestrator
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOMMENDED_NODE_PORT=3002

log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }

# Modules source if local
if [[ -f "$SCRIPT_DIR/modules/os.sh" ]]; then
    source "$SCRIPT_DIR/modules/os.sh"
fi
if [[ -f "$SCRIPT_DIR/modules/security.sh" ]]; then
    source "$SCRIPT_DIR/modules/security.sh"
fi

# The local ACME fixture is a test-only trust anchor. Its endpoint is pinned so
# enabling test mode never turns GOWAVE_ACME_SERVER into an arbitrary-URL option.
GOWAVE_ACME_TEST_ENDPOINT="https://pebble.testbed.internal:14000/dir"

acme_test_mode_enabled() {
    [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" ]]
}

validate_acme_test_ca() {
    local ca_file="${GOWAVE_ACME_TEST_CA_FILE:-}"
    local expected_sha256="${GOWAVE_ACME_TEST_CA_SHA256:-}"
    if [[ -z "$ca_file" || -z "$expected_sha256" ]]; then
        echo "Error: test-only ACME mode requires GOWAVE_ACME_TEST_CA_FILE and GOWAVE_ACME_TEST_CA_SHA256." >&2
        return 1
    fi
    if [[ -L "$ca_file" || ! -f "$ca_file" ]]; then
        echo "Error: GOWAVE_ACME_TEST_CA_FILE must be a regular file, not a symlink." >&2
        return 1
    fi
    if [[ ! "$expected_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "Error: GOWAVE_ACME_TEST_CA_SHA256 must be a 64-character hex digest." >&2
        return 1
    fi
    local actual_sha256
    actual_sha256=$(sha256sum -- "$ca_file" 2>/dev/null | awk '{print $1}')
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        echo "Error: ACME test CA digest mismatch; refusing an unpinned trust anchor." >&2
        return 1
    fi
    return 0
}

run_certbot() {
    if acme_test_mode_enabled && [[ "${GOWAVE_ACME_SERVER:-}" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        REQUESTS_CA_BUNDLE="$GOWAVE_ACME_TEST_CA_FILE" \
            SSL_CERT_FILE="$GOWAVE_ACME_TEST_CA_FILE" \
            certbot "$@"
        return
    fi
    certbot "$@"
}

validate_acme_server() {
    local server="${1:-}"
    if [[ -z "$server" ]]; then
        return 0
    fi
    if [[ "$server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        if ! acme_test_mode_enabled; then
            echo "Error: Invalid GOWAVE_ACME_SERVER: the local ACME fixture endpoint is accepted only with GOWAVE_ACME_TEST_MODE=1." >&2
            return 1
        fi
        validate_acme_test_ca || return 1
        return 0
    fi
    if [[ "$server" != "https://acme-staging-v02.api.letsencrypt.org/directory" && \
          "$server" != "https://acme-v02.api.letsencrypt.org/directory" ]]; then
        if acme_test_mode_enabled; then
            echo "Error: test-only ACME mode accepts only the pinned fixture endpoint '$GOWAVE_ACME_TEST_ENDPOINT' or a Let's Encrypt Staging/Production directory; refusing '$server'." >&2
        else
            echo "Error: Invalid GOWAVE_ACME_SERVER: '$server'. Only 'https://acme-staging-v02.api.letsencrypt.org/directory' or 'https://acme-v02.api.letsencrypt.org/directory' are supported." >&2
        fi
        return 1
    fi
    return 0
}

check_acme_lineage() {
    local domain="$1"
    local target_server="${2:-https://acme-v02.api.letsencrypt.org/directory}"
    local renewal_conf="${3:-/etc/letsencrypt/renewal/${domain}.conf}"
    local live_dir="${4:-/etc/letsencrypt/live/${domain}}"
    local fixture_target=0

    if [[ "$target_server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        if ! acme_test_mode_enabled; then
            echo "Error: ACME lineage for $domain targets the local fixture endpoint without GOWAVE_ACME_TEST_MODE=1." >&2
            return 1
        fi
        validate_acme_test_ca || return 1
        fixture_target=1
    fi

    if [[ -f "$renewal_conf" ]]; then
        local existing_server=""
        while IFS='=' read -r key val || [[ -n "$key" ]]; do
            key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [[ "$key" == "server" ]]; then
                existing_server=$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
                break
            fi
        done < "$renewal_conf"

        if [[ -z "$existing_server" ]]; then
            echo "Error: Existing renewal lineage for $domain has no readable 'server' field in $renewal_conf; failing closed to prevent cross-lineage staging/production reuse." >&2
            return 1
        fi

        local recognized=0
        if [[ "$existing_server" == "https://acme-staging-v02.api.letsencrypt.org/directory" || \
              "$existing_server" == "https://acme-v02.api.letsencrypt.org/directory" ]]; then
            recognized=1
        elif [[ "$existing_server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]] && acme_test_mode_enabled; then
            validate_acme_test_ca || return 1
            recognized=1
        fi
        if [[ "$recognized" -ne 1 ]]; then
            echo "Error: Existing renewal lineage for $domain uses unrecognized ACME directory: '$existing_server'." >&2
            return 1
        fi

        if [[ "$existing_server" != "$target_server" ]]; then
            echo "Error: ACME directory mismatch for $domain: existing lineage in $renewal_conf was issued by '$existing_server', but requested server is '$target_server'. Staging and production lineages cannot be mixed." >&2
            return 1
        fi
    fi

    local fullchain="$live_dir/fullchain.pem"
    if [[ -s "$fullchain" ]]; then
        if [[ "$fixture_target" -eq 1 ]]; then
            if ! openssl verify -CAfile "$GOWAVE_ACME_TEST_CA_FILE" -untrusted "$fullchain" "$fullchain" >/dev/null 2>&1; then
                echo "Error: Existing certificate for $domain does not chain to the pinned local ACME test CA; refusing to reuse a cross-lineage certificate." >&2
                return 1
            fi
        else
            local issuer
            issuer=$(openssl x509 -in "$fullchain" -noout -issuer 2>/dev/null || true)
            local is_staging_cert=0
            if [[ "$issuer" =~ \(STAGING\) ]]; then
                is_staging_cert=1
            fi
            if [[ "$target_server" == "https://acme-staging-v02.api.letsencrypt.org/directory" && "$is_staging_cert" -eq 0 ]]; then
                echo "Error: Existing certificate for $domain was issued by production ($issuer), but requested ACME server is staging ($target_server)." >&2
                return 1
            elif [[ "$target_server" == "https://acme-v02.api.letsencrypt.org/directory" && "$is_staging_cert" -eq 1 ]]; then
                echo "Error: Existing certificate for $domain was issued by staging ($issuer), but requested ACME server is production ($target_server)." >&2
                return 1
            fi
        fi
    fi

    return 0
}

snapshot_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    if [[ ! "$transaction_id" =~ ^[A-Za-z0-9._-]+$ || ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo "Error: Invalid transaction ID or domain for ACME snapshot." >&2
        return 1
    fi

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    mkdir -p "$snap_dir" || { echo "Error: Could not create ACME snapshot directory for $domain." >&2; return 1; }
    if [[ -L "$snap_dir" ]]; then
        echo "Error: ACME snapshot directory is an unsafe symlink for $domain." >&2
        return 1
    fi
    chmod 0700 "$snap_dir" 2>/dev/null || { echo "Error: Could not secure ACME snapshot directory for $domain." >&2; return 1; }

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"
    local existed_before=false cert_serial="" cert_fingerprint=""

    if [[ -e "$renewal_conf" || -L "$renewal_conf" || -e "$live_dir" || -L "$live_dir" ]]; then
        if [[ ! -f "$renewal_conf" || -L "$renewal_conf" || ! -d "$live_dir" || -L "$live_dir" ]]; then
            echo "Error: Existing ACME lineage for $domain is incomplete or unsafe; refusing to snapshot it." >&2
            return 1
        fi
        mkdir -p "$snap_dir/archive" "$snap_dir/live" || { echo "Error: Could not create ACME snapshot subdirectories for $domain." >&2; return 1; }
        chmod 0700 "$snap_dir/archive" "$snap_dir/live" 2>/dev/null || { echo "Error: Could not secure ACME snapshot subdirectories for $domain." >&2; return 1; }
        cp -p "$renewal_conf" "$snap_dir/renewal.conf" || { echo "Error: Could not snapshot ACME renewal config for $domain." >&2; return 1; }

        local archive_real
        archive_real=$(realpath -e -- "$archive_dir") || { echo "Error: ACME archive directory is missing for existing lineage $domain." >&2; return 1; }
        local f link_path target real_file bn
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            link_path="${live_dir}/${f}"
            if [[ -L "$link_path" ]]; then
                target=$(readlink "$link_path") || { echo "Error: Could not read ACME symlink $f for $domain." >&2; return 1; }
                if [[ -z "$target" || "$target" == /* ]]; then
                    echo "Error: Unsafe ACME symlink target for $domain/$f." >&2
                    return 1
                fi
                printf '%s\n' "$target" > "$snap_dir/live/${f}.target" || { echo "Error: Could not snapshot ACME symlink target for $domain/$f." >&2; return 1; }
                chmod 0600 "$snap_dir/live/${f}.target" 2>/dev/null || { echo "Error: Could not secure ACME symlink metadata for $domain/$f." >&2; return 1; }
                real_file=$(realpath -e -- "$link_path") || { echo "Error: ACME symlink $domain/$f is broken." >&2; return 1; }
                case "$real_file" in
                    "$archive_real"/*) ;;
                    *)
                        echo "Error: ACME symlink $domain/$f escapes its archive directory." >&2
                        return 1
                        ;;
                esac
                bn=$(basename "$real_file")
                cp -p "$real_file" "$snap_dir/archive/$bn" || { echo "Error: Could not snapshot ACME archive file $bn for $domain." >&2; return 1; }
                if [[ "$bn" =~ ^privkey ]]; then
                    chmod 0600 "$snap_dir/archive/$bn" 2>/dev/null || { echo "Error: Could not secure snapshotted ACME private key for $domain." >&2; return 1; }
                else
                    chmod 0644 "$snap_dir/archive/$bn" 2>/dev/null || { echo "Error: Could not set snapshotted ACME certificate permissions for $domain." >&2; return 1; }
                fi
            elif [[ -f "$link_path" ]]; then
                cp -p "$link_path" "$snap_dir/live/$f" || { echo "Error: Could not snapshot ACME live file $f for $domain." >&2; return 1; }
                if [[ "$f" == "privkey.pem" ]]; then
                    chmod 0600 "$snap_dir/live/$f" 2>/dev/null || { echo "Error: Could not secure snapshotted ACME private key for $domain." >&2; return 1; }
                fi
            else
                if [[ "$f" == "fullchain.pem" || "$f" == "privkey.pem" ]]; then
                    echo "Error: Existing ACME lineage is missing required file $domain/$f." >&2
                    return 1
                fi
                continue
            fi
        done

        local fullchain="${live_dir}/fullchain.pem" privkey="${live_dir}/privkey.pem"
        openssl x509 -in "$fullchain" -noout >/dev/null 2>&1 || { echo "Error: Existing ACME certificate is invalid for $domain." >&2; return 1; }
        local pub_from_cert pub_from_key
        pub_from_cert=$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null) || { echo "Error: Could not read existing ACME certificate key for $domain." >&2; return 1; }
        pub_from_key=$(openssl pkey -in "$privkey" -pubout 2>/dev/null) || { echo "Error: Could not read existing ACME private key for $domain." >&2; return 1; }
        if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
            echo "Error: Existing ACME certificate and private key do not match for $domain." >&2
            return 1
        fi
        cert_serial=$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null) || { echo "Error: Could not read existing ACME certificate serial for $domain." >&2; return 1; }
        cert_fingerprint=$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null) || { echo "Error: Could not read existing ACME certificate fingerprint for $domain." >&2; return 1; }
        if [[ -z "$cert_serial" || -z "$cert_fingerprint" ]]; then
            echo "Error: Existing ACME certificate identity metadata is empty for $domain." >&2
            return 1
        fi
        existed_before=true
    fi

    python3 - "$meta_file" "$domain" "$existed_before" "$cert_serial" "$cert_fingerprint" <<'PY'
import json
import os
import sys

meta_file, domain, existed, serial, fingerprint = sys.argv[1:6]
data = {
    "domain": domain,
    "existed_before": existed == "true",
    "serial": serial,
    "fingerprint": fingerprint,
}
tmp_path = meta_file + ".tmp"
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp_path, meta_file)
    dir_fd = os.open(os.path.dirname(meta_file), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
except Exception as exc:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    print(f"Failed to persist ACME snapshot manifest: {type(exc).__name__}", file=sys.stderr)
    raise SystemExit(1)
PY
}

restore_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"

    if [[ ! -f "$meta_file" ]]; then
        echo "Error: ACME lineage manifest not found for $domain in $snap_dir" >&2
        return 1
    fi

    local existed
    existed=$(python3 - "$meta_file" "$domain" <<'PY'
import json, sys
path, domain = sys.argv[1:3]
with open(path, encoding="utf-8") as stream:
    data = json.load(stream)
if not isinstance(data, dict) or data.get("domain") != domain or type(data.get("existed_before")) is not bool:
    raise SystemExit(1)
print("1" if data["existed_before"] else "0")
PY
) || { echo "Error: Invalid ACME lineage manifest for $domain" >&2; return 1; }
if [[ "$existed" != "0" && "$existed" != "1" ]]; then
    echo "Error: Invalid existed_before marker for $domain" >&2
    return 1
fi

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"

    if [[ "$existed" == "0" ]]; then
        echo "Removing transaction-created ACME lineage for $domain..." >&2
        rm -f "$renewal_conf" || { echo "Error: Could not remove transaction-created renewal config for $domain" >&2; return 1; }
        rm -rf "$live_dir" "$archive_dir" || { echo "Error: Could not remove transaction-created lineage for $domain" >&2; return 1; }
        return 0
    fi

    echo "Restoring pre-existing ACME lineage for $domain from snapshot..." >&2
    mkdir -p "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" || { echo "Error: Could not create ACME restore directories for $domain" >&2; return 1; }
    chmod 0755 "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" 2>/dev/null || { echo "Error: Could not set ACME directory permissions for $domain" >&2; return 1; }

    if [[ -f "$snap_dir/renewal.conf" ]]; then
        cp -p "$snap_dir/renewal.conf" "$renewal_conf" || { echo "Error: Could not restore renewal config for $domain" >&2; return 1; }
        chmod 0644 "$renewal_conf" 2>/dev/null || { echo "Error: Could not set renewal config permissions for $domain" >&2; return 1; }
    fi

    if [[ -d "$snap_dir/archive" ]]; then
        local arc
        for arc in "$snap_dir/archive"/*; do
            [[ -f "$arc" ]] || continue
            local bn
            bn=$(basename "$arc")
            cp -p "$arc" "$archive_dir/$bn" || { echo "Error: Could not restore ACME archive file $bn for $domain" >&2; return 1; }
            if [[ "$bn" =~ ^privkey ]]; then
                chmod 0600 "$archive_dir/$bn" 2>/dev/null || { echo "Error: Could not secure restored private key $bn for $domain" >&2; return 1; }
            else
                chmod 0644 "$archive_dir/$bn" 2>/dev/null || { echo "Error: Could not set restored certificate permissions for $bn ($domain)" >&2; return 1; }
            fi
        done
    fi

    if [[ -d "$snap_dir/live" ]]; then
        local f
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            if [[ -f "$snap_dir/live/${f}.target" ]]; then
                local tgt
                tgt=$(cat "$snap_dir/live/${f}.target") || { echo "Error: Could not read ACME symlink target for $f ($domain)" >&2; return 1; }
                ln -sf "$tgt" "$live_dir/$f" || { echo "Error: Could not restore ACME symlink $f for $domain" >&2; return 1; }
            elif [[ -f "$snap_dir/live/$f" ]]; then
                cp -p "$snap_dir/live/$f" "$live_dir/$f" || { echo "Error: Could not restore ACME live file $f for $domain" >&2; return 1; }
                if [[ "$f" == "privkey.pem" ]]; then
                    chmod 0600 "$live_dir/$f" 2>/dev/null || { echo "Error: Could not secure restored live private key for $domain" >&2; return 1; }
                else
                    chmod 0644 "$live_dir/$f" 2>/dev/null || { echo "Error: Could not set restored live certificate permissions for $domain" >&2; return 1; }
                fi
            fi
        done
    fi

    local fullchain="$live_dir/fullchain.pem"
    local privkey="$live_dir/privkey.pem"
    if [[ ! -s "$fullchain" || ! -s "$privkey" ]]; then
        echo "Error: Restored certificate or private key missing for $domain" >&2
        return 1
    fi

    if ! openssl x509 -in "$fullchain" -noout 2>/dev/null; then
        echo "Error: Restored certificate for $domain is corrupted" >&2
        return 1
    fi

    local pub_from_cert pub_from_key
    pub_from_cert=$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null || true)
    pub_from_key=$(openssl pkey -in "$privkey" -pubout 2>/dev/null || true)
    if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
        echo "Error: Restored certificate and private key public key mismatch for $domain" >&2
        return 1
    fi

    local exp_serial exp_fingerprint cur_serial cur_fingerprint
    exp_serial=$(python3 -c "import json; print(json.load(open('$meta_file', encoding='utf-8')).get('serial', ''))") || { echo "Error: Could not read snapshot certificate serial for $domain" >&2; return 1; }
    exp_fingerprint=$(python3 -c "import json; print(json.load(open('$meta_file', encoding='utf-8')).get('fingerprint', ''))") || { echo "Error: Could not read snapshot certificate fingerprint for $domain" >&2; return 1; }
    if [[ -z "$exp_serial" || -z "$exp_fingerprint" ]]; then
        echo "Error: ACME snapshot is missing certificate identity metadata for $domain" >&2
        return 1
    fi
    if [[ -n "$exp_serial" ]]; then
        cur_serial=$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null) || { echo "Error: Could not read restored certificate serial for $domain" >&2; return 1; }
        if [[ "$cur_serial" != "$exp_serial" ]]; then
            echo "Error: Restored certificate serial ($cur_serial) does not match snapshot ($exp_serial)" >&2
            return 1
        fi
    fi
    if [[ -n "$exp_fingerprint" ]]; then
        cur_fingerprint=$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null) || { echo "Error: Could not read restored certificate fingerprint for $domain" >&2; return 1; }
        if [[ "$cur_fingerprint" != "$exp_fingerprint" ]]; then
            echo "Error: Restored certificate fingerprint ($cur_fingerprint) does not match snapshot ($exp_fingerprint)" >&2
            return 1
        fi
    fi

    echo "ACME lineage for $domain successfully restored and verified." >&2
    return 0
}

cleanup_acme_snapshot() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    if [[ -d "$snap_dir" ]]; then
        rm -rf "$snap_dir"
    fi
}

if [[ "$(id -u)" -ne 0 ]]; then
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/tmp/gowave-managed-mutation-$(id -u).lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/tmp/gowave-mutation-lease-$(id -u).json}"
else
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/run/lock/gowave-managed-mutation.lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/run/lock/gowave-mutation-lease.json}"
fi

validate_lock_path() {
    local lock_file="${1:-$MUTATION_LOCK_FILE}"
    local lock_dir
    lock_dir="$(dirname "$lock_file")"

    if [[ ! -d "$lock_dir" ]]; then
        mkdir -p "$lock_dir"
        chmod 0755 "$lock_dir" 2>/dev/null || true
    fi

    if [[ -L "$lock_dir" ]]; then
        echo "Error: Lock directory $lock_dir is a symlink; unsafe." >&2
        return 1
    fi

    if [[ -L "$lock_file" ]]; then
        echo "Error: Lock file $lock_file is a symlink; refusing path substitution." >&2
        return 1
    fi

    if [[ -e "$lock_file" && ! -f "$lock_file" ]]; then
        echo "Error: Lock file $lock_file exists and is not a regular file." >&2
        return 1
    fi

    return 0
}

validate_mutation_lease() {
    local candidate_token="$1"
    local lease_file="${2:-$MUTATION_LEASE_FILE}"
    local lock_file="${3:-$MUTATION_LOCK_FILE}"

    python3 - "$candidate_token" "$lease_file" "$lock_file" <<'PY'
import json
import os
import sys

token, lease_path, lock_path = sys.argv[1:4]

if not os.path.exists(lease_path):
    sys.exit(1)

if os.path.islink(lease_path):
    sys.exit(1)

st = os.stat(lease_path)
if os.geteuid() == 0 and st.st_uid != 0:
    sys.exit(1)

try:
    with open(lease_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

expected_token = data.get("lease_token", "")
holder_pid = data.get("holder_pid")

if not expected_token or expected_token != token:
    sys.exit(1)

if not holder_pid or not isinstance(holder_pid, int):
    sys.exit(1)

try:
    os.kill(holder_pid, 0)
except OSError:
    sys.exit(1)

fd_dir = f"/proc/{holder_pid}/fd"
if os.path.exists(fd_dir):
    try:
        real_lock = os.path.realpath(lock_path)
        has_fd = False
        for fd in os.listdir(fd_dir):
            try:
                target = os.path.realpath(os.path.join(fd_dir, fd))
                if target == real_lock:
                    has_fd = True
                    break
            except Exception:
                continue
        if not has_fd:
            sys.exit(1)
    except Exception:
        pass

sys.exit(0)
PY
}

acquire_mutation_lock() {
    if [[ "${_MUTATION_LOCK_HELD:-0}" -eq 1 || "${_MUTATION_LEASE_VALIDATED:-0}" -eq 1 ]]; then
        return 0
    fi

    validate_lock_path "$MUTATION_LOCK_FILE" || return 1

    if [[ ! -f "$MUTATION_LOCK_FILE" ]]; then
        (
            umask 0177
            touch "$MUTATION_LOCK_FILE"
        ) 2>/dev/null || true
        chmod 0600 "$MUTATION_LOCK_FILE" 2>/dev/null || true
    fi

    exec 9>>"$MUTATION_LOCK_FILE"
    if flock -n 9; then
        _MUTATION_LOCK_HELD=1
        return 0
    fi

    local candidate_token=""
    if [[ -n "${GOWAVE_LEASE_TOKEN:-}" ]]; then
        candidate_token="$GOWAVE_LEASE_TOKEN"
    elif [[ ! -t 0 ]]; then
        local first_line=""
        if IFS= read -r -t 1 first_line; then
            if [[ "$first_line" =~ ^GOWAVE_LEASE:\ *(.*)$ ]]; then
                candidate_token="${BASH_REMATCH[1]}"
            fi
        fi
    fi

    if [[ -n "$candidate_token" ]]; then
        if validate_mutation_lease "$candidate_token" "$MUTATION_LEASE_FILE" "$MUTATION_LOCK_FILE"; then
            _MUTATION_LEASE_VALIDATED=1
            return 0
        fi
        echo "Error: Invalid or stale mutation lock lease provided." >&2
        return 1
    fi

    echo "Error: Another process currently holds the mutation lock ($MUTATION_LOCK_FILE)." >&2
    echo "Refusing concurrent mutation without an authorized re-entrant lease." >&2
    return 1
}

verify_deploy_hook_preflight() {
    local hook_file="${1:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local transaction_id="${2:-}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    if [[ -e "$hook_file" ]] || [[ -L "$hook_file" ]]; then
        if [[ -n "$transaction_id" ]]; then
            local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
            if [[ -f "$manifest" ]]; then
                local owned
                owned=$(python3 -c "import json; print('1' if json.load(open('$manifest')).get('created_by_tx') else '0')" 2>/dev/null || echo "0")
                if [[ "$owned" == "1" ]]; then
                    return 0
                fi
            fi
        fi
        echo "Error: Pre-existing unowned Certbot deploy hook found at $hook_file. Refusing to overwrite unmanaged host resource." >&2
        return 1
    fi

    local hook_dir
    hook_dir=$(dirname "$hook_file")
    if [[ -e "$hook_dir" && -L "$hook_dir" ]]; then
        echo "Error: Certbot renewal hook directory $hook_dir is an unsafe symlink." >&2
        return 1
    fi
    return 0
}

install_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    verify_deploy_hook_preflight "$hook_file" "$transaction_id" "$recovery_root" || return 1

    local hook_dir resolved_hook_dir metadata owner mode
    hook_dir=$(dirname "$hook_file") || return 1
    resolved_hook_dir=$(realpath -m -- "$hook_dir") || {
        echo "Error: Could not resolve Certbot deploy-hook directory." >&2
        return 1
    }
    if [[ "$resolved_hook_dir" != "$hook_dir" ]]; then
        echo "Error: Certbot deploy-hook directory contains a symlink or non-normalized path." >&2
        return 1
    fi
    mkdir -p -- "$hook_dir" || {
        echo "Error: Could not create Certbot deploy-hook directory." >&2
        return 1
    }
    if [[ ! -d "$hook_dir" || -L "$hook_dir" ]]; then
        echo "Error: Certbot deploy-hook directory is not a real directory." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$hook_dir") || {
        echo "Error: Could not verify Certbot deploy-hook directory." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "Error: Certbot deploy-hook directory is not owned by the current user." >&2
        return 1
    fi
    chmod 0755 -- "$hook_dir" || {
        echo "Error: Could not enforce Certbot deploy-hook directory permissions." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$hook_dir") || return 1
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "755" ]]; then
        echo "Error: Certbot deploy-hook directory owner or mode verification failed." >&2
        return 1
    fi

    local snap_dir="${recovery_root}/${transaction_id}" resolved_snap_dir
    resolved_snap_dir=$(realpath -m -- "$snap_dir") || {
        echo "Error: Could not resolve deploy-hook recovery directory." >&2
        return 1
    }
    if [[ "$snap_dir" != /* || "$snap_dir" == "/" || "$resolved_snap_dir" != "$snap_dir" ]]; then
        echo "Error: Deploy-hook recovery path is not a normalized absolute path without symlinks." >&2
        return 1
    fi
    mkdir -p -- "$snap_dir" || {
        echo "Error: Could not create deploy-hook recovery directory." >&2
        return 1
    }
    if [[ ! -d "$snap_dir" || -L "$snap_dir" ]]; then
        echo "Error: Deploy-hook recovery path is not a real directory." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$snap_dir") || {
        echo "Error: Could not verify deploy-hook recovery directory." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "Error: Deploy-hook recovery directory is not owned by the current user." >&2
        return 1
    fi
    chmod 0700 -- "$snap_dir" || {
        echo "Error: Could not secure deploy-hook recovery directory." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$snap_dir") || return 1
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
        echo "Error: Deploy-hook recovery directory owner or mode verification failed." >&2
        return 1
    fi

    local manifest="${snap_dir}/deploy-hook-manifest.json"
    local tmp_file="${hook_file}.tmp.$$"
    if ! cat > "$tmp_file" <<'EOF'
#!/bin/sh
# Managed by GoWave Auto NGINX: Automated ACME Reload Hook
if nginx -t -q; then
    systemctl reload nginx
fi
EOF
    then
        echo "Error: Could not write temporary Certbot deploy hook." >&2
        return 1
    fi
    if ! chmod 0755 -- "$tmp_file" || ! sync "$tmp_file"; then
        rm -f -- "$tmp_file" || true
        echo "Error: Could not secure and sync temporary Certbot deploy hook." >&2
        return 1
    fi

    local digest
    digest=$(sha256sum "$tmp_file" | awk '{print $1}') || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not calculate Certbot deploy-hook digest." >&2
        return 1
    }
    python3 -c 'import json, os, sys; manifest_path, tx_id, path, digest = sys.argv[1:5]; flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0); fd = os.open(manifest_path, flags, 0o600); stream = os.fdopen(fd, "w", encoding="utf-8"); json.dump({"transaction_id": tx_id, "path": path, "created_by_tx": True, "sha256": digest}, stream, indent=2); stream.flush(); os.fsync(stream.fileno()); stream.close()' "$manifest" "$transaction_id" "$hook_file" "$digest" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not create deploy-hook ownership manifest safely." >&2
        return 1
    }
    if ! chmod 0600 -- "$manifest"; then
        rm -f -- "$tmp_file" || true
        echo "Error: Could not enforce private deploy-hook manifest permissions." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$manifest") || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not verify deploy-hook ownership manifest." >&2
        return 1
    }
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "600" ]]; then
        rm -f -- "$tmp_file" || true
        echo "Error: Deploy-hook manifest owner or mode verification failed." >&2
        return 1
    fi
    sync "$manifest" && sync "$snap_dir" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not sync deploy-hook ownership manifest." >&2
        return 1
    }

    mv -f -- "$tmp_file" "$hook_file" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not install managed Certbot deploy hook." >&2
        return 1
    }
    sync "$hook_dir" || {
        echo "Error: Could not sync Certbot deploy-hook directory after installation." >&2
        return 1
    }
    echo "Configured managed ACME renewal hook in $hook_file."
}
rollback_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    if [[ -z "$transaction_id" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: ACME transaction ID is missing; preserving deploy hook with unknown ownership and reporting incomplete rollback." >&2
            return 1
        fi
        return 0
    fi

    local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
    if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: Deploy hook exists without an ownership manifest; refusing to claim rollback succeeded." >&2
            return 1
        fi
        return 0
    fi
    if [[ ! -f "$manifest" || -L "$manifest" ]]; then
        echo "Error: Deploy-hook rollback manifest is missing, non-regular, or a symlink." >&2
        return 1
    fi

    local manifest_data
    manifest_data=$(python3 - "$manifest" "$transaction_id" "$hook_file" <<'PY'
import json
import re
import sys

path, expected_tx, expected_hook = sys.argv[1:4]
try:
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    if data.get("transaction_id") != expected_tx or data.get("path") != expected_hook:
        raise ValueError("manifest transaction/path mismatch")
    created = data.get("created_by_tx")
    if type(created) is not bool:
        raise ValueError("created_by_tx must be a boolean")
    digest = data.get("sha256", "")
    if not isinstance(digest, str):
        raise ValueError("sha256 must be a string")
    if created and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("created hook digest is invalid")
    print("1" if created else "0")
    print(digest)
except Exception as exc:
    print(f"Invalid deploy-hook rollback manifest: {type(exc).__name__}", file=sys.stderr)
    sys.exit(1)
PY
    ) || {
        echo "Error: Refusing deploy-hook rollback because its ownership manifest is invalid." >&2
        return 1
    }

    local -a manifest_fields=()
    mapfile -t manifest_fields <<< "$manifest_data"
    if [[ "${#manifest_fields[@]}" -ne 2 ]]; then
        echo "Error: Deploy-hook rollback manifest has an invalid field count." >&2
        return 1
    fi
    local created_by_tx="${manifest_fields[0]}"
    local recorded_sha="${manifest_fields[1]}"
    if [[ "$created_by_tx" != "1" ]]; then
        return 0
    fi

    if [[ ! -e "$hook_file" && ! -L "$hook_file" ]]; then
        return 0
    fi
    if [[ -L "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is now a symlink; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi
    if [[ ! -f "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is not a regular file; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    local current_sha
    current_sha=$(sha256sum "$hook_file" | awk '{print $1}') || {
        echo "Error: Could not verify managed deploy-hook digest." >&2
        return 1
    }
    if [[ "$current_sha" != "$recorded_sha" ]]; then
        echo "Warning: Deploy hook $hook_file was modified after installation (digest mismatch); preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    rm -f "$hook_file" || {
        echo "Error: Could not remove transaction-owned deploy hook $hook_file." >&2
        return 1
    }
    sync "$(dirname "$hook_file")" || {
        echo "Error: Could not sync deploy-hook directory after rollback." >&2
        return 1
    }
    return 0
}

cleanup_deploy_hook_manifest() {
    local transaction_id="$1"
    local recovery_root="${2:-/var/lib/gowave-auto-nginx/recovery}"
    rm -f "${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
}

# Function to pack cover-reality into base64 string
pack_cover_reality() {
    local cover_dir="${1:-$SCRIPT_DIR/assets/cover-sites/cover-reality}"
    if [[ ! -d "$cover_dir" ]]; then
        echo "Error: Cover directory $cover_dir not found" >&2
        return 1
    fi
    tar -czf - -C "$cover_dir" . | base64 -w 0
}

# The remote orchestration payload streaming over SSH stdin
remote_payload() {
    local host="$1"
    local port="${2:-22}"
    local worker_domain="$3"
    local reality_domain="$4"
    local ssh_user="${5:-root}"

    local node_port="${NODE_PORT:-$RECOMMENDED_NODE_PORT}"
    local panel_ip="${PANEL_IP:-}"
    local panel_ipv6="${PANEL_IPV6:-}"
    local admin_email="${ADMIN_EMAIL:-admin@${worker_domain}}"
    local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
    validate_acme_server "${GOWAVE_ACME_SERVER:-}" || return 1
    local host_key="$host"
    if [[ "$port" != "22" ]]; then
        host_key="[$host]:$port"
    fi
    if [[ ! -s "$known_hosts" ]] || ! ssh-keygen -F "$host_key" -f "$known_hosts" >/dev/null 2>&1; then
        log_err "SSH host key for $host_key is not pre-pinned in $known_hosts."
        log_err "Obtain the host key over a trusted channel, compare its fingerprint out-of-band, then add it to known_hosts."
        return 1
    fi
    local installer_commit="${GOWAVE_NODE_INSTALLER_COMMIT:-7b3514d1ab8c674050597820d52d55525d4bece7}"
    local installer_sha256="${GOWAVE_NODE_INSTALLER_SHA256:-9a524f1383d3a6a8be42ac370699b0ec6725678ece4abe5b5bc61e8c2af682d0}"
    if [[ ! "$installer_commit" =~ ^[0-9a-fA-F]{40}$ ]]; then
        log_err "GOWAVE_NODE_INSTALLER_COMMIT must be a 40-character hex commit SHA."
        return 1
    fi
    if [[ ! "$installer_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        log_err "GOWAVE_NODE_INSTALLER_SHA256 must be a 64-character hex SHA-256 digest."
        return 1
    fi
    local verifier_b64=""
    if [[ -f "$SCRIPT_DIR/modules/verify_node_mtls.py" ]]; then
        verifier_b64=$(base64 -w 0 "$SCRIPT_DIR/modules/verify_node_mtls.py")
    else
        echo "Error: mTLS verifier is required for remote worker acceptance." >&2
        return 1
    fi
    local security_helper_b64=""
    if [[ -f "$SCRIPT_DIR/assets/security/managed.py" ]]; then
        security_helper_b64=$(base64 -w 0 "$SCRIPT_DIR/assets/security/managed.py")
    else
        echo "Error: Host security helper is required for remote worker hardening." >&2
        return 1
    fi

    # Validate node port and warn on host collisions if worker host matches panel IP
    if [[ "$host" == "127.0.0.1" || "$host" == "localhost" || "$host" == "$panel_ip" ]]; then
        if [[ "$node_port" != "$RECOMMENDED_NODE_PORT" ]]; then
            log_warn "Worker IP matches PANEL_IP or loopback; enforcing NODE_PORT=$RECOMMENDED_NODE_PORT to prevent port collision with Panel (3000)."
            node_port="$RECOMMENDED_NODE_PORT"
        fi
    fi

    # Pack cover-reality assets
    local cover_b64 cover_sha256
    cover_b64=$(pack_cover_reality)
    cover_sha256=$(echo -n "$cover_b64" | base64 -d | sha256sum | awk '{print $1}')

    log_info "Deploying GoWave Edge Worker to ${ssh_user}@${host}:${port} (Worker Domain: $worker_domain, Reality Domain: $reality_domain, Port: $node_port)..."

    {
        # 1. Environment variables strictly over stdin (NEVER in ssh argv)
        printf 'export PANEL_IP=%q\n' "$panel_ip"
        printf 'export PANEL_IPV6=%q\n' "$panel_ipv6"
        printf 'export NODE_PORT=%q\n' "$node_port"
        printf 'export GOWAVE_NODE_VERSION=%q\n' "${GOWAVE_NODE_VERSION:-latest}"
        printf 'export GOWAVE_NODE_INSTALLER_COMMIT=%q\n' "$installer_commit"
        printf 'export GOWAVE_NODE_INSTALLER_SHA256=%q\n' "$installer_sha256"
        printf 'export SSH_PORT=%q\n' "$port"
        printf 'export XRAY_SERVER_VERSION=%q\n' "${XRAY_SERVER_VERSION:-}"
        printf 'export VERIFY_NODE_MTLS_B64=%q\n' "$verifier_b64"
        printf 'export SECURITY_HELPER_B64=%q\n' "$security_helper_b64"
        printf 'export WORKER_DOMAIN=%q\n' "$worker_domain"
        printf 'export REALITY_DOMAIN=%q\n' "$reality_domain"
        printf 'export VISION_DOMAIN=%q\n' "${VISION_DOMAIN:-}"
        printf 'export ADMIN_EMAIL=%q\n' "$admin_email"
        printf 'export GOWAVE_ACME_SERVER=%q\n' "${GOWAVE_ACME_SERVER:-}"
        printf 'export GOWAVE_ACME_TEST_MODE=%q\n' "${GOWAVE_ACME_TEST_MODE:-0}"
        printf 'export GOWAVE_ACME_TEST_CA_SHA256=%q\n' "${GOWAVE_ACME_TEST_CA_SHA256:-}"
        # Test-only CA content travels over the validated SSH stdin stream; it is
        # materialized with mode 0600 and never placed in argv or logs.
        printf 'export GOWAVE_ACME_TEST_CA_B64=%q\n' "${GOWAVE_ACME_TEST_CA_B64:-}"
        printf 'export GOWAVE_PODMAN_TEST_MODE=%q\n' "${GOWAVE_PODMAN_TEST_MODE:-0}"
        printf 'export ACME_TX_ID=%q\n' "${ACME_TX_ID:-}"
        printf 'COVER_REALITY_B64=%q\n' "$cover_b64"
        printf 'COVER_REALITY_SHA256=%q\n' "$cover_sha256"
        # Secret strictly scoped, not exported globally
        printf '_NODE_SECRET_KEY=%q\n' "$SECRET_KEY"

        # 2. Remote helper functions
        cat <<'RUNNER_FUNCS'
log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }

# The local ACME fixture is a test-only trust anchor. Its endpoint is pinned so
# enabling test mode never turns GOWAVE_ACME_SERVER into an arbitrary-URL option.
GOWAVE_ACME_TEST_ENDPOINT="https://pebble.testbed.internal:14000/dir"

acme_test_mode_enabled() {
    [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" ]]
}

validate_acme_test_ca() {
    local ca_file="${GOWAVE_ACME_TEST_CA_FILE:-}"
    local expected_sha256="${GOWAVE_ACME_TEST_CA_SHA256:-}"
    if [[ -z "$ca_file" || -z "$expected_sha256" ]]; then
        echo "Error: test-only ACME mode requires GOWAVE_ACME_TEST_CA_FILE and GOWAVE_ACME_TEST_CA_SHA256." >&2
        return 1
    fi
    if [[ -L "$ca_file" || ! -f "$ca_file" ]]; then
        echo "Error: GOWAVE_ACME_TEST_CA_FILE must be a regular file, not a symlink." >&2
        return 1
    fi
    if [[ ! "$expected_sha256" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "Error: GOWAVE_ACME_TEST_CA_SHA256 must be a 64-character hex digest." >&2
        return 1
    fi
    local actual_sha256
    actual_sha256=$(sha256sum -- "$ca_file" 2>/dev/null | awk '{print $1}')
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        echo "Error: ACME test CA digest mismatch; refusing an unpinned trust anchor." >&2
        return 1
    fi
    return 0
}

run_certbot() {
    if acme_test_mode_enabled && [[ "${GOWAVE_ACME_SERVER:-}" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        REQUESTS_CA_BUNDLE="$GOWAVE_ACME_TEST_CA_FILE" \
            SSL_CERT_FILE="$GOWAVE_ACME_TEST_CA_FILE" \
            certbot "$@"
        return
    fi
    certbot "$@"
}

validate_acme_server() {
    local server="${1:-}"
    if [[ -z "$server" ]]; then
        return 0
    fi
    if [[ "$server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        if ! acme_test_mode_enabled; then
            echo "Error: Invalid GOWAVE_ACME_SERVER: the local ACME fixture endpoint is accepted only with GOWAVE_ACME_TEST_MODE=1." >&2
            return 1
        fi
        validate_acme_test_ca || return 1
        return 0
    fi
    if [[ "$server" != "https://acme-staging-v02.api.letsencrypt.org/directory" && \
          "$server" != "https://acme-v02.api.letsencrypt.org/directory" ]]; then
        if acme_test_mode_enabled; then
            echo "Error: test-only ACME mode accepts only the pinned fixture endpoint '$GOWAVE_ACME_TEST_ENDPOINT' or a Let's Encrypt Staging/Production directory; refusing '$server'." >&2
        else
            echo "Error: Invalid GOWAVE_ACME_SERVER: '$server'. Only 'https://acme-staging-v02.api.letsencrypt.org/directory' or 'https://acme-v02.api.letsencrypt.org/directory' are supported." >&2
        fi
        return 1
    fi
    return 0
}

check_acme_lineage() {
    local domain="$1"
    local target_server="${2:-https://acme-v02.api.letsencrypt.org/directory}"
    local renewal_conf="${3:-/etc/letsencrypt/renewal/${domain}.conf}"
    local live_dir="${4:-/etc/letsencrypt/live/${domain}}"
    local fixture_target=0

    if [[ "$target_server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]]; then
        if ! acme_test_mode_enabled; then
            echo "Error: ACME lineage for $domain targets the local fixture endpoint without GOWAVE_ACME_TEST_MODE=1." >&2
            return 1
        fi
        validate_acme_test_ca || return 1
        fixture_target=1
    fi

    if [[ -f "$renewal_conf" ]]; then
        local existing_server=""
        while IFS='=' read -r key val || [[ -n "$key" ]]; do
            key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [[ "$key" == "server" ]]; then
                existing_server=$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
                break
            fi
        done < "$renewal_conf"

        if [[ -z "$existing_server" ]]; then
            echo "Error: Existing renewal lineage for $domain has no readable 'server' field in $renewal_conf; failing closed to prevent cross-lineage staging/production reuse." >&2
            return 1
        fi

        local recognized=0
        if [[ "$existing_server" == "https://acme-staging-v02.api.letsencrypt.org/directory" || \
              "$existing_server" == "https://acme-v02.api.letsencrypt.org/directory" ]]; then
            recognized=1
        elif [[ "$existing_server" == "$GOWAVE_ACME_TEST_ENDPOINT" ]] && acme_test_mode_enabled; then
            validate_acme_test_ca || return 1
            recognized=1
        fi
        if [[ "$recognized" -ne 1 ]]; then
            echo "Error: Existing renewal lineage for $domain uses unrecognized ACME directory: '$existing_server'." >&2
            return 1
        fi

        if [[ "$existing_server" != "$target_server" ]]; then
            echo "Error: ACME directory mismatch for $domain: existing lineage in $renewal_conf was issued by '$existing_server', but requested server is '$target_server'. Staging and production lineages cannot be mixed." >&2
            return 1
        fi
    fi

    local fullchain="$live_dir/fullchain.pem"
    if [[ -s "$fullchain" ]]; then
        if [[ "$fixture_target" -eq 1 ]]; then
            if ! openssl verify -CAfile "$GOWAVE_ACME_TEST_CA_FILE" -untrusted "$fullchain" "$fullchain" >/dev/null 2>&1; then
                echo "Error: Existing certificate for $domain does not chain to the pinned local ACME test CA; refusing to reuse a cross-lineage certificate." >&2
                return 1
            fi
        else
            local issuer
            issuer=$(openssl x509 -in "$fullchain" -noout -issuer 2>/dev/null || true)
            local is_staging_cert=0
            if [[ "$issuer" =~ \(STAGING\) ]]; then
                is_staging_cert=1
            fi
            if [[ "$target_server" == "https://acme-staging-v02.api.letsencrypt.org/directory" && "$is_staging_cert" -eq 0 ]]; then
                echo "Error: Existing certificate for $domain was issued by production ($issuer), but requested ACME server is staging ($target_server)." >&2
                return 1
            elif [[ "$target_server" == "https://acme-v02.api.letsencrypt.org/directory" && "$is_staging_cert" -eq 1 ]]; then
                echo "Error: Existing certificate for $domain was issued by staging ($issuer), but requested ACME server is production ($target_server)." >&2
                return 1
            fi
        fi
    fi

    return 0
}

snapshot_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    if [[ ! "$transaction_id" =~ ^[A-Za-z0-9._-]+$ || ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
        echo "Error: Invalid transaction ID or domain for ACME snapshot." >&2
        return 1
    fi

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    mkdir -p "$snap_dir" || { echo "Error: Could not create ACME snapshot directory for $domain." >&2; return 1; }
    if [[ -L "$snap_dir" ]]; then
        echo "Error: ACME snapshot directory is an unsafe symlink for $domain." >&2
        return 1
    fi
    chmod 0700 "$snap_dir" 2>/dev/null || { echo "Error: Could not secure ACME snapshot directory for $domain." >&2; return 1; }

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"
    local existed_before=false cert_serial="" cert_fingerprint=""

    if [[ -e "$renewal_conf" || -L "$renewal_conf" || -e "$live_dir" || -L "$live_dir" ]]; then
        if [[ ! -f "$renewal_conf" || -L "$renewal_conf" || ! -d "$live_dir" || -L "$live_dir" ]]; then
            echo "Error: Existing ACME lineage for $domain is incomplete or unsafe; refusing to snapshot it." >&2
            return 1
        fi
        mkdir -p "$snap_dir/archive" "$snap_dir/live" || { echo "Error: Could not create ACME snapshot subdirectories for $domain." >&2; return 1; }
        chmod 0700 "$snap_dir/archive" "$snap_dir/live" 2>/dev/null || { echo "Error: Could not secure ACME snapshot subdirectories for $domain." >&2; return 1; }
        cp -p "$renewal_conf" "$snap_dir/renewal.conf" || { echo "Error: Could not snapshot ACME renewal config for $domain." >&2; return 1; }

        local archive_real
        archive_real=$(realpath -e -- "$archive_dir") || { echo "Error: ACME archive directory is missing for existing lineage $domain." >&2; return 1; }
        local f link_path target real_file bn
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            link_path="${live_dir}/${f}"
            if [[ -L "$link_path" ]]; then
                target=$(readlink "$link_path") || { echo "Error: Could not read ACME symlink $f for $domain." >&2; return 1; }
                if [[ -z "$target" || "$target" == /* ]]; then
                    echo "Error: Unsafe ACME symlink target for $domain/$f." >&2
                    return 1
                fi
                printf '%s\n' "$target" > "$snap_dir/live/${f}.target" || { echo "Error: Could not snapshot ACME symlink target for $domain/$f." >&2; return 1; }
                chmod 0600 "$snap_dir/live/${f}.target" 2>/dev/null || { echo "Error: Could not secure ACME symlink metadata for $domain/$f." >&2; return 1; }
                real_file=$(realpath -e -- "$link_path") || { echo "Error: ACME symlink $domain/$f is broken." >&2; return 1; }
                case "$real_file" in
                    "$archive_real"/*) ;;
                    *)
                        echo "Error: ACME symlink $domain/$f escapes its archive directory." >&2
                        return 1
                        ;;
                esac
                bn=$(basename "$real_file")
                cp -p "$real_file" "$snap_dir/archive/$bn" || { echo "Error: Could not snapshot ACME archive file $bn for $domain." >&2; return 1; }
                if [[ "$bn" =~ ^privkey ]]; then
                    chmod 0600 "$snap_dir/archive/$bn" 2>/dev/null || { echo "Error: Could not secure snapshotted ACME private key for $domain." >&2; return 1; }
                else
                    chmod 0644 "$snap_dir/archive/$bn" 2>/dev/null || { echo "Error: Could not set snapshotted ACME certificate permissions for $domain." >&2; return 1; }
                fi
            elif [[ -f "$link_path" ]]; then
                cp -p "$link_path" "$snap_dir/live/$f" || { echo "Error: Could not snapshot ACME live file $f for $domain." >&2; return 1; }
                if [[ "$f" == "privkey.pem" ]]; then
                    chmod 0600 "$snap_dir/live/$f" 2>/dev/null || { echo "Error: Could not secure snapshotted ACME private key for $domain." >&2; return 1; }
                fi
            else
                if [[ "$f" == "fullchain.pem" || "$f" == "privkey.pem" ]]; then
                    echo "Error: Existing ACME lineage is missing required file $domain/$f." >&2
                    return 1
                fi
                continue
            fi
        done

        local fullchain="${live_dir}/fullchain.pem" privkey="${live_dir}/privkey.pem"
        openssl x509 -in "$fullchain" -noout >/dev/null 2>&1 || { echo "Error: Existing ACME certificate is invalid for $domain." >&2; return 1; }
        local pub_from_cert pub_from_key
        pub_from_cert=$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null) || { echo "Error: Could not read existing ACME certificate key for $domain." >&2; return 1; }
        pub_from_key=$(openssl pkey -in "$privkey" -pubout 2>/dev/null) || { echo "Error: Could not read existing ACME private key for $domain." >&2; return 1; }
        if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
            echo "Error: Existing ACME certificate and private key do not match for $domain." >&2
            return 1
        fi
        cert_serial=$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null) || { echo "Error: Could not read existing ACME certificate serial for $domain." >&2; return 1; }
        cert_fingerprint=$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null) || { echo "Error: Could not read existing ACME certificate fingerprint for $domain." >&2; return 1; }
        if [[ -z "$cert_serial" || -z "$cert_fingerprint" ]]; then
            echo "Error: Existing ACME certificate identity metadata is empty for $domain." >&2
            return 1
        fi
        existed_before=true
    fi

    python3 - "$meta_file" "$domain" "$existed_before" "$cert_serial" "$cert_fingerprint" <<'PY'
import json
import os
import sys

meta_file, domain, existed, serial, fingerprint = sys.argv[1:6]
data = {
    "domain": domain,
    "existed_before": existed == "true",
    "serial": serial,
    "fingerprint": fingerprint,
}
tmp_path = meta_file + ".tmp"
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp_path, meta_file)
    dir_fd = os.open(os.path.dirname(meta_file), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
except Exception as exc:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    print(f"Failed to persist ACME snapshot manifest: {type(exc).__name__}", file=sys.stderr)
    raise SystemExit(1)
PY
}

restore_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"

    if [[ ! -f "$meta_file" ]]; then
        echo "Error: ACME lineage manifest not found for $domain in $snap_dir" >&2
        return 1
    fi

    local existed
    existed=$(python3 - "$meta_file" "$domain" <<'PY'
import json, sys
path, domain = sys.argv[1:3]
with open(path, encoding="utf-8") as stream:
    data = json.load(stream)
if not isinstance(data, dict) or data.get("domain") != domain or type(data.get("existed_before")) is not bool:
    raise SystemExit(1)
print("1" if data["existed_before"] else "0")
PY
) || { echo "Error: Invalid ACME lineage manifest for $domain" >&2; return 1; }
if [[ "$existed" != "0" && "$existed" != "1" ]]; then
    echo "Error: Invalid existed_before marker for $domain" >&2
    return 1
fi

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"

    if [[ "$existed" == "0" ]]; then
        echo "Removing transaction-created ACME lineage for $domain..." >&2
        rm -f "$renewal_conf" || { echo "Error: Could not remove transaction-created renewal config for $domain" >&2; return 1; }
        rm -rf "$live_dir" "$archive_dir" || { echo "Error: Could not remove transaction-created lineage for $domain" >&2; return 1; }
        return 0
    fi

    echo "Restoring pre-existing ACME lineage for $domain from snapshot..." >&2
    mkdir -p "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" || { echo "Error: Could not create ACME restore directories for $domain" >&2; return 1; }
    chmod 0755 "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" 2>/dev/null || { echo "Error: Could not set ACME directory permissions for $domain" >&2; return 1; }

    if [[ -f "$snap_dir/renewal.conf" ]]; then
        cp -p "$snap_dir/renewal.conf" "$renewal_conf" || { echo "Error: Could not restore renewal config for $domain" >&2; return 1; }
        chmod 0644 "$renewal_conf" 2>/dev/null || { echo "Error: Could not set renewal config permissions for $domain" >&2; return 1; }
    fi

    if [[ -d "$snap_dir/archive" ]]; then
        local arc
        for arc in "$snap_dir/archive"/*; do
            [[ -f "$arc" ]] || continue
            local bn
            bn=$(basename "$arc")
            cp -p "$arc" "$archive_dir/$bn" || { echo "Error: Could not restore ACME archive file $bn for $domain" >&2; return 1; }
            if [[ "$bn" =~ ^privkey ]]; then
                chmod 0600 "$archive_dir/$bn" 2>/dev/null || { echo "Error: Could not secure restored private key $bn for $domain" >&2; return 1; }
            else
                chmod 0644 "$archive_dir/$bn" 2>/dev/null || { echo "Error: Could not set restored certificate permissions for $bn ($domain)" >&2; return 1; }
            fi
        done
    fi

    if [[ -d "$snap_dir/live" ]]; then
        local f
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            if [[ -f "$snap_dir/live/${f}.target" ]]; then
                local tgt
                tgt=$(cat "$snap_dir/live/${f}.target") || { echo "Error: Could not read ACME symlink target for $f ($domain)" >&2; return 1; }
                ln -sf "$tgt" "$live_dir/$f" || { echo "Error: Could not restore ACME symlink $f for $domain" >&2; return 1; }
            elif [[ -f "$snap_dir/live/$f" ]]; then
                cp -p "$snap_dir/live/$f" "$live_dir/$f" || { echo "Error: Could not restore ACME live file $f for $domain" >&2; return 1; }
                if [[ "$f" == "privkey.pem" ]]; then
                    chmod 0600 "$live_dir/$f" 2>/dev/null || { echo "Error: Could not secure restored live private key for $domain" >&2; return 1; }
                else
                    chmod 0644 "$live_dir/$f" 2>/dev/null || { echo "Error: Could not set restored live certificate permissions for $domain" >&2; return 1; }
                fi
            fi
        done
    fi

    local fullchain="$live_dir/fullchain.pem"
    local privkey="$live_dir/privkey.pem"
    if [[ ! -s "$fullchain" || ! -s "$privkey" ]]; then
        echo "Error: Restored certificate or private key missing for $domain" >&2
        return 1
    fi

    if ! openssl x509 -in "$fullchain" -noout 2>/dev/null; then
        echo "Error: Restored certificate for $domain is corrupted" >&2
        return 1
    fi

    local pub_from_cert pub_from_key
    pub_from_cert=$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null || true)
    pub_from_key=$(openssl pkey -in "$privkey" -pubout 2>/dev/null || true)
    if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
        echo "Error: Restored certificate and private key public key mismatch for $domain" >&2
        return 1
    fi

    local exp_serial exp_fingerprint cur_serial cur_fingerprint
    exp_serial=$(python3 -c "import json; print(json.load(open('$meta_file', encoding='utf-8')).get('serial', ''))") || { echo "Error: Could not read snapshot certificate serial for $domain" >&2; return 1; }
    exp_fingerprint=$(python3 -c "import json; print(json.load(open('$meta_file', encoding='utf-8')).get('fingerprint', ''))") || { echo "Error: Could not read snapshot certificate fingerprint for $domain" >&2; return 1; }
    if [[ -z "$exp_serial" || -z "$exp_fingerprint" ]]; then
        echo "Error: ACME snapshot is missing certificate identity metadata for $domain" >&2
        return 1
    fi
    if [[ -n "$exp_serial" ]]; then
        cur_serial=$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null) || { echo "Error: Could not read restored certificate serial for $domain" >&2; return 1; }
        if [[ "$cur_serial" != "$exp_serial" ]]; then
            echo "Error: Restored certificate serial ($cur_serial) does not match snapshot ($exp_serial)" >&2
            return 1
        fi
    fi
    if [[ -n "$exp_fingerprint" ]]; then
        cur_fingerprint=$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null) || { echo "Error: Could not read restored certificate fingerprint for $domain" >&2; return 1; }
        if [[ "$cur_fingerprint" != "$exp_fingerprint" ]]; then
            echo "Error: Restored certificate fingerprint ($cur_fingerprint) does not match snapshot ($exp_fingerprint)" >&2
            return 1
        fi
    fi

    echo "ACME lineage for $domain successfully restored and verified." >&2
    return 0
}

cleanup_acme_snapshot() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    if [[ -d "$snap_dir" ]]; then
        rm -rf "$snap_dir"
    fi
}

if [[ "$(id -u)" -ne 0 ]]; then
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/tmp/gowave-managed-mutation-$(id -u).lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/tmp/gowave-mutation-lease-$(id -u).json}"
else
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/run/lock/gowave-managed-mutation.lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/run/lock/gowave-mutation-lease.json}"
fi

validate_lock_path() {
    local lock_file="${1:-$MUTATION_LOCK_FILE}"
    local lock_dir
    lock_dir="$(dirname "$lock_file")"

    if [[ ! -d "$lock_dir" ]]; then
        mkdir -p "$lock_dir"
        chmod 0755 "$lock_dir" 2>/dev/null || true
    fi

    if [[ -L "$lock_dir" ]]; then
        echo "Error: Lock directory $lock_dir is a symlink; unsafe." >&2
        return 1
    fi

    if [[ -L "$lock_file" ]]; then
        echo "Error: Lock file $lock_file is a symlink; refusing path substitution." >&2
        return 1
    fi

    if [[ -e "$lock_file" && ! -f "$lock_file" ]]; then
        echo "Error: Lock file $lock_file exists and is not a regular file." >&2
        return 1
    fi

    return 0
}

validate_mutation_lease() {
    local candidate_token="$1"
    local lease_file="${2:-$MUTATION_LEASE_FILE}"
    local lock_file="${3:-$MUTATION_LOCK_FILE}"

    python3 - "$candidate_token" "$lease_file" "$lock_file" <<'PY'
import json
import os
import sys

token, lease_path, lock_path = sys.argv[1:4]

if not os.path.exists(lease_path):
    sys.exit(1)

if os.path.islink(lease_path):
    sys.exit(1)

st = os.stat(lease_path)
if os.geteuid() == 0 and st.st_uid != 0:
    sys.exit(1)

try:
    with open(lease_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception:
    sys.exit(1)

expected_token = data.get("lease_token", "")
holder_pid = data.get("holder_pid")

if not expected_token or expected_token != token:
    sys.exit(1)

if not holder_pid or not isinstance(holder_pid, int):
    sys.exit(1)

try:
    os.kill(holder_pid, 0)
except OSError:
    sys.exit(1)

fd_dir = f"/proc/{holder_pid}/fd"
if os.path.exists(fd_dir):
    try:
        real_lock = os.path.realpath(lock_path)
        has_fd = False
        for fd in os.listdir(fd_dir):
            try:
                target = os.path.realpath(os.path.join(fd_dir, fd))
                if target == real_lock:
                    has_fd = True
                    break
            except Exception:
                continue
        if not has_fd:
            sys.exit(1)
    except Exception:
        pass

sys.exit(0)
PY
}

acquire_mutation_lock() {
    if [[ "${_MUTATION_LOCK_HELD:-0}" -eq 1 || "${_MUTATION_LEASE_VALIDATED:-0}" -eq 1 ]]; then
        return 0
    fi

    validate_lock_path "$MUTATION_LOCK_FILE" || return 1

    if [[ ! -f "$MUTATION_LOCK_FILE" ]]; then
        (
            umask 0177
            touch "$MUTATION_LOCK_FILE"
        ) 2>/dev/null || true
        chmod 0600 "$MUTATION_LOCK_FILE" 2>/dev/null || true
    fi

    exec 9>>"$MUTATION_LOCK_FILE"
    if flock -n 9; then
        _MUTATION_LOCK_HELD=1
        return 0
    fi

    local candidate_token=""
    if [[ -n "${GOWAVE_LEASE_TOKEN:-}" ]]; then
        candidate_token="$GOWAVE_LEASE_TOKEN"
    elif [[ ! -t 0 ]]; then
        local first_line=""
        if IFS= read -r -t 1 first_line; then
            if [[ "$first_line" =~ ^GOWAVE_LEASE:\ *(.*)$ ]]; then
                candidate_token="${BASH_REMATCH[1]}"
            fi
        fi
    fi

    if [[ -n "$candidate_token" ]]; then
        if validate_mutation_lease "$candidate_token" "$MUTATION_LEASE_FILE" "$MUTATION_LOCK_FILE"; then
            _MUTATION_LEASE_VALIDATED=1
            return 0
        fi
        echo "Error: Invalid or stale mutation lock lease provided." >&2
        return 1
    fi

    echo "Error: Another process currently holds the mutation lock ($MUTATION_LOCK_FILE)." >&2
    echo "Refusing concurrent mutation without an authorized re-entrant lease." >&2
    return 1
}

verify_deploy_hook_preflight() {
    local hook_file="${1:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local transaction_id="${2:-}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    if [[ -e "$hook_file" ]] || [[ -L "$hook_file" ]]; then
        if [[ -n "$transaction_id" ]]; then
            local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
            if [[ -f "$manifest" ]]; then
                local owned
                owned=$(python3 -c "import json; print('1' if json.load(open('$manifest')).get('created_by_tx') else '0')" 2>/dev/null || echo "0")
                if [[ "$owned" == "1" ]]; then
                    return 0
                fi
            fi
        fi
        echo "Error: Pre-existing unowned Certbot deploy hook found at $hook_file. Refusing to overwrite unmanaged host resource." >&2
        return 1
    fi

    local hook_dir
    hook_dir=$(dirname "$hook_file")
    if [[ -e "$hook_dir" && -L "$hook_dir" ]]; then
        echo "Error: Certbot renewal hook directory $hook_dir is an unsafe symlink." >&2
        return 1
    fi
    return 0
}

install_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    verify_deploy_hook_preflight "$hook_file" "$transaction_id" "$recovery_root" || return 1

    local hook_dir resolved_hook_dir metadata owner mode
    hook_dir=$(dirname "$hook_file") || return 1
    resolved_hook_dir=$(realpath -m -- "$hook_dir") || {
        echo "Error: Could not resolve Certbot deploy-hook directory." >&2
        return 1
    }
    if [[ "$resolved_hook_dir" != "$hook_dir" ]]; then
        echo "Error: Certbot deploy-hook directory contains a symlink or non-normalized path." >&2
        return 1
    fi
    mkdir -p -- "$hook_dir" || {
        echo "Error: Could not create Certbot deploy-hook directory." >&2
        return 1
    }
    if [[ ! -d "$hook_dir" || -L "$hook_dir" ]]; then
        echo "Error: Certbot deploy-hook directory is not a real directory." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$hook_dir") || {
        echo "Error: Could not verify Certbot deploy-hook directory." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "Error: Certbot deploy-hook directory is not owned by the current user." >&2
        return 1
    fi
    chmod 0755 -- "$hook_dir" || {
        echo "Error: Could not enforce Certbot deploy-hook directory permissions." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$hook_dir") || return 1
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "755" ]]; then
        echo "Error: Certbot deploy-hook directory owner or mode verification failed." >&2
        return 1
    fi

    local snap_dir="${recovery_root}/${transaction_id}" resolved_snap_dir
    resolved_snap_dir=$(realpath -m -- "$snap_dir") || {
        echo "Error: Could not resolve deploy-hook recovery directory." >&2
        return 1
    }
    if [[ "$snap_dir" != /* || "$snap_dir" == "/" || "$resolved_snap_dir" != "$snap_dir" ]]; then
        echo "Error: Deploy-hook recovery path is not a normalized absolute path without symlinks." >&2
        return 1
    fi
    mkdir -p -- "$snap_dir" || {
        echo "Error: Could not create deploy-hook recovery directory." >&2
        return 1
    }
    if [[ ! -d "$snap_dir" || -L "$snap_dir" ]]; then
        echo "Error: Deploy-hook recovery path is not a real directory." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$snap_dir") || {
        echo "Error: Could not verify deploy-hook recovery directory." >&2
        return 1
    }
    owner="${metadata%%:*}"
    if [[ "$owner" != "$(id -u)" ]]; then
        echo "Error: Deploy-hook recovery directory is not owned by the current user." >&2
        return 1
    fi
    chmod 0700 -- "$snap_dir" || {
        echo "Error: Could not secure deploy-hook recovery directory." >&2
        return 1
    }
    metadata=$(stat -c '%u:%a' -- "$snap_dir") || return 1
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "700" ]]; then
        echo "Error: Deploy-hook recovery directory owner or mode verification failed." >&2
        return 1
    fi

    local manifest="${snap_dir}/deploy-hook-manifest.json"
    local tmp_file="${hook_file}.tmp.$$"
    if ! cat > "$tmp_file" <<'EOF'
#!/bin/sh
# Managed by GoWave Auto NGINX: Automated ACME Reload Hook
if nginx -t -q; then
    systemctl reload nginx
fi
EOF
    then
        echo "Error: Could not write temporary Certbot deploy hook." >&2
        return 1
    fi
    if ! chmod 0755 -- "$tmp_file" || ! sync "$tmp_file"; then
        rm -f -- "$tmp_file" || true
        echo "Error: Could not secure and sync temporary Certbot deploy hook." >&2
        return 1
    fi

    local digest
    digest=$(sha256sum "$tmp_file" | awk '{print $1}') || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not calculate Certbot deploy-hook digest." >&2
        return 1
    }
    python3 -c 'import json, os, sys; manifest_path, tx_id, path, digest = sys.argv[1:5]; flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0); fd = os.open(manifest_path, flags, 0o600); stream = os.fdopen(fd, "w", encoding="utf-8"); json.dump({"transaction_id": tx_id, "path": path, "created_by_tx": True, "sha256": digest}, stream, indent=2); stream.flush(); os.fsync(stream.fileno()); stream.close()' "$manifest" "$transaction_id" "$hook_file" "$digest" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not create deploy-hook ownership manifest safely." >&2
        return 1
    }
    if ! chmod 0600 -- "$manifest"; then
        rm -f -- "$tmp_file" || true
        echo "Error: Could not enforce private deploy-hook manifest permissions." >&2
        return 1
    fi
    metadata=$(stat -c '%u:%a' -- "$manifest") || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not verify deploy-hook ownership manifest." >&2
        return 1
    }
    owner="${metadata%%:*}"
    mode="${metadata#*:}"
    if [[ "$owner" != "$(id -u)" || "$mode" != "600" ]]; then
        rm -f -- "$tmp_file" || true
        echo "Error: Deploy-hook manifest owner or mode verification failed." >&2
        return 1
    fi
    sync "$manifest" && sync "$snap_dir" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not sync deploy-hook ownership manifest." >&2
        return 1
    }

    mv -f -- "$tmp_file" "$hook_file" || {
        rm -f -- "$tmp_file" || true
        echo "Error: Could not install managed Certbot deploy hook." >&2
        return 1
    }
    sync "$hook_dir" || {
        echo "Error: Could not sync Certbot deploy-hook directory after installation." >&2
        return 1
    }
    echo "Configured managed ACME renewal hook in $hook_file."
}
rollback_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    if [[ -z "$transaction_id" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: ACME transaction ID is missing; preserving deploy hook with unknown ownership and reporting incomplete rollback." >&2
            return 1
        fi
        return 0
    fi

    local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
    if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: Deploy hook exists without an ownership manifest; refusing to claim rollback succeeded." >&2
            return 1
        fi
        return 0
    fi
    if [[ ! -f "$manifest" || -L "$manifest" ]]; then
        echo "Error: Deploy-hook rollback manifest is missing, non-regular, or a symlink." >&2
        return 1
    fi

    local manifest_data
    manifest_data=$(python3 - "$manifest" "$transaction_id" "$hook_file" <<'PY'
import json
import re
import sys

path, expected_tx, expected_hook = sys.argv[1:4]
try:
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    if data.get("transaction_id") != expected_tx or data.get("path") != expected_hook:
        raise ValueError("manifest transaction/path mismatch")
    created = data.get("created_by_tx")
    if type(created) is not bool:
        raise ValueError("created_by_tx must be a boolean")
    digest = data.get("sha256", "")
    if not isinstance(digest, str):
        raise ValueError("sha256 must be a string")
    if created and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("created hook digest is invalid")
    print("1" if created else "0")
    print(digest)
except Exception as exc:
    print(f"Invalid deploy-hook rollback manifest: {type(exc).__name__}", file=sys.stderr)
    sys.exit(1)
PY
    ) || {
        echo "Error: Refusing deploy-hook rollback because its ownership manifest is invalid." >&2
        return 1
    }

    local -a manifest_fields=()
    mapfile -t manifest_fields <<< "$manifest_data"
    if [[ "${#manifest_fields[@]}" -ne 2 ]]; then
        echo "Error: Deploy-hook rollback manifest has an invalid field count." >&2
        return 1
    fi
    local created_by_tx="${manifest_fields[0]}"
    local recorded_sha="${manifest_fields[1]}"
    if [[ "$created_by_tx" != "1" ]]; then
        return 0
    fi

    if [[ ! -e "$hook_file" && ! -L "$hook_file" ]]; then
        return 0
    fi
    if [[ -L "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is now a symlink; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi
    if [[ ! -f "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is not a regular file; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    local current_sha
    current_sha=$(sha256sum "$hook_file" | awk '{print $1}') || {
        echo "Error: Could not verify managed deploy-hook digest." >&2
        return 1
    }
    if [[ "$current_sha" != "$recorded_sha" ]]; then
        echo "Warning: Deploy hook $hook_file was modified after installation (digest mismatch); preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    rm -f "$hook_file" || {
        echo "Error: Could not remove transaction-owned deploy hook $hook_file." >&2
        return 1
    }
    sync "$(dirname "$hook_file")" || {
        echo "Error: Could not sync deploy-hook directory after rollback." >&2
        return 1
    }
    return 0
}

cleanup_deploy_hook_manifest() {
    local transaction_id="$1"
    local recovery_root="${2:-/var/lib/gowave-auto-nginx/recovery}"
    rm -f "${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
}

setup_system_prereqs() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        nginx-full libnginx-mod-stream certbot python3 python3-systemd \
        curl tar gzip openssl ufw fail2ban iproute2 ca-certificates
}

# The mutation lease and the ACME lineage snapshots are python3, and every
# certificate check they make is openssl. Both arrive with setup_system_prereqs,
# yet the snapshots run before it: on a minimal host the transaction died at its
# first Python call and took the compensation down with it, leaving the Worker
# half-provisioned. modules/os.sh bootstraps this same set on the Master before
# its prerequisites; the Worker gets the payload without the checkout, so the
# list is repeated here instead of sourced.
get_bootstrap_packages() {
    cat <<'EOF'
python3
iproute2
curl
ca-certificates
openssl
EOF
}

missing_bootstrap_packages() {
    local pkg
    for pkg in "$@"; do
        [[ -z "$pkg" || "$pkg" =~ ^# ]] && continue
        if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            printf '%s\n' "$pkg"
        fi
    done
}

bootstrap_early_tools() {
    local packages=() missing=()
    mapfile -t packages < <(get_bootstrap_packages)
    mapfile -t missing < <(missing_bootstrap_packages "${packages[@]}")

    if [[ ${#missing[@]} -eq 0 ]]; then
        return 0
    fi
    echo "[INFO] Bootstrapping early tools required before prerequisites: ${missing[*]}..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
}

configure_dot() {
    # The shared host-security helper is streamed with the payload because the
    # Worker never receives the project checkout at /opt/gowave-auto-nginx.
    echo "Configuring strict DNS-over-TLS via systemd-resolved..."
    if [[ -z "${SECURITY_HELPER_B64:-}" ]]; then
        log_warn "Host security helper was not delivered to this Worker."
        return 1
    fi
    local helper=/tmp/gowave-managed-security.py
    if ! printf '%s' "$SECURITY_HELPER_B64" | base64 -d > "$helper"; then
        log_warn "Could not materialize the host security helper."
        return 1
    fi
    chmod 0700 "$helper"
    local rc=0
    python3 "$helper" --prepare-dns </dev/null || rc=$?
    rm -f "$helper"
    return "$rc"
}

configure_worker_dot() {
    local dot_conf="${1:-/etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf}"
    if [[ -e "$dot_conf" ]]; then
        _DOT_CREATED_BY_US=0
    else
        _DOT_CREATED_BY_US=1
    fi
    if declare -F configure_dot >/dev/null 2>&1; then
        if ! configure_dot </dev/null; then
            log_warn "Strict DNS-over-TLS setup failed; the Worker resolver remains unhardened."
            _DOT_CREATED_BY_US=0
        fi
    else
        log_warn "DNS-over-TLS helper unavailable; the Worker resolver remains unhardened."
        _DOT_CREATED_BY_US=0
    fi
}

configure_host_security() {
    # Keep MTU/file-limit tuning independent from optional BBR support.
    mkdir -p /etc/sysctl.d
    if [[ ! -e /etc/sysctl.d/99-gowave-node.conf ]]; then
        _SYSCTL_CREATED_BY_US=1
    fi
    modprobe tcp_bbr 2>/dev/null || true
    {
        echo "# Managed by GoWave Auto NGINX"
        echo "net.ipv4.tcp_mtu_probing = 1"
        echo "fs.file-max = 1048576"
        if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        else
            echo "Warning: BBR is unavailable in this kernel; retaining the system congestion-control default." >&2
        fi
    } > /etc/sysctl.d/99-gowave-node.conf
    sysctl -p /etc/sysctl.d/99-gowave-node.conf

    # Allocate swap only on small-memory hosts. Do not persist a failed swapon.
    local mem_kb fs_type swap_tmp
    mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    if [[ "$mem_kb" -le 1048576 && "$mem_kb" -gt 0 ]] && ! swapon --show --noheadings | grep -q .; then
        if [[ -e /swapfile ]]; then
            log_warn "/swapfile already exists; refusing to overwrite an unmanaged file."
        else
            _SWAP_CREATED_BY_US=1
            fs_type=$(findmnt -n -o FSTYPE /)
            if [[ "$fs_type" == "btrfs" ]]; then
                if ! command -v btrfs >/dev/null 2>&1 || ! btrfs filesystem mkswapfile --size 1G /swapfile; then
                    log_warn "Could not create a Btrfs-compatible swapfile; continuing without swap."
                    rm -f /swapfile
                fi
            elif fallocate -l 1G /swapfile 2>/dev/null; then
                chmod 0600 /swapfile
                mkswap /swapfile >/dev/null
            else
                rm -f /swapfile
                dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
                chmod 0600 /swapfile
                mkswap /swapfile >/dev/null
            fi
            if [[ -f /swapfile ]] && swapon /swapfile; then
                if ! grep -qE '^[[:space:]]*/swapfile[[:space:]]' /etc/fstab; then
                    swap_tmp=$(mktemp /etc/fstab.gowave.XXXXXX)
                    cat /etc/fstab > "$swap_tmp"
                    printf '/swapfile none swap sw 0 0\n' >> "$swap_tmp"
                    chmod --reference=/etc/fstab "$swap_tmp"
                    chown --reference=/etc/fstab "$swap_tmp"
                    mv -f "$swap_tmp" /etc/fstab
                fi
            else
                log_warn "Swap activation failed; no /etc/fstab entry was written."
                swapoff /swapfile 2>/dev/null || true
                rm -f /swapfile
            fi
        fi
    fi

    # Xray and Go cache no resolver answers, so a single dropped UDP/53 query
    # stalls tunnel setup for the full resolver timeout. Strict DoT uses TCP/853
    # with retransmission and keeps the Worker's data plane reliable.
    configure_worker_dot
}

# Whether this host has IPv6 is decided by the address table's content, never
# by its size: procfs reports a zero inode size for /proc/net/if_inet6 however
# many addresses it prints.
kernel_has_ipv6() {
    local if_inet6="${1:-/proc/net/if_inet6}"
    [[ -f "$if_inet6" ]] && grep -q '[^[:space:]]' "$if_inet6" 2>/dev/null
}

configure_firewall() {
    local ufw_default="${1:-/etc/default/ufw}"
    local panel_ip="${PANEL_IP:-}" panel_ipv6="${PANEL_IPV6:-}" ssh_port="${SSH_PORT:-22}"
    if [[ -z "$panel_ip" && -z "$panel_ipv6" ]]; then
        echo "Fatal: PANEL_IP or PANEL_IPV6 is required; refusing an unscoped Node API firewall rule." >&2
        return 1
    fi
    python3 - "$panel_ip" "$panel_ipv6" "$ssh_port" "$NODE_PORT" <<'PY'
import ipaddress, sys
v4, v6, ssh_port, node_port = sys.argv[1:]
if v4 and ipaddress.ip_address(v4).version != 4:
    raise SystemExit("PANEL_IP must be an IPv4 address")
if v6 and ipaddress.ip_address(v6).version != 6:
    raise SystemExit("PANEL_IPV6 must be an IPv6 address")
for name, value in (("SSH_PORT", ssh_port), ("NODE_PORT", node_port)):
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise SystemExit(f"{name} must be a valid TCP port")
PY

    # Detect an existing unrestricted API-port exception rather than claiming
    # the new source-specific rule makes an already-open port private.
    if ufw status | awk -v p="$NODE_PORT/tcp" 'index($0, p) == 1 && $0 ~ /ALLOW[[:space:]]+IN/ && $0 ~ /Anywhere/ {found=1} END {exit !found}'; then
        echo "Fatal: UFW already contains an unrestricted allow rule for NODE_PORT=$NODE_PORT; remove it manually before retrying." >&2
        return 1
    fi

    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        _UFW_WAS_ACTIVE=1
    else
        _UFW_WAS_ACTIVE=0
    fi
    _UFW_RULES_CONFIGURED=1

    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$ssh_port/tcp" comment "SSH administration"
    ufw allow 80/tcp comment "HTTP ACME challenge"
    ufw allow 443/tcp comment "HTTPS and Xray Stream"
    if [[ -n "$panel_ip" ]]; then
        ufw allow proto tcp from "$panel_ip" to any port "$NODE_PORT" comment "GoWave Control Plane IPv4"
    fi
    if [[ -n "$panel_ipv6" ]]; then
        ufw allow proto tcp from "$panel_ipv6" to any port "$NODE_PORT" comment "GoWave Control Plane IPv6"
    fi
    # UFW's own declaration has to follow the same host decision the listeners
    # render, or the distro default claims a v6 stack this host does not have
    # (and, where that default is ``no``, leaves a v6 listener unfiltered).
    if [[ -f "$ufw_default" ]]; then
        if kernel_has_ipv6; then
            sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_default" || true
        else
            sed -i 's/^IPV6=.*/IPV6=no/' "$ufw_default" || true
        fi
    fi
    ufw --force enable
    ufw status | grep -q '^Status: active$' || {
        echo "Fatal: UFW did not enter the active state." >&2
        return 1
    }
}

unpack_cover_reality() {
    mkdir -p /var/www/gowave-auto-nginx/cover-reality
    local actual_sha
    actual_sha=$(echo -n "$COVER_REALITY_B64" | base64 -d | sha256sum | awk '{print $1}')
    if [ "$actual_sha" != "$COVER_REALITY_SHA256" ]; then
        echo "Error: Cover reality archive SHA-256 verification failed!" >&2
        echo "Expected: $COVER_REALITY_SHA256, got: $actual_sha" >&2
        exit 1
    fi
    echo -n "$COVER_REALITY_B64" | base64 -d | tar -xzf - -C /var/www/gowave-auto-nginx/cover-reality
    chmod -R 0755 /var/www/gowave-auto-nginx/cover-reality
    _COVER_UNPACKED=1
}

derive_cover_domain() {
    local panel_domain="${1:-}"
    local labels
    [[ -n "$panel_domain" ]] || return 0
    IFS='.' read -r -a labels <<< "${panel_domain%.}"
    local count="${#labels[@]}"
    if [[ "$count" -lt 3 ]]; then
        return 0
    fi
    printf '%s.%s\n' "${labels[count - 2]}" "${labels[count - 1]}"
}

cover_brand_from_domain() {
    local domain="${1:-}"
    local labels label word out=""
    [[ -n "$domain" ]] || return 0
    IFS='.' read -r -a labels <<< "${domain%.}"
    local count="${#labels[@]}"
    if [[ "$count" -ge 3 ]]; then
        label="${labels[count - 2]}"
    else
        label="${labels[0]}"
    fi
    label="${label//-/ }"
    for word in $label; do
        out+="${word^} "
    done
    printf '%s\n' "${out% }"
}

cover_domains_resolve_here() {
    local cover_domain="${1:-}"
    local server_ip="${2:-}"
    [[ -n "$cover_domain" && -n "$server_ip" ]] || return 1
    local name resolved
    for name in "$cover_domain" "www.$cover_domain"; do
        resolved=$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1 {print $1}')
        [[ "$resolved" == "$server_ip" ]] || return 1
    done
}

# The single cover-site decision, identical to the Master's: the apex on
# stdout, nothing when the decoy stays off, and the reason on stderr. A domain
# without a subdomain has no registrable apex, and an empty render would leave
# the operator guessing which of the two refusals happened.
cover_domain_for() {
    local panel_domain="${1:-}"
    local server_ip="${2:-}"
    local cover_domain
    cover_domain=$(derive_cover_domain "$panel_domain")
    if [[ -z "$cover_domain" ]]; then
        if [[ -n "$panel_domain" ]]; then
            echo "Camouflage apex disabled — $panel_domain has no subdomain, so no cover apex exists." >&2
        fi
        return 0
    fi
    if ! cover_domains_resolve_here "$cover_domain" "$server_ip"; then
        echo "Camouflage apex disabled — $cover_domain / www.$cover_domain do not resolve to ${server_ip:-this host}, so HTTP-01 would fail." >&2
        return 0
    fi
    printf '%s\n' "$cover_domain"
}

render_cover_site() {
    local cover_root="$1"
    local domain="${2:-}"
    local source_dir="${SCRIPT_DIR:-}/assets/cover-sites/cover-reality"

    [[ -d "$cover_root" ]] || return 0
    if [[ -d "$source_dir" ]]; then
        cp -r "$source_dir/." "$cover_root/" || return 1
    fi
    chmod -R 0755 "$cover_root" 2>/dev/null || true

    local brand="${GOWAVE_COVER_BRAND:-}"
    if [[ -z "$brand" ]]; then
        brand=$(cover_brand_from_domain "$domain")
    fi
    brand="${brand//&/}"
    brand="${brand//|/}"

    local file tmp
    while IFS= read -r file; do
        tmp="$file.tmp.$$"
        if ! sed -e "s|{{BRAND}}|$brand|g" \
                 -e "s|{{ACCENT2}}|${GOWAVE_COVER_ACCENT2:-#14876f}|g" \
                 -e "s|{{ACCENT}}|${GOWAVE_COVER_ACCENT:-#0f6b5c}|g" \
                 -e "s|{{SOFT}}|${GOWAVE_COVER_SOFT:-#e7f3ee}|g" \
                 -e "s|{{HOME_HEADLINE}}|${GOWAVE_COVER_HEADLINE:-Plan the work, keep the context, move on.}|g" \
                 -e "s|{{HOME_LEDE}}|${GOWAVE_COVER_LEDE:-Projects, notes and next steps in one calm place, with just enough structure to keep everyone oriented.}|g" \
                 "$file" > "$tmp"; then
            rm -f "$tmp"
            echo "Error: failed to render $file" >&2
            return 1
        fi
        chmod 0644 "$tmp" && mv "$tmp" "$file" || { rm -f "$tmp"; return 1; }
    done < <(find "$cover_root" -type f \( -name '*.html' -o -name '*.css' -o -name '*.svg' \) -print)

    if grep -rq '{{' "$cover_root" --include='*.html' --include='*.css' --include='*.svg'; then
        echo "Error: camouflage site still contains unrendered placeholders under $cover_root" >&2
        return 1
    fi
    echo "Rendered worker camouflage site for ${domain:-unknown domain}."
}

configure_edge_nginx() {
    mkdir -p /etc/nginx/stream-enabled /etc/nginx/conf.d /var/www/gowave-acme
    chmod 0755 /var/www/gowave-acme

    # Camouflage apex: the bare domain of this Worker serves the static decoy.
    # ACME validates it over port 80 here, so it requires the apex and www
    # records to point at this host; the decision names its own refusal, so a
    # domain without a subdomain is reported instead of rendering nothing.
    local cover_domain="" cover_server_ip=""
    if [[ -n "$(derive_cover_domain "$WORKER_DOMAIN")" ]]; then
        if [[ "${GOWAVE_PODMAN_TEST_MODE:-0}" == "1" ]]; then
            cover_server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        else
            cover_server_ip=$(curl -s4 --connect-timeout 5 --max-time 10 https://ifconfig.me 2>/dev/null || \
                              curl -s4 --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true)
        fi
    fi
    cover_domain=$(cover_domain_for "$WORKER_DOMAIN" "$cover_server_ip")
    local cover_names=""
    if [[ -n "$cover_domain" ]]; then
        cover_names=" $cover_domain www.$cover_domain"
    fi

    # Port 80 ACME webroot vhost. It stays in place after issuance: certbot's
    # HTTP-01 renewal revalidates through this same path, so removing it makes
    # every later `certbot renew` fail with a 404.
    local cover_http_redirect=""
    if [[ -n "$cover_domain" ]]; then
        # Keep the plain-HTTP visit to the camouflage apex as ordinary as the
        # Master's: redirect to HTTPS instead of dropping the connection.
        local cover_regex="${cover_domain//./\\.}"
        cover_http_redirect="        if (\$host ~* ^(${cover_regex}|www\\.${cover_regex})\$) {
            return 301 https://\$host\$request_uri;
        }
"
    fi
    cat > /etc/nginx/conf.d/00-worker-acme-challenge.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Port 80 ACME Challenge
server {
    listen 80;
    server_name $WORKER_DOMAIN $REALITY_DOMAIN ${VISION_DOMAIN:-}$cover_names;
    location /.well-known/acme-challenge/ {
        root /var/www/gowave-acme;
    }
    location / {
${cover_http_redirect}        return 444;
    }
}
EOF
    _NGINX_BOOTSTRAP_CREATED=1
    nginx -t
    systemctl reload nginx || systemctl restart nginx
    systemctl is-active --quiet nginx || { echo "Fatal: NGINX failed to activate bootstrap ACME config" >&2; return 1; }

    local certbot_extra_args=()
    if [[ -n "${GOWAVE_ACME_SERVER:-}" ]]; then
        certbot_extra_args+=(--server "$GOWAVE_ACME_SERVER")
    fi

    echo "Acquiring Let's Encrypt TLS certificate for Worker ($WORKER_DOMAIN)..."
    run_certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$WORKER_DOMAIN" --cert-name "$WORKER_DOMAIN" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring \
        "${certbot_extra_args[@]}"
    _ACME_WORKER_ISSUED=1

    echo "Acquiring Let's Encrypt TLS certificate for REALITY decoy ($REALITY_DOMAIN)..."
    # The camouflage certificate also covers the apex website served by this
    # Worker, so one lineage backs both the probe fallback and the plain domain.
    local reality_cert_args=(-d "$REALITY_DOMAIN")
    local reality_cert_flags=()
    if [[ -n "$cover_domain" ]]; then
        reality_cert_args+=(-d "$cover_domain" -d "www.$cover_domain")
        reality_cert_flags+=(--expand)
    fi
    run_certbot certonly --webroot -w /var/www/gowave-acme \
        "${reality_cert_args[@]}" "${reality_cert_flags[@]}" --cert-name "$REALITY_DOMAIN" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring \
        "${certbot_extra_args[@]}"
    _ACME_REALITY_ISSUED=1

    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        echo "Acquiring Let's Encrypt TLS certificate for Vision ($VISION_DOMAIN)..."
        run_certbot certonly --webroot -w /var/www/gowave-acme \
            -d "$VISION_DOMAIN" --cert-name "$VISION_DOMAIN" \
            --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring \
            "${certbot_extra_args[@]}"
        _ACME_VISION_ISSUED=1
    fi

    verify_worker_certificate() {
        local domain="$1" lineage="${2:-/etc/letsencrypt/live/$1}"
        local cert="$lineage/fullchain.pem" key="$lineage/privkey.pem"
        [[ -s "$cert" && -s "$key" ]] || { echo "Fatal: certificate/key missing for $domain" >&2; return 1; }
        openssl x509 -in "$cert" -noout -checkhost "$domain" >/dev/null
        openssl x509 -in "$cert" -noout -checkend 86400 >/dev/null
        local cert_pub key_pub
        cert_pub=$(openssl x509 -in "$cert" -noout -pubkey)
        key_pub=$(openssl pkey -in "$key" -pubout)
        [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || {
            echo "Fatal: certificate/private-key mismatch for $domain" >&2
            return 1
        }
    }
    verify_worker_certificate "$WORKER_DOMAIN"
    verify_worker_certificate "$REALITY_DOMAIN"
    if [[ -n "$cover_domain" ]]; then
        verify_worker_certificate "$cover_domain" "/etc/letsencrypt/live/$REALITY_DOMAIN"
    fi
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        verify_worker_certificate "$VISION_DOMAIN"
    fi

    # Configure automated ACME reload hook for Worker
    install_managed_deploy_hook "$_ACME_TX_ID" "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh"

    # Hook top-level stream if missing
    if ! grep -q 'stream-enabled' /etc/nginx/nginx.conf; then
        _STREAM_INCLUDE_ADDED=1
        sed -i '/events {/i stream { include /etc/nginx/stream-enabled/*.conf; }' /etc/nginx/nginx.conf || \
        echo "stream { include /etc/nginx/stream-enabled/*.conf; }" >> /etc/nginx/nginx.conf
    fi

    local listen_v6=""
    # One host decision drives the listener and the firewall declaration.
    if kernel_has_ipv6; then
        listen_v6="listen [::]:443 so_keepalive=on;"
    fi

    # Stream SNI Preread on 443
    local worker_vision=""
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        worker_vision="    $VISION_DOMAIN 127.0.0.1:8444;"
    fi
    local worker_cover=""
    if [[ -n "$cover_domain" ]]; then
        worker_cover="    $cover_domain 127.0.0.1:9443;
    www.$cover_domain 127.0.0.1:9443;"
    fi
    cat > /etc/nginx/stream-enabled/gowave-worker-stream.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Stream
map \$ssl_preread_server_name \$worker_dest {
    $WORKER_DOMAIN 127.0.0.1:7443;
    $REALITY_DOMAIN 127.0.0.1:8443;
$worker_vision
$worker_cover
    default 127.0.0.1:8443;
}

server {
    listen 443 so_keepalive=on;
    $listen_v6
    ssl_preread on;
    proxy_protocol on;
    proxy_timeout 1h;
    proxy_connect_timeout 5s;
    proxy_pass \$worker_dest;
}
EOF

    # Detect NGINX version for HTTP/2 syntax compatibility (< 1.25.1 vs >= 1.25.1)
    local listen_7443="listen 127.0.0.1:7443 ssl http2 proxy_protocol;"
    local listen_9443="listen 127.0.0.1:9443 ssl http2 proxy_protocol;"
    local ngx_ver=""
    ngx_ver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+' || echo "1.24.0")
    if [[ "$(printf '%s\n1.25.1\n' "$ngx_ver" | sort -V | head -n1)" == "1.25.1" ]]; then
        listen_7443="listen 127.0.0.1:7443 ssl proxy_protocol;
    http2 on;"
        listen_9443="listen 127.0.0.1:9443 ssl proxy_protocol;
    http2 on;"
    fi

    # Edge HTTPS listener on 7443
    cat > /etc/nginx/conf.d/gowave-worker-https.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge HTTPS
server {
    $listen_7443
    server_name $WORKER_DOMAIN;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate /etc/letsencrypt/live/$WORKER_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$WORKER_DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location ^~ /xhttp-down/ {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        client_max_body_size 0;
        client_body_timeout 1h;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location = /ws {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10003;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        client_body_timeout 1h;
    }

    location / {
        return 404;
    }
}
EOF

    # Decoy on 9443
    cat > /etc/nginx/conf.d/gowave-worker-decoy.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Decoy
server {
    $listen_9443
    server_name $REALITY_DOMAIN$cover_names;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
    ssl_protocols TLSv1.3;

    ssl_certificate /etc/letsencrypt/live/$REALITY_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$REALITY_DOMAIN/privkey.pem;

    root /var/www/gowave-auto-nginx/cover-reality;
    index index.html;
    error_page 404 /404.html;
    access_log /var/log/nginx/gowave-decoy-access.log;
}
EOF
    render_cover_site "/var/www/gowave-auto-nginx/cover-reality" "${cover_domain:-$REALITY_DOMAIN}" || return 1

    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        cat > /etc/nginx/conf.d/gowave-worker-vision-fallback.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Vision Fallback Decoy
server {
    listen 127.0.0.1:9444 proxy_protocol;
    server_name $VISION_DOMAIN;
    server_tokens off;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    root /var/www/gowave-auto-nginx/cover-reality;
    index index.html;
    access_log /var/log/nginx/gowave-vision-fallback-access.log;
}
EOF
    fi

    nginx -t
    systemctl reload nginx || systemctl restart nginx
    systemctl is-active --quiet nginx || { echo "Fatal: NGINX failed to activate production configuration" >&2; return 1; }
    _NGINX_CONFIGS_CREATED=1
}

core_version_matches() {
    local reported="${1:-}"
    local expected="${2:-}"
    [[ -n "$expected" ]] || return 1
    local token
    for token in $reported; do
        if [[ "$token" == "$expected" ]]; then
            return 0
        fi
    done
    return 1
}

ensure_pinned_xray_core() {
    local node_bin="${1:-/opt/gowave-node/gowave-node}"
    local core_bin="${2:-/opt/gowave-node/rw-core}"

    # "latest" is the shipped default: it means the core the node installation
    # already brought is the one to keep, not a version to reinstall.
    local requested="${XRAY_SERVER_VERSION:-}"
    if [[ -z "$requested" || "${requested,,}" == "latest" || "${requested,,}" == "vlatest" || ! -x "$node_bin" ]]; then
        return 0
    fi

    local expected_core cur_core
    expected_core="${requested#v}"
    cur_core=$("$core_bin" version 2>/dev/null || true)
    if core_version_matches "$cur_core" "$expected_core"; then
        return 0
    fi

    log_info "Installing explicit Xray server version $XRAY_SERVER_VERSION..."
    if ! "$node_bin" core install --version "v$expected_core" -y 2>/dev/null && \
       ! "$node_bin" core install --version "$expected_core" -y 2>/dev/null; then
        log_err "Failed to install requested Xray server version $XRAY_SERVER_VERSION."
        return 1
    fi
    cur_core=$("$core_bin" version 2>/dev/null || true)
    if core_version_matches "$cur_core" "$expected_core"; then
        return 0
    fi
    log_err "Xray server version mismatch after installation: expected $expected_core, got ${cur_core:-unknown}."
    return 1
}

run_upstream_node_installer() {
    local tmp_inst
    : "${GOWAVE_NODE_INSTALLER_COMMIT:?Pinned upstream installer commit is required}"
    : "${GOWAVE_NODE_INSTALLER_SHA256:?Pinned upstream installer SHA256 digest is required}"
    [[ "$GOWAVE_NODE_INSTALLER_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] || {
        echo "Fatal: invalid pinned upstream installer commit: expected 40-hex SHA." >&2
        return 1
    }
    [[ "$GOWAVE_NODE_INSTALLER_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || {
        echo "Fatal: invalid pinned upstream installer SHA256: expected 64-hex digest." >&2
        return 1
    }
    tmp_inst=$(mktemp "/tmp/gowave-node-install-XXXXXX.sh")
    if ! curl -fsSL --retry 2 --connect-timeout 15 --max-time 60 \
        "https://raw.githubusercontent.com/aaaSaZaN/gowave-node/$GOWAVE_NODE_INSTALLER_COMMIT/install.sh" -o "$tmp_inst"; then
        rm -f "$tmp_inst"
        echo "Fatal: failed to fetch the pinned GoWave Node installer." >&2
        return 1
    fi
    local fetched_sha256
    fetched_sha256=$(sha256sum "$tmp_inst" | awk '{print $1}')
    if [[ "$fetched_sha256" != "$GOWAVE_NODE_INSTALLER_SHA256" ]]; then
        rm -f "$tmp_inst"
        echo "Fatal: upstream installer SHA256 mismatch: expected $GOWAVE_NODE_INSTALLER_SHA256, got $fetched_sha256." >&2
        return 1
    fi
    chmod 0700 "$tmp_inst"
    local normalized_node_ver="${GOWAVE_NODE_VERSION:-latest}"
    if [[ "$normalized_node_ver" != "latest" && "$normalized_node_ver" != v* ]]; then
        normalized_node_ver="v$normalized_node_ver"
    fi
    if GOWAVE_NODE_VERSION="$normalized_node_ver" bash "$tmp_inst" </dev/null; then
        rm -f "$tmp_inst"
    else
        local installer_rc=$?
        rm -f "$tmp_inst"
        echo "Fatal: upstream installer failed with exit code $installer_rc" >&2
        return "$installer_rc"
    fi

    # Configure drop-in for NODE_PORT
    mkdir -p /etc/systemd/system/gowave-node.service.d
    cat > /etc/systemd/system/gowave-node.service.d/10-port.conf <<EOF
[Service]
Environment="NODE_PORT=$NODE_PORT"
EOF

    # Install pinned Xray core version if explicitly configured and mismatched
    ensure_pinned_xray_core || return 1
    systemctl daemon-reload
    systemctl restart gowave-node.service
    systemctl is-active --quiet gowave-node.service || {
        echo "Fatal: gowave-node.service is not active after upstream installation." >&2
        return 1
    }
    _NODE_SERVICE_CONFIGURED=1
}

compensate_remote_worker() {
    local exit_code="${1:-1}"
    if [[ "${_ROLLBACK_IN_PROGRESS:-0}" -eq 1 ]]; then
        return "$exit_code"
    fi
    _ROLLBACK_IN_PROGRESS=1
    local rollback_failed=0
    echo "[ROLLBACK] Remote worker deployment failed (exit code: $exit_code). Initiating automated compensating rollback..." >&2

    # 1. Stop and remove GoWave Node and Xray systemd services
    if [[ "${_NODE_SERVICE_CONFIGURED:-0}" -eq 1 ]] || systemctl list-unit-files gowave-node.service 2>/dev/null | grep -q gowave-node; then
        echo "[ROLLBACK] Stopping and disabling gowave-node.service and drop-ins..." >&2
        systemctl stop gowave-node.service 2>/dev/null || rollback_failed=1
        systemctl disable gowave-node.service 2>/dev/null || rollback_failed=1
        systemctl stop xray.service 2>/dev/null || rollback_failed=1
        systemctl disable xray.service 2>/dev/null || rollback_failed=1
        rm -rf /etc/systemd/system/gowave-node.service.d || rollback_failed=1
        rm -f /etc/systemd/system/gowave-node.service /etc/systemd/system/remnanode.service || rollback_failed=1
        systemctl daemon-reload 2>/dev/null || rollback_failed=1
        rm -rf /opt/gowave-node /run/gowave-node /opt/remnanode || rollback_failed=1
        rm -f /usr/local/bin/gowave-node /usr/local/bin/xray || rollback_failed=1
    fi

    # 2. Revert NGINX and ACME bootstrap
    if [[ "${_NGINX_CONFIGS_CREATED:-0}" -eq 1 ]] || [[ "${_NGINX_BOOTSTRAP_CREATED:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Cleaning up worker NGINX virtual hosts and stream routing..." >&2
        rm -f /etc/nginx/conf.d/00-worker-acme-challenge.conf /etc/nginx/conf.d/00-bootstrap-worker-acme.conf /etc/nginx/conf.d/gowave-worker-https.conf /etc/nginx/conf.d/gowave-worker-decoy.conf /etc/nginx/conf.d/gowave-worker-vision-fallback.conf /etc/nginx/stream-enabled/gowave-worker-stream.conf || rollback_failed=1
        rollback_managed_deploy_hook "${_ACME_TX_ID:-}" "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" 2>/dev/null || rollback_failed=1
        rm -rf /var/www/gowave-acme || rollback_failed=1
        if [[ "${_STREAM_INCLUDE_ADDED:-0}" -eq 1 ]]; then
            sed -i '\#stream { include /etc/nginx/stream-enabled/\*\.conf; }#d' /etc/nginx/nginx.conf 2>/dev/null || rollback_failed=1
        fi
        if nginx -t >/dev/null 2>&1; then
            systemctl reload nginx 2>/dev/null || rollback_failed=1
        else
            rollback_failed=1
        fi
    fi

    # 3. Clean Cover Reality decoy site
    if [[ "${_COVER_UNPACKED:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Removing cover decoy site assets..." >&2
        rm -rf /var/www/gowave-auto-nginx/cover-reality || rollback_failed=1
        if [[ -d /var/www/gowave-auto-nginx ]]; then
            rmdir /var/www/gowave-auto-nginx 2>/dev/null || rollback_failed=1
        fi
    fi

    # 4. Revert ACME certificates
    if [[ -n "${_ACME_TX_ID:-}" ]]; then
        echo "[ROLLBACK] Restoring or cleaning up ACME certificates via snapshot..." >&2
        restore_acme_lineage "$_ACME_TX_ID" "$WORKER_DOMAIN" 2>/dev/null || rollback_failed=1
        restore_acme_lineage "$_ACME_TX_ID" "$REALITY_DOMAIN" 2>/dev/null || rollback_failed=1
        if [[ -n "${VISION_DOMAIN:-}" ]]; then
            restore_acme_lineage "$_ACME_TX_ID" "$VISION_DOMAIN" 2>/dev/null || rollback_failed=1
        fi
    else
        if [[ "${_ACME_WORKER_ISSUED:-0}" -eq 1 ]] && [[ -n "${WORKER_DOMAIN:-}" ]]; then
            echo "[ROLLBACK] Deleting ACME certificate for $WORKER_DOMAIN..." >&2
            certbot delete --cert-name "$WORKER_DOMAIN" --non-interactive 2>/dev/null || rollback_failed=1
            rm -rf "/etc/letsencrypt/live/$WORKER_DOMAIN" "/etc/letsencrypt/archive/$WORKER_DOMAIN" "/etc/letsencrypt/renewal/$WORKER_DOMAIN.conf" 2>/dev/null || rollback_failed=1
        fi
        if [[ "${_ACME_REALITY_ISSUED:-0}" -eq 1 ]] && [[ -n "${REALITY_DOMAIN:-}" ]]; then
            echo "[ROLLBACK] Deleting ACME certificate for $REALITY_DOMAIN..." >&2
            certbot delete --cert-name "$REALITY_DOMAIN" --non-interactive 2>/dev/null || rollback_failed=1
            rm -rf "/etc/letsencrypt/live/$REALITY_DOMAIN" "/etc/letsencrypt/archive/$REALITY_DOMAIN" "/etc/letsencrypt/renewal/$REALITY_DOMAIN.conf" 2>/dev/null || rollback_failed=1
        fi
    fi

    # 5. Revert UFW firewall changes
    if [[ "${_UFW_RULES_CONFIGURED:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Reverting UFW firewall rules..." >&2
        if [[ "${_UFW_WAS_ACTIVE:-0}" -eq 0 ]]; then
            ufw --force disable 2>/dev/null || rollback_failed=1
        else
            if [[ -n "${PANEL_IP:-}" ]]; then
                ufw delete allow proto tcp from "$PANEL_IP" to any port "${NODE_PORT:-3002}" 2>/dev/null || rollback_failed=1
            fi
            if [[ -n "${PANEL_IPV6:-}" ]]; then
                ufw delete allow proto tcp from "$PANEL_IPV6" to any port "${NODE_PORT:-3002}" 2>/dev/null || rollback_failed=1
            fi
            ufw delete allow 80/tcp 2>/dev/null || rollback_failed=1
            ufw delete allow 443/tcp 2>/dev/null || rollback_failed=1
        fi
    fi

    # 6. Revert Swap
    if [[ "${_SWAP_CREATED_BY_US:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Deactivating and removing swapfile..." >&2
        local swap_is_inactive=0 active_swaps
        if active_swaps=$(swapon --noheadings --raw --output NAME 2>/dev/null); then
            if grep -Fxq /swapfile <<< "$active_swaps"; then
                if swapoff /swapfile 2>/dev/null; then
                    swap_is_inactive=1
                else
                    rollback_failed=1
                fi
            else
                swap_is_inactive=1
            fi
        else
            rollback_failed=1
        fi
        if [[ -f /etc/fstab ]]; then
            local swap_tmp
            if swap_tmp=$(mktemp /etc/fstab.gowave.XXXXXX); then
                if grep -v -E '^[[:space:]]*/swapfile[[:space:]]' /etc/fstab > "$swap_tmp" &&
                    chmod --reference=/etc/fstab "$swap_tmp" &&
                    chown --reference=/etc/fstab "$swap_tmp" &&
                    mv -f "$swap_tmp" /etc/fstab; then
                    :
                else
                    rm -f "$swap_tmp"
                    rollback_failed=1
                fi
            else
                rollback_failed=1
            fi
        fi
        if [[ "$swap_is_inactive" -eq 1 ]]; then
            rm -f /swapfile || rollback_failed=1
        fi
    fi

    # 7. Revert Sysctl
    if [[ "${_SYSCTL_CREATED_BY_US:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Removing sysctl configuration..." >&2
        rm -f /etc/sysctl.d/99-gowave-node.conf || rollback_failed=1
        sysctl --system 2>/dev/null || rollback_failed=1
    fi

    # 7b. Revert the strict DNS-over-TLS drop-in created by this run
    if [[ "${_DOT_CREATED_BY_US:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Removing strict DNS-over-TLS configuration..." >&2
        if [[ -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf ]] &&
            grep -qF 'Managed by GoWave Auto NGINX: VPS Security' /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf; then
            rm -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf || rollback_failed=1
            systemctl restart systemd-resolved 2>/dev/null || rollback_failed=1
        fi
    fi

    # 8. Clean temporary files and unset secrets
    unset _NODE_SECRET_KEY SECRET_KEY VERIFY_NODE_MTLS_B64 SECURITY_HELPER_B64 GOWAVE_ACME_TEST_CA_B64
    rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.py /tmp/gowave-node-install-*.sh /run/gowave-acme-test-ca.pem || rollback_failed=1

    if [[ "$rollback_failed" -ne 0 ]]; then
        echo "[ROLLBACK] ERROR: compensating rollback incomplete; one or more cleanup operations failed." >&2
    else
        echo "[ROLLBACK] Compensating rollback actions completed on worker host." >&2
    fi
    return "$exit_code"
}
RUNNER_FUNCS

        # 3. Main entrypoint executed remotely
        cat <<'REMOTE_EOF'
set -euo pipefail
main() {
    umask 077
    _ROLLBACK_IN_PROGRESS=0
    _SWAP_CREATED_BY_US=0
    _SYSCTL_CREATED_BY_US=0
    _UFW_WAS_ACTIVE=0
    _UFW_RULES_CONFIGURED=0
    _COVER_UNPACKED=0
    _NGINX_BOOTSTRAP_CREATED=0
    _ACME_WORKER_ISSUED=0
    _ACME_REALITY_ISSUED=0
    _NGINX_CONFIGS_CREATED=0
    _STREAM_INCLUDE_ADDED=0
    _NODE_SERVICE_CONFIGURED=0

    if [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" && -n "${GOWAVE_ACME_TEST_CA_B64:-}" ]]; then
        printf '%s' "$GOWAVE_ACME_TEST_CA_B64" | base64 -d > /run/gowave-acme-test-ca.pem
        chmod 0600 /run/gowave-acme-test-ca.pem
        export GOWAVE_ACME_TEST_CA_FILE=/run/gowave-acme-test-ca.pem
        unset GOWAVE_ACME_TEST_CA_B64
    fi

    _COMPENSATED=0
    cleanup_temp_and_secrets() {
        unset _NODE_SECRET_KEY SECRET_KEY VERIFY_NODE_MTLS_B64 SECURITY_HELPER_B64 GOWAVE_ACME_TEST_CA_B64 2>/dev/null || true
        rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.py /tmp/gowave-node-install-*.sh /run/gowave-acme-test-ca.pem 2>/dev/null || true
    }
    handle_signal() {
        local sig="$1"
        echo "Received signal $sig. Halting and invoking compensation..." >&2
        if [[ "${_COMPENSATED:-0}" -eq 0 ]]; then
            _COMPENSATED=1
            compensate_remote_worker 128
        fi
        cleanup_temp_and_secrets
        exit 128
    }
    handle_error() {
        local exit_code="${1:-1}"
        if [[ "${_COMPENSATED:-0}" -eq 0 ]]; then
            _COMPENSATED=1
            compensate_remote_worker "$exit_code"
        fi
        cleanup_temp_and_secrets
        exit "$exit_code"
    }

    trap 'handle_signal HUP' HUP
    trap 'handle_signal INT' INT
    trap 'handle_signal TERM' TERM
    trap 'exit_code=$?; compensate_remote_worker "$exit_code"; exit "$exit_code"' ERR
    trap 'cleanup_temp_and_secrets' EXIT

    # Before the lease and the snapshots, not after: both are python3, and a
    # snapshot that dies for a missing interpreter has no snapshot to roll back
    # to, which is exactly how this Worker ended up half-provisioned.
    bootstrap_early_tools </dev/null
    acquire_mutation_lock
    verify_deploy_hook_preflight "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" "${_ACME_TX_ID:-}" || return 1

    validate_acme_server "${GOWAVE_ACME_SERVER:-}"
    local effective_acme_server="${GOWAVE_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
    check_acme_lineage "$WORKER_DOMAIN" "$effective_acme_server"
    check_acme_lineage "$REALITY_DOMAIN" "$effective_acme_server"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        check_acme_lineage "$VISION_DOMAIN" "$effective_acme_server"
    fi

    _ACME_TX_ID="${ACME_TX_ID:-worker_install_$(date +%s)}"
    if [[ ! "$_ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
        echo "Error: Invalid Worker ACME transaction ID." >&2
        exit 1
    fi
    snapshot_acme_lineage "$_ACME_TX_ID" "$WORKER_DOMAIN"
    snapshot_acme_lineage "$_ACME_TX_ID" "$REALITY_DOMAIN"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        snapshot_acme_lineage "$_ACME_TX_ID" "$VISION_DOMAIN"
    fi

    setup_system_prereqs </dev/null
    configure_host_security </dev/null
    configure_firewall </dev/null
    umask 022
    unpack_cover_reality </dev/null
    configure_edge_nginx </dev/null
    umask 077
    printf '%s' "$VERIFY_NODE_MTLS_B64" | base64 -d > /tmp/gowave-verify-node-mtls.py
    chmod 0700 /tmp/gowave-verify-node-mtls.py
    # Pass secret strictly scoped to upstream installer execution only.
    SECRET_KEY="$_NODE_SECRET_KEY" run_upstream_node_installer </dev/null
    unset SECRET_KEY
    systemctl is-active --quiet gowave-node.service
    printf '%s' "$_NODE_SECRET_KEY" | python3 /tmp/gowave-verify-node-mtls.py --host 127.0.0.1 --port "$NODE_PORT" --mode crypto-only
    nginx -t
    systemctl is-active --quiet nginx

    # Disable ERR compensation trap on verified success
    trap - ERR
    # Keep the ACME before-image until the controller durably commits NODE_ADD.
    # The controller calls remote_finalize only after that commit succeeds.
    unset _NODE_SECRET_KEY VERIFY_NODE_MTLS_B64 SECURITY_HELPER_B64
    echo "GoWave Edge Worker deployment complete (service, NGINX, TLS and mTLS health verified)."
}
main "$@" </dev/null
REMOTE_EOF
    } | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
}

# Standalone remote rollback mechanism callable on failure or deprovisioning
remote_rollback() {
    local host="$1"
    local port="${2:-22}"
    local worker_domain="${3:-}"
    local reality_domain="${4:-}"
    local ssh_user="${5:-root}"

    local node_port="${NODE_PORT:-$RECOMMENDED_NODE_PORT}"
    local panel_ip="${PANEL_IP:-}"
    local panel_ipv6="${PANEL_IPV6:-}"
    local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
    local host_key="$host"
    if [[ "$port" != "22" ]]; then
        host_key="[$host]:$port"
    fi
    if [[ ! -s "$known_hosts" ]] || ! ssh-keygen -F "$host_key" -f "$known_hosts" >/dev/null 2>&1; then
        log_err "SSH host key for $host_key is not pre-pinned in $known_hosts."
        return 1
    fi

    log_info "Initiating compensating remote rollback on ${ssh_user}@${host}:${port}..."

    {
        printf 'export PANEL_IP=%q\n' "$panel_ip"
        printf 'export PANEL_IPV6=%q\n' "$panel_ipv6"
        printf 'export NODE_PORT=%q\n' "$node_port"
        printf 'export WORKER_DOMAIN=%q\n' "$worker_domain"
        printf 'export REALITY_DOMAIN=%q\n' "$reality_domain"
        printf 'export VISION_DOMAIN=%q\n' "${VISION_DOMAIN:-}"
        printf 'export ACME_TX_ID=%q\n' "${ACME_TX_ID:-}"

        cat <<'ROLLBACK_REMOTE_SCRIPT'
set -euo pipefail

if [[ -n "${ACME_TX_ID:-}" && ! "$ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
    echo "Error: Invalid Worker ACME transaction ID." >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/tmp/gowave-managed-mutation-$(id -u).lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/tmp/gowave-mutation-lease-$(id -u).json}"
else
    MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/run/lock/gowave-managed-mutation.lock}"
    MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/run/lock/gowave-mutation-lease.json}"
fi

validate_lock_path() {
    local lock_file="${1:-$MUTATION_LOCK_FILE}"
    local lock_dir
    lock_dir="$(dirname "$lock_file")"
    if [[ ! -d "$lock_dir" ]]; then
        mkdir -p "$lock_dir"
        chmod 0755 "$lock_dir" 2>/dev/null || true
    fi
    if [[ -L "$lock_dir" || -L "$lock_file" ]]; then
        return 1
    fi
    return 0
}

acquire_mutation_lock() {
    validate_lock_path "$MUTATION_LOCK_FILE" || return 1
    if [[ ! -e "$MUTATION_LOCK_FILE" ]]; then
        ( umask 0177; : > "$MUTATION_LOCK_FILE" ) 2>/dev/null || {
            echo "Error: Cannot create mutation lock file ($MUTATION_LOCK_FILE)." >&2
            return 1
        }
    fi
    if [[ -L "$MUTATION_LOCK_FILE" || ! -f "$MUTATION_LOCK_FILE" ]]; then
        echo "Error: Mutation lock path is not a regular file." >&2
        return 1
    fi
    chmod 0600 "$MUTATION_LOCK_FILE" 2>/dev/null || {
        echo "Error: Cannot secure mutation lock file ($MUTATION_LOCK_FILE)." >&2
        return 1
    }
    exec 9>>"$MUTATION_LOCK_FILE" || return 1
    if ! flock -n 9; then
        echo "Error: Another process currently holds the mutation lock ($MUTATION_LOCK_FILE)." >&2
        return 1
    fi
    return 0
}

acquire_mutation_lock || {
    echo "Error: Refusing remote rollback without the mutation lock." >&2
    exit 1
}

rollback_managed_deploy_hook() {
    local transaction_id="$1"
    local hook_file="${2:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    if [[ -z "$transaction_id" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: ACME transaction ID is missing; preserving deploy hook with unknown ownership and reporting incomplete rollback." >&2
            return 1
        fi
        return 0
    fi

    local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
    if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
        if [[ -e "$hook_file" || -L "$hook_file" ]]; then
            echo "Error: Deploy hook exists without an ownership manifest; refusing to claim rollback succeeded." >&2
            return 1
        fi
        return 0
    fi
    if [[ ! -f "$manifest" || -L "$manifest" ]]; then
        echo "Error: Deploy-hook rollback manifest is missing, non-regular, or a symlink." >&2
        return 1
    fi

    local manifest_data
    manifest_data=$(python3 - "$manifest" "$transaction_id" "$hook_file" <<'PY'
import json
import re
import sys

path, expected_tx, expected_hook = sys.argv[1:4]
try:
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("manifest root must be an object")
    if data.get("transaction_id") != expected_tx or data.get("path") != expected_hook:
        raise ValueError("manifest transaction/path mismatch")
    created = data.get("created_by_tx")
    if type(created) is not bool:
        raise ValueError("created_by_tx must be a boolean")
    digest = data.get("sha256", "")
    if not isinstance(digest, str):
        raise ValueError("sha256 must be a string")
    if created and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("created hook digest is invalid")
    print("1" if created else "0")
    print(digest)
except Exception as exc:
    print(f"Invalid deploy-hook rollback manifest: {type(exc).__name__}", file=sys.stderr)
    sys.exit(1)
PY
    ) || {
        echo "Error: Refusing deploy-hook rollback because its ownership manifest is invalid." >&2
        return 1
    }

    local -a manifest_fields=()
    mapfile -t manifest_fields <<< "$manifest_data"
    if [[ "${#manifest_fields[@]}" -ne 2 ]]; then
        echo "Error: Deploy-hook rollback manifest has an invalid field count." >&2
        return 1
    fi
    local created_by_tx="${manifest_fields[0]}"
    local recorded_sha="${manifest_fields[1]}"
    if [[ "$created_by_tx" != "1" ]]; then
        return 0
    fi

    if [[ ! -e "$hook_file" && ! -L "$hook_file" ]]; then
        return 0
    fi
    if [[ -L "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is now a symlink; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi
    if [[ ! -f "$hook_file" ]]; then
        echo "Warning: Deploy hook $hook_file is not a regular file; preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    local current_sha
    current_sha=$(sha256sum "$hook_file" | awk '{print $1}') || {
        echo "Error: Could not verify managed deploy-hook digest." >&2
        return 1
    }
    if [[ "$current_sha" != "$recorded_sha" ]]; then
        echo "Warning: Deploy hook $hook_file was modified after installation (digest mismatch); preserving modified object and reporting incomplete recovery." >&2
        return 1
    fi

    rm -f "$hook_file" || {
        echo "Error: Could not remove transaction-owned deploy hook $hook_file." >&2
        return 1
    }
    sync "$(dirname "$hook_file")" || {
        echo "Error: Could not sync deploy-hook directory after rollback." >&2
        return 1
    }
    return 0
}

restore_acme_lineage() {
    local transaction_id="$1"
    local domain="$2"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"
    local letsencrypt_root="${4:-/etc/letsencrypt}"

    local snap_dir="${recovery_root}/${transaction_id}/acme/${domain}"
    local meta_file="${snap_dir}/lineage-manifest.json"
    if [[ ! -f "$meta_file" || -L "$meta_file" ]]; then
        echo "Error: ACME lineage manifest missing or unsafe for $domain" >&2
        return 1
    fi

    local manifest_data
    manifest_data=$(python3 - "$meta_file" "$domain" <<'PY'
import json
import sys

path, expected_domain = sys.argv[1:3]
try:
    with open(path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or data.get("domain") != expected_domain:
        raise ValueError("manifest root/domain mismatch")
    existed = data.get("existed_before")
    if type(existed) is not bool:
        raise ValueError("existed_before must be a boolean")
    serial = data.get("serial", "")
    fingerprint = data.get("fingerprint", "")
    if not isinstance(serial, str) or not isinstance(fingerprint, str):
        raise ValueError("certificate metadata must be strings")
    if existed and (not serial or not fingerprint):
        raise ValueError("pre-existing lineage snapshot lacks certificate identity")
    print("1" if existed else "0")
    print(serial)
    print(fingerprint)
except Exception as exc:
    print(f"Invalid ACME lineage manifest: {type(exc).__name__}", file=sys.stderr)
    sys.exit(1)
PY
    ) || {
        echo "Error: Refusing ACME rollback for $domain because its snapshot manifest is invalid." >&2
        return 1
    }

    local existed serial fingerprint
    local -a manifest_fields=()
    mapfile -t manifest_fields <<< "$manifest_data"
    if [[ "${#manifest_fields[@]}" -ne 3 ]]; then
        echo "Error: ACME lineage manifest has an invalid field count for $domain." >&2
        return 1
    fi
    existed="${manifest_fields[0]}"
    serial="${manifest_fields[1]}"
    fingerprint="${manifest_fields[2]}"

    local renewal_conf="${letsencrypt_root}/renewal/${domain}.conf"
    local live_dir="${letsencrypt_root}/live/${domain}"
    local archive_dir="${letsencrypt_root}/archive/${domain}"

    if [[ "$existed" == "0" ]]; then
        rm -f "$renewal_conf" || return 1
        rm -rf "$live_dir" "$archive_dir" || return 1
        return 0
    fi
    if [[ "$existed" != "1" ]]; then
        echo "Error: Invalid existed_before value for $domain." >&2
        return 1
    fi

    mkdir -p "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" || return 1
    chmod 0755 "${letsencrypt_root}/renewal" "$live_dir" "$archive_dir" || return 1

    if [[ -f "$snap_dir/renewal.conf" ]]; then
        cp -p "$snap_dir/renewal.conf" "$renewal_conf" || return 1
    fi
    if [[ -d "$snap_dir/archive" ]]; then
        local arc
        for arc in "$snap_dir/archive"/*; do
            [[ -f "$arc" ]] || continue
            cp -p "$arc" "$archive_dir/$(basename "$arc")" || return 1
        done
    fi
    if [[ -d "$snap_dir/live" ]]; then
        local f target
        for f in cert.pem chain.pem fullchain.pem privkey.pem; do
            if [[ -f "$snap_dir/live/${f}.target" ]]; then
                target="$(cat "$snap_dir/live/${f}.target")" || return 1
                [[ -n "$target" && "$target" != /* ]] || {
                    echo "Error: Unsafe ACME snapshot symlink target for $domain/$f." >&2
                    return 1
                }
                local resolved_target
                resolved_target="$(realpath -m -- "$live_dir/$target")" || return 1
                case "$resolved_target" in
                    "$archive_dir"/*) ;;
                    *)
                        echo "Error: ACME snapshot symlink target escapes the archive for $domain/$f." >&2
                        return 1
                        ;;
                esac
                ln -sf "$target" "$live_dir/$f" || return 1
            elif [[ -f "$snap_dir/live/$f" ]]; then
                cp -p "$snap_dir/live/$f" "$live_dir/$f" || return 1
            fi
        done
    fi

    local fullchain="$live_dir/fullchain.pem"
    local privkey="$live_dir/privkey.pem"
    if [[ ! -s "$fullchain" || ! -s "$privkey" ]]; then
        echo "Error: Restored certificate or private key missing for $domain" >&2
        return 1
    fi
    openssl x509 -in "$fullchain" -noout >/dev/null 2>&1 || {
        echo "Error: Restored certificate for $domain is invalid." >&2
        return 1
    }
    local pub_from_cert pub_from_key cur_serial cur_fingerprint
    pub_from_cert="$(openssl x509 -in "$fullchain" -noout -pubkey 2>/dev/null)" || return 1
    pub_from_key="$(openssl pkey -in "$privkey" -pubout 2>/dev/null)" || return 1
    if [[ -z "$pub_from_cert" || "$pub_from_cert" != "$pub_from_key" ]]; then
        echo "Error: Restored certificate and private key do not match for $domain." >&2
        return 1
    fi
    cur_serial="$(openssl x509 -in "$fullchain" -noout -serial 2>/dev/null)" || return 1
    cur_fingerprint="$(openssl x509 -in "$fullchain" -noout -fingerprint -sha256 2>/dev/null)" || return 1
    if [[ "$cur_serial" != "$serial" || "$cur_fingerprint" != "$fingerprint" ]]; then
        echo "Error: Restored certificate identity does not match the ACME snapshot for $domain." >&2
        return 1
    fi
    return 0
}

# The compensation is python3 too, so a Worker left without an interpreter
# cannot even be cleaned up. This is best effort: a host whose package manager
# is broken still deserves the rest of the teardown attempt.
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ROLLBACK] Bootstrapping python3 so the compensation can run..." >&2
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 openssl || true
fi

acquire_mutation_lock
echo "Executing worker compensation teardown..." >&2

rollback_failed=0

# 1. Stop and disable systemd services that are actually installed or active.
for unit in gowave-node.service xray.service; do
    if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "^$unit" ||
        systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl stop "$unit" 2>/dev/null || rollback_failed=1
        systemctl disable "$unit" 2>/dev/null || rollback_failed=1
    fi
done
rm -rf /etc/systemd/system/gowave-node.service.d || rollback_failed=1
rm -f /etc/systemd/system/gowave-node.service /etc/systemd/system/remnanode.service || rollback_failed=1
systemctl daemon-reload 2>/dev/null || rollback_failed=1
rm -rf /opt/gowave-node /run/gowave-node /opt/remnanode || rollback_failed=1
rm -f /usr/local/bin/gowave-node /usr/local/bin/xray || rollback_failed=1

# 2. Remove NGINX worker configs
rm -f /etc/nginx/conf.d/00-worker-acme-challenge.conf /etc/nginx/conf.d/00-bootstrap-worker-acme.conf /etc/nginx/conf.d/gowave-worker-https.conf /etc/nginx/conf.d/gowave-worker-decoy.conf /etc/nginx/conf.d/gowave-worker-vision-fallback.conf /etc/nginx/stream-enabled/gowave-worker-stream.conf || rollback_failed=1
rollback_managed_deploy_hook "${ACME_TX_ID:-}" "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" 2>/dev/null || rollback_failed=1
rm -rf /var/www/gowave-acme /var/www/gowave-auto-nginx/cover-reality || rollback_failed=1
if [[ -d /var/www/gowave-auto-nginx ]]; then
    rmdir /var/www/gowave-auto-nginx 2>/dev/null || true
fi

# Revert stream include in nginx.conf if stream-enabled is empty
if [[ -d /etc/nginx/stream-enabled ]] && ! ls -1 /etc/nginx/stream-enabled/*.conf >/dev/null 2>&1; then
    sed -i '\#stream { include /etc/nginx/stream-enabled/\*\.conf; }#d' /etc/nginx/nginx.conf 2>/dev/null || rollback_failed=1
fi
if command -v nginx >/dev/null 2>&1; then
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || rollback_failed=1
    else
        rollback_failed=1
    fi
fi

# 3. Clean ACME certificates
if [[ -n "${ACME_TX_ID:-}" ]]; then
    echo "[ROLLBACK] Restoring ACME lineages via snapshot for transaction $ACME_TX_ID..." >&2
    restore_acme_lineage "$ACME_TX_ID" "$WORKER_DOMAIN" 2>/dev/null || rollback_failed=1
    restore_acme_lineage "$ACME_TX_ID" "$REALITY_DOMAIN" 2>/dev/null || rollback_failed=1
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        restore_acme_lineage "$ACME_TX_ID" "$VISION_DOMAIN" 2>/dev/null || rollback_failed=1
    fi
else
    # Without the original transaction ID there is no trustworthy snapshot
    # proving which certificate lineages predate this deployment. Preserve
    # all existing certificates rather than deleting operator-owned state.
    for domain in "${WORKER_DOMAIN:-}" "${REALITY_DOMAIN:-}" "${VISION_DOMAIN:-}"; do
        [[ -n "$domain" ]] || continue
        if [[ -e "/etc/letsencrypt/live/$domain" ||
              -e "/etc/letsencrypt/archive/$domain" ||
              -e "/etc/letsencrypt/renewal/$domain.conf" ]]; then
            echo "Error: ACME_TX_ID missing; preserving unknown certificate lineage for $domain." >&2
            rollback_failed=1
        fi
    done
fi
# 4. Remove UFW rules added for Control Plane. Missing rules are already clean;
# only attempt deletion when the active ruleset confirms the exact rule exists.
if command -v ufw >/dev/null 2>&1; then
    ufw_rules=$(ufw status numbered 2>/dev/null) || {
        rollback_failed=1
        ufw_rules=""
    }
    if [[ -n "${PANEL_IP:-}" ]] &&
        awk -v port="${NODE_PORT:-3002}/tcp" -v ip="$PANEL_IP" '$3 == port && index($0, ip) > 0 { found=1 } END { exit !found }' <<< "$ufw_rules"; then
        ufw delete allow proto tcp from "$PANEL_IP" to any port "${NODE_PORT:-3002}" 2>/dev/null || rollback_failed=1
    fi
    if [[ -n "${PANEL_IPV6:-}" ]] &&
        awk -v port="${NODE_PORT:-3002}/tcp" -v ip="$PANEL_IPV6" '$3 == port && index($0, ip) > 0 { found=1 } END { exit !found }' <<< "$ufw_rules"; then
        ufw delete allow proto tcp from "$PANEL_IPV6" to any port "${NODE_PORT:-3002}" 2>/dev/null || rollback_failed=1
    fi
    if awk '$3 == "80/tcp" { found=1 } END { exit !found }' <<< "$ufw_rules"; then
        ufw delete allow 80/tcp 2>/dev/null || rollback_failed=1
    fi
    if awk '$3 == "443/tcp" { found=1 } END { exit !found }' <<< "$ufw_rules"; then
        ufw delete allow 443/tcp 2>/dev/null || rollback_failed=1
    fi
fi
# 5. Clean sysctl, project-owned DNS drop-in and scratch
rm -f /etc/sysctl.d/99-gowave-node.conf || rollback_failed=1
if [[ -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf ]] &&
    grep -qF 'Managed by GoWave Auto NGINX: VPS Security' /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf; then
    rm -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf || rollback_failed=1
    systemctl restart systemd-resolved 2>/dev/null || rollback_failed=1
fi
rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.py /tmp/gowave-node-install-*.sh || rollback_failed=1
sysctl --system 2>/dev/null || rollback_failed=1

# Delete the ACME snapshot only after every rollback action has succeeded.
# Retain it on any failure so an operator can retry or inspect recovery evidence.
if [[ -n "${ACME_TX_ID:-}" && "$rollback_failed" -eq 0 ]]; then
    if [[ ! "$ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]] ||
        [[ -L /var/lib/gowave-auto-nginx || -L /var/lib/gowave-auto-nginx/recovery ||
           -L "/var/lib/gowave-auto-nginx/recovery/$ACME_TX_ID" ]]; then
        rollback_failed=1
    else
        rm -rf -- "/var/lib/gowave-auto-nginx/recovery/$ACME_TX_ID" || rollback_failed=1
    fi
fi

if [[ "$rollback_failed" -ne 0 ]]; then
    echo "Error: Remote worker compensation teardown incomplete; one or more cleanup or restoration operations failed." >&2
    exit 1
fi
echo "Remote worker compensation teardown finished." >&2
ROLLBACK_REMOTE_SCRIPT
    } | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
}

remote_finalize() {
    local host="${1}"
    local port="${2:-22}"
    local ssh_user="${3:-root}"
    local acme_tx_id="${ACME_TX_ID:-}"
    local known_hosts="${SSH_KNOWN_HOSTS:-/root/.ssh/known_hosts}"
    if [[ ! "$acme_tx_id" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
        log_err "A valid Worker ACME transaction ID is required for finalization."
        return 1
    fi
    local host_key="$host"
    if [[ "$port" != "22" ]]; then
        host_key="[$host]:$port"
    fi
    if [[ ! -s "$known_hosts" ]] || ! ssh-keygen -F "$host_key" -f "$known_hosts" >/dev/null 2>&1; then
        log_err "SSH host key for $host_key is not pre-pinned in $known_hosts."
        return 1
    fi

    {
        printf 'export ACME_TX_ID=%q\n' "$acme_tx_id"
        cat <<'FINALIZE_REMOTE_SCRIPT'
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: Worker snapshot finalization requires root." >&2
    exit 1
fi
if [[ ! "$ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
    echo "Error: Invalid Worker ACME transaction ID." >&2
    exit 1
fi
recovery_root="/var/lib/gowave-auto-nginx/recovery"
transaction_dir="$recovery_root/$ACME_TX_ID"
for path in /var/lib/gowave-auto-nginx "$recovery_root" "$transaction_dir"; do
    if [[ -L "$path" ]]; then
        echo "Error: Refusing to finalize a symlinked recovery path." >&2
        exit 1
    fi
done
if [[ ! -e "$transaction_dir" ]]; then
    echo "Worker ACME snapshot is already absent." >&2
    exit 0
fi
if [[ ! -d "$transaction_dir" ]]; then
    echo "Error: Worker ACME snapshot path is not a directory." >&2
    exit 1
fi
lock_dir="/run/lock"
lock_file="$lock_dir/gowave-managed-mutation.lock"
if [[ -L "$lock_dir" || -L "$lock_file" ||
      ( -e "$lock_file" && ! -f "$lock_file" ) ]]; then
    echo "Error: Mutation lock path is unsafe." >&2
    exit 1
fi
mkdir -p "$lock_dir"
( umask 077; : >> "$lock_file" )
chmod 0600 "$lock_file"
exec 9>>"$lock_file"
if ! flock -n 9; then
    echo "Error: Another process currently holds the mutation lock." >&2
    exit 1
fi
rm -rf -- "$transaction_dir"
echo "Worker ACME recovery snapshot finalized." >&2
FINALIZE_REMOTE_SCRIPT
    } | ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        pack-cover)
            pack_cover_reality
            ;;
        remote_payload)
            shift
            remote_payload "$@"
            ;;
        remote_rollback|rollback)
            shift
            remote_rollback "$@"
            ;;
        remote_finalize)
            shift
            remote_finalize "$@"
            ;;
        *)
            echo "Usage: gowave-node-auto.sh <pack-cover|remote_payload|remote_rollback|remote_finalize> [args]"
            exit 1
            ;;
    esac
fi

