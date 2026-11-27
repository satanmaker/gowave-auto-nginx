#!/usr/bin/env bash
# gowave-node-auto.sh - Distributed Edge Worker Deployment and Hardening Orchestrator
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOMMENDED_NODE_PORT=3002

log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }

# Refuse to delete a tree that is not strictly below a directory this script
# owns: ${var:?} rejects only unset and empty values, while "/", "..", or a
# domain that resolves elsewhere all pass it.
require_tree_under() {
    local path="$1" parent="$2"
    local resolved_path resolved_parent
    [[ -n "$path" && -n "$parent" ]] || return 1
    resolved_path=$(realpath -m -- "$path") || return 1
    resolved_parent=$(realpath -m -- "$parent") || return 1
    [[ "$resolved_parent" != "/" ]] || return 1
    [[ "$resolved_path" == "$resolved_parent"/* ]] || return 1
    [[ "$resolved_path" != "$resolved_parent" ]]
}

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

# select_acme_lineage NAME TARGET_SERVER [LETSENCRYPT_ROOT]
#
# Print the live directory of a lineage that already covers NAME, or nothing when
# the name has to be issued one of its own. A Worker in a shared zone is often
# left with a suffixed lineage (`cover2.example.net-0001`); asking certbot for the
# plain name would issue a second lineage beside it, and the vhost would then
# serve whichever one its path happened to name. Adoption follows the Master's
# rules so both roles read the same tree the same way: the renewal config must
# name TARGET_SERVER, the certificate must not be expired, and it must cover
# NAME; the exact-name lineage is tried first, the rest in directory order.
select_acme_lineage() {
    local name="$1"
    local target_server="${2:-https://acme-v02.api.letsencrypt.org/directory}"
    local letsencrypt_root="${3:-/etc/letsencrypt}"
    local live_root="${letsencrypt_root}/live"
    local renewal_root="${letsencrypt_root}/renewal"

    # A host that has never had a lineage is not an error.
    [[ -d "$live_root" ]] || return 0

    local -a order=()
    local entry candidate
    if [[ -d "${live_root}/${name}" && ! -L "${live_root}/${name}" ]]; then
        order+=("$name")
    fi
    while IFS= read -r entry; do
        candidate=$(basename -- "$entry")
        [[ "$candidate" == "$name" ]] && continue
        order+=("$candidate")
    done < <(find "$live_root" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | LC_ALL=C sort)

    (( ${#order[@]} )) || return 0

    for candidate in "${order[@]}"; do
        local live_dir="${live_root}/${candidate}"
        local renewal_conf="${renewal_root}/${candidate}.conf"
        [[ -s "${live_dir}/fullchain.pem" && -f "$renewal_conf" ]] || continue

        local issued_by="" key val
        while IFS='=' read -r key val || [[ -n "$key" ]]; do
            key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [[ "$key" == "server" ]]; then
                issued_by=$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
                break
            fi
        done < "$renewal_conf"
        if [[ "$issued_by" != "$target_server" ]]; then
            echo "Not adopting the ACME lineage $candidate for $name: it was not issued by $target_server." >&2
            continue
        fi
        if ! openssl x509 -checkend 0 -noout -in "${live_dir}/fullchain.pem" >/dev/null 2>&1; then
            echo "Not adopting the ACME lineage $candidate for $name: its certificate has expired." >&2
            continue
        fi
        local host_check
        if ! host_check=$(openssl x509 -checkhost "$name" -noout -in "${live_dir}/fullchain.pem" 2>&1); then
            continue
        fi
        [[ "$host_check" == "Hostname $name does match certificate" ]] || continue

        printf '%s\n' "$live_dir"
        echo "Adopting the ACME lineage $candidate for $name: it covers the name and matches the ACME directory." >&2
        return 0
    done
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
        if ! require_tree_under "$live_dir" "$letsencrypt_root" ||
            ! require_tree_under "$archive_dir" "$letsencrypt_root"; then
            echo "Error: Refusing to remove ACME lineage for $domain outside $letsencrypt_root." >&2
            return 1
        fi
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
        if ! require_tree_under "$snap_dir" "$recovery_root"; then
            echo "Error: Refusing to remove ACME snapshot outside $recovery_root (transaction $transaction_id)." >&2
            return 1
        fi
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

# The deploy hook outlives both the transaction that installed it and its
# recovery snapshot, which is deleted once the install commits. Ownership is
# therefore recorded outside the snapshot as well, so the next transaction can
# still tell its own hook from one an operator or another product left behind.
deploy_hook_ownership_record() {
    printf '%s\n' "${1:-/var/lib/gowave-auto-nginx/recovery}/deploy-hook-ownership.json"
}

deploy_hook_record_matches() {
    local record="$1"
    local hook_file="$2"
    local digest="$3"
    if [[ ! -f "$record" || -L "$record" ]]; then
        return 1
    fi
    python3 - "$record" "$hook_file" "$digest" <<'PY'
import json
import sys

record_path, hook_path, digest = sys.argv[1:4]
try:
    with open(record_path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if (
    isinstance(data, dict)
    and data.get("created_by_tx") is True
    and data.get("path") == hook_path
    and data.get("sha256") == digest
) else 1)
PY
}

deploy_hook_owned_by_prior_transaction() {
    local hook_file="$1"
    local recovery_root="$2"
    if [[ ! -f "$hook_file" || -L "$hook_file" ]]; then
        return 1
    fi
    if [[ ! -d "$recovery_root" || -L "$recovery_root" ]]; then
        return 1
    fi
    local digest
    digest=$(sha256sum -- "$hook_file" 2>/dev/null | awk '{print $1}' || true)
    if [[ -z "$digest" ]]; then
        return 1
    fi
    if deploy_hook_record_matches "$(deploy_hook_ownership_record "$recovery_root")" "$hook_file" "$digest"; then
        return 0
    fi
    local manifest
    for manifest in "${recovery_root}"/*/deploy-hook-manifest.json; do
        if deploy_hook_record_matches "$manifest" "$hook_file" "$digest"; then
            return 0
        fi
    done
    return 1
}

verify_deploy_hook_preflight() {
    local hook_file="${1:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local transaction_id="${2:-}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    if [[ -e "$hook_file" ]] || [[ -L "$hook_file" ]]; then
        if [[ -n "$transaction_id" ]]; then
            local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
            # The manifest records that a transaction created a hook at this path;
            # it does not say that what now sits there is that hook. A symlink, a
            # directory or a FIFO is never adopted on the strength of the manifest
            # alone, and neither is a file whose bytes or path differ from the
            # recorded ones.
            if [[ -f "$manifest" && ! -L "$manifest" && -f "$hook_file" && ! -L "$hook_file" ]]; then
                local owned
                owned=$(python3 -c 'import hashlib,json,sys; m,h=sys.argv[1:3]; d=json.load(open(m,"r",encoding="utf-8")); s=hashlib.sha256(open(h,"rb").read()).hexdigest(); print("1" if d.get("created_by_tx") is True and d.get("path")==h and d.get("sha256")==s else "0")' "$manifest" "$hook_file" 2>/dev/null || echo "0")
                if [[ "$owned" == "1" ]]; then
                    return 0
                fi
            fi
        fi
        # A repeated install finds the hook an earlier transaction installed. It is
        # only recognised as ours when that transaction recorded this exact path and
        # the file still hashes to what was recorded, so a hook written or edited by
        # someone else stays a refusal rather than a file this product overwrites.
        if deploy_hook_owned_by_prior_transaction "$hook_file" "$recovery_root"; then
            return 0
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

worker_mutation_targets() {
    # The paths this install creates and its rollback removes. A path that is
    # already here is only touched when the ownership record names it.
    cat <<'WORKER_TARGETS'
/etc/systemd/system/gowave-node.service
/etc/systemd/system/gowave-node.service.d
/etc/systemd/system/remnanode.service
/opt/gowave-node
/run/gowave-node
/opt/remnanode
/usr/local/bin/gowave-node
/usr/local/bin/xray
/etc/nginx/conf.d/00-worker-acme-challenge.conf
/etc/nginx/conf.d/00-bootstrap-worker-acme.conf
/etc/nginx/conf.d/gowave-worker-https.conf
/etc/nginx/conf.d/gowave-worker-decoy.conf
/etc/nginx/conf.d/gowave-worker-vision-fallback.conf
/etc/nginx/stream-enabled/gowave-worker-stream.conf
/var/www/gowave-acme
/var/www/gowave-auto-nginx/cover-reality
WORKER_TARGETS
}

worker_ownership_record() {
    local base="${1:-/var/lib/gowave-auto-nginx}"
    # "/" is the host itself, where the state root is the product's own.
    [[ "$base" == "/" ]] && base="/var/lib/gowave-auto-nginx"
    printf '%s\n' "$base/worker-install-ownership.json"
}

verify_worker_mutation_targets_preflight() {
    # The root and the record are arguments so a test can drive this guard over
    # a directory it owns; the install passes neither and gets the host.
    local root="${1:-/}"
    local record="${2:-$(worker_ownership_record "$root")}"
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$record" "$targets" <<'WORKER_PREFLIGHT_PY'
import hashlib
import json
import os
import sys

root, record, listed = sys.argv[1:4]
targets = [line.strip() for line in listed.splitlines() if line.strip()]


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def refuse(path, what):
    print(
        "Error: Pre-existing unowned Worker " + what + " " + path + ". Refusing to "
        "overwrite or remove an unmanaged host resource.",
        file=sys.stderr,
    )
    raise SystemExit(1)


recorded = {}
if os.path.lexists(record):
    if os.path.islink(record) or not os.path.isfile(record):
        print("Error: Worker ownership record " + record + " is not a regular file.", file=sys.stderr)
        raise SystemExit(1)
    try:
        with open(record, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        print("Error: Worker ownership record " + record + " is not readable JSON.", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        print(
            "Error: Worker ownership record " + record + " does not claim this product created anything.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    recorded = data.get("targets")
    if not isinstance(recorded, dict):
        print("Error: Worker ownership record " + record + " names no targets.", file=sys.stderr)
        raise SystemExit(1)

for target in targets:
    path = under(target)
    if not os.path.lexists(path):
        continue
    entry = recorded.get(target)
    if os.path.islink(path):
        # The upstream installer links the Worker binary into /usr/local/bin,
        # so a link this install wrote is adopted by the target it recorded.
        # Any other link stays foreign even when its target holds our bytes.
        if isinstance(entry, dict) and entry.get("kind") == "symlink" and entry.get("target") == os.readlink(path):
            continue
        refuse(path, "path")
    if os.path.isdir(path):
        if isinstance(entry, dict) and entry.get("kind") == "directory":
            continue
        refuse(path, "directory")
    if not os.path.isfile(path):
        refuse(path, "path")
    try:
        current = digest(path)
    except OSError:
        current = ""
    if current and isinstance(entry, dict) and entry.get("kind") == "file" and entry.get("sha256") == current:
        continue
    # The operator confirmed migration: a regular file this product did not
    # record is adopted (rewritten) instead of refused. Symlinks and directories
    # are still refused above, so confirmation never writes through a link.
    if os.environ.get("GOWAVE_ADOPT_UNOWNED") == "1":
        continue
    refuse(path, "file")
WORKER_PREFLIGHT_PY
}

record_worker_mutation_targets() {
    local root="${1:-/}"
    local record="${2:-$(worker_ownership_record "$root")}"
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$record" "$targets" <<'WORKER_RECORD_PY'
import hashlib
import json
import os
import sys
import tempfile

root, record, listed = sys.argv[1:4]
targets = [line.strip() for line in listed.splitlines() if line.strip()]


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


data = {"created_by_tx": True, "targets": {}}
for target in targets:
    path = under(target)
    if not os.path.lexists(path):
        continue
    if os.path.islink(path):
        data["targets"][target] = {"kind": "symlink", "target": os.readlink(path)}
    elif os.path.isdir(path):
        data["targets"][target] = {"kind": "directory"}
    elif os.path.isfile(path):
        data["targets"][target] = {"kind": "file", "sha256": digest(path)}

directory = os.path.dirname(record) or "."
os.makedirs(directory, mode=0o700, exist_ok=True)
handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-ownership.", suffix=".tmp")
try:
    os.fchmod(handle, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, record)
except BaseException:
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
directory_handle = os.open(directory, os.O_RDONLY)
try:
    os.fsync(directory_handle)
finally:
    os.close(directory_handle)
WORKER_RECORD_PY
}

firewall_before_image() {
    # Per transaction, beside the ACME snapshot: the recovery root is removed
    # by remote_finalize after a verified install, so a successful run leaves
    # no image behind and a failed one leaves exactly the one it needs.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${ACME_TX_ID:-}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$root/firewall-before-image"
        return 0
    fi
    printf '%s\n' "$root/recovery/$transaction/firewall-before-image"
}

firewall_image() {
    # One heredoc, two actions: what the firewall read before this install
    # changed it, and the only way back to that state. The rollback script
    # carries the same text, and a test refuses the tree if the copies drift.
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(firewall_before_image)}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: firewall_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    python3 - "$root" "$image" "$action" <<'FIREWALL_IMAGE_PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

root, image, action = sys.argv[1:4]

CONFIG_FILES = (
    "/etc/default/ufw",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/ufw/before.rules",
    "/etc/ufw/before6.rules",
    "/etc/ufw/after.rules",
    "/etc/ufw/after6.rules",
)
MANIFEST = os.path.join(image, "manifest.json")


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def run(argv, stdin_text=None):
    result = subprocess.run(argv, capture_output=True, text=True, input=stdin_text)
    return result.returncode, result.stdout, result.stderr


def digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def digest_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def normalized(text):
    """The ruleset without the bookkeeping `iptables-save` adds on its own.

    Every dump is stamped with the moment it ran and carries the live
    counters of each chain, and `iptables-restore` zeroes those counters.
    Neither is a rule, so a read-back compares what is left.
    """
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(":") and line.endswith("]"):
            line = line[: line.rindex("[")] + "[0:0]"
        lines.append(line)
    return "\n".join(lines)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".firewall-image.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def capture():
    if os.path.lexists(image):
        fail("Firewall before-image " + image + " already exists; refusing to overwrite the state it holds.")
    status_code, status_text, status_error = run(["ufw", "status", "verbose"])
    if status_code != 0:
        fail(
            "ufw status verbose exited " + str(status_code) + "; refusing to change a firewall this install cannot "
            "restore: " + status_error.strip()[-300:]
        )
    first = status_text.splitlines()[0].strip() if status_text.strip() else ""
    if first not in ("Status: active", "Status: inactive"):
        fail("ufw status verbose printed no status line; refusing to change a firewall this install cannot restore.")
    defaults = {}
    for line in status_text.splitlines():
        if not line.startswith("Default:"):
            continue
        for part in line[len("Default:"):].split(","):
            words = part.split()
            if len(words) >= 2:
                defaults[words[1].strip("()")] = words[0]
    # `ufw status verbose` prints no Default line until the firewall has been
    # enabled once: an inactive firewall holds no policy, so there is none to
    # restore and the image records that instead of refusing the install.
    if first == "Status: active" and set(defaults) != {"incoming", "outgoing", "routed"}:
        fail(
            "ufw status verbose printed no complete default policy line; refusing to change a firewall this "
            "install cannot restore."
        )
    dumps = {}
    for name, argv in (("iptables", ["iptables-save"]), ("ip6tables", ["ip6tables-save"])):
        code, text, error = run(argv)
        if code != 0:
            if name == "ip6tables" and not os.path.exists(under("/proc/net/if_inet6")):
                dumps[name] = None
                continue
            fail(
                argv[0] + " exited " + str(code) + "; refusing to change a firewall this install cannot restore: "
                + error.strip()[-300:]
            )
        dumps[name] = text
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {
        "created_by_tx": True,
        "enabled": first == "Status: active",
        "status_verbose": status_text,
        "defaults": defaults,
        "files": {},
        "iptables": None,
        "ip6tables": None,
    }
    try:
        for path in CONFIG_FILES:
            real = under(path)
            if not os.path.lexists(real):
                continue
            if os.path.islink(real) or not os.path.isfile(real):
                fail(
                    "UFW configuration " + real + " is not a regular file; refusing to change a firewall this "
                    "install cannot restore."
                )
            with open(real, "rb") as stream:
                payload = stream.read()
            copy = "file-" + digest_bytes(path.encode("utf-8"))[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(real)
            data["files"][path] = {
                "copy": copy,
                "sha256": digest_bytes(payload),
                "mode": state.st_mode & 0o7777,
                "uid": state.st_uid,
                "gid": state.st_gid,
            }
        for name, text in dumps.items():
            if text is None:
                continue
            copy = name + "-save.txt"
            write_atomic(os.path.join(image, copy), text.encode("utf-8"), 0o600)
            data[name] = {"copy": copy, "sha256": digest_bytes(text.encode("utf-8"))}
        write_atomic(MANIFEST, (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8"), 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def restore():
    if not os.path.isfile(MANIFEST):
        fail("No firewall before-image at " + image + "; refusing to guess which rules this install added.")
    if os.path.islink(MANIFEST):
        fail("Firewall before-image " + MANIFEST + " is a symlink; refusing to restore from it.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail("Firewall before-image " + MANIFEST + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Firewall before-image " + MANIFEST + " does not claim this product created it.")
    for key in ("enabled", "status_verbose", "defaults", "files", "iptables"):
        if key not in data:
            fail("Firewall before-image " + MANIFEST + " is incomplete: no " + key + ".")
    if not isinstance(data["files"], dict) or not isinstance(data["iptables"], dict):
        fail("Firewall before-image " + MANIFEST + " names no restorable files.")
    for path, meta in data["files"].items():
        copy = os.path.join(image, str(meta.get("copy") or ""))
        if not os.path.isfile(copy) or os.path.islink(copy):
            fail("Firewall before-image copy for " + path + " is missing.")
        if digest_file(copy) != meta.get("sha256"):
            fail("Firewall before-image copy for " + path + " changed after it was written.")
        with open(copy, "rb") as stream:
            payload = stream.read()
        target = under(path)
        write_atomic(target, payload, int(meta.get("mode") or 0o644))
        try:
            os.chown(target, int(meta.get("uid") or 0), int(meta.get("gid") or 0))
        except OSError:
            pass
    # The enabled state first: `ufw --force disable` flushes the chains, so a
    # dump applied before it would be the rules this install added, not these.
    state = "enable" if data["enabled"] else "disable"
    code, _, error = run(["ufw", "--force", state])
    if code != 0:
        fail("ufw --force " + state + " exited " + str(code) + ": " + error.strip()[-300:])
    restored = {}
    for name, argv in (("iptables", ["iptables-restore"]), ("ip6tables", ["ip6tables-restore"])):
        entry = data.get(name)
        if not isinstance(entry, dict):
            continue
        copy = os.path.join(image, str(entry.get("copy") or ""))
        if not os.path.isfile(copy):
            fail("Firewall before-image copy for " + name + " is missing.")
        with open(copy, "r", encoding="utf-8") as stream:
            text = stream.read()
        code, _, error = run(argv, stdin_text=text)
        if code != 0:
            fail(argv[0] + " exited " + str(code) + ": " + error.strip()[-300:])
        restored[name] = text
    code, status_text, _ = run(["ufw", "status", "verbose"])
    if code != 0 or status_text != data["status_verbose"]:
        fail("The restored firewall does not read back as the before-image.")
    code, saved, _ = run(["iptables-save"])
    if code != 0 or normalized(saved) != normalized(restored.get("iptables", "")):
        fail("The restored IPv4 ruleset does not match the before-image.")
    # A dual-stack host filters on two tables, and a restored v4 ruleset proves
    # nothing about the v6 one the failed install opened.
    if "ip6tables" in restored:
        code, saved, _ = run(["ip6tables-save"])
        if code != 0 or normalized(saved) != normalized(restored["ip6tables"]):
            fail("The restored IPv6 ruleset does not match the before-image.")


if action == "capture":
    capture()
else:
    restore()
FIREWALL_IMAGE_PY
}

record_firewall_before_image() {
    firewall_image capture "${1:-/}" "${2:-$(firewall_before_image)}"
}

restore_firewall_before_image() {
    firewall_image restore "${1:-/}" "${2:-$(firewall_before_image)}"
}

worker_targets_before_image() {
    # Per transaction, beside the ACME snapshot and the firewall image: what
    # every inventoried path held before this transaction touched it. The
    # recovery root is removed by remote_finalize after a verified install, so
    # a successful run leaves no image behind and a failed one keeps exactly
    # the one its rollback needs.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-${ACME_TX_ID:-}}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$root/worker-targets-before-image"
        return 0
    fi
    printf '%s\n' "$root/recovery/$transaction/worker-targets-before-image"
}

worker_targets_image() {
    # The state of every inventoried path before this transaction wrote it, and
    # the way back to that state. A created path is removed only while it is
    # still what this install wrote — the ownership record is the proof — and a
    # pre-existing path is put back with its content and metadata. Anything
    # changed after the write, or that no record can prove, is preserved with
    # the cleanup reported incomplete. The payload carries this text twice and
    # the rollback script once; a test refuses the tree if the copies drift.
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(worker_targets_before_image)}"
    local record="${4:-$(worker_ownership_record "$root")}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: worker_targets_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$image" "$action" "$record" "$targets" <<'WORKER_TARGETS_PY'
import hashlib
import json
import os
import shutil
import sys
import tempfile

root, image, action, record, listed = sys.argv[1:6]
targets = [line.strip() for line in listed.splitlines() if line.strip()]
MANIFEST = os.path.join(image, "manifest.json")
preserved = []


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def keep(path, why):
    preserved.append(path)
    print("Error: Preserving " + path + ": " + why + "; cleanup is incomplete.", file=sys.stderr)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o755, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-targets.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def describe(path):
    # What sits at the path now, in the same words the ownership record uses.
    if os.path.islink(path):
        return {"kind": "symlink", "target": os.readlink(path)}
    if os.path.isdir(path):
        return {"kind": "directory"}
    if os.path.isfile(path):
        return {"kind": "file", "sha256": digest(path)}
    return None


def record_entries():
    # The record of what this transaction wrote, or None when there is nothing
    # an operator can be asked to trust.
    if not os.path.lexists(record):
        return None
    if os.path.islink(record) or not os.path.isfile(record):
        return None
    try:
        with open(record, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        return None
    entries = data.get("targets")
    return entries if isinstance(entries, dict) else None


def capture():
    if os.path.lexists(image):
        fail("Worker targets before-image " + image + " already exists; refusing to overwrite the state it holds.")
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {"created_by_tx": True, "targets": {}}
    try:
        for target in targets:
            path = under(target)
            if not os.path.lexists(path):
                data["targets"][target] = {"state": "absent"}
                continue
            if os.path.islink(path):
                data["targets"][target] = {"state": "symlink", "target": os.readlink(path)}
                continue
            if os.path.isdir(path):
                data["targets"][target] = {"state": "directory"}
                continue
            if not os.path.isfile(path):
                fail(
                    "Worker target " + path + " is not a regular file; refusing to record a state this install "
                    "cannot restore."
                )
            with open(path, "rb") as stream:
                payload = stream.read()
            copy = "file-" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(path)
            data["targets"][target] = {
                "state": "file",
                "copy": copy,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "mode": state.st_mode & 0o7777,
                "owner": [state.st_uid, state.st_gid],
            }
        document = (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8")
        write_atomic(MANIFEST, document, 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def remove_created(path, entry):
    # A path that did not exist before: remove it only while it is what we wrote.
    current = describe(path)
    if current is None:
        keep(path, "its state cannot be read")
        return
    if not isinstance(entry, dict) or entry != current:
        keep(path, "it changed after this transaction wrote it")
        return
    try:
        if current["kind"] == "directory":
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError as error:
        keep(path, "it could not be removed: " + str(error))


def restore_pre_existing(path, entry):
    # A path that was here before: put back its recorded content and metadata.
    state = entry.get("state")
    if state == "symlink":
        try:
            if os.path.lexists(path):
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
            os.symlink(entry.get("target") or "", path)
        except OSError as error:
            keep(path, "the link could not be restored: " + str(error))
            return
        if not os.path.islink(path) or os.readlink(path) != entry.get("target"):
            keep(path, "the restored link does not read back as the before-image")
        return
    if state == "directory":
        try:
            if not os.path.isdir(path) or os.path.islink(path):
                if os.path.lexists(path):
                    os.unlink(path)
                os.makedirs(path, mode=0o755, exist_ok=True)
        except OSError as error:
            keep(path, "the directory could not be restored: " + str(error))
        return
    if state != "file":
        keep(path, "the before-image names no state this install can restore")
        return
    copy = os.path.join(image, str(entry.get("copy") or ""))
    if not os.path.isfile(copy) or os.path.islink(copy):
        keep(path, "its before-image copy is missing")
        return
    with open(copy, "rb") as stream:
        payload = stream.read()
    if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
        keep(path, "its before-image copy changed after it was written")
        return
    try:
        if os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        write_atomic(path, payload, int(entry.get("mode") or 0o644))
        owner = entry.get("owner") or [0, 0]
        os.chown(path, int(owner[0]), int(owner[1]))
    except OSError as error:
        keep(path, "it could not be restored: " + str(error))
        return
    if digest(path) != entry.get("sha256"):
        keep(path, "the restored file does not read back as the before-image")


def restore():
    if not os.path.isfile(MANIFEST) or os.path.islink(MANIFEST):
        fail("No Worker targets before-image at " + image + "; preserving every path this install wrote.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail(
            "Worker targets before-image " + MANIFEST + " is not readable JSON; preserving every path this "
            "install wrote."
        )
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Worker targets before-image " + MANIFEST + " does not claim this product created it.")
    recorded = data.get("targets")
    if not isinstance(recorded, dict):
        fail("Worker targets before-image " + MANIFEST + " names no targets.")
    entries = record_entries()
    for target in targets:
        path = under(target)
        if not os.path.lexists(path):
            continue
        entry = recorded.get(target)
        if not isinstance(entry, dict):
            keep(path, "the before-image does not name it")
            continue
        if entry.get("state") == "absent":
            if entries is None:
                keep(path, "no ownership record proves this transaction wrote it")
                continue
            remove_created(path, entries.get(target))
        else:
            restore_pre_existing(path, entry)
    if preserved:
        print(
            "Error: " + str(len(preserved)) + " Worker path(s) preserved, so the cleanup is incomplete: "
            + ", ".join(preserved),
            file=sys.stderr,
        )
        raise SystemExit(1)


if action == "capture":
    capture()
else:
    restore()
WORKER_TARGETS_PY
}

record_worker_targets_before_image() {
    worker_targets_image capture "${1:-/}" "${2:-$(worker_targets_before_image)}"
}

worker_transaction_journal() {
    # One journal per transaction, beside the ACME snapshot and the two
    # before-images. It is the only record of a run that was killed before it
    # could finish: the next entrypoint reads it and knows what that run had
    # already begun to change.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-}"
    [[ "$root" == "/" ]] && root="/var/lib/gowave-auto-nginx"
    printf '%s\n' "${root%/}/recovery/${transaction}/transaction-journal.json"
}

worker_journal_action() {
    # One writer for the journal, so the install, the reconcile and the rollback
    # all read the same bytes back. "started" is written before the first
    # mutation, "installed" once every mutation has been verified, and a
    # transaction that never reached "installed" is the one a later entrypoint
    # has to reconcile.
    local action="$1"
    local journal="$2"
    local transaction="$3"
    local journal_state="${4:-}"
    python3 - "$action" "$journal" "$transaction" "$journal_state" <<'JOURNAL_PY'
import json
import os
import shutil
import sys
import tempfile
import time

action, journal, transaction, journal_state = sys.argv[1:5]
STATES = ("started", "installed")


def refuse(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def read():
    if os.path.islink(journal) or not os.path.isfile(journal):
        refuse("Worker transaction journal " + journal + " is not a regular file.")
    try:
        with open(journal, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        refuse("Worker transaction journal " + journal + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("schema") != 1:
        refuse("Worker transaction journal " + journal + " is not a journal this product wrote.")
    if data.get("transaction") != transaction:
        refuse(
            "Worker transaction journal " + journal + " records "
            + json.dumps(data.get("transaction")) + ", not " + json.dumps(transaction) + "."
        )
    if data.get("state") not in STATES:
        refuse("Worker transaction journal " + journal + " records no state this product knows.")
    return data


def store(state):
    # An installed transaction is closed: rewriting it as started would let a
    # later run undo an install that already verified every path it wrote.
    if state == "started" and os.path.lexists(journal) and read().get("state") == "installed":
        refuse("Worker transaction journal " + journal + " is already installed; refusing to reopen it.")
    directory = os.path.dirname(journal)
    if os.path.islink(directory):
        refuse("Worker transaction directory " + directory + " is a symlink.")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    document = {
        "schema": 1,
        "transaction": transaction,
        "state": state,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".transaction-journal.", suffix=".tmp")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, journal)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def remove():
    # The directory goes only while it is strictly below the recovery root it was
    # found in, so a transaction name can never name its way out of that root.
    recovery_root = os.path.realpath(os.path.dirname(os.path.dirname(journal)))
    transaction_dir = os.path.realpath(os.path.dirname(journal))
    if recovery_root == os.sep or not transaction_dir.startswith(recovery_root + os.sep):
        refuse("Worker transaction directory " + transaction_dir + " is not below " + recovery_root + ".")
    if os.path.islink(os.path.dirname(journal)):
        refuse("Worker transaction directory " + os.path.dirname(journal) + " is a symlink.")
    if not os.path.isdir(transaction_dir):
        refuse("Worker transaction directory " + transaction_dir + " is not a directory.")
    shutil.rmtree(transaction_dir)


if action == "write":
    if journal_state not in STATES:
        refuse("Unknown Worker transaction state " + json.dumps(journal_state) + ".")
    store(journal_state)
elif action == "mark":
    if journal_state not in STATES:
        refuse("Unknown Worker transaction state " + json.dumps(journal_state) + ".")
    if not os.path.lexists(journal):
        raise SystemExit(0)
    read()
    store(journal_state)
elif action == "state":
    print(read().get("state"))
elif action == "remove":
    read()
    remove()
else:
    refuse("Unknown Worker transaction journal action " + json.dumps(action) + ".")
JOURNAL_PY
}

record_worker_transaction_journal() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    if [[ ! "$transaction" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
        echo "Error: A Worker transaction journal needs a valid transaction ID." >&2
        return 1
    fi
    worker_journal_action write "$(worker_transaction_journal "$root" "$transaction")" "$transaction" started
}

mark_worker_transaction_state() {
    local transaction_state="${1:-}"
    local transaction="${2:-}"
    local root="${3:-/var/lib/gowave-auto-nginx}"
    worker_journal_action mark "$(worker_transaction_journal "$root" "$transaction")" "$transaction" "$transaction_state"
}

reconcile_worker_transaction_journals() {
    # Every entrypoint pays for the previous run's crash before it writes
    # anything of its own. A transaction that never reached "installed" is
    # restored from its own before-images and its directory is released; a
    # transaction this product cannot restore, or that already installed but
    # was never finalized, keeps its journal and the new operation is refused,
    # so a half-written host is never built upon. The state root is where the
    # journals live and the host root is where the inventoried paths sit; the
    # two differ only for a test that owns a scratch tree.
    local skip="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local host_root="${3:-/}"
    local journal transaction transaction_dir state failed=0
    [[ "$root" == "/" ]] && root="/var/lib/gowave-auto-nginx"
    local recovery_root="${root%/}/recovery"
    [[ -d "$recovery_root" ]] || return 0
    for journal in "$recovery_root"/*/transaction-journal.json; do
        [[ -e "$journal" ]] || continue
        transaction_dir="$(dirname "$journal")"
        transaction="$(basename "$transaction_dir")"
        [[ -n "$skip" && "$transaction" == "$skip" ]] && continue
        if ! state="$(worker_journal_action state "$journal" "$transaction")"; then
            echo "Error: Uncommitted Worker transaction $transaction cannot be read back; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if [[ "$state" != "started" ]]; then
            echo "Error: Worker transaction $transaction is '$state' and was never finalized; refusing to start a new install and retaining $transaction_dir. Finalize or roll it back first." >&2
            failed=1
            continue
        fi
        if [[ -d "$transaction_dir/worker-targets-before-image" ]] &&
            ! restore_worker_targets_before_image "$host_root" "$transaction_dir/worker-targets-before-image"; then
            echo "Error: Worker transaction $transaction could not be restored to its Worker before-image; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if [[ -d "$transaction_dir/firewall-before-image" ]] &&
            ! restore_firewall_before_image "$host_root" "$transaction_dir/firewall-before-image"; then
            echo "Error: Worker transaction $transaction could not be restored to its firewall before-image; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if ! worker_journal_action remove "$journal" "$transaction"; then
            echo "Error: Worker transaction $transaction was restored but its journal could not be released; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        echo "Reconciled uncommitted Worker transaction $transaction from its before-images." >&2
    done
    return "$failed"
}

# --- package change record -------------------------------------------------
# HOOK-04: a rollback restores the paths this run wrote, never the packages it
# installed. What the package manager changed is therefore recorded while the
# transaction still knows it, so a preserved host can be reported as carrying
# residual state instead of being called clean.

worker_package_record_dir() {
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-}"
    printf '%s\n' "${root%/}/recovery/${transaction}"
}

worker_package_inventory() {
    # One `package<TAB>version` line per installed package, sorted, so two runs
    # of the same host agree byte for byte and a diff of them is the package
    # change a transaction caused.
    if ! command -v dpkg-query >/dev/null 2>&1; then
        return 1
    fi
    dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | LC_ALL=C sort
}

record_worker_package_baseline() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local directory file temporary
    directory="$(worker_package_record_dir "$root" "$transaction")"
    if [[ ! -d "$directory" ]]; then
        echo "Error: The transaction directory $directory is absent, so a package baseline would not belong to a journal." >&2
        return 1
    fi
    file="$directory/packages-before.txt"
    temporary="$(mktemp "$directory/.packages-before.XXXXXX")" || return 1
    if worker_package_inventory >"$temporary" && [[ -s "$temporary" ]]; then
        :
    else
        # A host whose package manager cannot answer is not a host with no
        # packages; the baseline says what it could not learn.
        printf '%s\n' "#unavailable" >"$temporary"
    fi
    if ! chmod 0600 -- "$temporary" || ! sync "$temporary" ||
        ! mv -f -- "$temporary" "$file" || ! sync "$directory"; then
        rm -f -- "$temporary"
        return 1
    fi
}

record_worker_package_changes() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local directory before after changes temporary
    directory="$(worker_package_record_dir "$root" "$transaction")"
    before="$directory/packages-before.txt"
    if [[ ! -f "$before" ]]; then
        echo "Error: The package baseline for $transaction is absent, so the package changes it caused cannot be stated." >&2
        return 1
    fi
    after="$(mktemp "$directory/.packages-after.XXXXXX")" || return 1
    if worker_package_inventory >"$after" && [[ -s "$after" ]]; then
        :
    else
        printf '%s\n' "#unavailable" >"$after"
    fi
    changes="$(mktemp "$directory/.package-changes.XXXXXX")" || {
        rm -f -- "$after"
        return 1
    }
    if [[ "$(head -n 1 "$before")" == "#unavailable" ]] ||
        [[ "$(head -n 1 "$after")" == "#unavailable" ]]; then
        printf '%s\n' "#gowave-package-changes/v1" "#unavailable" >"$changes"
    else
        {
            printf '%s\n' "#gowave-package-changes/v1"
            awk -F'\t' '
                FNR == NR { before[$1] = $2; next }
                { after[$1] = $2 }
                END {
                    for (name in after) {
                        if (!(name in before)) print "installed\t" name "\t" after[name]
                        else if (before[name] != after[name]) print "upgraded\t" name "\t" before[name] "\t" after[name]
                    }
                    for (name in before) if (!(name in after)) print "removed\t" name "\t" before[name]
                }
            ' "$before" "$after" | LC_ALL=C sort
        } >"$changes"
    fi
    rm -f -- "$after"
    if ! chmod 0600 -- "$changes" || ! sync "$changes" ||
        ! mv -f -- "$changes" "$directory/package-changes.tsv" || ! sync "$directory"; then
        rm -f -- "$changes"
        return 1
    fi
}
restore_worker_targets_before_image() {
    worker_targets_image restore "${1:-/}" "${2:-$(worker_targets_before_image)}"
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
    local ownership_record ownership_tmp
    ownership_record=$(deploy_hook_ownership_record "$recovery_root")
    ownership_tmp="${ownership_record}.tmp.$$"
    python3 -c 'import json, os, sys; record, tx_id, path, digest = sys.argv[1:5]; flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0); fd = os.open(record, flags, 0o600); stream = os.fdopen(fd, "w", encoding="utf-8"); json.dump({"transaction_id": tx_id, "path": path, "created_by_tx": True, "sha256": digest}, stream, indent=2); stream.flush(); os.fsync(stream.fileno()); stream.close()' "$ownership_tmp" "$transaction_id" "$hook_file" "$digest" || {
        rm -f -- "$ownership_tmp" || true
        echo "Error: Could not record deploy-hook ownership for later transactions." >&2
        return 1
    }
    if ! chmod 0600 -- "$ownership_tmp" || ! sync "$ownership_tmp" ||
        ! mv -f -- "$ownership_tmp" "$ownership_record" || ! sync "$recovery_root"; then
        rm -f -- "$ownership_tmp" || true
        echo "Error: Could not publish the deploy-hook ownership record." >&2
        return 1
    fi
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
            # A repeated install finds the hook an earlier transaction installed
            # and this transaction never touched. The ownership records name that
            # earlier transaction, so a hook that still hashes to what they
            # recorded is provably the product's own and there is nothing here to
            # undo: refusing would report an incomplete rollback, and demand
            # manual recovery, for a failure that left no side effect behind.
            if python3 - "$hook_file" "$recovery_root" <<'PY'
import hashlib, json, os, sys
hook, root = sys.argv[1], sys.argv[2]
try:
    with open(hook, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
except OSError:
    sys.exit(1)
records = [os.path.join(root, "deploy-hook-ownership.json")]
try:
    records += [os.path.join(root, name, "deploy-hook-manifest.json")
                for name in sorted(os.listdir(root))]
except OSError:
    pass
for record in records:
    try:
        with open(record, encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        continue
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        continue
    if data.get("path") == hook and data.get("sha256") == digest:
        sys.exit(0)
sys.exit(1)
PY
            then
                return 0
            fi
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
    rm -f -- "$(deploy_hook_ownership_record "$recovery_root")" || {
        echo "Error: Could not clear the deploy-hook ownership record after rollback." >&2
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
    local -a ssh_command=(ssh)
    if [[ "${GOWAVE_WORKER_INTERACTIVE_DEPLOYMENT:-0}" == 1 ]]; then
        ssh_command=(timeout --kill-after=10s 60m ssh)
    fi
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

    local preflight_module="$SCRIPT_DIR/modules/preflight.sh"
    if [[ ! -f "$preflight_module" ]]; then
        echo "Error: the required-input contract is missing at $preflight_module." >&2
        return 1
    fi
    local artifact_module="$SCRIPT_DIR/modules/artifact.sh"
    if [[ ! -f "$artifact_module" ]]; then
        echo "Error: the pinned-artifact helper is missing at $artifact_module." >&2
        return 1
    fi
    local nginx_package_module="$SCRIPT_DIR/modules/nginx_package.sh"
    if [[ ! -f "$nginx_package_module" ]]; then
        echo "Error: the NGINX package policy is missing at $nginx_package_module." >&2
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
        # An existing Worker's edge identity is rewritten only for a caller that
        # confirmed the migration preview; `node reapply` sets this after its own
        # prompt, and a direct payload call stays `no`.
        printf 'export GOWAVE_MIGRATE_EXISTING=%q\n' "${GOWAVE_MIGRATE_EXISTING:-no}"
        printf 'export ACME_TX_ID=%q\n' "${ACME_TX_ID:-}"
        # The Worker's re-entrant lease belongs to this host's lock holder, which
        # the dispatching Master holds; it is forwarded only as an export so the
        # Worker's own management code can prove the caller owns its lock.
        printf 'export GOWAVE_LEASE_TOKEN=%q\n' "${GOWAVE_WORKER_LEASE_TOKEN:-}"
        printf 'COVER_REALITY_B64=%q\n' "$cover_b64"
        printf 'COVER_REALITY_SHA256=%q\n' "$cover_sha256"
        # Secret strictly scoped, not exported globally
        printf '_NODE_SECRET_KEY=%q\n' "$SECRET_KEY"

        # 1b. The required-input contract travels as the module itself, not as a
        # copy of it: the Worker refuses the same values the controller refused
        # because it runs the same function bodies.
        cat "$preflight_module"

        # 1c. The pinned core is fetched and verified by the same body the
        # controller runs, for the same reason: the Worker's own copy of the
        # pinned step calls fetch_verified_artifact, and a payload that carried
        # the call without the helper died on it at the pin.
        cat "$artifact_module"

        # 1d. The approved NGINX package policy travels as the same body the
        # Master runs, so the Worker selects and verifies the same package.
        cat "$nginx_package_module"

        # 2. Remote helper functions
        cat <<'RUNNER_FUNCS'
log_info() { printf '[INFO] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*" >&2; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }

# Refuse to delete a tree that is not strictly below a directory this script
# owns: ${var:?} rejects only unset and empty values, while "/", "..", or a
# domain that resolves elsewhere all pass it.
require_tree_under() {
    local path="$1" parent="$2"
    local resolved_path resolved_parent
    [[ -n "$path" && -n "$parent" ]] || return 1
    resolved_path=$(realpath -m -- "$path") || return 1
    resolved_parent=$(realpath -m -- "$parent") || return 1
    [[ "$resolved_parent" != "/" ]] || return 1
    [[ "$resolved_path" == "$resolved_parent"/* ]] || return 1
    [[ "$resolved_path" != "$resolved_parent" ]]
}

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

# select_acme_lineage NAME TARGET_SERVER [LETSENCRYPT_ROOT]
#
# Print the live directory of a lineage that already covers NAME, or nothing when
# the name has to be issued one of its own. A Worker in a shared zone is often
# left with a suffixed lineage (`cover2.example.net-0001`); asking certbot for the
# plain name would issue a second lineage beside it, and the vhost would then
# serve whichever one its path happened to name. Adoption follows the Master's
# rules so both roles read the same tree the same way: the renewal config must
# name TARGET_SERVER, the certificate must not be expired, and it must cover
# NAME; the exact-name lineage is tried first, the rest in directory order.
select_acme_lineage() {
    local name="$1"
    local target_server="${2:-https://acme-v02.api.letsencrypt.org/directory}"
    local letsencrypt_root="${3:-/etc/letsencrypt}"
    local live_root="${letsencrypt_root}/live"
    local renewal_root="${letsencrypt_root}/renewal"

    # A host that has never had a lineage is not an error.
    [[ -d "$live_root" ]] || return 0

    local -a order=()
    local entry candidate
    if [[ -d "${live_root}/${name}" && ! -L "${live_root}/${name}" ]]; then
        order+=("$name")
    fi
    while IFS= read -r entry; do
        candidate=$(basename -- "$entry")
        [[ "$candidate" == "$name" ]] && continue
        order+=("$candidate")
    done < <(find "$live_root" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null | LC_ALL=C sort)

    (( ${#order[@]} )) || return 0

    for candidate in "${order[@]}"; do
        local live_dir="${live_root}/${candidate}"
        local renewal_conf="${renewal_root}/${candidate}.conf"
        [[ -s "${live_dir}/fullchain.pem" && -f "$renewal_conf" ]] || continue

        local issued_by="" key val
        while IFS='=' read -r key val || [[ -n "$key" ]]; do
            key=$(echo "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            if [[ "$key" == "server" ]]; then
                issued_by=$(echo "$val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
                break
            fi
        done < "$renewal_conf"
        if [[ "$issued_by" != "$target_server" ]]; then
            echo "Not adopting the ACME lineage $candidate for $name: it was not issued by $target_server." >&2
            continue
        fi
        if ! openssl x509 -checkend 0 -noout -in "${live_dir}/fullchain.pem" >/dev/null 2>&1; then
            echo "Not adopting the ACME lineage $candidate for $name: its certificate has expired." >&2
            continue
        fi
        local host_check
        if ! host_check=$(openssl x509 -checkhost "$name" -noout -in "${live_dir}/fullchain.pem" 2>&1); then
            continue
        fi
        [[ "$host_check" == "Hostname $name does match certificate" ]] || continue

        printf '%s\n' "$live_dir"
        echo "Adopting the ACME lineage $candidate for $name: it covers the name and matches the ACME directory." >&2
        return 0
    done
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
        if ! require_tree_under "$live_dir" "$letsencrypt_root" ||
            ! require_tree_under "$archive_dir" "$letsencrypt_root"; then
            echo "Error: Refusing to remove ACME lineage for $domain outside $letsencrypt_root." >&2
            return 1
        fi
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
        if ! require_tree_under "$snap_dir" "$recovery_root"; then
            echo "Error: Refusing to remove ACME snapshot outside $recovery_root (transaction $transaction_id)." >&2
            return 1
        fi
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

# The deploy hook outlives both the transaction that installed it and its
# recovery snapshot, which is deleted once the install commits. Ownership is
# therefore recorded outside the snapshot as well, so the next transaction can
# still tell its own hook from one an operator or another product left behind.
deploy_hook_ownership_record() {
    printf '%s\n' "${1:-/var/lib/gowave-auto-nginx/recovery}/deploy-hook-ownership.json"
}

deploy_hook_record_matches() {
    local record="$1"
    local hook_file="$2"
    local digest="$3"
    if [[ ! -f "$record" || -L "$record" ]]; then
        return 1
    fi
    python3 - "$record" "$hook_file" "$digest" <<'PY'
import json
import sys

record_path, hook_path, digest = sys.argv[1:4]
try:
    with open(record_path, "r", encoding="utf-8") as stream:
        data = json.load(stream)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if (
    isinstance(data, dict)
    and data.get("created_by_tx") is True
    and data.get("path") == hook_path
    and data.get("sha256") == digest
) else 1)
PY
}

deploy_hook_owned_by_prior_transaction() {
    local hook_file="$1"
    local recovery_root="$2"
    if [[ ! -f "$hook_file" || -L "$hook_file" ]]; then
        return 1
    fi
    if [[ ! -d "$recovery_root" || -L "$recovery_root" ]]; then
        return 1
    fi
    local digest
    digest=$(sha256sum -- "$hook_file" 2>/dev/null | awk '{print $1}' || true)
    if [[ -z "$digest" ]]; then
        return 1
    fi
    if deploy_hook_record_matches "$(deploy_hook_ownership_record "$recovery_root")" "$hook_file" "$digest"; then
        return 0
    fi
    local manifest
    for manifest in "${recovery_root}"/*/deploy-hook-manifest.json; do
        if deploy_hook_record_matches "$manifest" "$hook_file" "$digest"; then
            return 0
        fi
    done
    return 1
}

verify_deploy_hook_preflight() {
    local hook_file="${1:-/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh}"
    local transaction_id="${2:-}"
    local recovery_root="${3:-/var/lib/gowave-auto-nginx/recovery}"

    if [[ -e "$hook_file" ]] || [[ -L "$hook_file" ]]; then
        if [[ -n "$transaction_id" ]]; then
            local manifest="${recovery_root}/${transaction_id}/deploy-hook-manifest.json"
            # The manifest records that a transaction created a hook at this path;
            # it does not say that what now sits there is that hook. A symlink, a
            # directory or a FIFO is never adopted on the strength of the manifest
            # alone, and neither is a file whose bytes or path differ from the
            # recorded ones.
            if [[ -f "$manifest" && ! -L "$manifest" && -f "$hook_file" && ! -L "$hook_file" ]]; then
                local owned
                owned=$(python3 -c 'import hashlib,json,sys; m,h=sys.argv[1:3]; d=json.load(open(m,"r",encoding="utf-8")); s=hashlib.sha256(open(h,"rb").read()).hexdigest(); print("1" if d.get("created_by_tx") is True and d.get("path")==h and d.get("sha256")==s else "0")' "$manifest" "$hook_file" 2>/dev/null || echo "0")
                if [[ "$owned" == "1" ]]; then
                    return 0
                fi
            fi
        fi
        # A repeated install finds the hook an earlier transaction installed. It is
        # only recognised as ours when that transaction recorded this exact path and
        # the file still hashes to what was recorded, so a hook written or edited by
        # someone else stays a refusal rather than a file this product overwrites.
        if deploy_hook_owned_by_prior_transaction "$hook_file" "$recovery_root"; then
            return 0
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

worker_mutation_targets() {
    # The paths this install creates and its rollback removes. A path that is
    # already here is only touched when the ownership record names it.
    cat <<'WORKER_TARGETS'
/etc/systemd/system/gowave-node.service
/etc/systemd/system/gowave-node.service.d
/etc/systemd/system/remnanode.service
/opt/gowave-node
/run/gowave-node
/opt/remnanode
/usr/local/bin/gowave-node
/usr/local/bin/xray
/etc/nginx/conf.d/00-worker-acme-challenge.conf
/etc/nginx/conf.d/00-bootstrap-worker-acme.conf
/etc/nginx/conf.d/gowave-worker-https.conf
/etc/nginx/conf.d/gowave-worker-decoy.conf
/etc/nginx/conf.d/gowave-worker-vision-fallback.conf
/etc/nginx/stream-enabled/gowave-worker-stream.conf
/var/www/gowave-acme
/var/www/gowave-auto-nginx/cover-reality
WORKER_TARGETS
}

worker_ownership_record() {
    local base="${1:-/var/lib/gowave-auto-nginx}"
    # "/" is the host itself, where the state root is the product's own.
    [[ "$base" == "/" ]] && base="/var/lib/gowave-auto-nginx"
    printf '%s\n' "$base/worker-install-ownership.json"
}

verify_worker_mutation_targets_preflight() {
    # The root and the record are arguments so a test can drive this guard over
    # a directory it owns; the install passes neither and gets the host.
    local root="${1:-/}"
    local record="${2:-$(worker_ownership_record "$root")}"
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$record" "$targets" <<'WORKER_PREFLIGHT_PY'
import hashlib
import json
import os
import sys

root, record, listed = sys.argv[1:4]
targets = [line.strip() for line in listed.splitlines() if line.strip()]


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def refuse(path, what):
    print(
        "Error: Pre-existing unowned Worker " + what + " " + path + ". Refusing to "
        "overwrite or remove an unmanaged host resource.",
        file=sys.stderr,
    )
    raise SystemExit(1)


recorded = {}
if os.path.lexists(record):
    if os.path.islink(record) or not os.path.isfile(record):
        print("Error: Worker ownership record " + record + " is not a regular file.", file=sys.stderr)
        raise SystemExit(1)
    try:
        with open(record, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        print("Error: Worker ownership record " + record + " is not readable JSON.", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        print(
            "Error: Worker ownership record " + record + " does not claim this product created anything.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    recorded = data.get("targets")
    if not isinstance(recorded, dict):
        print("Error: Worker ownership record " + record + " names no targets.", file=sys.stderr)
        raise SystemExit(1)

for target in targets:
    path = under(target)
    if not os.path.lexists(path):
        continue
    entry = recorded.get(target)
    if os.path.islink(path):
        # The upstream installer links the Worker binary into /usr/local/bin,
        # so a link this install wrote is adopted by the target it recorded.
        # Any other link stays foreign even when its target holds our bytes.
        if isinstance(entry, dict) and entry.get("kind") == "symlink" and entry.get("target") == os.readlink(path):
            continue
        refuse(path, "path")
    if os.path.isdir(path):
        if isinstance(entry, dict) and entry.get("kind") == "directory":
            continue
        refuse(path, "directory")
    if not os.path.isfile(path):
        refuse(path, "path")
    try:
        current = digest(path)
    except OSError:
        current = ""
    if current and isinstance(entry, dict) and entry.get("kind") == "file" and entry.get("sha256") == current:
        continue
    # The operator confirmed migration: a regular file this product did not
    # record is adopted (rewritten) instead of refused. Symlinks and directories
    # are still refused above, so confirmation never writes through a link.
    if os.environ.get("GOWAVE_ADOPT_UNOWNED") == "1":
        continue
    refuse(path, "file")
WORKER_PREFLIGHT_PY
}

record_worker_mutation_targets() {
    local root="${1:-/}"
    local record="${2:-$(worker_ownership_record "$root")}"
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$record" "$targets" <<'WORKER_RECORD_PY'
import hashlib
import json
import os
import sys
import tempfile

root, record, listed = sys.argv[1:4]
targets = [line.strip() for line in listed.splitlines() if line.strip()]


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


data = {"created_by_tx": True, "targets": {}}
for target in targets:
    path = under(target)
    if not os.path.lexists(path):
        continue
    if os.path.islink(path):
        data["targets"][target] = {"kind": "symlink", "target": os.readlink(path)}
    elif os.path.isdir(path):
        data["targets"][target] = {"kind": "directory"}
    elif os.path.isfile(path):
        data["targets"][target] = {"kind": "file", "sha256": digest(path)}

directory = os.path.dirname(record) or "."
os.makedirs(directory, mode=0o700, exist_ok=True)
handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-ownership.", suffix=".tmp")
try:
    os.fchmod(handle, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, record)
except BaseException:
    try:
        os.unlink(temporary)
    except OSError:
        pass
    raise
directory_handle = os.open(directory, os.O_RDONLY)
try:
    os.fsync(directory_handle)
finally:
    os.close(directory_handle)
WORKER_RECORD_PY
}

firewall_before_image() {
    # Per transaction, beside the ACME snapshot: the recovery root is removed
    # by remote_finalize after a verified install, so a successful run leaves
    # no image behind and a failed one leaves exactly the one it needs.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${ACME_TX_ID:-}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$root/firewall-before-image"
        return 0
    fi
    printf '%s\n' "$root/recovery/$transaction/firewall-before-image"
}

firewall_image() {
    # One heredoc, two actions: what the firewall read before this install
    # changed it, and the only way back to that state. The rollback script
    # carries the same text, and a test refuses the tree if the copies drift.
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(firewall_before_image)}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: firewall_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    python3 - "$root" "$image" "$action" <<'FIREWALL_IMAGE_PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

root, image, action = sys.argv[1:4]

CONFIG_FILES = (
    "/etc/default/ufw",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/ufw/before.rules",
    "/etc/ufw/before6.rules",
    "/etc/ufw/after.rules",
    "/etc/ufw/after6.rules",
)
MANIFEST = os.path.join(image, "manifest.json")


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def run(argv, stdin_text=None):
    result = subprocess.run(argv, capture_output=True, text=True, input=stdin_text)
    return result.returncode, result.stdout, result.stderr


def digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def digest_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def normalized(text):
    """The ruleset without the bookkeeping `iptables-save` adds on its own.

    Every dump is stamped with the moment it ran and carries the live
    counters of each chain, and `iptables-restore` zeroes those counters.
    Neither is a rule, so a read-back compares what is left.
    """
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(":") and line.endswith("]"):
            line = line[: line.rindex("[")] + "[0:0]"
        lines.append(line)
    return "\n".join(lines)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".firewall-image.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def capture():
    if os.path.lexists(image):
        fail("Firewall before-image " + image + " already exists; refusing to overwrite the state it holds.")
    status_code, status_text, status_error = run(["ufw", "status", "verbose"])
    if status_code != 0:
        fail(
            "ufw status verbose exited " + str(status_code) + "; refusing to change a firewall this install cannot "
            "restore: " + status_error.strip()[-300:]
        )
    first = status_text.splitlines()[0].strip() if status_text.strip() else ""
    if first not in ("Status: active", "Status: inactive"):
        fail("ufw status verbose printed no status line; refusing to change a firewall this install cannot restore.")
    defaults = {}
    for line in status_text.splitlines():
        if not line.startswith("Default:"):
            continue
        for part in line[len("Default:"):].split(","):
            words = part.split()
            if len(words) >= 2:
                defaults[words[1].strip("()")] = words[0]
    # `ufw status verbose` prints no Default line until the firewall has been
    # enabled once: an inactive firewall holds no policy, so there is none to
    # restore and the image records that instead of refusing the install.
    if first == "Status: active" and set(defaults) != {"incoming", "outgoing", "routed"}:
        fail(
            "ufw status verbose printed no complete default policy line; refusing to change a firewall this "
            "install cannot restore."
        )
    dumps = {}
    for name, argv in (("iptables", ["iptables-save"]), ("ip6tables", ["ip6tables-save"])):
        code, text, error = run(argv)
        if code != 0:
            if name == "ip6tables" and not os.path.exists(under("/proc/net/if_inet6")):
                dumps[name] = None
                continue
            fail(
                argv[0] + " exited " + str(code) + "; refusing to change a firewall this install cannot restore: "
                + error.strip()[-300:]
            )
        dumps[name] = text
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {
        "created_by_tx": True,
        "enabled": first == "Status: active",
        "status_verbose": status_text,
        "defaults": defaults,
        "files": {},
        "iptables": None,
        "ip6tables": None,
    }
    try:
        for path in CONFIG_FILES:
            real = under(path)
            if not os.path.lexists(real):
                continue
            if os.path.islink(real) or not os.path.isfile(real):
                fail(
                    "UFW configuration " + real + " is not a regular file; refusing to change a firewall this "
                    "install cannot restore."
                )
            with open(real, "rb") as stream:
                payload = stream.read()
            copy = "file-" + digest_bytes(path.encode("utf-8"))[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(real)
            data["files"][path] = {
                "copy": copy,
                "sha256": digest_bytes(payload),
                "mode": state.st_mode & 0o7777,
                "uid": state.st_uid,
                "gid": state.st_gid,
            }
        for name, text in dumps.items():
            if text is None:
                continue
            copy = name + "-save.txt"
            write_atomic(os.path.join(image, copy), text.encode("utf-8"), 0o600)
            data[name] = {"copy": copy, "sha256": digest_bytes(text.encode("utf-8"))}
        write_atomic(MANIFEST, (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8"), 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def restore():
    if not os.path.isfile(MANIFEST):
        fail("No firewall before-image at " + image + "; refusing to guess which rules this install added.")
    if os.path.islink(MANIFEST):
        fail("Firewall before-image " + MANIFEST + " is a symlink; refusing to restore from it.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail("Firewall before-image " + MANIFEST + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Firewall before-image " + MANIFEST + " does not claim this product created it.")
    for key in ("enabled", "status_verbose", "defaults", "files", "iptables"):
        if key not in data:
            fail("Firewall before-image " + MANIFEST + " is incomplete: no " + key + ".")
    if not isinstance(data["files"], dict) or not isinstance(data["iptables"], dict):
        fail("Firewall before-image " + MANIFEST + " names no restorable files.")
    for path, meta in data["files"].items():
        copy = os.path.join(image, str(meta.get("copy") or ""))
        if not os.path.isfile(copy) or os.path.islink(copy):
            fail("Firewall before-image copy for " + path + " is missing.")
        if digest_file(copy) != meta.get("sha256"):
            fail("Firewall before-image copy for " + path + " changed after it was written.")
        with open(copy, "rb") as stream:
            payload = stream.read()
        target = under(path)
        write_atomic(target, payload, int(meta.get("mode") or 0o644))
        try:
            os.chown(target, int(meta.get("uid") or 0), int(meta.get("gid") or 0))
        except OSError:
            pass
    # The enabled state first: `ufw --force disable` flushes the chains, so a
    # dump applied before it would be the rules this install added, not these.
    state = "enable" if data["enabled"] else "disable"
    code, _, error = run(["ufw", "--force", state])
    if code != 0:
        fail("ufw --force " + state + " exited " + str(code) + ": " + error.strip()[-300:])
    restored = {}
    for name, argv in (("iptables", ["iptables-restore"]), ("ip6tables", ["ip6tables-restore"])):
        entry = data.get(name)
        if not isinstance(entry, dict):
            continue
        copy = os.path.join(image, str(entry.get("copy") or ""))
        if not os.path.isfile(copy):
            fail("Firewall before-image copy for " + name + " is missing.")
        with open(copy, "r", encoding="utf-8") as stream:
            text = stream.read()
        code, _, error = run(argv, stdin_text=text)
        if code != 0:
            fail(argv[0] + " exited " + str(code) + ": " + error.strip()[-300:])
        restored[name] = text
    code, status_text, _ = run(["ufw", "status", "verbose"])
    if code != 0 or status_text != data["status_verbose"]:
        fail("The restored firewall does not read back as the before-image.")
    code, saved, _ = run(["iptables-save"])
    if code != 0 or normalized(saved) != normalized(restored.get("iptables", "")):
        fail("The restored IPv4 ruleset does not match the before-image.")
    # A dual-stack host filters on two tables, and a restored v4 ruleset proves
    # nothing about the v6 one the failed install opened.
    if "ip6tables" in restored:
        code, saved, _ = run(["ip6tables-save"])
        if code != 0 or normalized(saved) != normalized(restored["ip6tables"]):
            fail("The restored IPv6 ruleset does not match the before-image.")


if action == "capture":
    capture()
else:
    restore()
FIREWALL_IMAGE_PY
}

record_firewall_before_image() {
    firewall_image capture "${1:-/}" "${2:-$(firewall_before_image)}"
}

restore_firewall_before_image() {
    firewall_image restore "${1:-/}" "${2:-$(firewall_before_image)}"
}

worker_targets_before_image() {
    # Per transaction, beside the ACME snapshot and the firewall image: what
    # every inventoried path held before this transaction touched it. The
    # recovery root is removed by remote_finalize after a verified install, so
    # a successful run leaves no image behind and a failed one keeps exactly
    # the one its rollback needs.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-${ACME_TX_ID:-}}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$root/worker-targets-before-image"
        return 0
    fi
    printf '%s\n' "$root/recovery/$transaction/worker-targets-before-image"
}

worker_targets_image() {
    # The state of every inventoried path before this transaction wrote it, and
    # the way back to that state. A created path is removed only while it is
    # still what this install wrote — the ownership record is the proof — and a
    # pre-existing path is put back with its content and metadata. Anything
    # changed after the write, or that no record can prove, is preserved with
    # the cleanup reported incomplete. The payload carries this text twice and
    # the rollback script once; a test refuses the tree if the copies drift.
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(worker_targets_before_image)}"
    local record="${4:-$(worker_ownership_record "$root")}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: worker_targets_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$image" "$action" "$record" "$targets" <<'WORKER_TARGETS_PY'
import hashlib
import json
import os
import shutil
import sys
import tempfile

root, image, action, record, listed = sys.argv[1:6]
targets = [line.strip() for line in listed.splitlines() if line.strip()]
MANIFEST = os.path.join(image, "manifest.json")
preserved = []


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def keep(path, why):
    preserved.append(path)
    print("Error: Preserving " + path + ": " + why + "; cleanup is incomplete.", file=sys.stderr)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o755, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-targets.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def describe(path):
    # What sits at the path now, in the same words the ownership record uses.
    if os.path.islink(path):
        return {"kind": "symlink", "target": os.readlink(path)}
    if os.path.isdir(path):
        return {"kind": "directory"}
    if os.path.isfile(path):
        return {"kind": "file", "sha256": digest(path)}
    return None


def record_entries():
    # The record of what this transaction wrote, or None when there is nothing
    # an operator can be asked to trust.
    if not os.path.lexists(record):
        return None
    if os.path.islink(record) or not os.path.isfile(record):
        return None
    try:
        with open(record, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        return None
    entries = data.get("targets")
    return entries if isinstance(entries, dict) else None


def capture():
    if os.path.lexists(image):
        fail("Worker targets before-image " + image + " already exists; refusing to overwrite the state it holds.")
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {"created_by_tx": True, "targets": {}}
    try:
        for target in targets:
            path = under(target)
            if not os.path.lexists(path):
                data["targets"][target] = {"state": "absent"}
                continue
            if os.path.islink(path):
                data["targets"][target] = {"state": "symlink", "target": os.readlink(path)}
                continue
            if os.path.isdir(path):
                data["targets"][target] = {"state": "directory"}
                continue
            if not os.path.isfile(path):
                fail(
                    "Worker target " + path + " is not a regular file; refusing to record a state this install "
                    "cannot restore."
                )
            with open(path, "rb") as stream:
                payload = stream.read()
            copy = "file-" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(path)
            data["targets"][target] = {
                "state": "file",
                "copy": copy,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "mode": state.st_mode & 0o7777,
                "owner": [state.st_uid, state.st_gid],
            }
        document = (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8")
        write_atomic(MANIFEST, document, 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def remove_created(path, entry):
    # A path that did not exist before: remove it only while it is what we wrote.
    current = describe(path)
    if current is None:
        keep(path, "its state cannot be read")
        return
    if not isinstance(entry, dict) or entry != current:
        keep(path, "it changed after this transaction wrote it")
        return
    try:
        if current["kind"] == "directory":
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError as error:
        keep(path, "it could not be removed: " + str(error))


def restore_pre_existing(path, entry):
    # A path that was here before: put back its recorded content and metadata.
    state = entry.get("state")
    if state == "symlink":
        try:
            if os.path.lexists(path):
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
            os.symlink(entry.get("target") or "", path)
        except OSError as error:
            keep(path, "the link could not be restored: " + str(error))
            return
        if not os.path.islink(path) or os.readlink(path) != entry.get("target"):
            keep(path, "the restored link does not read back as the before-image")
        return
    if state == "directory":
        try:
            if not os.path.isdir(path) or os.path.islink(path):
                if os.path.lexists(path):
                    os.unlink(path)
                os.makedirs(path, mode=0o755, exist_ok=True)
        except OSError as error:
            keep(path, "the directory could not be restored: " + str(error))
        return
    if state != "file":
        keep(path, "the before-image names no state this install can restore")
        return
    copy = os.path.join(image, str(entry.get("copy") or ""))
    if not os.path.isfile(copy) or os.path.islink(copy):
        keep(path, "its before-image copy is missing")
        return
    with open(copy, "rb") as stream:
        payload = stream.read()
    if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
        keep(path, "its before-image copy changed after it was written")
        return
    try:
        if os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        write_atomic(path, payload, int(entry.get("mode") or 0o644))
        owner = entry.get("owner") or [0, 0]
        os.chown(path, int(owner[0]), int(owner[1]))
    except OSError as error:
        keep(path, "it could not be restored: " + str(error))
        return
    if digest(path) != entry.get("sha256"):
        keep(path, "the restored file does not read back as the before-image")


def restore():
    if not os.path.isfile(MANIFEST) or os.path.islink(MANIFEST):
        fail("No Worker targets before-image at " + image + "; preserving every path this install wrote.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail(
            "Worker targets before-image " + MANIFEST + " is not readable JSON; preserving every path this "
            "install wrote."
        )
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Worker targets before-image " + MANIFEST + " does not claim this product created it.")
    recorded = data.get("targets")
    if not isinstance(recorded, dict):
        fail("Worker targets before-image " + MANIFEST + " names no targets.")
    entries = record_entries()
    for target in targets:
        path = under(target)
        if not os.path.lexists(path):
            continue
        entry = recorded.get(target)
        if not isinstance(entry, dict):
            keep(path, "the before-image does not name it")
            continue
        if entry.get("state") == "absent":
            if entries is None:
                keep(path, "no ownership record proves this transaction wrote it")
                continue
            remove_created(path, entries.get(target))
        else:
            restore_pre_existing(path, entry)
    if preserved:
        print(
            "Error: " + str(len(preserved)) + " Worker path(s) preserved, so the cleanup is incomplete: "
            + ", ".join(preserved),
            file=sys.stderr,
        )
        raise SystemExit(1)


if action == "capture":
    capture()
else:
    restore()
WORKER_TARGETS_PY
}

record_worker_targets_before_image() {
    worker_targets_image capture "${1:-/}" "${2:-$(worker_targets_before_image)}"
}

worker_transaction_journal() {
    # One journal per transaction, beside the ACME snapshot and the two
    # before-images. It is the only record of a run that was killed before it
    # could finish: the next entrypoint reads it and knows what that run had
    # already begun to change.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-}"
    [[ "$root" == "/" ]] && root="/var/lib/gowave-auto-nginx"
    printf '%s\n' "${root%/}/recovery/${transaction}/transaction-journal.json"
}

worker_journal_action() {
    # One writer for the journal, so the install, the reconcile and the rollback
    # all read the same bytes back. "started" is written before the first
    # mutation, "installed" once every mutation has been verified, and a
    # transaction that never reached "installed" is the one a later entrypoint
    # has to reconcile.
    local action="$1"
    local journal="$2"
    local transaction="$3"
    local journal_state="${4:-}"
    python3 - "$action" "$journal" "$transaction" "$journal_state" <<'JOURNAL_PY'
import json
import os
import shutil
import sys
import tempfile
import time

action, journal, transaction, journal_state = sys.argv[1:5]
STATES = ("started", "installed")


def refuse(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def read():
    if os.path.islink(journal) or not os.path.isfile(journal):
        refuse("Worker transaction journal " + journal + " is not a regular file.")
    try:
        with open(journal, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        refuse("Worker transaction journal " + journal + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("schema") != 1:
        refuse("Worker transaction journal " + journal + " is not a journal this product wrote.")
    if data.get("transaction") != transaction:
        refuse(
            "Worker transaction journal " + journal + " records "
            + json.dumps(data.get("transaction")) + ", not " + json.dumps(transaction) + "."
        )
    if data.get("state") not in STATES:
        refuse("Worker transaction journal " + journal + " records no state this product knows.")
    return data


def store(state):
    # An installed transaction is closed: rewriting it as started would let a
    # later run undo an install that already verified every path it wrote.
    if state == "started" and os.path.lexists(journal) and read().get("state") == "installed":
        refuse("Worker transaction journal " + journal + " is already installed; refusing to reopen it.")
    directory = os.path.dirname(journal)
    if os.path.islink(directory):
        refuse("Worker transaction directory " + directory + " is a symlink.")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    document = {
        "schema": 1,
        "transaction": transaction,
        "state": state,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".transaction-journal.", suffix=".tmp")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, journal)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def remove():
    # The directory goes only while it is strictly below the recovery root it was
    # found in, so a transaction name can never name its way out of that root.
    recovery_root = os.path.realpath(os.path.dirname(os.path.dirname(journal)))
    transaction_dir = os.path.realpath(os.path.dirname(journal))
    if recovery_root == os.sep or not transaction_dir.startswith(recovery_root + os.sep):
        refuse("Worker transaction directory " + transaction_dir + " is not below " + recovery_root + ".")
    if os.path.islink(os.path.dirname(journal)):
        refuse("Worker transaction directory " + os.path.dirname(journal) + " is a symlink.")
    if not os.path.isdir(transaction_dir):
        refuse("Worker transaction directory " + transaction_dir + " is not a directory.")
    shutil.rmtree(transaction_dir)


if action == "write":
    if journal_state not in STATES:
        refuse("Unknown Worker transaction state " + json.dumps(journal_state) + ".")
    store(journal_state)
elif action == "mark":
    if journal_state not in STATES:
        refuse("Unknown Worker transaction state " + json.dumps(journal_state) + ".")
    if not os.path.lexists(journal):
        raise SystemExit(0)
    read()
    store(journal_state)
elif action == "state":
    print(read().get("state"))
elif action == "remove":
    read()
    remove()
else:
    refuse("Unknown Worker transaction journal action " + json.dumps(action) + ".")
JOURNAL_PY
}

record_worker_transaction_journal() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    if [[ ! "$transaction" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
        echo "Error: A Worker transaction journal needs a valid transaction ID." >&2
        return 1
    fi
    worker_journal_action write "$(worker_transaction_journal "$root" "$transaction")" "$transaction" started
}

mark_worker_transaction_state() {
    local transaction_state="${1:-}"
    local transaction="${2:-}"
    local root="${3:-/var/lib/gowave-auto-nginx}"
    worker_journal_action mark "$(worker_transaction_journal "$root" "$transaction")" "$transaction" "$transaction_state"
}

reconcile_worker_transaction_journals() {
    # Every entrypoint pays for the previous run's crash before it writes
    # anything of its own. A transaction that never reached "installed" is
    # restored from its own before-images and its directory is released; a
    # transaction this product cannot restore, or that already installed but
    # was never finalized, keeps its journal and the new operation is refused,
    # so a half-written host is never built upon. The state root is where the
    # journals live and the host root is where the inventoried paths sit; the
    # two differ only for a test that owns a scratch tree.
    local skip="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local host_root="${3:-/}"
    local journal transaction transaction_dir state failed=0
    [[ "$root" == "/" ]] && root="/var/lib/gowave-auto-nginx"
    local recovery_root="${root%/}/recovery"
    [[ -d "$recovery_root" ]] || return 0
    for journal in "$recovery_root"/*/transaction-journal.json; do
        [[ -e "$journal" ]] || continue
        transaction_dir="$(dirname "$journal")"
        transaction="$(basename "$transaction_dir")"
        [[ -n "$skip" && "$transaction" == "$skip" ]] && continue
        if ! state="$(worker_journal_action state "$journal" "$transaction")"; then
            echo "Error: Uncommitted Worker transaction $transaction cannot be read back; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if [[ "$state" != "started" ]]; then
            echo "Error: Worker transaction $transaction is '$state' and was never finalized; refusing to start a new install and retaining $transaction_dir. Finalize or roll it back first." >&2
            failed=1
            continue
        fi
        if [[ -d "$transaction_dir/worker-targets-before-image" ]] &&
            ! restore_worker_targets_before_image "$host_root" "$transaction_dir/worker-targets-before-image"; then
            echo "Error: Worker transaction $transaction could not be restored to its Worker before-image; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if [[ -d "$transaction_dir/firewall-before-image" ]] &&
            ! restore_firewall_before_image "$host_root" "$transaction_dir/firewall-before-image"; then
            echo "Error: Worker transaction $transaction could not be restored to its firewall before-image; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if ! worker_journal_action remove "$journal" "$transaction"; then
            echo "Error: Worker transaction $transaction was restored but its journal could not be released; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        echo "Reconciled uncommitted Worker transaction $transaction from its before-images." >&2
    done
    return "$failed"
}

# --- package change record -------------------------------------------------
# HOOK-04: a rollback restores the paths this run wrote, never the packages it
# installed. What the package manager changed is therefore recorded while the
# transaction still knows it, so a preserved host can be reported as carrying
# residual state instead of being called clean.

worker_package_record_dir() {
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-}"
    printf '%s\n' "${root%/}/recovery/${transaction}"
}

worker_package_inventory() {
    # One `package<TAB>version` line per installed package, sorted, so two runs
    # of the same host agree byte for byte and a diff of them is the package
    # change a transaction caused.
    if ! command -v dpkg-query >/dev/null 2>&1; then
        return 1
    fi
    dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | LC_ALL=C sort
}

record_worker_package_baseline() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local directory file temporary
    directory="$(worker_package_record_dir "$root" "$transaction")"
    if [[ ! -d "$directory" ]]; then
        echo "Error: The transaction directory $directory is absent, so a package baseline would not belong to a journal." >&2
        return 1
    fi
    file="$directory/packages-before.txt"
    temporary="$(mktemp "$directory/.packages-before.XXXXXX")" || return 1
    if worker_package_inventory >"$temporary" && [[ -s "$temporary" ]]; then
        :
    else
        # A host whose package manager cannot answer is not a host with no
        # packages; the baseline says what it could not learn.
        printf '%s\n' "#unavailable" >"$temporary"
    fi
    if ! chmod 0600 -- "$temporary" || ! sync "$temporary" ||
        ! mv -f -- "$temporary" "$file" || ! sync "$directory"; then
        rm -f -- "$temporary"
        return 1
    fi
}

record_worker_package_changes() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local directory before after changes temporary
    directory="$(worker_package_record_dir "$root" "$transaction")"
    before="$directory/packages-before.txt"
    if [[ ! -f "$before" ]]; then
        echo "Error: The package baseline for $transaction is absent, so the package changes it caused cannot be stated." >&2
        return 1
    fi
    after="$(mktemp "$directory/.packages-after.XXXXXX")" || return 1
    if worker_package_inventory >"$after" && [[ -s "$after" ]]; then
        :
    else
        printf '%s\n' "#unavailable" >"$after"
    fi
    changes="$(mktemp "$directory/.package-changes.XXXXXX")" || {
        rm -f -- "$after"
        return 1
    }
    if [[ "$(head -n 1 "$before")" == "#unavailable" ]] ||
        [[ "$(head -n 1 "$after")" == "#unavailable" ]]; then
        printf '%s\n' "#gowave-package-changes/v1" "#unavailable" >"$changes"
    else
        {
            printf '%s\n' "#gowave-package-changes/v1"
            awk -F'\t' '
                FNR == NR { before[$1] = $2; next }
                { after[$1] = $2 }
                END {
                    for (name in after) {
                        if (!(name in before)) print "installed\t" name "\t" after[name]
                        else if (before[name] != after[name]) print "upgraded\t" name "\t" before[name] "\t" after[name]
                    }
                    for (name in before) if (!(name in after)) print "removed\t" name "\t" before[name]
                }
            ' "$before" "$after" | LC_ALL=C sort
        } >"$changes"
    fi
    rm -f -- "$after"
    if ! chmod 0600 -- "$changes" || ! sync "$changes" ||
        ! mv -f -- "$changes" "$directory/package-changes.tsv" || ! sync "$directory"; then
        rm -f -- "$changes"
        return 1
    fi
}
restore_worker_targets_before_image() {
    worker_targets_image restore "${1:-/}" "${2:-$(worker_targets_before_image)}"
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
    local ownership_record ownership_tmp
    ownership_record=$(deploy_hook_ownership_record "$recovery_root")
    ownership_tmp="${ownership_record}.tmp.$$"
    python3 -c 'import json, os, sys; record, tx_id, path, digest = sys.argv[1:5]; flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0); fd = os.open(record, flags, 0o600); stream = os.fdopen(fd, "w", encoding="utf-8"); json.dump({"transaction_id": tx_id, "path": path, "created_by_tx": True, "sha256": digest}, stream, indent=2); stream.flush(); os.fsync(stream.fileno()); stream.close()' "$ownership_tmp" "$transaction_id" "$hook_file" "$digest" || {
        rm -f -- "$ownership_tmp" || true
        echo "Error: Could not record deploy-hook ownership for later transactions." >&2
        return 1
    }
    if ! chmod 0600 -- "$ownership_tmp" || ! sync "$ownership_tmp" ||
        ! mv -f -- "$ownership_tmp" "$ownership_record" || ! sync "$recovery_root"; then
        rm -f -- "$ownership_tmp" || true
        echo "Error: Could not publish the deploy-hook ownership record." >&2
        return 1
    fi
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
            # A repeated install finds the hook an earlier transaction installed
            # and this transaction never touched. The ownership records name that
            # earlier transaction, so a hook that still hashes to what they
            # recorded is provably the product's own and there is nothing here to
            # undo: refusing would report an incomplete rollback, and demand
            # manual recovery, for a failure that left no side effect behind.
            if python3 - "$hook_file" "$recovery_root" <<'PY'
import hashlib, json, os, sys
hook, root = sys.argv[1], sys.argv[2]
try:
    with open(hook, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
except OSError:
    sys.exit(1)
records = [os.path.join(root, "deploy-hook-ownership.json")]
try:
    records += [os.path.join(root, name, "deploy-hook-manifest.json")
                for name in sorted(os.listdir(root))]
except OSError:
    pass
for record in records:
    try:
        with open(record, encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        continue
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        continue
    if data.get("path") == hook and data.get("sha256") == digest:
        sys.exit(0)
sys.exit(1)
PY
            then
                return 0
            fi
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
    rm -f -- "$(deploy_hook_ownership_record "$recovery_root")" || {
        echo "Error: Could not clear the deploy-hook ownership record after rollback." >&2
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
    local os_id="" os_version="" codename="" key value
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        certbot python3 python3-systemd gnupg \
        curl tar gzip openssl ufw fail2ban iproute2 ca-certificates
    # The Worker installs the same approved NGINX package as the Master: the
    # distribution's nginx-full is replaced by the pinned official build, so it
    # is not requested above and the pin owns the package and Stream module.
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        case "$value" in \"*\"|\'*\') value=${value:1:-1} ;; esac
        case "$key" in
            ID) os_id=$value ;;
            VERSION_ID) os_version=$value ;;
            VERSION_CODENAME) codename=$value ;;
        esac
    done < /etc/os-release
    if [[ -z "$codename" ]]; then
        case "${os_id}-${os_version}" in
            ubuntu-24.04) codename="noble" ;;
            ubuntu-26.04) codename="resolute" ;;
            debian-12) codename="bookworm" ;;
            debian-13) codename="trixie" ;;
        esac
    fi
    install_pinned_nginx "$os_id" "$codename" || return 1
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

materialize_security_helper() {
    # The shared host-security helper is streamed with the payload because the
    # Worker never receives the project checkout at /opt/gowave-auto-nginx. The
    # path is random per call: a fixed name in /tmp is a file another local
    # account can pre-create, and this process writes it as root.
    if [[ -z "${SECURITY_HELPER_B64:-}" ]]; then
        log_warn "Host security helper was not delivered to this Worker."
        return 1
    fi
    local helper
    if ! helper=$(mktemp /tmp/gowave-managed-security.XXXXXX); then
        log_warn "Could not create a path for the host security helper."
        return 1
    fi
    if ! printf '%s' "$SECURITY_HELPER_B64" | base64 -d > "$helper"; then
        rm -f "$helper"
        log_warn "Could not materialize the host security helper."
        return 1
    fi
    chmod 0700 "$helper"
    printf '%s\n' "$helper"
}

configure_dot() {
    local policy="${GOWAVE_DOT_POLICY:-best-effort}"
    local helper output rc=0 status
    # The report keeps the recovery outcome this run observed; an attempt that
    # never happened leaves it unknown, which blocks readiness instead of
    # reading as a pass.
    _DOT_RECOVERY=unknown
    case "$policy" in
        off|best-effort|required) ;;
        *)
            log_warn "Unsupported DNS-over-TLS policy '$policy'; expected off, best-effort or required."
            return 1
            ;;
    esac
    echo "Configuring DNS-over-TLS policy: $policy..."
    helper=$(materialize_security_helper) || return 1
    output=$(GOWAVE_DOT_POLICY="$policy" python3 "$helper" --prepare-dns </dev/null) || rc=$?
    rm -f "$helper"
    printf '%s\n' "$output"
    if [[ "$rc" -eq 0 ]]; then
        _DOT_RECOVERY=not-needed
        return 0
    fi
    status=$(printf '%s' "$output" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("status", ""))
except Exception:
    print("")' 2>/dev/null || true)
    # The helper already restored and verified the resolver for
    # `failed_rolled_back`; only a hard requirement or an unproven rollback stops.
    if [[ "$policy" != "required" && "$status" == "failed_rolled_back" ]]; then
        _DOT_RECOVERY=verified
        log_warn "DNS-over-TLS was not applied; the original resolver state was restored and verified."
        return 0
    fi
    log_warn "DNS-over-TLS policy '$policy' was not applied and the resolver rollback was not verified."
    return 1
}

configure_worker_fail2ban() {
    # Mandatory, unlike DoT: a jail that was never configured and read back
    # leaves the discovered SSH ports protected only by a package install,
    # which the security report must not call verified SSH protection.
    echo "Configuring Fail2ban for the discovered SSH ports..."
    local helper
    helper=$(materialize_security_helper) || return 1
    local rc=0
    python3 "$helper" --configure-fail2ban </dev/null || rc=$?
    rm -f "$helper"
    return "$rc"
}

configure_worker_security_updates() {
    # Same policy and the same read-back as the Master. A host that installs
    # the package but leaves the periodic timers inactive is a host nothing
    # patches on a schedule.
    echo "Configuring unattended security updates..."
    local helper
    helper=$(materialize_security_helper) || return 1
    local rc=0
    python3 "$helper" --configure-apt </dev/null || rc=$?
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
    if ! declare -F configure_dot >/dev/null 2>&1; then
        _DOT_CREATED_BY_US=0
        log_warn "DNS-over-TLS helper unavailable; the Worker resolver remains unhardened."
        if [[ "${GOWAVE_DOT_POLICY:-best-effort}" == "required" ]]; then
            log_warn "Required DNS-over-TLS cannot even be attempted; stopping the Worker installation."
            return 1
        fi
        return 0
    fi
    # configure_dot owns the policy decision: it returns 0 after applying the
    # policy, after `off`, or after a best-effort failure whose resolver
    # rollback it verified. A non-zero result is a `required` failure or an
    # unproven rollback, and neither may finish a Worker installation.
    if configure_dot </dev/null; then
        return 0
    fi
    log_warn "DNS-over-TLS was not applied and its rollback was not verified; stopping the Worker installation."
    return 1
}

configure_host_security() {
    # Keep MTU/file-limit tuning independent from optional BBR support.
    local sysctl_conf="${1:-/etc/sysctl.d/99-gowave-node.conf}"
    mkdir -p "$(dirname "$sysctl_conf")"
    # A file this install did not write is not its to truncate: only our own
    # marker plus our own lines is adopted, and a symlink is never written through.
    if [[ -e "$sysctl_conf" || -L "$sysctl_conf" ]]; then
        if [[ -L "$sysctl_conf" ]] ||
            ! grep -qxF '# Managed by GoWave Auto NGINX' "$sysctl_conf" ||
            grep -qvxF -e '# Managed by GoWave Auto NGINX' \
                -e 'net.ipv4.tcp_mtu_probing = 1' \
                -e 'fs.file-max = 1048576' \
                -e 'net.core.default_qdisc = fq' \
                -e 'net.ipv4.tcp_congestion_control = bbr' "$sysctl_conf"; then
            echo "Error: Pre-existing unmanaged sysctl configuration at $sysctl_conf. Refusing to overwrite unmanaged host resource." >&2
            _SYSCTL_CREATED_BY_US=0
            return 1
        fi
    else
        _SYSCTL_CREATED_BY_US=1
    fi
    modprobe tcp_bbr 2>/dev/null || true
    local sysctl_tmp
    sysctl_tmp=$(mktemp "${sysctl_conf}.gowave.XXXXXX") || return 1
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
    } > "$sysctl_tmp" || { rm -f "$sysctl_tmp"; return 1; }
    chmod 0644 "$sysctl_tmp" || { rm -f "$sysctl_tmp"; return 1; }
    sync "$sysctl_tmp" 2>/dev/null || true
    mv -f "$sysctl_tmp" "$sysctl_conf" || { rm -f "$sysctl_tmp"; return 1; }
    sync "$(dirname "$sysctl_conf")" 2>/dev/null || true
    sysctl -p "$sysctl_conf"

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
    # stalls tunnel setup for the full resolver timeout. Encrypted DNS over
    # TCP/853 with retransmission keeps the Worker's data plane reliable when
    # the operator asked for it; `off` leaves the resolver alone.
    configure_worker_dot
}

# Whether this host has IPv6 is decided by the address table's content, never
# by its size: procfs reports a zero inode size for /proc/net/if_inet6 however
# many addresses it prints.
kernel_has_ipv6() {
    local if_inet6="${1:-/proc/net/if_inet6}"
    [[ -f "$if_inet6" ]] && grep -q '[^[:space:]]' "$if_inet6" 2>/dev/null
}

worker_firewall_policy_json() {
    local ipv6=false
    if kernel_has_ipv6; then ipv6=true; fi
    python3 - "${NODE_PORT:?}" "${PANEL_IP:-}" "${PANEL_IPV6:-}" "$ipv6" <<'PY' | python3 -c 'import base64, os; exec(compile(base64.b64decode(os.environ["SECURITY_HELPER_B64"], validate=True), "managed.py", "exec"))' --firewall-policy
import json, sys
port, v4, v6, ipv6 = sys.argv[1:]
json.dump({'role': 'worker', 'node_port': int(port), 'master_sources': [value for value in (v4, v6) if value], 'ipv6': ipv6 == 'true'}, sys.stdout)
PY
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

    # The rules come from the shared helper, so the ports this Worker opens are
    # the policy a Master would apply to a Node host — not a hand-written list
    # that can drift from it. The policy is preflighted against the persisted
    # UFW state, applied verbatim and read back from the running kernel; a
    # failure after the first mutation restores the captured baseline.
    local policy preflight helper preserved rules rc=0
    if ! policy=$(worker_firewall_policy_json); then
        echo "Fatal: the Worker firewall policy could not be derived; refusing to change a firewall without one." >&2
        return 1
    fi
    helper=$(materialize_security_helper) || return 1
    # An existing unrestricted NODE_PORT allow is a preflight conflict, so the
    # new source-specific rule cannot be described as making that port private.
    if ! preflight=$(printf '%s' "$policy" | python3 -c 'import json,sys
json.dump(json.load(sys.stdin)["policy"], sys.stdout)' | python3 "$helper" --firewall-preflight /); then
        rm -f "$helper"
        printf 'Fatal: %s\n' "$(printf '%s' "$preflight" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("error", "firewall preflight failed"))
except Exception:
    print("firewall preflight failed")' 2>/dev/null || echo "firewall preflight failed")" >&2
        echo "Fatal: the managed Worker ingress conflicts with existing firewall policy; resolve it before retrying." >&2
        return 1
    fi
    preserved=$(printf '%s' "$preflight" | python3 -c 'import json,sys
try:
    print(len(json.load(sys.stdin).get("preserved_exceptions", [])))
except Exception:
    print(0)' 2>/dev/null || echo 0)
    if [[ "$preserved" != "0" ]]; then
        echo "Firewall preflight preserved $preserved unrelated administrator allow rule(s)." >&2
    fi

    # What the firewall read before the first rule changes, in the transaction's
    # own recovery directory: the rollback restores this, not "our rules removed
    # from whatever is left". A baseline this install cannot read back and
    # restore is refused here, before anything is mutated.
    record_firewall_before_image || { rm -f "$helper"; return 1; }

    if ufw status 2>/dev/null | grep -q '^Status: active'; then
        _UFW_WAS_ACTIVE=1
    else
        _UFW_WAS_ACTIVE=0
    fi
    _UFW_RULES_CONFIGURED=1

    if ! rules=$(printf '%s' "$policy" | python3 -c 'import json,sys
policy = json.load(sys.stdin)["policy"]
for command in policy.get("commands", []):
    print("\x1f".join(str(token) for token in command))'); then
        rm -f "$helper"
        echo "Fatal: the prepared Worker firewall policy is not readable." >&2
        return 1
    fi
    local -a rule
    while IFS=$'\x1f' read -r -a rule; do
        [[ "${#rule[@]}" -gt 0 ]] || continue
        # The rule is echoed before it runs: an operator reading a failed
        # install sees the last rule UFW accepted, not only the error.
        printf 'UFW: %s\n' "${rule[*]}"
        if [[ "${rule[0]}" == "default" ]]; then
            if ! ufw "${rule[@]}" </dev/null; then
                rc=1
                break
            fi
        elif ! ufw "${rule[@]}" comment "GoWave Auto NGINX" </dev/null; then
            rc=1
            break
        fi
    done <<< "$rules"

    # UFW's own declaration has to follow the same host decision the listeners
    # render, or the distro default claims a v6 stack this host does not have
    # (and, where that default is ``no``, leaves a v6 listener unfiltered).
    if [[ "$rc" -eq 0 && -f "$ufw_default" ]]; then
        if kernel_has_ipv6; then
            sed -i 's/^IPV6=.*/IPV6=yes/' "$ufw_default" || true
        else
            sed -i 's/^IPV6=.*/IPV6=no/' "$ufw_default" || true
        fi
    fi
    if [[ "$rc" -eq 0 ]]; then
        if ! ufw --force enable </dev/null || ! ufw status 2>/dev/null | grep -q '^Status: active$'; then
            echo "Error: UFW did not enter the active state." >&2
            rc=1
        fi
    fi

    if [[ "$rc" -eq 0 ]]; then
        local verdict
        if ! verdict=$(printf '%s' "$policy" | python3 -c 'import json,sys
json.dump(json.load(sys.stdin)["policy"], sys.stdout)' | python3 "$helper" --firewall-verify /); then
            printf 'Error: %s\n' "$(printf '%s' "$verdict" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin).get("error", "firewall verification failed"))
except Exception:
    print("firewall verification failed")' 2>/dev/null || echo "firewall verification failed")" >&2
            rc=1
        fi
    fi
    rm -f "$helper"

    if [[ "$rc" -ne 0 ]]; then
        # One restoration attempt: the outer compensation must not replay it over
        # a state this attempt already rewrote.
        _UFW_RULES_CONFIGURED=0
        if restore_firewall_before_image; then
            echo "Fatal: the Worker ingress could not be applied and verified; the firewall baseline was restored." >&2
        else
            echo "CRITICAL: the Worker ingress failed and the firewall baseline could not be restored; the before-image is retained for operator intervention." >&2
        fi
        return 1
    fi
}

write_worker_security_report() {
    # One report per Worker, produced from effective state: the helper reads the
    # firewall, the jail, the update schedule and the resolver back, so the file
    # describes this host now instead of restating the steps this run printed.
    local helper request output rc=0 ipv6=false
    if kernel_has_ipv6; then ipv6=true; fi
    helper=$(materialize_security_helper) || return 1
    request=$(python3 - "${NODE_PORT:-3002}" "${PANEL_IP:-}" "${PANEL_IPV6:-}" \
        "${GOWAVE_DOT_POLICY:-best-effort}" "${_DOT_RECOVERY:-unknown}" "$ipv6" <<'PY'
import json, sys
port, v4, v6, policy, recovery, ipv6 = sys.argv[1:]
json.dump({'role': 'worker', 'node_port': int(port),
           'master_sources': [value for value in (v4, v6) if value],
           'ipv6': ipv6 == 'true', 'dot_policy': policy,
           'dot_recovery': recovery}, sys.stdout)
PY
    ) || { rm -f "$helper"; return 1; }
    output=$(printf '%s' "$request" | python3 "$helper" --security-report) || rc=$?
    rm -f "$helper"
    printf '%s\n' "$output"
    if [[ "$rc" -ne 0 ]]; then
        log_warn "This Worker is not ready for deployment; the security report names the control that failed."
        return 1
    fi
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

# A Worker owns no cover apex. Its camouflage site is served under its own
# camouflage name, which is also its REALITY SNI, so this payload carries no
# apex decision at all: there is no suffix to derive and no name a shared zone
# could lend it. Only the brand helper is needed, because the decoy is rendered
# from a domain like the Master's is.
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

# The edge identity this Worker serves right now, read from the files this
# product manages: one `sni <name> <backend>` line per stream map entry and one
# `cert <role> <live directory>` line per listener. An empty answer is a host
# that serves no Worker edge yet, which is a first install rather than a
# migration. A managed path that is a symlink or not a regular file is refused
# instead of followed, exactly as the install refuses to write through one.
worker_edge_identity() {
    local stream_file="${1:-/etc/nginx/stream-enabled/gowave-worker-stream.conf}"
    local conf_dir="${2:-/etc/nginx/conf.d}"
    python3 - "$stream_file" "$conf_dir" <<'PY'
import os
import re
import sys

stream_file, conf_dir = sys.argv[1:3]


def managed(path):
    if not os.path.lexists(path):
        return ""
    if os.path.islink(path) or not os.path.isfile(path):
        sys.stderr.write(
            "Error: %s is not a regular file; refusing to read a managed Worker "
            "listener through it.\n" % path
        )
        raise SystemExit(1)
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except OSError as exc:
        sys.stderr.write("Error: cannot read %s: %s.\n" % (path, exc.__class__.__name__))
        raise SystemExit(1)


def stream_entries(body):
    block = re.search(
        r"map\s+\$ssl_preread_server_name\s+\$worker_dest\s*\{(.*?)\}",
        body, re.DOTALL,
    )
    if not block:
        return []
    entries = []
    for match in re.finditer(r"^\s*(\S+)\s+(127\.0\.0\.1:\d+);", block.group(1), re.MULTILINE):
        entries.append("sni %s %s" % (match.group(1), match.group(2)))
    return entries


def certificate_directory(body):
    match = re.search(r"^\s*ssl_certificate\s+([^;]+);", body, re.MULTILINE)
    if not match:
        return ""
    path = match.group(1).strip()
    return os.path.dirname(path) if path.endswith("/fullchain.pem") else ""


for entry in stream_entries(managed(stream_file)):
    print(entry)
for role, name in (("worker", "gowave-worker-https.conf"),
                   ("reality", "gowave-worker-decoy.conf"),
                   ("vision", "gowave-worker-vision-fallback.conf")):
    directory = certificate_directory(managed(os.path.join(conf_dir, name)))
    if directory:
        print("cert %s %s" % (role, directory))
PY
}

# The edge identity this run is about to serve, from the values the controller
# streamed and the lineages the run selected.
worker_target_edge_identity() {
    local worker_live="$1"
    local reality_live="$2"
    local vision_live="${3:-}"
    printf 'sni %s 127.0.0.1:7443\n' "$WORKER_DOMAIN"
    printf 'sni %s 127.0.0.1:8443\n' "$REALITY_DOMAIN"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        printf 'sni %s 127.0.0.1:8444\n' "$VISION_DOMAIN"
    fi
    printf 'sni default 127.0.0.1:8443\n'
    printf 'cert worker %s\n' "$worker_live"
    printf 'cert reality %s\n' "$reality_live"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        printf 'cert vision %s\n' "$vision_live"
    fi
}

# require_worker_edge_migration_confirmation WORKER_LIVE_DIR REALITY_LIVE_DIR [VISION_LIVE_DIR] [STREAM_FILE] [CONF_DIR]
#
# Rewriting an installed Worker's routes and certificate references is a
# migration, not a repair: it changes what every client of this host reaches.
# The two identities are therefore printed and compared before the first managed
# path is touched, and a difference needs the controller's confirmation
# (GOWAVE_MIGRATE_EXISTING=yes, which `node reapply` sends only after its own
# prompt). A host that serves nothing yet, or already serves exactly this
# identity, is not a migration and needs none. The last two arguments name where
# the managed files live; the install leaves them at their defaults.
require_worker_edge_migration_confirmation() {
    local worker_live="$1"
    local reality_live="$2"
    local vision_live="${3:-}"
    local stream_file="${4:-/etc/nginx/stream-enabled/gowave-worker-stream.conf}"
    local conf_dir="${5:-/etc/nginx/conf.d}"
    local current desired

    current=$(worker_edge_identity "$stream_file" "$conf_dir") || return 1
    desired=$(worker_target_edge_identity "$worker_live" "$reality_live" "$vision_live") || return 1

    if [[ -z "$current" ]]; then
        echo "[MIGRATION] No managed Worker edge is installed on this host; nothing to migrate."
        return 0
    fi

    current=$(printf '%s\n' "$current" | LC_ALL=C sort)
    desired=$(printf '%s\n' "$desired" | LC_ALL=C sort)

    if [[ "$current" == "$desired" ]]; then
        echo "[MIGRATION] The managed Worker edge already serves this identity; nothing to migrate."
        return 0
    fi

    echo "[MIGRATION] Edge identity currently served by this Worker:"
    printf '%s\n' "$current" | while IFS= read -r entry; do
        [[ -n "$entry" ]] && printf '[MIGRATION]   %s\n' "$entry"
    done
    echo "[MIGRATION] Edge identity this run will serve:"
    printf '%s\n' "$desired" | while IFS= read -r entry; do
        [[ -n "$entry" ]] && printf '[MIGRATION]   %s\n' "$entry"
    done

    if [[ "${GOWAVE_MIGRATE_EXISTING:-no}" == "yes" ]]; then
        echo "[MIGRATION] Migration confirmed by GOWAVE_MIGRATE_EXISTING=yes."
        return 0
    fi
    echo "Error: this Worker already serves a different edge identity, and nothing may be rewritten without an explicit migration confirmation." >&2
    echo "Re-run the controller's 'node reapply' for this host: it shows the preview, asks for confirmation and streams GOWAVE_MIGRATE_EXISTING=yes." >&2
    return 1
}

# verify_renewal_dry_run LINEAGE [CERTBOT_ARGS...]
# The issuance that just succeeded says nothing about renewal: the port-80
# webroot vhost, the authenticator recorded in `renewal/<lineage>.conf` and the
# deploy hook all take part only when a renewal runs. A dry run revalidates one
# named lineage through that recorded path while NGINX serves, and it stores no
# certificate, so a Worker can run it without touching the Master's lineages.
verify_renewal_dry_run() {
    local lineage="${1:?a lineage name is required}"
    shift
    echo "Verifying renewal of the $lineage lineage with a dry run..."
    run_certbot renew --dry-run --cert-name "$lineage" --non-interactive "$@"
}

configure_edge_nginx() {
    # The live directories are the ones this run selected, passed in rather than
    # re-derived: a suffixed lineage (`cover2.example.net-0001`) is served from the
    # path that was checked, and the heredocs below are rendered from that same
    # value, so no listener points at a lineage the run did not verify.
    local worker_live="${1:-/etc/letsencrypt/live/$WORKER_DOMAIN}"
    local reality_live="${2:-/etc/letsencrypt/live/$REALITY_DOMAIN}"
    local vision_live="${3:-${VISION_DOMAIN:+/etc/letsencrypt/live/$VISION_DOMAIN}}"
    local worker_lineage reality_lineage vision_lineage
    worker_lineage=$(basename -- "$worker_live")
    reality_lineage=$(basename -- "$reality_live")
    if [[ -n "$vision_live" ]]; then
        vision_lineage=$(basename -- "$vision_live")
    fi

    mkdir -p /etc/nginx/stream-enabled /etc/nginx/conf.d /var/www/gowave-acme
    chmod 0755 /var/www/gowave-acme

    # This Worker owns no cover apex. Its camouflage site is served under its
    # own camouflage name on port 443 and under its primary name on the edge
    # listener, so no apex or `www` name is inferred, requested from ACME or
    # routed here: a name a shared zone lends the Master stays with the Master.

    # Port 80 ACME webroot vhost. It stays in place after issuance: certbot's
    # HTTP-01 renewal revalidates through this same path, so removing it makes
    # every later `certbot renew` fail with a 404. A managed name keeps an
    # ordinary HTTPS visit; a host this Worker was never configured with is
    # refused, which is also what keeps a shared zone's apex from being served.
    local managed_http_regex="${WORKER_DOMAIN//./\\.}|${REALITY_DOMAIN//./\\.}"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        managed_http_regex+="|${VISION_DOMAIN//./\\.}"
    fi
    cat > /etc/nginx/conf.d/00-worker-acme-challenge.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Port 80 ACME Challenge
server {
    listen 80;
    server_name $WORKER_DOMAIN $REALITY_DOMAIN ${VISION_DOMAIN:-};
    location /.well-known/acme-challenge/ {
        root /var/www/gowave-acme;
    }
    location / {
        if (\$host ~* ^(${managed_http_regex})\$) {
            return 301 https://\$host\$request_uri;
        }
        return 444;
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
        -d "$WORKER_DOMAIN" --cert-name "$worker_lineage" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring \
        "${certbot_extra_args[@]}"
    _ACME_WORKER_ISSUED=1

    echo "Acquiring Let's Encrypt TLS certificate for REALITY decoy ($REALITY_DOMAIN)..."
    # One lineage backs the probe fallback and the camouflage site this Worker
    # serves. It names the Worker's own camouflage name only: no apex or `www`
    # of a shared zone is requested here, so a same-zone Master keeps its pair.
    run_certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$REALITY_DOMAIN" --cert-name "$reality_lineage" \
        --non-interactive --agree-tos -m "$ADMIN_EMAIL" --keep-until-expiring \
        "${certbot_extra_args[@]}"
    _ACME_REALITY_ISSUED=1

    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        echo "Acquiring Let's Encrypt TLS certificate for Vision ($VISION_DOMAIN)..."
        run_certbot certonly --webroot -w /var/www/gowave-acme \
            -d "$VISION_DOMAIN" --cert-name "$vision_lineage" \
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
    verify_worker_certificate "$WORKER_DOMAIN" "$worker_live"
    verify_worker_certificate "$REALITY_DOMAIN" "$reality_live"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        verify_worker_certificate "$VISION_DOMAIN" "$vision_live"
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
    cat > /etc/nginx/stream-enabled/gowave-worker-stream.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Stream
# Same edge log as the Master: the Worker's 443 is the surface a client meets,
# so an operator diagnosing "did this node carry the connection" reads here.
log_format gowave_edge '\$ssl_preread_server_name \$ssl_preread_protocol \$remote_addr \$server_port \$time_iso8601';
access_log /var/log/nginx/gowave-edge-access.log gowave_edge;
map \$ssl_preread_server_name \$worker_dest {
    $WORKER_DOMAIN 127.0.0.1:7443;
    $REALITY_DOMAIN 127.0.0.1:8443;
$worker_vision
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
    server_tokens off;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate $worker_live/fullchain.pem;
    ssl_certificate_key $worker_live/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # The primary name is an ordinary website: the root and every known asset
    # are the rendered cover site, and an unknown path keeps the brand's own
    # 404 page instead of a bare server error.
    root /var/www/gowave-auto-nginx/cover-reality;
    index index.html;
    error_page 404 /404.html;

    # No Panel runs on a Worker. Its management and subscription surface is
    # refused before static handling, so a probe reads no control content and
    # nothing reaches a transport.
    location ^~ /api/ {
        return 444;
    }

    location ^~ /xhttp-down/ {
        grpc_pass grpc://127.0.0.1:10001;
        client_max_body_size 0;
        client_body_timeout 1h;
        grpc_read_timeout 1h;
        grpc_send_timeout 1h;
        grpc_set_header Connection "";
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$remote_addr;
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
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # Decoy on 9443
    cat > /etc/nginx/conf.d/gowave-worker-decoy.conf <<EOF
# Managed by GoWave Auto NGINX: Worker Edge Decoy
server {
    $listen_9443
    server_name $REALITY_DOMAIN;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
    ssl_protocols TLSv1.3;

    ssl_certificate $reality_live/fullchain.pem;
    ssl_certificate_key $reality_live/privkey.pem;

    root /var/www/gowave-auto-nginx/cover-reality;
    index index.html;
    error_page 404 /404.html;
    access_log /var/log/nginx/gowave-decoy-access.log;
}
EOF
    render_cover_site "/var/www/gowave-auto-nginx/cover-reality" "$REALITY_DOMAIN" || return 1

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

    # The production vhost is live, so this is the path the next renewal takes:
    # the dry run proves that path answers while storing no certificate. Only the
    # lineages this Worker owns are named, so a shared zone's Master pair is
    # never revalidated from here.
    local owned_lineage
    for owned_lineage in "$worker_lineage" "$reality_lineage" ${vision_lineage:+"$vision_lineage"}; do
        verify_renewal_dry_run "$owned_lineage" "${certbot_extra_args[@]}" || {
            echo "Fatal: the renewal dry run for $owned_lineage failed; this Worker would not renew." >&2
            return 1
        }
    done
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

# The pinned core is placed before the upstream installer runs, because an
# executable rw-core is what makes install.sh skip its own api.github.com
# purchase. The table is a copy of modules/xray_core.sh: this payload is one
# file streamed over SSH and cannot source modules/.
GOWAVE_PINNED_XRAY_VERSION="26.11.9"
GOWAVE_PINNED_XRAY_AMD64_URL="https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-64.zip"
GOWAVE_PINNED_XRAY_AMD64_SHA256="b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"
GOWAVE_PINNED_XRAY_ARM64_URL="https://github.com/XTLS/Xray-core/releases/download/v26.11.9/Xray-linux-arm64-v8a.zip"
GOWAVE_PINNED_XRAY_ARM64_SHA256="64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be"

pinned_xray_artifact() {
    local version="${1#v}"
    local arch="$2"

    [[ "$version" == "$GOWAVE_PINNED_XRAY_VERSION" ]] || return 1
    case "$arch" in
        amd64) printf '%s %s\n' "$GOWAVE_PINNED_XRAY_AMD64_URL" "$GOWAVE_PINNED_XRAY_AMD64_SHA256" ;;
        arm64) printf '%s %s\n' "$GOWAVE_PINNED_XRAY_ARM64_URL" "$GOWAVE_PINNED_XRAY_ARM64_SHA256" ;;
        *) return 1 ;;
    esac
}

pinned_xray_arch() {
    local m
    m=$(uname -m)
    case "$m" in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)
            log_err "Unsupported architecture: $m"
            return 1
            ;;
    esac
}

pinned_xray_fail() {
    local reason="$1"
    local artifact="${2:-}"
    local subject="pinned Xray core $GOWAVE_PINNED_XRAY_VERSION"
    local opt_out="Set XRAY_SERVER_VERSION=latest to let the upstream installer fetch a core instead."

    if [[ -n "$artifact" ]]; then
        log_err "$subject could not be installed from $artifact: $reason. $opt_out"
    else
        log_err "$subject could not be installed: $reason. $opt_out"
    fi
    return 1
}

pinned_xray_deliver() {
    local scratch="$1"
    local install_dir="$2"
    local url="$3"
    local digest="$4"
    local zip="$scratch/Xray.zip"
    local member="$scratch/xray"
    local reported=""
    local fetch_rc=0

    fetch_verified_artifact "$zip" "Xray core $GOWAVE_PINNED_XRAY_VERSION" "$url" "$digest" || fetch_rc=$?
    if (( fetch_rc == 2 )); then
        pinned_xray_fail "the archive did not match the pinned SHA-256" "$url"
        return 1
    elif (( fetch_rc != 0 )); then
        pinned_xray_fail "no artifact host delivered the archive" "$url"
        return 1
    fi

    if ! python3 - "$zip" "$member" <<'PY'
import sys
import zipfile

archive, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as bundle, bundle.open("xray") as src, open(dest, "wb") as out:
    out.write(src.read())
PY
    then
        pinned_xray_fail "the archive carries no readable xray member" "$url"
        return 1
    fi

    chmod 0755 "$member"
    reported=$("$member" version 2>/dev/null || true)
    if ! core_version_matches "$reported" "$GOWAVE_PINNED_XRAY_VERSION"; then
        pinned_xray_fail "the extracted core reports ${reported:-nothing}, not $GOWAVE_PINNED_XRAY_VERSION" "$url"
        return 1
    fi

    mkdir -p "$install_dir"
    local staged="$install_dir/.rw-core.pinned.$$"
    rm -f -- "$staged"
    if ! install -m 0755 -- "$member" "$staged"; then
        pinned_xray_fail "the verified core could not be staged in $install_dir" "$url"
        return 1
    fi
    sync "$staged" 2>/dev/null || true
    if ! mv -f -- "$staged" "$install_dir/rw-core"; then
        rm -f -- "$staged" || true
        pinned_xray_fail "the verified core could not be installed at $install_dir/rw-core" "$url"
        return 1
    fi
    sync "$install_dir" 2>/dev/null || true

    log_info "Installed pinned Xray core $GOWAVE_PINNED_XRAY_VERSION from $url (SHA-256 $digest)."
}

install_pinned_xray_core() {
    local install_dir="${1:?an install directory is required}"
    local requested="${XRAY_SERVER_VERSION:-}"
    local version="${requested,,}"

    if [[ -n "$version" ]]; then
        version="${version#v}"
        [[ "$version" == "$GOWAVE_PINNED_XRAY_VERSION" ]] || return 0
    fi

    local arch="" artifact=""
    if ! arch=$(pinned_xray_arch 2>/dev/null); then
        pinned_xray_fail "the host architecture is not described by the pin table"
        return 1
    fi
    if ! artifact=$(pinned_xray_artifact "$GOWAVE_PINNED_XRAY_VERSION" "$arch"); then
        pinned_xray_fail "no artifact is pinned for architecture $arch"
        return 1
    fi

    local url="${artifact% *}"
    local digest="${artifact##* }"
    local dest="$install_dir/rw-core"

    if [[ -x "$dest" ]]; then
        local reported
        reported=$("$dest" version 2>/dev/null || true)
        if core_version_matches "$reported" "$GOWAVE_PINNED_XRAY_VERSION"; then
            return 0
        fi
    fi

    local scratch rc=0
    scratch=$(mktemp -d "/tmp/gowave-xray-core-XXXXXX")
    pinned_xray_deliver "$scratch" "$install_dir" "$url" "$digest" || rc=$?
    rm -rf -- "$scratch"
    return "$rc"
}

# gowave-node resolves the Xray core through one HTTPS GET to api.github.com with
# a 10-second deadline and no retry of its own, so a single slow answer ends a
# Worker whose whole provisioning then rolls back. A repeat is the only repair such
# a hiccup has, while a configuration error would only print itself twice: the
# retry is therefore limited to failures whose own stderr names a network fault.
NODE_INSTALLER_ATTEMPTS=3
NODE_INSTALLER_RETRY_DELAYS=(10 30)
NODE_INSTALLER_NETWORK_FAULTS='context deadline exceeded|i/o timeout|TLS handshake timeout|Client\.Timeout|Temporary failure in name resolution|Could not resolve host|Connection reset by peer|Connection refused|network is unreachable|No route to host|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout'

node_installer_stderr_names_network_fault() {
    grep -Eqi "$NODE_INSTALLER_NETWORK_FAULTS" "$1"
}

# run_node_installer_with_retry INSTALLER SECRET_KEY NODE_PORT VERSION
#
# The installer's stderr is captured so the finished attempt can be classified;
# it is replayed to stderr at once, so the payload's own output keeps both streams
# apart exactly as the operator's SSH session receives them.
run_node_installer_with_retry() {
    local installer="$1"
    local secret_key="$2"
    local node_port="$3"
    local version="$4"
    local attempt=1 rc=0 workdir stdout_log stderr_log delay

    workdir=$(mktemp -d "/tmp/gowave-node-install-attempts-XXXXXX")
    while : ; do
        stdout_log="$workdir/attempt-$attempt.stdout.log"
        stderr_log="$workdir/attempt-$attempt.stderr.log"
        rc=0
        if ! (
            export SECRET_KEY="$secret_key"
            export NODE_PORT="$node_port"
            export GOWAVE_NODE_VERSION="$version"
            bash "$installer" </dev/null
        ) 2>"$stderr_log" | tee "$stdout_log"; then
            rc=${PIPESTATUS[0]}
        fi
        cat "$stderr_log" >&2 || true
        if (( rc == 0 )); then
            break
        fi
        if (( attempt >= NODE_INSTALLER_ATTEMPTS )) ||
            ! node_installer_stderr_names_network_fault "$stderr_log"; then
            break
        fi
        delay=${NODE_INSTALLER_RETRY_DELAYS[$(( attempt - 1 ))]}
        echo "GoWave Node installer failed on a network fault (exit $rc); retrying in ${delay}s (attempt $(( attempt + 1 )) of $NODE_INSTALLER_ATTEMPTS)..."
        sleep "$delay"
        attempt=$(( attempt + 1 ))
    done
    rm -rf -- "$workdir"
    return "$rc"
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
    # The core goes in before the installer is even fetched, so a failed pin
    # leaves no installer temp file behind.
    install_pinned_xray_core "/opt/gowave-node" || return 1
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
    if run_node_installer_with_retry "$tmp_inst" "${SECRET_KEY:-}" "${NODE_PORT:-}" "$normalized_node_ver"; then
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

    # The state root is where this transaction recorded its before-images and
    # its ACME snapshot, and the host root is the tree those records describe.
    # Both are the host itself for a real run, and they are the same two things
    # a reconcile of the same journal is given. The service manager, the firewall
    # and the swap, sysctl and NGINX files belong to the host rather than to the
    # record, and stay where they are.
    local state_root="${WORKER_STATE_ROOT:-/var/lib/gowave-auto-nginx}"
    local host_root="${WORKER_HOST_ROOT:-/}"

    # The before-image is the first thing this run captures and the
    # only thing a rollback restores from. Without it nothing this run
    # wrote can be proven and undone, so the refusal that stopped the
    # run is the whole outcome and the steps below have nothing to do.
    if [[ -z "${_ACME_TX_ID:-}" ]] ||
        [[ ! -d "$(worker_targets_before_image "$state_root" "$_ACME_TX_ID")" ]]; then
        echo "[ROLLBACK] No Worker before-image was captured; nothing to compensate." >&2
        return "$exit_code"
    fi

    # A rollback puts the paths back and leaves the packages installed. The
    # delta is recorded here, before the paths are restored, so the teardown
    # report can name the residue instead of calling the host clean.
    record_worker_package_changes "$_ACME_TX_ID" "$state_root" ||
        echo "[ROLLBACK] The package changes this transaction caused could not be recorded; they stay on the host unrecorded." >&2

    # 1. Stop and remove GoWave Node and Xray systemd services
    if [[ "${_NODE_SERVICE_CONFIGURED:-0}" -eq 1 ]] || systemctl list-unit-files gowave-node.service 2>/dev/null | grep -q gowave-node; then
        echo "[ROLLBACK] Stopping and disabling gowave-node.service and drop-ins..." >&2
        # Xray is supervised by gowave-node in this product and the upstream
        # installer may leave no unit of its own, so an absent unit is a clean
        # host rather than a failed cleanup: only a unit that exists is stopped.
        for unit in gowave-node.service xray.service; do
            if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "^$unit" ||
                systemctl is-active --quiet "$unit" 2>/dev/null; then
                systemctl stop "$unit" 2>/dev/null || rollback_failed=1
                systemctl disable "$unit" 2>/dev/null || rollback_failed=1
            fi
        done
        systemctl daemon-reload 2>/dev/null || rollback_failed=1
    fi

    # The inventoried paths come back from the transaction's before-image, and
    # only from it: a path that did not exist is removed only while the ownership
    # record still matches it, a path that was here is restored with its content
    # and metadata, and one changed afterwards is preserved with the cleanup
    # reported incomplete. The image is named from this transaction, as the
    # capture named it: the ambient ACME_TX_ID is empty on a fresh install, so a
    # default lookup would read an image no transaction wrote.
    restore_worker_targets_before_image \
        "$host_root" "$(worker_targets_before_image "$state_root" "$_ACME_TX_ID")" ||
        rollback_failed=1

    # 2. Revert NGINX and ACME bootstrap
    if [[ "${_NGINX_CONFIGS_CREATED:-0}" -eq 1 ]] || [[ "${_NGINX_BOOTSTRAP_CREATED:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Cleaning up worker NGINX virtual hosts and stream routing..." >&2
        rollback_managed_deploy_hook "${_ACME_TX_ID:-}" "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" 2>/dev/null || rollback_failed=1
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
        if [[ -d /var/www/gowave-auto-nginx ]]; then
            rmdir /var/www/gowave-auto-nginx 2>/dev/null || rollback_failed=1
        fi
    fi

    # 4. Revert ACME certificates
    if [[ -n "${_ACME_TX_ID:-}" ]]; then
        echo "[ROLLBACK] Restoring or cleaning up ACME certificates via snapshot..." >&2
        # Restored under the lineage this run snapshotted: the plain name has no
        # manifest when a suffixed lineage was adopted, and restoring nothing there
        # would leave an issued certificate behind a rollback that claims to be done.
        restore_acme_lineage "$_ACME_TX_ID" "${_WORKER_LINEAGE:-$WORKER_DOMAIN}" "$state_root/recovery" "$host_root/etc/letsencrypt" 2>/dev/null || rollback_failed=1
        restore_acme_lineage "$_ACME_TX_ID" "${_REALITY_LINEAGE:-$REALITY_DOMAIN}" "$state_root/recovery" "$host_root/etc/letsencrypt" 2>/dev/null || rollback_failed=1
        if [[ -n "${VISION_DOMAIN:-}" ]]; then
            restore_acme_lineage "$_ACME_TX_ID" "${_VISION_LINEAGE:-$VISION_DOMAIN}" "$state_root/recovery" "$host_root/etc/letsencrypt" 2>/dev/null || rollback_failed=1
        fi
    else
        worker_lineage="${_WORKER_LINEAGE:-$WORKER_DOMAIN}"
        if [[ "${_ACME_WORKER_ISSUED:-0}" -eq 1 ]] && [[ -n "${WORKER_DOMAIN:-}" ]]; then
            echo "[ROLLBACK] Deleting ACME certificate for $worker_lineage..." >&2
            certbot delete --cert-name "$worker_lineage" --non-interactive 2>/dev/null || rollback_failed=1
            rm -rf "/etc/letsencrypt/live/$worker_lineage" "/etc/letsencrypt/archive/$worker_lineage" "/etc/letsencrypt/renewal/$worker_lineage.conf" 2>/dev/null || rollback_failed=1
        fi
        reality_lineage="${_REALITY_LINEAGE:-$REALITY_DOMAIN}"
        if [[ "${_ACME_REALITY_ISSUED:-0}" -eq 1 ]] && [[ -n "${REALITY_DOMAIN:-}" ]]; then
            echo "[ROLLBACK] Deleting ACME certificate for $reality_lineage..." >&2
            certbot delete --cert-name "$reality_lineage" --non-interactive 2>/dev/null || rollback_failed=1
            rm -rf "/etc/letsencrypt/live/$reality_lineage" "/etc/letsencrypt/archive/$reality_lineage" "/etc/letsencrypt/renewal/$reality_lineage.conf" 2>/dev/null || rollback_failed=1
        fi
    fi

    # 5. Restore the UFW firewall before-image. Deleting the four rules this
    # install adds returns a firewall that never had them to the wrong state:
    # the operator's own rules, the default policies and the enabled state are
    # part of what this transaction changed.
    if [[ "${_UFW_RULES_CONFIGURED:-0}" -eq 1 ]]; then
        echo "[ROLLBACK] Restoring the UFW firewall before-image..." >&2
        restore_firewall_before_image || rollback_failed=1
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
    rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.* /tmp/gowave-node-install-*.sh /run/gowave-acme-test-ca.pem || rollback_failed=1

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
set -Eeuo pipefail
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

    _COMPENSATED=0
    cleanup_temp_and_secrets() {
        unset _NODE_SECRET_KEY SECRET_KEY VERIFY_NODE_MTLS_B64 SECURITY_HELPER_B64 GOWAVE_ACME_TEST_CA_B64 2>/dev/null || true
        rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.* /tmp/gowave-node-install-*.sh /run/gowave-acme-test-ca.pem 2>/dev/null || true
    }
    compensate_once() {
        # One compensation per run. A signal, a failing step and the EXIT trap
        # all reach the same failure, and the compensator hands back the exit
        # code it was given — so its nonzero return would re-enter the ERR trap
        # and run the rollback a second time over a host the first pass already
        # put back. The trap is disarmed before the rollback starts, and the
        # flag closes the door for a signal that arrives while it runs.
        local exit_code="${1:-1}"
        [[ "${_COMPENSATED:-0}" -eq 0 ]] || return 0
        _COMPENSATED=1
        trap - ERR
        compensate_remote_worker "$exit_code" ||
            printf '[ROLLBACK] Compensation exited %s for exit code %s.\n' "$?" "$exit_code" >&2
        return 0
    }
    handle_signal() {
        local sig="$1"
        echo "Received signal $sig. Halting and invoking compensation..." >&2
        compensate_once 128
        cleanup_temp_and_secrets
        exit 128
    }
    handle_error() {
        local exit_code="${1:-1}"
        compensate_once "$exit_code"
        cleanup_temp_and_secrets
        exit "$exit_code"
    }

    trap 'handle_signal HUP' HUP
    trap 'handle_signal INT' INT
    trap 'handle_signal TERM' TERM
    trap 'handle_error "$?"' ERR
    trap 'cleanup_temp_and_secrets' EXIT

    # The controller validates the same fields before it opens the channel; the
    # side that has to act on them checks again, because the values arrive over
    # the stream and nothing here may reach a mutation on a spliced payload.
    preflight_require_inputs worker \
        "$WORKER_DOMAIN" "$REALITY_DOMAIN" "${VISION_DOMAIN:-}" "$NODE_PORT" || return 1

    # The test-only trust anchor is the next thing written, so it comes after
    # the contract and inside the traps that remove it.
    if [[ "${GOWAVE_ACME_TEST_MODE:-0}" == "1" && -n "${GOWAVE_ACME_TEST_CA_B64:-}" ]]; then
        printf '%s' "$GOWAVE_ACME_TEST_CA_B64" | base64 -d > /run/gowave-acme-test-ca.pem
        chmod 0600 /run/gowave-acme-test-ca.pem
        export GOWAVE_ACME_TEST_CA_FILE=/run/gowave-acme-test-ca.pem
        unset GOWAVE_ACME_TEST_CA_B64
    fi

    # Before the lease and the snapshots, not after: both are python3, and a
    # snapshot that dies for a missing interpreter has no snapshot to roll back
    # to, which is exactly how this Worker ended up half-provisioned.
    bootstrap_early_tools </dev/null
    acquire_mutation_lock
    verify_deploy_hook_preflight "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" "${_ACME_TX_ID:-}" || return 1
    # Before the first managed path is touched: a unit, a binary or a webroot
    # this install did not write is not a rollback target. The confirmed
    # migration (`GOWAVE_MIGRATE_EXISTING=yes`, which `node reapply` forwards
    # only after the operator answers) adopts a regular file this product did
    # not record; an unconfirmed run keeps refusing it.
    if [[ "${GOWAVE_MIGRATE_EXISTING:-no}" == "yes" ]]; then
        GOWAVE_ADOPT_UNOWNED=1 verify_worker_mutation_targets_preflight || return 1
    else
        verify_worker_mutation_targets_preflight || return 1
    fi

    validate_acme_server "${GOWAVE_ACME_SERVER:-}"
    local effective_acme_server="${GOWAVE_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
    # The lineage a host already serves is adopted instead of issuing a second one
    # beside it, exactly as the Master does: a Worker in a shared zone often has
    # `cover2.example.net-0001`, and certbot named a plain lineage beside it would
    # leave one name with two answers. The selection is also the path the vhosts
    # are rendered from, so the listener serves the lineage that was checked.
    _WORKER_LIVE_DIR=$(select_acme_lineage "$WORKER_DOMAIN" "$effective_acme_server") || return 1
    _REALITY_LIVE_DIR=$(select_acme_lineage "$REALITY_DOMAIN" "$effective_acme_server") || return 1
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        _VISION_LIVE_DIR=$(select_acme_lineage "$VISION_DOMAIN" "$effective_acme_server") || return 1
    fi
    _WORKER_LIVE_DIR="${_WORKER_LIVE_DIR:-/etc/letsencrypt/live/$WORKER_DOMAIN}"
    _REALITY_LIVE_DIR="${_REALITY_LIVE_DIR:-/etc/letsencrypt/live/$REALITY_DOMAIN}"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        _VISION_LIVE_DIR="${_VISION_LIVE_DIR:-/etc/letsencrypt/live/$VISION_DOMAIN}"
    fi
    _WORKER_LINEAGE=$(basename -- "$_WORKER_LIVE_DIR")
    _REALITY_LINEAGE=$(basename -- "$_REALITY_LIVE_DIR")
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        _VISION_LINEAGE=$(basename -- "$_VISION_LIVE_DIR")
    fi
    check_acme_lineage "$WORKER_DOMAIN" "$effective_acme_server" \
        "/etc/letsencrypt/renewal/$_WORKER_LINEAGE.conf" "$_WORKER_LIVE_DIR"
    check_acme_lineage "$REALITY_DOMAIN" "$effective_acme_server" \
        "/etc/letsencrypt/renewal/$_REALITY_LINEAGE.conf" "$_REALITY_LIVE_DIR"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        check_acme_lineage "$VISION_DOMAIN" "$effective_acme_server" \
            "/etc/letsencrypt/renewal/$_VISION_LINEAGE.conf" "$_VISION_LIVE_DIR"
    fi

    # Before the snapshots and the before-image: an installed Worker keeps the
    # routes and certificates it serves until its controller confirms the
    # rewrite, and this refusal happens while there is nothing to roll back.
    require_worker_edge_migration_confirmation \
        "$_WORKER_LIVE_DIR" "$_REALITY_LIVE_DIR" "${_VISION_LIVE_DIR:-}" || return 1

    _ACME_TX_ID="${ACME_TX_ID:-worker_install_$(date +%s)}"
    if [[ ! "$_ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
        echo "Error: Invalid Worker ACME transaction ID." >&2
        exit 1
    fi
    # A run that was killed before it could finish left its journal
    # behind: it is reconciled here, before this run records a
    # transaction of its own.
    reconcile_worker_transaction_journals || return 1
    # Snapshotted under the lineage name, not the requested one: an adopted lineage
    # is thereby recorded as pre-existing, which is what keeps the rollback from
    # deleting a certificate this run did not create.
    snapshot_acme_lineage "$_ACME_TX_ID" "$_WORKER_LINEAGE"
    snapshot_acme_lineage "$_ACME_TX_ID" "$_REALITY_LINEAGE"
    if [[ -n "${VISION_DOMAIN:-}" ]]; then
        snapshot_acme_lineage "$_ACME_TX_ID" "$_VISION_LINEAGE"
    fi
    # What those inventoried paths held before this transaction writes them: the
    # rollback restores a pre-existing object from these bytes, removes a created
    # one only while the ownership record still matches it, and preserves
    # anything it cannot prove.
    record_worker_targets_before_image \
        "/" "$(worker_targets_before_image "/var/lib/gowave-auto-nginx" "$_ACME_TX_ID")" || return 1

    # Recorded after the before-image and before the first mutation: a
    # run that dies from here on leaves a journal a later entrypoint can
    # act on.
    record_worker_transaction_journal "$_ACME_TX_ID" || return 1

    # The package inventory this run starts from, captured while the journal's
    # directory is still the only thing written: what the package manager
    # changes from here on is this transaction's residue, and a rollback
    # cannot undo it.
    record_worker_package_baseline "$_ACME_TX_ID" || return 1
    printf 'GOWAVE-WORKER-STAGE:hardening\n'
    setup_system_prereqs </dev/null
    configure_host_security </dev/null
    # Before the firewall, as on the Master: the jail bantime and UFW are two
    # controls, and a Worker that aborts here has not yet changed its ingress.
    configure_worker_fail2ban </dev/null
    configure_worker_security_updates </dev/null
    configure_firewall </dev/null
    umask 022
    unpack_cover_reality </dev/null
    printf 'GOWAVE-WORKER-STAGE:acme\n'
    configure_edge_nginx "$_WORKER_LIVE_DIR" "$_REALITY_LIVE_DIR" "${_VISION_LIVE_DIR:-}" </dev/null
    umask 077
    printf '%s' "$VERIFY_NODE_MTLS_B64" | base64 -d > /tmp/gowave-verify-node-mtls.py
    chmod 0700 /tmp/gowave-verify-node-mtls.py
    # Pass secret strictly scoped to upstream installer execution only.
    SECRET_KEY="$_NODE_SECRET_KEY" run_upstream_node_installer </dev/null
    unset SECRET_KEY
    printf 'GOWAVE-WORKER-STAGE:verification\n'
    systemctl is-active --quiet gowave-node.service
    printf '%s' "$_NODE_SECRET_KEY" | python3 /tmp/gowave-verify-node-mtls.py --host 127.0.0.1 --port "$NODE_PORT" --mode crypto-only
    nginx -t
    systemctl is-active --quiet nginx

    # The report is written once every control it covers has been applied and
    # read back: a Worker whose ingress or jail drifted is not a finished host.
    write_worker_security_report </dev/null

    # Every package-mutating step is behind us, so the delta between the
    # baseline and the host now is what this run left installed.
    record_worker_package_changes "$_ACME_TX_ID" || return 1

    # What this install now owns: the next run adopts these paths by digest
    # instead of refusing them, and a rollback can tell them apart from a host
    # object that was already here.
    record_worker_mutation_targets

    # The journal's last word from this side: every path this run wrote
    # has been verified, so a later entrypoint finds a transaction to
    # finalize rather than one to undo.
    mark_worker_transaction_state installed "$_ACME_TX_ID" || return 1

    # Disable ERR compensation trap on verified success
    trap - ERR
    # Keep the ACME before-image until the controller durably commits NODE_ADD.
    # The controller calls remote_finalize only after that commit succeeds.
    unset _NODE_SECRET_KEY VERIFY_NODE_MTLS_B64 SECURITY_HELPER_B64
    echo "GoWave Edge Worker deployment complete (service, NGINX, TLS and mTLS health verified)."
}
main "$@" </dev/null
REMOTE_EOF
    } | "${ssh_command[@]}" -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known_hosts" -o ServerAliveInterval=15 -p "$port" "${ssh_user}@${host}" 'bash -s'
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
        # A rollback is a mutation too: the run that owns the Worker's lock passes
        # its lease here, and a rollback started by anyone else still refuses.
        printf 'export GOWAVE_LEASE_TOKEN=%q\n' "${GOWAVE_WORKER_LEASE_TOKEN:-}"

        cat <<'ROLLBACK_REMOTE_SCRIPT'
set -Eeuo pipefail

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
    if flock -n 9; then
        _MUTATION_LOCK_HELD=1
        return 0
    fi

    local candidate_token="${GOWAVE_LEASE_TOKEN:-}"
    if [[ -n "$candidate_token" ]] \
        && validate_mutation_lease "$candidate_token" "$MUTATION_LEASE_FILE" "$MUTATION_LOCK_FILE"; then
        _MUTATION_LEASE_VALIDATED=1
        return 0
    fi
    if [[ -n "$candidate_token" ]]; then
        echo "Error: Invalid or stale mutation lock lease provided." >&2
        return 1
    fi

    echo "Error: Another process currently holds the mutation lock ($MUTATION_LOCK_FILE)." >&2
    return 1
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
            # A repeated install finds the hook an earlier transaction installed
            # and this transaction never touched. The ownership records name that
            # earlier transaction, so a hook that still hashes to what they
            # recorded is provably the product's own and there is nothing here to
            # undo: refusing would report an incomplete rollback, and demand
            # manual recovery, for a failure that left no side effect behind.
            if python3 - "$hook_file" "$recovery_root" <<'PY'
import hashlib, json, os, sys
hook, root = sys.argv[1], sys.argv[2]
try:
    with open(hook, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
except OSError:
    sys.exit(1)
records = [os.path.join(root, "deploy-hook-ownership.json")]
try:
    records += [os.path.join(root, name, "deploy-hook-manifest.json")
                for name in sorted(os.listdir(root))]
except OSError:
    pass
for record in records:
    try:
        with open(record, encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        continue
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        continue
    if data.get("path") == hook and data.get("sha256") == digest:
        sys.exit(0)
sys.exit(1)
PY
            then
                return 0
            fi
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
    # This standalone recovery script carries no ownership helper, so the record
    # that outlives the snapshot is cleared by its documented path.
    rm -f -- "${recovery_root}/deploy-hook-ownership.json" || {
        echo "Error: Could not clear the deploy-hook ownership record after rollback." >&2
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
    # One tab-separated line: a lineage that did not exist before has an empty
    # serial and fingerprint, and two blank lines would collapse under the
    # command substitution, leaving the reader one field where it expects three.
    print("\t".join(("1" if existed else "0", serial, fingerprint)))
except Exception as exc:
    print(f"Invalid ACME lineage manifest: {type(exc).__name__}", file=sys.stderr)
    sys.exit(1)
PY
    ) || {
        echo "Error: Refusing ACME rollback for $domain because its snapshot manifest is invalid." >&2
        return 1
    }

    local existed serial fingerprint
    if ! IFS=$'\t' read -r existed serial fingerprint <<< "$manifest_data" ||
        [[ "$manifest_data" != *$'\t'*$'\t'* ]]; then
        echo "Error: ACME lineage manifest has an invalid field count for $domain." >&2
        return 1
    fi

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

worker_mutation_targets() {
    # The paths this install creates and its rollback removes. A path that is
    # already here is only touched when the ownership record names it.
    cat <<'WORKER_TARGETS'
/etc/systemd/system/gowave-node.service
/etc/systemd/system/gowave-node.service.d
/etc/systemd/system/remnanode.service
/opt/gowave-node
/run/gowave-node
/opt/remnanode
/usr/local/bin/gowave-node
/usr/local/bin/xray
/etc/nginx/conf.d/00-worker-acme-challenge.conf
/etc/nginx/conf.d/00-bootstrap-worker-acme.conf
/etc/nginx/conf.d/gowave-worker-https.conf
/etc/nginx/conf.d/gowave-worker-decoy.conf
/etc/nginx/conf.d/gowave-worker-vision-fallback.conf
/etc/nginx/stream-enabled/gowave-worker-stream.conf
/var/www/gowave-acme
/var/www/gowave-auto-nginx/cover-reality
WORKER_TARGETS
}

worker_ownership_record() {
    local base="${1:-/var/lib/gowave-auto-nginx}"
    # "/" is the host itself, where the state root is the product's own.
    [[ "$base" == "/" ]] && base="/var/lib/gowave-auto-nginx"
    printf '%s\n' "$base/worker-install-ownership.json"
}

worker_targets_before_image() {
    # Per transaction, beside the ACME snapshot and the firewall image: what
    # every inventoried path held before this transaction touched it. The
    # recovery root is removed by remote_finalize after a verified install, so
    # a successful run leaves no image behind and a failed one keeps exactly
    # the one its rollback needs.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-${ACME_TX_ID:-}}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$root/worker-targets-before-image"
        return 0
    fi
    printf '%s\n' "$root/recovery/$transaction/worker-targets-before-image"
}

worker_targets_image() {
    # The state of every inventoried path before this transaction wrote it, and
    # the way back to that state. A created path is removed only while it is
    # still what this install wrote — the ownership record is the proof — and a
    # pre-existing path is put back with its content and metadata. Anything
    # changed after the write, or that no record can prove, is preserved with
    # the cleanup reported incomplete. The payload carries this text twice and
    # the rollback script once; a test refuses the tree if the copies drift.
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(worker_targets_before_image)}"
    local record="${4:-$(worker_ownership_record "$root")}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: worker_targets_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    local targets
    targets=$(worker_mutation_targets)
    python3 - "$root" "$image" "$action" "$record" "$targets" <<'WORKER_TARGETS_PY'
import hashlib
import json
import os
import shutil
import sys
import tempfile

root, image, action, record, listed = sys.argv[1:6]
targets = [line.strip() for line in listed.splitlines() if line.strip()]
MANIFEST = os.path.join(image, "manifest.json")
preserved = []


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def keep(path, why):
    preserved.append(path)
    print("Error: Preserving " + path + ": " + why + "; cleanup is incomplete.", file=sys.stderr)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o755, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".worker-targets.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def describe(path):
    # What sits at the path now, in the same words the ownership record uses.
    if os.path.islink(path):
        return {"kind": "symlink", "target": os.readlink(path)}
    if os.path.isdir(path):
        return {"kind": "directory"}
    if os.path.isfile(path):
        return {"kind": "file", "sha256": digest(path)}
    return None


def record_entries():
    # The record of what this transaction wrote, or None when there is nothing
    # an operator can be asked to trust.
    if not os.path.lexists(record):
        return None
    if os.path.islink(record) or not os.path.isfile(record):
        return None
    try:
        with open(record, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        return None
    entries = data.get("targets")
    return entries if isinstance(entries, dict) else None


def capture():
    if os.path.lexists(image):
        fail("Worker targets before-image " + image + " already exists; refusing to overwrite the state it holds.")
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {"created_by_tx": True, "targets": {}}
    try:
        for target in targets:
            path = under(target)
            if not os.path.lexists(path):
                data["targets"][target] = {"state": "absent"}
                continue
            if os.path.islink(path):
                data["targets"][target] = {"state": "symlink", "target": os.readlink(path)}
                continue
            if os.path.isdir(path):
                data["targets"][target] = {"state": "directory"}
                continue
            if not os.path.isfile(path):
                fail(
                    "Worker target " + path + " is not a regular file; refusing to record a state this install "
                    "cannot restore."
                )
            with open(path, "rb") as stream:
                payload = stream.read()
            copy = "file-" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(path)
            data["targets"][target] = {
                "state": "file",
                "copy": copy,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "mode": state.st_mode & 0o7777,
                "owner": [state.st_uid, state.st_gid],
            }
        document = (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8")
        write_atomic(MANIFEST, document, 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def remove_created(path, entry):
    # A path that did not exist before: remove it only while it is what we wrote.
    current = describe(path)
    if current is None:
        keep(path, "its state cannot be read")
        return
    if not isinstance(entry, dict) or entry != current:
        keep(path, "it changed after this transaction wrote it")
        return
    try:
        if current["kind"] == "directory":
            shutil.rmtree(path)
        else:
            os.unlink(path)
    except OSError as error:
        keep(path, "it could not be removed: " + str(error))


def restore_pre_existing(path, entry):
    # A path that was here before: put back its recorded content and metadata.
    state = entry.get("state")
    if state == "symlink":
        try:
            if os.path.lexists(path):
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
            os.symlink(entry.get("target") or "", path)
        except OSError as error:
            keep(path, "the link could not be restored: " + str(error))
            return
        if not os.path.islink(path) or os.readlink(path) != entry.get("target"):
            keep(path, "the restored link does not read back as the before-image")
        return
    if state == "directory":
        try:
            if not os.path.isdir(path) or os.path.islink(path):
                if os.path.lexists(path):
                    os.unlink(path)
                os.makedirs(path, mode=0o755, exist_ok=True)
        except OSError as error:
            keep(path, "the directory could not be restored: " + str(error))
        return
    if state != "file":
        keep(path, "the before-image names no state this install can restore")
        return
    copy = os.path.join(image, str(entry.get("copy") or ""))
    if not os.path.isfile(copy) or os.path.islink(copy):
        keep(path, "its before-image copy is missing")
        return
    with open(copy, "rb") as stream:
        payload = stream.read()
    if hashlib.sha256(payload).hexdigest() != entry.get("sha256"):
        keep(path, "its before-image copy changed after it was written")
        return
    try:
        if os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)
        write_atomic(path, payload, int(entry.get("mode") or 0o644))
        owner = entry.get("owner") or [0, 0]
        os.chown(path, int(owner[0]), int(owner[1]))
    except OSError as error:
        keep(path, "it could not be restored: " + str(error))
        return
    if digest(path) != entry.get("sha256"):
        keep(path, "the restored file does not read back as the before-image")


def restore():
    if not os.path.isfile(MANIFEST) or os.path.islink(MANIFEST):
        fail("No Worker targets before-image at " + image + "; preserving every path this install wrote.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail(
            "Worker targets before-image " + MANIFEST + " is not readable JSON; preserving every path this "
            "install wrote."
        )
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Worker targets before-image " + MANIFEST + " does not claim this product created it.")
    recorded = data.get("targets")
    if not isinstance(recorded, dict):
        fail("Worker targets before-image " + MANIFEST + " names no targets.")
    entries = record_entries()
    for target in targets:
        path = under(target)
        if not os.path.lexists(path):
            continue
        entry = recorded.get(target)
        if not isinstance(entry, dict):
            keep(path, "the before-image does not name it")
            continue
        if entry.get("state") == "absent":
            if entries is None:
                keep(path, "no ownership record proves this transaction wrote it")
                continue
            remove_created(path, entries.get(target))
        else:
            restore_pre_existing(path, entry)
    if preserved:
        print(
            "Error: " + str(len(preserved)) + " Worker path(s) preserved, so the cleanup is incomplete: "
            + ", ".join(preserved),
            file=sys.stderr,
        )
        raise SystemExit(1)


if action == "capture":
    capture()
else:
    restore()
WORKER_TARGETS_PY
}

record_worker_targets_before_image() {
    worker_targets_image capture "${1:-/}" "${2:-$(worker_targets_before_image)}"
}

worker_transaction_journal() {
    # One journal per transaction, beside the ACME snapshot and the two
    # before-images. It is the only record of a run that was killed before it
    # could finish: the next entrypoint reads it and knows what that run had
    # already begun to change.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-}"
    [[ "$root" == "/" ]] && root="/var/lib/gowave-auto-nginx"
    printf '%s\n' "${root%/}/recovery/${transaction}/transaction-journal.json"
}

worker_journal_action() {
    # One writer for the journal, so the install, the reconcile and the rollback
    # all read the same bytes back. "started" is written before the first
    # mutation, "installed" once every mutation has been verified, and a
    # transaction that never reached "installed" is the one a later entrypoint
    # has to reconcile.
    local action="$1"
    local journal="$2"
    local transaction="$3"
    local journal_state="${4:-}"
    python3 - "$action" "$journal" "$transaction" "$journal_state" <<'JOURNAL_PY'
import json
import os
import shutil
import sys
import tempfile
import time

action, journal, transaction, journal_state = sys.argv[1:5]
STATES = ("started", "installed")


def refuse(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def read():
    if os.path.islink(journal) or not os.path.isfile(journal):
        refuse("Worker transaction journal " + journal + " is not a regular file.")
    try:
        with open(journal, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        refuse("Worker transaction journal " + journal + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("schema") != 1:
        refuse("Worker transaction journal " + journal + " is not a journal this product wrote.")
    if data.get("transaction") != transaction:
        refuse(
            "Worker transaction journal " + journal + " records "
            + json.dumps(data.get("transaction")) + ", not " + json.dumps(transaction) + "."
        )
    if data.get("state") not in STATES:
        refuse("Worker transaction journal " + journal + " records no state this product knows.")
    return data


def store(state):
    # An installed transaction is closed: rewriting it as started would let a
    # later run undo an install that already verified every path it wrote.
    if state == "started" and os.path.lexists(journal) and read().get("state") == "installed":
        refuse("Worker transaction journal " + journal + " is already installed; refusing to reopen it.")
    directory = os.path.dirname(journal)
    if os.path.islink(directory):
        refuse("Worker transaction directory " + directory + " is a symlink.")
    os.makedirs(directory, mode=0o700, exist_ok=True)
    document = {
        "schema": 1,
        "transaction": transaction,
        "state": state,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".transaction-journal.", suffix=".tmp")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, journal)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def remove():
    # The directory goes only while it is strictly below the recovery root it was
    # found in, so a transaction name can never name its way out of that root.
    recovery_root = os.path.realpath(os.path.dirname(os.path.dirname(journal)))
    transaction_dir = os.path.realpath(os.path.dirname(journal))
    if recovery_root == os.sep or not transaction_dir.startswith(recovery_root + os.sep):
        refuse("Worker transaction directory " + transaction_dir + " is not below " + recovery_root + ".")
    if os.path.islink(os.path.dirname(journal)):
        refuse("Worker transaction directory " + os.path.dirname(journal) + " is a symlink.")
    if not os.path.isdir(transaction_dir):
        refuse("Worker transaction directory " + transaction_dir + " is not a directory.")
    shutil.rmtree(transaction_dir)


if action == "write":
    if journal_state not in STATES:
        refuse("Unknown Worker transaction state " + json.dumps(journal_state) + ".")
    store(journal_state)
elif action == "mark":
    if journal_state not in STATES:
        refuse("Unknown Worker transaction state " + json.dumps(journal_state) + ".")
    if not os.path.lexists(journal):
        raise SystemExit(0)
    read()
    store(journal_state)
elif action == "state":
    print(read().get("state"))
elif action == "remove":
    read()
    remove()
else:
    refuse("Unknown Worker transaction journal action " + json.dumps(action) + ".")
JOURNAL_PY
}

record_worker_transaction_journal() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    if [[ ! "$transaction" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]; then
        echo "Error: A Worker transaction journal needs a valid transaction ID." >&2
        return 1
    fi
    worker_journal_action write "$(worker_transaction_journal "$root" "$transaction")" "$transaction" started
}

mark_worker_transaction_state() {
    local transaction_state="${1:-}"
    local transaction="${2:-}"
    local root="${3:-/var/lib/gowave-auto-nginx}"
    worker_journal_action mark "$(worker_transaction_journal "$root" "$transaction")" "$transaction" "$transaction_state"
}

reconcile_worker_transaction_journals() {
    # Every entrypoint pays for the previous run's crash before it writes
    # anything of its own. A transaction that never reached "installed" is
    # restored from its own before-images and its directory is released; a
    # transaction this product cannot restore, or that already installed but
    # was never finalized, keeps its journal and the new operation is refused,
    # so a half-written host is never built upon. The state root is where the
    # journals live and the host root is where the inventoried paths sit; the
    # two differ only for a test that owns a scratch tree.
    local skip="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local host_root="${3:-/}"
    local journal transaction transaction_dir state failed=0
    [[ "$root" == "/" ]] && root="/var/lib/gowave-auto-nginx"
    local recovery_root="${root%/}/recovery"
    [[ -d "$recovery_root" ]] || return 0
    for journal in "$recovery_root"/*/transaction-journal.json; do
        [[ -e "$journal" ]] || continue
        transaction_dir="$(dirname "$journal")"
        transaction="$(basename "$transaction_dir")"
        [[ -n "$skip" && "$transaction" == "$skip" ]] && continue
        if ! state="$(worker_journal_action state "$journal" "$transaction")"; then
            echo "Error: Uncommitted Worker transaction $transaction cannot be read back; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if [[ "$state" != "started" ]]; then
            echo "Error: Worker transaction $transaction is '$state' and was never finalized; refusing to start a new install and retaining $transaction_dir. Finalize or roll it back first." >&2
            failed=1
            continue
        fi
        if [[ -d "$transaction_dir/worker-targets-before-image" ]] &&
            ! restore_worker_targets_before_image "$host_root" "$transaction_dir/worker-targets-before-image"; then
            echo "Error: Worker transaction $transaction could not be restored to its Worker before-image; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if [[ -d "$transaction_dir/firewall-before-image" ]] &&
            ! restore_firewall_before_image "$host_root" "$transaction_dir/firewall-before-image"; then
            echo "Error: Worker transaction $transaction could not be restored to its firewall before-image; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        if ! worker_journal_action remove "$journal" "$transaction"; then
            echo "Error: Worker transaction $transaction was restored but its journal could not be released; refusing to start a new install and retaining $transaction_dir." >&2
            failed=1
            continue
        fi
        echo "Reconciled uncommitted Worker transaction $transaction from its before-images." >&2
    done
    return "$failed"
}

# --- package change record -------------------------------------------------
# HOOK-04: a rollback restores the paths this run wrote, never the packages it
# installed. What the package manager changed is therefore recorded while the
# transaction still knows it, so a preserved host can be reported as carrying
# residual state instead of being called clean.

worker_package_record_dir() {
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${2:-}"
    printf '%s\n' "${root%/}/recovery/${transaction}"
}

worker_package_inventory() {
    # One `package<TAB>version` line per installed package, sorted, so two runs
    # of the same host agree byte for byte and a diff of them is the package
    # change a transaction caused.
    if ! command -v dpkg-query >/dev/null 2>&1; then
        return 1
    fi
    dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null | LC_ALL=C sort
}

record_worker_package_baseline() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local directory file temporary
    directory="$(worker_package_record_dir "$root" "$transaction")"
    if [[ ! -d "$directory" ]]; then
        echo "Error: The transaction directory $directory is absent, so a package baseline would not belong to a journal." >&2
        return 1
    fi
    file="$directory/packages-before.txt"
    temporary="$(mktemp "$directory/.packages-before.XXXXXX")" || return 1
    if worker_package_inventory >"$temporary" && [[ -s "$temporary" ]]; then
        :
    else
        # A host whose package manager cannot answer is not a host with no
        # packages; the baseline says what it could not learn.
        printf '%s\n' "#unavailable" >"$temporary"
    fi
    if ! chmod 0600 -- "$temporary" || ! sync "$temporary" ||
        ! mv -f -- "$temporary" "$file" || ! sync "$directory"; then
        rm -f -- "$temporary"
        return 1
    fi
}

record_worker_package_changes() {
    local transaction="${1:-}"
    local root="${2:-/var/lib/gowave-auto-nginx}"
    local directory before after changes temporary
    directory="$(worker_package_record_dir "$root" "$transaction")"
    before="$directory/packages-before.txt"
    if [[ ! -f "$before" ]]; then
        echo "Error: The package baseline for $transaction is absent, so the package changes it caused cannot be stated." >&2
        return 1
    fi
    after="$(mktemp "$directory/.packages-after.XXXXXX")" || return 1
    if worker_package_inventory >"$after" && [[ -s "$after" ]]; then
        :
    else
        printf '%s\n' "#unavailable" >"$after"
    fi
    changes="$(mktemp "$directory/.package-changes.XXXXXX")" || {
        rm -f -- "$after"
        return 1
    }
    if [[ "$(head -n 1 "$before")" == "#unavailable" ]] ||
        [[ "$(head -n 1 "$after")" == "#unavailable" ]]; then
        printf '%s\n' "#gowave-package-changes/v1" "#unavailable" >"$changes"
    else
        {
            printf '%s\n' "#gowave-package-changes/v1"
            awk -F'\t' '
                FNR == NR { before[$1] = $2; next }
                { after[$1] = $2 }
                END {
                    for (name in after) {
                        if (!(name in before)) print "installed\t" name "\t" after[name]
                        else if (before[name] != after[name]) print "upgraded\t" name "\t" before[name] "\t" after[name]
                    }
                    for (name in before) if (!(name in after)) print "removed\t" name "\t" before[name]
                }
            ' "$before" "$after" | LC_ALL=C sort
        } >"$changes"
    fi
    rm -f -- "$after"
    if ! chmod 0600 -- "$changes" || ! sync "$changes" ||
        ! mv -f -- "$changes" "$directory/package-changes.tsv" || ! sync "$directory"; then
        rm -f -- "$changes"
        return 1
    fi
}
restore_worker_targets_before_image() {
    worker_targets_image restore "${1:-/}" "${2:-$(worker_targets_before_image)}"
}

rollback_failed=0

# A previous run that was killed before it could finish left its
# journal behind: it is reconciled under this lock, before this
# entrypoint accepts work of its own.
reconcile_worker_transaction_journals "${ACME_TX_ID:-}" || rollback_failed=1

# 1. Stop and disable systemd services that are actually installed or active.
for unit in gowave-node.service xray.service; do
    if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "^$unit" ||
        systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl stop "$unit" 2>/dev/null || rollback_failed=1
        systemctl disable "$unit" 2>/dev/null || rollback_failed=1
    fi
done
# Every inventoried path comes back from the transaction's before-image: a path
# that did not exist is removed only while the ownership record still matches it,
# a path that was here is restored with its content and metadata, and one changed
# afterwards is preserved with the cleanup reported incomplete.
restore_worker_targets_before_image || rollback_failed=1
systemctl daemon-reload 2>/dev/null || rollback_failed=1

# 2. Remove NGINX worker configs
rollback_managed_deploy_hook "${ACME_TX_ID:-}" "/etc/letsencrypt/renewal-hooks/deploy/gowave-nginx.sh" 2>/dev/null || rollback_failed=1
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
    # The snapshot names the lineage, not the requested name: an adopted suffixed
    # lineage (`cover2.example.net-0001`) is recorded under its own directory, and
    # asking for the plain name would find no manifest and restore nothing. The
    # journal is written after the snapshots, so a transaction without any is a
    # rollback that cannot finish, not one with nothing to do.
    acme_snapshot_root="/var/lib/gowave-auto-nginx/recovery/$ACME_TX_ID/acme"
    restored_acme_lineage=0
    if [[ -d "$acme_snapshot_root" ]]; then
        for acme_snapshot in "$acme_snapshot_root"/*/; do
            [[ -d "$acme_snapshot" ]] || continue
            restored_acme_lineage=1
            restore_acme_lineage "$ACME_TX_ID" "$(basename -- "$acme_snapshot")" 2>/dev/null || rollback_failed=1
        done
    fi
    if [[ "$restored_acme_lineage" -eq 0 ]]; then
        echo "[ROLLBACK] ERROR: transaction $ACME_TX_ID has no ACME snapshot to restore." >&2
        rollback_failed=1
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
firewall_before_image() {
    # Per transaction, beside the ACME snapshot: the recovery root is removed
    # by remote_finalize after a verified install, so a successful run leaves
    # no image behind and a failed one leaves exactly the one it needs.
    local root="${1:-/var/lib/gowave-auto-nginx}"
    local transaction="${ACME_TX_ID:-}"
    if [[ -z "$transaction" ]]; then
        printf '%s\n' "$root/firewall-before-image"
        return 0
    fi
    printf '%s\n' "$root/recovery/$transaction/firewall-before-image"
}

firewall_image() {
    # One heredoc, two actions: what the firewall read before this install
    # changed it, and the only way back to that state. The rollback script
    # carries the same text, and a test refuses the tree if the copies drift.
    local action="${1:-}"
    local root="${2:-/}"
    local image="${3:-$(firewall_before_image)}"
    case "$action" in
        capture|restore) ;;
        *)
            echo "Error: firewall_image needs capture or restore, not '$action'." >&2
            return 2
            ;;
    esac
    python3 - "$root" "$image" "$action" <<'FIREWALL_IMAGE_PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

root, image, action = sys.argv[1:4]

CONFIG_FILES = (
    "/etc/default/ufw",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/ufw/before.rules",
    "/etc/ufw/before6.rules",
    "/etc/ufw/after.rules",
    "/etc/ufw/after6.rules",
)
MANIFEST = os.path.join(image, "manifest.json")


def under(path):
    return path if root == "/" else os.path.join(root, path.lstrip("/"))


def run(argv, stdin_text=None):
    result = subprocess.run(argv, capture_output=True, text=True, input=stdin_text)
    return result.returncode, result.stdout, result.stderr


def digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def digest_file(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def fail(message):
    print("Error: " + message, file=sys.stderr)
    raise SystemExit(1)


def normalized(text):
    """The ruleset without the bookkeeping `iptables-save` adds on its own.

    Every dump is stamped with the moment it ran and carries the live
    counters of each chain, and `iptables-restore` zeroes those counters.
    Neither is a rule, so a read-back compares what is left.
    """
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(":") and line.endswith("]"):
            line = line[: line.rindex("[")] + "[0:0]"
        lines.append(line)
    return "\n".join(lines)


def write_atomic(path, payload, mode):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".firewall-image.", suffix=".tmp")
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    directory_handle = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_handle)
    finally:
        os.close(directory_handle)


def capture():
    if os.path.lexists(image):
        fail("Firewall before-image " + image + " already exists; refusing to overwrite the state it holds.")
    status_code, status_text, status_error = run(["ufw", "status", "verbose"])
    if status_code != 0:
        fail(
            "ufw status verbose exited " + str(status_code) + "; refusing to change a firewall this install cannot "
            "restore: " + status_error.strip()[-300:]
        )
    first = status_text.splitlines()[0].strip() if status_text.strip() else ""
    if first not in ("Status: active", "Status: inactive"):
        fail("ufw status verbose printed no status line; refusing to change a firewall this install cannot restore.")
    defaults = {}
    for line in status_text.splitlines():
        if not line.startswith("Default:"):
            continue
        for part in line[len("Default:"):].split(","):
            words = part.split()
            if len(words) >= 2:
                defaults[words[1].strip("()")] = words[0]
    # `ufw status verbose` prints no Default line until the firewall has been
    # enabled once: an inactive firewall holds no policy, so there is none to
    # restore and the image records that instead of refusing the install.
    if first == "Status: active" and set(defaults) != {"incoming", "outgoing", "routed"}:
        fail(
            "ufw status verbose printed no complete default policy line; refusing to change a firewall this "
            "install cannot restore."
        )
    dumps = {}
    for name, argv in (("iptables", ["iptables-save"]), ("ip6tables", ["ip6tables-save"])):
        code, text, error = run(argv)
        if code != 0:
            if name == "ip6tables" and not os.path.exists(under("/proc/net/if_inet6")):
                dumps[name] = None
                continue
            fail(
                argv[0] + " exited " + str(code) + "; refusing to change a firewall this install cannot restore: "
                + error.strip()[-300:]
            )
        dumps[name] = text
    os.makedirs(image, mode=0o700, exist_ok=True)
    data = {
        "created_by_tx": True,
        "enabled": first == "Status: active",
        "status_verbose": status_text,
        "defaults": defaults,
        "files": {},
        "iptables": None,
        "ip6tables": None,
    }
    try:
        for path in CONFIG_FILES:
            real = under(path)
            if not os.path.lexists(real):
                continue
            if os.path.islink(real) or not os.path.isfile(real):
                fail(
                    "UFW configuration " + real + " is not a regular file; refusing to change a firewall this "
                    "install cannot restore."
                )
            with open(real, "rb") as stream:
                payload = stream.read()
            copy = "file-" + digest_bytes(path.encode("utf-8"))[:16]
            write_atomic(os.path.join(image, copy), payload, 0o600)
            state = os.stat(real)
            data["files"][path] = {
                "copy": copy,
                "sha256": digest_bytes(payload),
                "mode": state.st_mode & 0o7777,
                "uid": state.st_uid,
                "gid": state.st_gid,
            }
        for name, text in dumps.items():
            if text is None:
                continue
            copy = name + "-save.txt"
            write_atomic(os.path.join(image, copy), text.encode("utf-8"), 0o600)
            data[name] = {"copy": copy, "sha256": digest_bytes(text.encode("utf-8"))}
        write_atomic(MANIFEST, (json.dumps(data, indent=1, sort_keys=True) + "\n").encode("utf-8"), 0o600)
    except BaseException:
        shutil.rmtree(image, ignore_errors=True)
        raise


def restore():
    if not os.path.isfile(MANIFEST):
        fail("No firewall before-image at " + image + "; refusing to guess which rules this install added.")
    if os.path.islink(MANIFEST):
        fail("Firewall before-image " + MANIFEST + " is a symlink; refusing to restore from it.")
    try:
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    except Exception:
        fail("Firewall before-image " + MANIFEST + " is not readable JSON.")
    if not isinstance(data, dict) or data.get("created_by_tx") is not True:
        fail("Firewall before-image " + MANIFEST + " does not claim this product created it.")
    for key in ("enabled", "status_verbose", "defaults", "files", "iptables"):
        if key not in data:
            fail("Firewall before-image " + MANIFEST + " is incomplete: no " + key + ".")
    if not isinstance(data["files"], dict) or not isinstance(data["iptables"], dict):
        fail("Firewall before-image " + MANIFEST + " names no restorable files.")
    for path, meta in data["files"].items():
        copy = os.path.join(image, str(meta.get("copy") or ""))
        if not os.path.isfile(copy) or os.path.islink(copy):
            fail("Firewall before-image copy for " + path + " is missing.")
        if digest_file(copy) != meta.get("sha256"):
            fail("Firewall before-image copy for " + path + " changed after it was written.")
        with open(copy, "rb") as stream:
            payload = stream.read()
        target = under(path)
        write_atomic(target, payload, int(meta.get("mode") or 0o644))
        try:
            os.chown(target, int(meta.get("uid") or 0), int(meta.get("gid") or 0))
        except OSError:
            pass
    # The enabled state first: `ufw --force disable` flushes the chains, so a
    # dump applied before it would be the rules this install added, not these.
    state = "enable" if data["enabled"] else "disable"
    code, _, error = run(["ufw", "--force", state])
    if code != 0:
        fail("ufw --force " + state + " exited " + str(code) + ": " + error.strip()[-300:])
    restored = {}
    for name, argv in (("iptables", ["iptables-restore"]), ("ip6tables", ["ip6tables-restore"])):
        entry = data.get(name)
        if not isinstance(entry, dict):
            continue
        copy = os.path.join(image, str(entry.get("copy") or ""))
        if not os.path.isfile(copy):
            fail("Firewall before-image copy for " + name + " is missing.")
        with open(copy, "r", encoding="utf-8") as stream:
            text = stream.read()
        code, _, error = run(argv, stdin_text=text)
        if code != 0:
            fail(argv[0] + " exited " + str(code) + ": " + error.strip()[-300:])
        restored[name] = text
    code, status_text, _ = run(["ufw", "status", "verbose"])
    if code != 0 or status_text != data["status_verbose"]:
        fail("The restored firewall does not read back as the before-image.")
    code, saved, _ = run(["iptables-save"])
    if code != 0 or normalized(saved) != normalized(restored.get("iptables", "")):
        fail("The restored IPv4 ruleset does not match the before-image.")
    # A dual-stack host filters on two tables, and a restored v4 ruleset proves
    # nothing about the v6 one the failed install opened.
    if "ip6tables" in restored:
        code, saved, _ = run(["ip6tables-save"])
        if code != 0 or normalized(saved) != normalized(restored["ip6tables"]):
            fail("The restored IPv6 ruleset does not match the before-image.")


if action == "capture":
    capture()
else:
    restore()
FIREWALL_IMAGE_PY
}

record_firewall_before_image() {
    firewall_image capture "${1:-/}" "${2:-$(firewall_before_image)}"
}

restore_firewall_before_image() {
    firewall_image restore "${1:-/}" "${2:-$(firewall_before_image)}"
}

# 4. Restore the UFW before-image this transaction recorded. A host installed
# before the image existed keeps the old behaviour -- delete exactly the rules
# this payload adds -- and says so, because the alternative is guessing.
firewall_image_path="$(firewall_before_image)"
if [[ -d "$firewall_image_path" ]]; then
    echo "[ROLLBACK] Restoring the UFW firewall before-image..." >&2
    restore_firewall_before_image || rollback_failed=1
elif command -v ufw >/dev/null 2>&1; then
    echo "[ROLLBACK] No firewall before-image; deleting only the rules this install adds." >&2
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
if [[ -f /etc/sysctl.d/99-gowave-node.conf ]] &&
    grep -qxF '# Managed by GoWave Auto NGINX' /etc/sysctl.d/99-gowave-node.conf; then
    rm -f /etc/sysctl.d/99-gowave-node.conf || rollback_failed=1
fi
if [[ -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf ]] &&
    grep -qF 'Managed by GoWave Auto NGINX: VPS Security' /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf; then
    rm -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf || rollback_failed=1
    systemctl restart systemd-resolved 2>/dev/null || rollback_failed=1
fi
rm -f /tmp/gowave-verify-node-mtls.py /tmp/gowave-managed-security.* /tmp/gowave-node-install-*.sh || rollback_failed=1
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
        # A finalization is a mutation too: the run that owns the Worker's lock
        # passes its lease here, and one started by anyone else still refuses.
        printf 'export GOWAVE_LEASE_TOKEN=%q\n' "${GOWAVE_WORKER_LEASE_TOKEN:-}"
        cat <<'FINALIZE_REMOTE_SCRIPT'
set -Eeuo pipefail
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
# Root-only, so the module's non-root lock fallback cannot apply here.
MUTATION_LOCK_FILE="${MUTATION_LOCK_FILE:-/run/lock/gowave-managed-mutation.lock}"
MUTATION_LEASE_FILE="${MUTATION_LEASE_FILE:-/run/lock/gowave-mutation-lease.json}"

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

lock_dir="$(dirname "$MUTATION_LOCK_FILE")"
lock_file="$MUTATION_LOCK_FILE"
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
    # The run that owns this host holds the lock from a session of its own and
    # publishes a lease for the work it starts; finalizing the snapshot that
    # run's own install produced is such work. Refusing the lease here left a
    # verified install's snapshot in place, and every later install on the host
    # then refused with an unfinalized transaction.
    if [[ -z "${GOWAVE_LEASE_TOKEN:-}" ]] \
        || ! validate_mutation_lease "$GOWAVE_LEASE_TOKEN" "$MUTATION_LEASE_FILE" "$MUTATION_LOCK_FILE"; then
        echo "Error: Another process currently holds the mutation lock." >&2
        exit 1
    fi
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

