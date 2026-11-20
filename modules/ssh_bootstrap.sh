#!/usr/bin/env bash
# modules/ssh_bootstrap.sh - temporary SSH access for onboarding a Worker
#
# The Panel host authorises an Ed25519 key on the Worker only after the
# operator types the Worker's host-key fingerprint in full. A systemd timer on
# the Worker removes the key within two hours even if this host dies mid-add.
# The private key, the password file and the askpass helper live in a 0700
# directory that is removed on exit.
set -Eeuo pipefail

_ssh_bootstrap_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=modules/i18n.sh
source "$_ssh_bootstrap_dir/i18n.sh"

GOWAVE_SSH_TEMP_ROOT=""
GOWAVE_SSH_KEY=""
GOWAVE_SSH_KNOWN_HOSTS=""
GOWAVE_SSH_AGENT_PID=""
GOWAVE_SSH_AGENT_SOCK=""
GOWAVE_SSH_MARKER=""
GOWAVE_SSH_TIMER_ID=""
GOWAVE_SSH_LIFETIME_MINUTES=115

ssh_bootstrap_fingerprint() {
    ssh-keygen -lf - -E sha256 2>/dev/null | awk 'NR == 1 { print $2 }'
}

# The operator's typed value is authoritative; it has to equal what the host
# actually presents, whitespace aside.
ssh_bootstrap_fingerprint_matches() {
    local provided="${1//[[:space:]]/}"
    local expected="${2//[[:space:]]/}"
    [[ -n "$provided" && -n "$expected" && "$provided" == "$expected" ]]
}

ssh_bootstrap_key_entry() {
    local pubkey="$1" marker="$2" deadline="$3"
    printf 'expiry-time="%s" %s %s' "$deadline" "$pubkey" "$marker"
}

ssh_bootstrap_timer_id() {
    printf '%s' "$1" | sha256sum | cut -c1-12
}

# Installed before the key is authorised. If any step fails, the caller aborts
# and no authorized_keys write ever happens.
ssh_bootstrap_render_timer_payload() {
    local marker="$1" timer_id="$2"
    local template
    template=$(cat <<'REMOTE'
set -Eeuo pipefail
umask 077
install -d -m 0755 /usr/local/sbin
cat > /usr/local/sbin/gowave-temp-key-revoke-@ID@ <<'REVOKE'
#!/bin/sh
set -eu
marker="$1"
id="$2"
auth=/root/.ssh/authorized_keys
if [ -f "$auth" ]; then
    tmp=$(mktemp "${auth}.XXXXXX")
    chmod 600 "$tmp"
    grep -vF -- "$marker" "$auth" > "$tmp" || true
    mv "$tmp" "$auth"
fi
systemctl disable --now "gowave-temp-key-$id.timer" >/dev/null 2>&1 || true
rm -f "/etc/systemd/system/gowave-temp-key-$id.timer" \
      "/etc/systemd/system/gowave-temp-key-$id.service" \
      "/usr/local/sbin/gowave-temp-key-revoke-$id"
systemctl daemon-reload >/dev/null 2>&1 || true
REVOKE
chmod 0755 /usr/local/sbin/gowave-temp-key-revoke-@ID@
cat > /etc/systemd/system/gowave-temp-key-@ID@.service <<'SERVICE'
[Unit]
Description=Remove the temporary GoWave onboarding key
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/gowave-temp-key-revoke-@ID@ @MARKER@ @ID@
SERVICE
cat > /etc/systemd/system/gowave-temp-key-@ID@.timer <<'TIMER'
[Unit]
Description=Expire the temporary GoWave onboarding key
[Timer]
OnActiveSec=@LIFETIME@min
AccuracySec=1min
Persistent=false
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now gowave-temp-key-@ID@.timer
REMOTE
)
    template="${template//@LIFETIME@/$GOWAVE_SSH_LIFETIME_MINUTES}"
    template="${template//@ID@/$timer_id}"
    printf '%s' "${template//@MARKER@/$marker}"
}

ssh_bootstrap_render_key_payload() {
    local entry="$1"
    printf '%s' "set -Eeuo pipefail
umask 077
mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
tmp=\$(mktemp /root/.ssh/authorized_keys.XXXXXX)
cat /root/.ssh/authorized_keys > \"\$tmp\"
printf '%s\n' '$entry' >> \"\$tmp\"
mv \"\$tmp\" /root/.ssh/authorized_keys"
}

# The revoke script removes the marker, stops and disables the timer, and
# deletes itself; a host whose timer already fired has no script left, which is
# the success case as well.
ssh_bootstrap_render_revoke_payload() {
    local marker="$1" timer_id="$2"
    printf '%s' "set -Eeuo pipefail
script=/usr/local/sbin/gowave-temp-key-revoke-$timer_id
if [ -x \"\$script\" ]; then
    \"\$script\" '$marker' '$timer_id'
fi"
}

ssh_bootstrap_scan() {
    local host="$1" port="$2" output
    if ! output=$(ssh-keyscan -T 10 -p "$port" -t ed25519 "$host" 2>/dev/null); then
        return 1
    fi
    # OpenSSH 9.x leads with a banner comment ("# host:port SSH-2.0-..."); only
    # the key line carries a key, and a fingerprint of the comment is empty.
    output=$(printf '%s\n' "$output" | awk '!/^[[:space:]]*#/ && NF > 0 { print; exit }')
    [[ -n "$output" ]] || return 1
    printf '%s' "$output"
}

ssh_bootstrap_prepare_key() {
    local directory
    directory=$(mktemp -d "${TMPDIR:-/tmp}/gowave-wizard-ssh.XXXXXX")
    chmod 700 "$directory"
    ssh-keygen -q -t ed25519 -N '' -C "gowave-wizard" -f "$directory/id_ed25519"
    GOWAVE_SSH_TEMP_ROOT="$directory"
    GOWAVE_SSH_KEY="$directory/id_ed25519"
    GOWAVE_SSH_KNOWN_HOSTS="$directory/known_hosts"
    : > "$GOWAVE_SSH_KNOWN_HOSTS"
    chmod 600 "$GOWAVE_SSH_KNOWN_HOSTS"
    if declare -F track_temp_dir >/dev/null 2>&1; then
        track_temp_dir "$directory"
    fi
}

ssh_bootstrap_prepare_password() {
    local host="$1" file="${GOWAVE_SSH_PASSWORD_FILE:-}"
    local directory="${GOWAVE_SSH_TEMP_ROOT:-}"
    if [[ -z "$directory" ]]; then
        printf 'Error: the temporary key directory is missing.\n' >&2
        return 1
    fi
    if [[ -n "$file" ]]; then
        if [[ ! -r "$file" ]]; then
            printf 'Error: the SSH password file is not readable: %s\n' "$file" >&2
            return 1
        fi
        if [[ "$(stat -c '%a' "$file" 2>/dev/null)" != "600" ]]; then
            printf 'Error: the SSH password file must have mode 0600: %s\n' "$file" >&2
            return 1
        fi
        printf '%s' "$file"
        return 0
    fi
    local secret="$directory/password" password=""
    printf '%s' "$(tf wizard.ssh.password "$host")" >&2
    if ! IFS= read -r -s password; then
        printf '\n' >&2
        return 1
    fi
    printf '\n' >&2
    printf '%s' "$password" > "$secret"
    chmod 600 "$secret"
    unset password
    printf '%s' "$secret"
}

ssh_bootstrap_askpass() {
    local password_file="$1" helper="$GOWAVE_SSH_TEMP_ROOT/askpass"
    printf '#!/bin/sh\nexec cat %s\n' "'$password_file'" > "$helper"
    chmod 700 "$helper"
    printf '%s' "$helper"
}

# Password authentication only for the first contact: the key is not
# authorised yet, and the password never reaches an argument list.
ssh_bootstrap_exec() {
    local host="$1" port="$2" password_file="$3" payload="$4"
    local helper
    helper=$(ssh_bootstrap_askpass "$password_file")
    local -a prefix=()
    if command -v setsid >/dev/null 2>&1; then
        prefix=(setsid -w)
    fi
    SSH_ASKPASS="$helper" SSH_ASKPASS_REQUIRE=force DISPLAY=gowave:0 \
        "${prefix[@]}" ssh -T \
        -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$GOWAVE_SSH_KNOWN_HOSTS" \
        -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=15 \
        -o LogLevel=ERROR \
        -p "$port" "root@$host" 'bash -s' < "$payload"
}

ssh_bootstrap_confirm_fingerprint() {
    local host="$1" expected="$2" provided="${GOWAVE_SSH_FINGERPRINT:-}" typed=""
    if [[ -z "$provided" ]]; then
        printf '%s' "$(tf wizard.ssh.fingerprint "$host")" >&2
        if ! IFS= read -r typed; then
            printf '\n' >&2
            return 1
        fi
        provided="$typed"
    fi
    if ! ssh_bootstrap_fingerprint_matches "$provided" "$expected"; then
        printf '%s\n' "$(tf wizard.ssh.fingerprint_mismatch "$host")" >&2
        return 1
    fi
    return 0
}

ssh_bootstrap_authorise() {
    local host="$1" port="$2" password_file="$3"
    local timer_id marker deadline entry
    timer_id=$(ssh_bootstrap_timer_id "$host")
    marker="gowave-wizard-$timer_id"
    deadline=$(date -u -d "+2 hours" +%Y%m%d%H%M)
    entry=$(ssh_bootstrap_key_entry "$(cat "$GOWAVE_SSH_KEY.pub")" "$marker" "$deadline")

    ssh_bootstrap_render_timer_payload "$marker" "$timer_id" > "$GOWAVE_SSH_TEMP_ROOT/timer.sh"
    if ! ssh_bootstrap_exec "$host" "$port" "$password_file" "$GOWAVE_SSH_TEMP_ROOT/timer.sh"; then
        printf '%s\n' "$(tf wizard.ssh.timer_failed "$host")" >&2
        return 1
    fi
    GOWAVE_SSH_MARKER="$marker"
    GOWAVE_SSH_TIMER_ID="$timer_id"

    ssh_bootstrap_render_key_payload "$entry" > "$GOWAVE_SSH_TEMP_ROOT/key.sh"
    if ! ssh_bootstrap_exec "$host" "$port" "$password_file" "$GOWAVE_SSH_TEMP_ROOT/key.sh"; then
        ssh_bootstrap_render_revoke_payload "$marker" "$timer_id" > "$GOWAVE_SSH_TEMP_ROOT/revoke.sh"
        ssh_bootstrap_exec "$host" "$port" "$password_file" "$GOWAVE_SSH_TEMP_ROOT/revoke.sh" || true
        return 1
    fi
    return 0
}

ssh_bootstrap_revoke() {
    local host="$1" port="$2" password_file="$3"
    if [[ -z "$GOWAVE_SSH_MARKER" || -z "$GOWAVE_SSH_TIMER_ID" ]]; then
        return 0
    fi
    printf '%s\n' "$(tf wizard.ssh.cleanup "$host")"
    ssh_bootstrap_render_revoke_payload "$GOWAVE_SSH_MARKER" "$GOWAVE_SSH_TIMER_ID" \
        > "$GOWAVE_SSH_TEMP_ROOT/revoke.sh"
    if ! ssh_bootstrap_exec "$host" "$port" "$password_file" "$GOWAVE_SSH_TEMP_ROOT/revoke.sh"; then
        printf '%s\n' "$(tf wizard.ssh.cleanup_failed "$host")" >&2
        return 1
    fi
    GOWAVE_SSH_MARKER=""
    GOWAVE_SSH_TIMER_ID=""
    return 0
}

ssh_bootstrap_start_agent() {
    local output=""
    if ! output=$(ssh-agent -s 2>/dev/null); then
        return 1
    fi
    eval "$output" >/dev/null 2>&1
    GOWAVE_SSH_AGENT_PID="${SSH_AGENT_PID:-}"
    GOWAVE_SSH_AGENT_SOCK="${SSH_AUTH_SOCK:-}"
    ssh-add "$GOWAVE_SSH_KEY" >/dev/null 2>&1
}

ssh_bootstrap_stop_agent() {
    if [[ -n "${GOWAVE_SSH_AGENT_PID:-}" ]]; then
        kill "$GOWAVE_SSH_AGENT_PID" 2>/dev/null || true
    fi
    GOWAVE_SSH_AGENT_PID=""
    GOWAVE_SSH_AGENT_SOCK=""
}

# Pins the host key the operator just confirmed and the address `node add`
# checks, so that command finds a pre-pinned entry rather than trusting a
# fresh one.
ssh_bootstrap_pin_host_key() {
    local scanned="$1" ip="$2" port="$3" host_key="$ip"
    if [[ "$port" != "22" ]]; then
        host_key="[$ip]:$port"
    fi
    printf '%s\n' "$scanned" >> "$GOWAVE_SSH_KNOWN_HOSTS"
    printf '%s %s\n' "$host_key" "${scanned#* }" >> "$GOWAVE_SSH_KNOWN_HOSTS"
    chmod 600 "$GOWAVE_SSH_KNOWN_HOSTS"
}

ssh_bootstrap_onboard_one() {
    local host="$1" camouflage="$2" vision="${3:-}"
    local port="${GOWAVE_SSH_PORT:-22}"
    local ip="" scanned="" expected="" password_file="" rc=0

    printf '==> Onboarding %s\n' "$host"
    if ! ssh_bootstrap_prepare_key; then
        printf '%s\n' "$(tf wizard.ssh.failed "$host")" >&2
        return 1
    fi
    if ! scanned=$(ssh_bootstrap_scan "$host" "$port"); then
        printf '%s\n' "$(tf wizard.ssh.scan_failed "$host")" >&2
        return 1
    fi
    expected=$(printf '%s\n' "$scanned" | ssh_bootstrap_fingerprint)
    if [[ -z "$expected" ]]; then
        printf '%s\n' "$(tf wizard.ssh.scan_failed "$host")" >&2
        return 1
    fi
    if ! ssh_bootstrap_confirm_fingerprint "$host" "$expected"; then
        return 1
    fi
    if ! ip=$(wizard_resolve_ipv4 "$host"); then
        printf '%s\n' "$(tf wizard.dns.failed "$host")" >&2
        return 1
    fi
    ssh_bootstrap_pin_host_key "$scanned" "$ip" "$port"
    if ! password_file=$(ssh_bootstrap_prepare_password "$host"); then
        return 1
    fi
    if ! ssh_bootstrap_authorise "$host" "$port" "$password_file"; then
        return 1
    fi
    if ! ssh_bootstrap_start_agent; then
        ssh_bootstrap_revoke "$host" "$port" "$password_file" || true
        return 1
    fi

    local -a add_args=(add "$host" "$ip" "$host" "$camouflage")
    if [[ -n "$vision" ]]; then
        add_args=(add --vision-domain "$vision" "$host" "$ip" "$host" "$camouflage")
    fi
    SSH_KNOWN_HOSTS="$GOWAVE_SSH_KNOWN_HOSTS" cmd_node "${add_args[@]}" || rc=1

    ssh_bootstrap_revoke "$host" "$port" "$password_file" || rc=1
    ssh_bootstrap_stop_agent
    if (( rc == 0 )); then
        printf '%s\n' "$(tf wizard.ssh.registered "$host")"
    else
        printf '%s\n' "$(tf wizard.ssh.failed "$host")" >&2
    fi
    return "$rc"
}
