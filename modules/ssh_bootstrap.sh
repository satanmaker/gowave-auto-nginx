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
# The exit country asked of the Worker this module authorises access to.
# shellcheck source=modules/geoip.sh
source "$_ssh_bootstrap_dir/geoip.sh"

GOWAVE_SSH_TEMP_ROOT=""
GOWAVE_SSH_KEY=""
GOWAVE_SSH_KNOWN_HOSTS=""
GOWAVE_SSH_AGENT_PID=""
GOWAVE_SSH_AGENT_SOCK=""
GOWAVE_SSH_MARKER=""
GOWAVE_SSH_TIMER_ID=""
GOWAVE_SSH_LIFETIME_MINUTES=115

# The node API port `cmd_node add` registers. It is fixed in the entrypoint: a
# Worker never shares the Panel's 3000, and a Worker on the Panel's own address
# is forced to the same value.
GOWAVE_SSH_NODE_PORT=3002

# Where an interactive prompt writes.
#
# Onboarding captures each node's stderr into a file so the phase and the
# failure reason survive, which means a prompt written to fd 2 never reaches the
# operator: the run sits waiting for an answer nobody was asked for. The
# terminal is the only stream the operator is looking at, so prompt text goes
# there and falls back to fd 2 where there is no controlling terminal (tests,
# non-interactive runs). Answers keep coming from stdin, so a run whose input is
# redirected still reads the input it was given.
GOWAVE_SSH_PROMPT_OUT=/dev/stderr

# Where an allowlisted stage notice writes.
#
# The whole point of the notice is that the operator sees the stage while the
# step runs: onboarding captures each node's streams and prints them afterwards,
# so a notice on stderr would arrive only once the wait it describes is over.
# There is no terminal in a captured or non-interactive run, and then the
# machine-readable `PHASE:<id>` marker on stderr is the whole record.
GOWAVE_SSH_NOTICE_OUT=/dev/null

_ssh_bootstrap_bind_terminal() {
    if { : >/dev/tty; } 2>/dev/null; then
        GOWAVE_SSH_PROMPT_OUT=/dev/tty
        GOWAVE_SSH_NOTICE_OUT=/dev/tty
    fi
    return 0
}

# Print the localized sentence for a stage id, and nothing for an id the
# catalog does not know. The allowlist is the catalog itself: a stage reaches
# the operator only because someone wrote its sentence in both languages,
# never because a subprocess happened to print something.
#
# Args: stage id, node as the operator knows it
ssh_bootstrap_phase_notice() {
    local id="$1" node="$2"
    local text
    text="$(t "wizard.phase.$id")"
    if [[ "$text" == "wizard.phase.$id" ]]; then
        return 0
    fi
    # The format string is a catalog entry, never operator input.
    # shellcheck disable=SC2059
    printf "$text\n" "$node" > "$GOWAVE_SSH_NOTICE_OUT" 2>/dev/null || true
    return 0
}

ssh_bootstrap_fingerprint() {
    # ssh-keygen fails on non-key input; prevent set -e from aborting.
    ssh-keygen -lf - -E sha256 2>/dev/null | awk 'NR == 1 { print $2 }' || true
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
    local host="$1" port="$2" output banner_line
    if ! output=$(ssh-keyscan -T 10 -p "$port" -t ed25519 "$host" 2>/dev/null); then
        return 1
    fi
    # OpenSSH 9.x leads with a banner comment ("# host:port SSH-2.0-..."); only
    # the key line carries a key, and a fingerprint of the comment is empty.
    # Capture the banner line (if any) before filtering.
    banner_line=$(printf '%s\n' "$output" | awk '/^[[:space:]]*#/ { print; exit }')
    output=$(printf '%s\n' "$output" | awk '!/^[[:space:]]*#/ && NF > 0 { print; exit }')
    if [[ -n "$output" ]]; then
        printf '%s' "$output"
        return 0
    fi
    # No key line found; if a banner line was present, return it for detection.
    if [[ -n "$banner_line" ]]; then
        # Strip leading # and whitespace for the caller to detect.
        printf '%s' "${banner_line#*# }"
        return 0
    fi
    return 1
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
    _ssh_bootstrap_bind_terminal
    printf '%s' "$(tf wizard.ssh.password "$host")" > "$GOWAVE_SSH_PROMPT_OUT"
    if ! IFS= read -r -s password; then
        printf '\n' > "$GOWAVE_SSH_PROMPT_OUT"
        return 1
    fi
    printf '\n' > "$GOWAVE_SSH_PROMPT_OUT"
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
    local prompted=0
    if [[ -z "$provided" ]]; then
        # The operator compares this with the value the provider's console
        # shows. A prompt that asks for the fingerprint without presenting the
        # one the host actually offers asks for a value nobody can know, and
        # spec interactive-deployment requires the flow to present it.
        prompted=1
        _ssh_bootstrap_bind_terminal
        printf '%s\n' "$(tf wizard.ssh.fingerprint_presented "$host" "$expected")" > "$GOWAVE_SSH_PROMPT_OUT"
        printf '%s' "$(tf wizard.ssh.fingerprint "$host")" > "$GOWAVE_SSH_PROMPT_OUT"
        if ! IFS= read -r typed; then
            printf '\n' > "$GOWAVE_SSH_PROMPT_OUT"
            return 1
        fi
        provided="$typed"
    fi
    if ! ssh_bootstrap_fingerprint_matches "$provided" "$expected"; then
        (( prompted )) && printf '\n' > "$GOWAVE_SSH_PROMPT_OUT"
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

# Ask the Worker where it reaches the internet, and the operator to confirm it.
#
# The request runs on the Worker over the session the temporary key was just
# authorised for, so the address the service sees is the Worker's own outbound
# address and never the Panel's. The answer is a suggestion: the operator
# confirms it or types the code this node actually exits from. A lookup that
# fails asks for the code instead of aborting the onboarding.
#
# Args: SSH target, SSH port, node label. Prints the confirmed code, or nothing.
ssh_bootstrap_country() {
    local target="$1" port="$2" label="$3"
    local payload="$GOWAVE_SSH_TEMP_ROOT/country.sh" suggestion="" code=""
    country_asking || return 0
    printf 'set -Eeuo pipefail\n' > "$payload"
    country_lookup_command >> "$payload"
    suggestion=$(ssh -T \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile="$GOWAVE_SSH_KNOWN_HOSTS" \
        -o ConnectTimeout=15 \
        -o LogLevel=ERROR \
        -p "$port" "root@$target" 'bash -s' < "$payload" 2>/dev/null) || suggestion=""
    suggestion=$(printf '%s\n' "$suggestion" | country_parse)
    # Onboarding captures a Worker's stderr, so a question written there is asked
    # where nobody is looking. The terminal the run already bound is where the
    # operator is, and stdin keeps carrying the answer.
    code=$(GOWAVE_COUNTRY_PROMPT_OUT="${GOWAVE_SSH_PROMPT_OUT:-/dev/stderr}" \
        country_confirm "$label" "$suggestion") || code=""
    printf '%s' "$code"
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
    local node_name="${4:-}" node_ip="${5:-}"
    local port="${GOWAVE_SSH_PORT:-22}"
    # The SSH target is the address when the caller knows it: a Worker that is
    # being added before its name resolves is reachable by address, and the host
    # key that gets pinned belongs to that address either way.
    local target="${node_ip:-$host}"
    local ip="" scanned="" expected="" password_file="" rc=0
    local phase="" node_country=""

    # The terminal is bound before the first stage so every notice below has
    # somewhere the operator is actually looking.
    _ssh_bootstrap_bind_terminal

    # Phase tracking: print phase markers to stderr for the caller to capture
    _ssh_phase() {
        phase="$1"
        printf 'PHASE:%s\n' "$phase" >&2
        ssh_bootstrap_phase_notice "$phase" "$host"
    }

    _ssh_phase "prepare_key"
    printf '==> Onboarding %s\n' "$host"
    if ! ssh_bootstrap_prepare_key; then
        printf '%s\n' "$(tf wizard.ssh.failed "$host")" >&2
        return 1
    fi

    _ssh_phase "scan"
    if ! scanned=$(ssh_bootstrap_scan "$target" "$port"); then
        printf '%s\n' "$(tf wizard.ssh.scan_failed "$host")" >&2
        return 1
    fi

    _ssh_phase "fingerprint"
    expected=$(printf '%s\n' "$scanned" | ssh_bootstrap_fingerprint)
    if [[ -z "$expected" ]]; then
        printf '%s\n' "$(tf wizard.ssh.scan_failed "$host")" >&2
        return 1
    fi

    _ssh_phase "confirm_fingerprint"
    if ! ssh_bootstrap_confirm_fingerprint "$host" "$expected"; then
        _release_ssh_temp
        return 1
    fi

    _ssh_phase "resolve_ip"
    if [[ -n "$node_ip" ]]; then
        ip="$node_ip"
    elif ! ip=$(wizard_resolve_ipv4 "$host"); then
        printf '%s\n' "$(tf wizard.dns.failed "$host")" >&2
        _release_ssh_temp
        return 1
    fi

    _ssh_phase "pin_host_key"
    ssh_bootstrap_pin_host_key "$scanned" "$ip" "$port"

    _ssh_phase "prepare_password"
    if ! password_file=$(ssh_bootstrap_prepare_password "$host"); then
        _release_ssh_temp
        return 1
    fi

    _ssh_phase "authorise"
    if ! ssh_bootstrap_authorise "$target" "$port" "$password_file"; then
        _release_ssh_temp
        return 1
    fi

    _ssh_phase "start_agent"
    if ! ssh_bootstrap_start_agent; then
        ssh_bootstrap_revoke "$target" "$port" "$password_file" || true
        _release_ssh_temp
        return 1
    fi

    # Asked here, between the authorised session and the registration, because
    # this is the last moment the node is reachable without the Panel holding a
    # record of it: a country the operator walked away from leaves nothing to
    # clean up. A run that never entered the wizard asks nothing at all.
    if country_asking; then
        _ssh_phase "country"
        node_country=$(ssh_bootstrap_country "$target" "$port" "${node_name:-$host}") \
            || node_country=""
    fi

    _ssh_phase "add_node"
    # The identity `node add` is about to register, so the caller reads this
    # node back by exactly the name, address and port the Panel was told. A
    # marker rather than a second lookup: re-resolving the name here would
    # compare the Panel against a different answer than the one it was given.
    printf 'NODE-IDENTITY:%s\t%s\t%s\n' \
        "${node_name:-$host}" "$ip" "$GOWAVE_SSH_NODE_PORT" >&2
    local -a add_args=(add "${node_name:-$host}" "$ip" "$host" "$camouflage")
    if [[ -n "$vision" ]]; then
        add_args=(add --vision-domain "$vision" "${node_name:-$host}" "$ip" "$host" "$camouflage")
    fi
    GOWAVE_NODE_COUNTRY="$node_country" \
        SSH_KNOWN_HOSTS="$GOWAVE_SSH_KNOWN_HOSTS" cmd_node "${add_args[@]}" || rc=1

    _ssh_phase "revoke"
    ssh_bootstrap_revoke "$target" "$port" "$password_file" || rc=1

    _ssh_phase "stop_agent"
    ssh_bootstrap_stop_agent
    _release_ssh_temp

    if (( rc == 0 )); then
        printf '%s\n' "$(tf wizard.ssh.registered "$host")"
    else
        printf '%s\n' "$(tf wizard.ssh.failed "$host")" >&2
    fi
    return "$rc"
}

# Release the SSH temp directory immediately after onboarding completes.
# This ensures passwords and keys are not retained on the Panel host.
_release_ssh_temp() {
    if [[ -n "${GOWAVE_SSH_TEMP_ROOT:-}" ]]; then
        if declare -F release_temp_dir >/dev/null 2>&1; then
            release_temp_dir "$GOWAVE_SSH_TEMP_ROOT"
        fi
        GOWAVE_SSH_TEMP_ROOT=""
        GOWAVE_SSH_KEY=""
        GOWAVE_SSH_KNOWN_HOSTS=""
        GOWAVE_SSH_MARKER=""
        GOWAVE_SSH_TIMER_ID=""
    fi
}
