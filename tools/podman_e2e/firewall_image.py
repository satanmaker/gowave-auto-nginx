#!/usr/bin/env python3
"""Existing firewall policy is preserved, not partially deleted.

``openspec/specs/podman-e2e/spec.md`` §Complete
Mutation-Target Baseline and Resource Ownership: when UFW is active, or holds
rules and default policies the operator set, an injected failure must leave
them as they were — every original rule, every default policy and the enabled
state — and not merely the four rules this install added removed from whatever
is left.

The Worker payload answers that with a before-image taken inside
``configure_firewall`` before the first rule changes: ``firewall_image capture``
writes the enabled state, the three default policies, the rule text, the IPv4
and IPv6 kernel dumps and the UFW configuration files it may rewrite into the
transaction's recovery directory, and ``restore`` puts them back (configuration
files, then the enabled state, then the dumps, then a read-back check). A
baseline that cannot be read and restored is refused before anything is
mutated, so the install never starts on a firewall it could not put back.

The case drives the shipped functions on the host each contour installs, over a
scratch root with ``ufw``, ``iptables-save``, ``ip6tables-save``,
``iptables-restore`` and ``ip6tables-restore`` answered by shims that keep the
state in files — the same shape the host has, without touching the container's
own firewall.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from tools.podman_e2e.runner import CaseBlocked, require

CASE_ID = "OWN-03"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKER_INSTALLER = REPO_ROOT / "gowave-node-auto.sh"

_SENTENCES = {
    "image_is_per_transaction":
        "the before-image was not written in the transaction's own recovery directory",
    "capture_mutates_nothing": "taking the before-image changed the firewall it records",
    "image_names_enabled_state": "the before-image does not record whether UFW was active",
    "image_names_default_policies":
        "the before-image does not record the three default policies it replaces",
    "image_keeps_rule_text": "the before-image does not hold the rule text it restores",
    "image_keeps_ipv4_dump": "the before-image does not hold the IPv4 ruleset",
    "image_keeps_ipv6_dump": "the before-image does not hold the IPv6 ruleset",
    "image_keeps_ufw_config": "the before-image does not hold the UFW configuration it rewrites",
    "image_mode_is_private": "the firewall before-image is readable by every user",
    "existing_image_refused": "a second capture overwrote the state the first one holds",
    "restore_returns_active_state": "the restore left UFW inactive on a host where it was active",
    "restore_returns_foreign_rule":
        "the restore lost a rule this install never wrote",
    "restore_returns_default_policies":
        "the restore left the default policies the install set",
    "inactive_baseline_captured":
        "a firewall that was off was refused instead of captured",
    "restore_returns_inactive_state":
        "the restore left UFW active on a host where it was inactive",
    "restore_returns_ufw_config": "the restore left the UFW configuration the install rewrote",
    "read_back_compares_the_rules":
        "the read-back compared the counters and the timestamp, not the rules",
    "restore_is_idempotent": "a second restore of the same image changed the firewall",
    "missing_image_refused":
        "a rollback with no before-image guessed which rules this install added",
    "unrestorable_baseline_refused":
        "an install began on a firewall it could not write a restorable image of",
}

_FUNCTION_SIGNATURES = (
    "firewall_before_image() {",
    "firewall_image() {",
    "record_firewall_before_image() {",
    "restore_firewall_before_image() {",
)

_SHIMS = r"""\
mkdir -p "$work/bin" "$work/state"
cat > "$work/bin/ufw" <<'UFW_SHIM'
#!/usr/bin/env bash
set -u
state="$FAKE_STATE"
root="$FAKE_ROOT"
log() { printf '%s\n' "$*" >> "$state/mutations.log"; }
render() {
    if [[ "$(cat "$state/enabled")" != "yes" ]]; then
        # A firewall that was never switched on answers with its status and
        # nothing else: no Default line and no rule table, because no policy is
        # in force. Printing them here would hide a capture that cannot read a
        # host whose UFW has never been enabled — the state of every new Worker.
        printf 'Status: inactive\n'
        return
    fi
    printf 'Status: active\n'
    # The three default policies are the kernel's chain policies, which is where
    # `iptables-save` prints them and where `iptables-restore` puts them back.
    awk '
        function word(value) {
            if (value == "ACCEPT") return "allow"
            if (value == "DROP") return "deny"
            if (value == "REJECT") return "reject"
            return "disabled"
        }
        $1 ~ /^:(INPUT|OUTPUT|FORWARD)$/ { policy[$1] = $2 }
        END {
            routed = policy[":FORWARD"]
            if (routed == "DROP") routed = "DISABLED"
            printf "Default: %s (incoming), %s (outgoing), %s (routed)\n",
                word(policy[":INPUT"]), word(policy[":OUTPUT"]), word(routed)
        }
    ' "$state/iptables.txt"
    printf '\nTo                         Action      From\n--                         ------      ----\n'
    awk '$1 == "-A" && $2 == "ufw-user-input" {
            port = ""; source = "Anywhere"
            for (i = 3; i < NF; i++) {
                if ($i == "--dport") port = $(i + 1)
                if ($i == "-s") source = $(i + 1)
            }
            if (port != "") printf "%-26s ALLOW IN    %s\n", port "/tcp", source
        }' "$state/iptables.txt"
}
case "${1:-}" in
    status)
        render
        ;;
    default)
        shift
        policy="$1"; direction="$2"
        case "$policy" in
            allow) target="ACCEPT" ;;
            deny) target="DROP" ;;
            reject) target="REJECT" ;;
            *) echo "ufw: unsupported default policy ${policy}" >&2; exit 2 ;;
        esac
        case "$direction" in
            incoming) chain=":INPUT"; key="DEFAULT_INPUT_POLICY" ;;
            outgoing) chain=":OUTPUT"; key="DEFAULT_OUTPUT_POLICY" ;;
            routed) chain=":FORWARD"; key="DEFAULT_FORWARD_POLICY" ;;
            *) echo "ufw: unsupported default direction ${direction}" >&2; exit 2 ;;
        esac
        awk -v chain="$chain" -v target="$target" '
            $1 == chain { print chain, target, "[0:0]"; next }
            { print }
        ' "$state/iptables.txt" > "$state/iptables.next"
        mv "$state/iptables.next" "$state/iptables.txt"
        if [[ -f "$root/etc/default/ufw" ]]; then
            awk -v key="$key" -v value="$target" '
                index($0, key "=") == 1 { print key "=\"" value "\""; next }
                { print }
            ' "$root/etc/default/ufw" > "$root/etc/default/ufw.next"
            mv "$root/etc/default/ufw.next" "$root/etc/default/ufw"
        fi
        log "default $policy $direction"
        ;;
    allow)
        shift
        spec="$1"
        rule="-A ufw-user-input -p tcp -m tcp --dport ${spec%%/*} -j ACCEPT"
        awk -v rule="$rule" '
            $1 == "COMMIT" { print rule }
            { print }
        ' "$state/iptables.txt" > "$state/iptables.next"
        mv "$state/iptables.next" "$state/iptables.txt"
        printf '%s\n' "$rule" >> "$root/etc/ufw/user.rules"
        log "allow $spec"
        ;;
    --force)
        shift
        case "${1:-}" in
            enable)
                incoming="DROP"; outgoing="ACCEPT"; routed="DROP"
                if [[ -f "$root/etc/default/ufw" ]]; then
                    while IFS='=' read -r key value; do
                        value="${value%\"}"; value="${value#\"}"
                        case "$key" in
                            DEFAULT_INPUT_POLICY) incoming="$value" ;;
                            DEFAULT_OUTPUT_POLICY) outgoing="$value" ;;
                            DEFAULT_FORWARD_POLICY) routed="$value" ;;
                        esac
                    done < "$root/etc/default/ufw"
                fi
                {
                    printf '*filter\n'
                    printf ':INPUT %s [0:0]\n:FORWARD %s [0:0]\n:OUTPUT %s [0:0]\n' "$incoming" "$routed" "$outgoing"
                    printf ':ufw-user-input - [0:0]\n'
                    if [[ -f "$root/etc/ufw/user.rules" ]]; then
                        cat "$root/etc/ufw/user.rules"
                    fi
                    printf 'COMMIT\n'
                } > "$state/iptables.txt"
                printf 'yes\n' > "$state/enabled"
                log enable
                ;;
            disable)
                {
                    printf '*filter\n'
                    printf ':INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n'
                    printf ':ufw-user-input - [0:0]\nCOMMIT\n'
                } > "$state/iptables.txt"
                printf 'no\n' > "$state/enabled"
                log disable
                ;;
            *)
                echo "ufw: unsupported force verb ${1:-}" >&2
                exit 2
                ;;
        esac
        ;;
    *)
        echo "ufw: unsupported verb ${1:-}" >&2
        exit 2
        ;;
esac
UFW_SHIM
cat > "$work/bin/iptables-save" <<'SAVE_SHIM'
#!/usr/bin/env bash
set -u
# A real `iptables-save` stamps the moment it ran into a header and prints the
# live counters of every chain, and `iptables-restore` puts those counters back
# at zero. Two dumps of one ruleset are therefore never the same bytes, which is
# why a read-back has to compare the rules and not the text.
count=$(cat "$FAKE_STATE/saves" 2>/dev/null || printf '0')
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_STATE/saves"
printf '# Generated by iptables-save (shim) on call %s\n' "$count"
awk -v n="$count" '
    $1 ~ /^:(INPUT|OUTPUT|FORWARD|ufw-user-input)$/ { sub(/\[[0-9]+:[0-9]+\]$/, "[" n ":" n "]") }
    { print }
' "$FAKE_STATE/iptables.txt"
printf '# Completed\n'
SAVE_SHIM
cat > "$work/bin/ip6tables-save" <<'SAVE6_SHIM'
#!/usr/bin/env bash
set -u
count=$(cat "$FAKE_STATE/saves6" 2>/dev/null || printf '0')
count=$((count + 1))
printf '%s\n' "$count" > "$FAKE_STATE/saves6"
printf '# Generated by ip6tables-save (shim) on call %s\n' "$count"
awk -v n="$count" '
    $1 ~ /^:(INPUT|OUTPUT|FORWARD|ufw6-user-input)$/ { sub(/\[[0-9]+:[0-9]+\]/, "[" n ":" n "]") }
    { print }
' "$FAKE_STATE/ip6tables.txt"
printf '# Completed\n'
SAVE6_SHIM
cat > "$work/bin/iptables-restore" <<'RESTORE_SHIM'
#!/usr/bin/env bash
set -u
cat > "$FAKE_STATE/iptables.txt"
printf 'restore-iptables\n' >> "$FAKE_STATE/mutations.log"
RESTORE_SHIM
cat > "$work/bin/ip6tables-restore" <<'RESTORE6_SHIM'
#!/usr/bin/env bash
set -u
cat > "$FAKE_STATE/ip6tables.txt"
printf 'restore-ip6tables\n' >> "$FAKE_STATE/mutations.log"
RESTORE6_SHIM
chmod +x "$work/bin"/*
"""

_SCENARIOS = r"""\
report() { printf '%s=%s\n' "$1" "$2"; }
digest() { sha256sum "$1" | cut -d' ' -f1; }

export FAKE_ROOT="$work/root"
export FAKE_STATE="$work/state"
PATH="$work/bin:$PATH"
export PATH
mkdir -p "$FAKE_ROOT/etc/ufw" "$FAKE_ROOT/etc/default" "$FAKE_ROOT/proc/net"
printf 'yes\n' > "$FAKE_STATE/enabled"
printf '2001:db8::1\n' > "$FAKE_ROOT/proc/net/if_inet6"
: > "$FAKE_STATE/mutations.log"
# The operator's own host: UFW active, a permissive incoming policy, forwarding
# off, and a rule written straight to the kernel — in no file UFW reloads, so a
# rollback that only deletes this install's four rules loses it for good.
cat > "$FAKE_ROOT/etc/default/ufw" <<'DEFAULT_UFW'
# /etc/default/ufw
IPV6=yes
DEFAULT_INPUT_POLICY="ACCEPT"
DEFAULT_UFW
cat > "$FAKE_ROOT/etc/ufw/user.rules" <<'USER_RULES'
-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
USER_RULES
cat > "$FAKE_STATE/iptables.txt" <<'IPV4'
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ufw-user-input - [0:0]
-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT
-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT
COMMIT
IPV4
cat > "$FAKE_STATE/ip6tables.txt" <<'IPV6'
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ufw6-user-input - [0:0]
-A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT
COMMIT
IPV6
cp "$FAKE_STATE/iptables.txt" "$work/iptables.before"
cp "$FAKE_STATE/ip6tables.txt" "$work/ip6tables.before"
config_before=$(digest "$FAKE_ROOT/etc/default/ufw")
ufw status verbose > "$work/status.before"

# 1. The image belongs to the transaction, and taking it changes nothing.
ACME_TX_ID="worker_install_casetx"
image=$(firewall_before_image "$FAKE_ROOT/var/lib/gowave-auto-nginx")
report image_is_per_transaction "$(case "$image" in */var/lib/gowave-auto-nginx/recovery/worker_install_casetx/firewall-before-image) echo 1;; *) echo 0;; esac)"
record_firewall_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/capture.err"
capture_rc=$?
report capture_mutates_nothing "$([[ "$capture_rc" -eq 0 && ! -s "$FAKE_STATE/mutations.log" ]] && echo 1 || echo 0)"

# 2. What the image holds, read from the image itself.
manifest="$image/manifest.json"
while IFS='=' read -r key value; do report "$key" "$value"; done < <(python3 - "$manifest" "$work/iptables.before" "$work/ip6tables.before" "$FAKE_ROOT/etc/default/ufw" <<'MANIFEST_FACTS'
import hashlib
import json
import os
import sys

manifest, ipv4, ipv6, config = sys.argv[1:5]


def digest(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def normalized(text):
    # The ruleset without the timestamp and the counters a dump carries.
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(":") and line.endswith("]"):
            line = line[: line.rindex("[")] + "[0:0]"
        lines.append(line)
    return "\n".join(lines)


def dump_text(entry):
    path = os.path.join(os.path.dirname(manifest), str((entry or {}).get("copy") or ""))
    return open(path, encoding="utf-8").read() if os.path.isfile(path) else ""


try:
    data = json.load(open(manifest, encoding="utf-8"))
except Exception:
    data = {}
entry = (data.get("files") or {}).get("/etc/default/ufw") or {}
print("image_names_enabled_state=%d" % (1 if data.get("enabled") is True else 0))
print("image_names_default_policies=%d" % (1 if data.get("defaults") == {"incoming": "allow", "outgoing": "allow", "routed": "disabled"} else 0))
print("image_keeps_rule_text=%d" % (1 if "8080/tcp" in (data.get("status_verbose") or "") else 0))
print("image_keeps_ipv4_dump=%d" % (1 if normalized(dump_text(data.get("iptables"))) == normalized(open(ipv4, encoding="utf-8").read()) else 0))
print("image_keeps_ipv6_dump=%d" % (1 if normalized(dump_text(data.get("ip6tables"))) == normalized(open(ipv6, encoding="utf-8").read()) else 0))
print("image_keeps_ufw_config=%d" % (1 if entry.get("sha256") == digest(config) else 0))
MANIFEST_FACTS
)
report image_mode_is_private "$([[ "$(stat -c '%a' "$manifest" 2>/dev/null)" == "600" ]] && echo 1 || echo 0)"

# 3. A second capture must not overwrite a restorable image.
record_firewall_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/repeat.err"
report existing_image_refused "$([[ "$?" -ne 0 ]] && grep -q 'already exists' "$work/repeat.err" && echo 1 || echo 0)"

# 4. The failure this compensates: the install ran its own sequence over the
# operator's host — user.rules rewritten with its two rules, the permissive
# incoming policy set to deny, UFW enabled — and then aborted. Every original
# rule, the operator's policy and the original file go with it.
: > "$FAKE_ROOT/etc/ufw/user.rules"
sed -i 's/^IPV6=.*/IPV6=no/' "$FAKE_ROOT/etc/default/ufw"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null
ufw --force enable >/dev/null
: > "$FAKE_STATE/mutations.log"
restore_firewall_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/restore.err"
restore_rc=$?
ufw status verbose > "$work/status.after"
report restore_returns_active_state "$([[ "$restore_rc" -eq 0 && "$(head -1 "$work/status.after")" == "Status: active" ]] && echo 1 || echo 0)"
report restore_returns_foreign_rule "$(grep -q '8080/tcp' "$work/status.after" && echo 1 || echo 0)"
report restore_returns_default_policies "$([[ "$(grep '^Default:' "$work/status.after")" == "$(grep '^Default:' "$work/status.before")" ]] && echo 1 || echo 0)"
report restore_returns_ufw_config "$([[ "$(digest "$FAKE_ROOT/etc/default/ufw")" == "$config_before" ]] && echo 1 || echo 0)"

# The read-back is the product's own, and what it compares has to be the rules:
# the dump it is handed back differs in its header and its counters, so a check
# that compared the text would refuse a restore that put every rule back.
iptables-save > "$work/save.after-restore"
readback=$(python3 - "$image/iptables-save.txt" "$work/save.after-restore" <<'READBACK_FACTS'
import sys

image_text, saved_text = (open(path, encoding="utf-8").read() for path in sys.argv[1:3])


def normalized(text):
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        if line.startswith(":") and line.endswith("]"):
            line = line[: line.rindex("[")] + "[0:0]"
        lines.append(line)
    return "\n".join(lines)


same_rules = normalized(image_text) == normalized(saved_text)
bookkeeping_moved = image_text != saved_text
print(1 if same_rules and bookkeeping_moved else 0)
READBACK_FACTS
)
report read_back_compares_the_rules "$([[ "$restore_rc" -eq 0 && "$readback" == "1" ]] && echo 1 || echo 0)"

# 5. Restoring the same image twice is the same firewall.
cp "$work/status.after" "$work/status.first"
restore_firewall_before_image "$FAKE_ROOT" "$image" >/dev/null 2>"$work/restore-again.err"
again_rc=$?
ufw status verbose > "$work/status.second"
report restore_is_idempotent "$([[ "$again_rc" -eq 0 ]] && cmp -s "$work/status.first" "$work/status.second" && echo 1 || echo 0)"

# 6. The other direction: UFW was inactive while the kernel still held the
# operator's rules, and the install switched it on over its own policy.
printf 'no\n' > "$FAKE_STATE/enabled"
cp "$work/iptables.before" "$FAKE_STATE/iptables.txt"
cp "$work/ip6tables.before" "$FAKE_STATE/ip6tables.txt"
sed -i 's/^IPV6=.*/IPV6=yes/' "$FAKE_ROOT/etc/default/ufw"
image_inactive="$work/image-inactive"
ufw status verbose > "$work/status.inactive.before"
record_firewall_before_image "$FAKE_ROOT" "$image_inactive" >/dev/null 2>"$work/capture-inactive.err"
inactive_capture_rc=$?
inactive_capture_facts=$(python3 - "$image_inactive/manifest.json" <<'INACTIVE_FACTS'
import json
import sys

try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    data = {}
print(1 if data.get("enabled") is False and data.get("defaults") == {} else 0)
INACTIVE_FACTS
)
report inactive_baseline_captured "$([[ "$inactive_capture_rc" -eq 0 && "$inactive_capture_facts" == "1" ]] && echo 1 || echo 0)"
ufw default deny incoming >/dev/null
ufw --force enable >/dev/null
: > "$FAKE_STATE/mutations.log"
restore_firewall_before_image "$FAKE_ROOT" "$image_inactive" >/dev/null 2>"$work/restore-inactive.err"
inactive_rc=$?
ufw status verbose > "$work/status.inactive"
# With UFW off the rule table is not what carries the rules: the operator's
# `--dport 8080` is in the kernel dump, so that is where a restore has to put it.
report restore_returns_inactive_state "$([[ "$inactive_rc" -eq 0 && "$(head -1 "$work/status.inactive")" == "Status: inactive" && "$(grep -c 'dport 8080' "$FAKE_STATE/iptables.txt")" -eq 1 ]] && echo 1 || echo 0)"

# 7. No image is a refusal, not an empty rule list to work from.
restore_firewall_before_image "$FAKE_ROOT" "$work/no-such-image" >/dev/null 2>"$work/missing.err"
report missing_image_refused "$([[ "$?" -ne 0 ]] && grep -q 'No firewall before-image' "$work/missing.err" && echo 1 || echo 0)"

# 8. A baseline the install cannot read back and restore is refused before the
# first mutation, and leaves no half image behind.
mkdir -p "$work/broken"
cp "$work/bin/ufw" "$work/bin/ip6tables-save" "$work/broken/"
cat > "$work/broken/iptables-save" <<'BROKEN_SAVE'
#!/usr/bin/env bash
echo "iptables-save: permission denied" >&2
exit 4
BROKEN_SAVE
chmod +x "$work/broken"/*
(
    PATH="$work/broken:$PATH"
    record_firewall_before_image "$FAKE_ROOT" "$work/image-broken" >/dev/null 2>"$work/broken.err"
)
report unrestorable_baseline_refused "$([[ "$?" -ne 0 && ! -e "$work/image-broken" ]] && echo 1 || echo 0)"

exit 0
"""


def _function_body(path: Path, signature: str) -> str:
    """The function as the product ships it, sliced out of its own file."""
    text = path.read_text(encoding="utf-8")
    start = text.index(signature)
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def guard_functions(path: Path = None) -> str:
    """The four shipped functions the case drives, in the order they appear."""
    source = path or WORKER_INSTALLER
    return "".join(_function_body(source, signature) for signature in _FUNCTION_SIGNATURES)


def image_body(path: Path = None) -> str:
    """The one heredoc the payload and the rollback script must agree on."""
    source = (path or WORKER_INSTALLER).read_text(encoding="utf-8")
    start = source.index("<<'FIREWALL_IMAGE_PY'\n") + len("<<'FIREWALL_IMAGE_PY'\n")
    end = source.index("\nFIREWALL_IMAGE_PY\n", start)
    return source[start:end]


def driver_script(path: Path = None) -> str:
    """A scratch host, the shipped image functions, and the states they decide."""
    return (
        "set -u\n"
        "work=$(mktemp -d)\n"
        "trap 'rm -rf \"$work\"' EXIT\n\n"
        + _SHIMS
        + "\n"
        + guard_functions(path)
        + "\n"
        + _SCENARIOS
    )


def _facts(result: Any, keys: List[str]) -> Dict[str, bool]:
    """The probe's ``key=1`` lines, read back as the facts the case asserts."""
    require(CASE_ID, result.returncode == 0,
            f"the firewall probe exited {result.returncode}: "
            f"{(result.stderr or '').strip()[-400:]}")
    values: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    missing = [key for key in keys if key not in values]
    require(CASE_ID, not missing,
            f"the firewall probe reported nothing for {', '.join(missing)}")
    return {key: values[key] == "1" for key in keys}


def _refuse(evidence: Dict[str, bool]) -> None:
    refused = [_SENTENCES[key] for key, fact in evidence.items() if not fact]
    if refused:
        raise AssertionError(f"{CASE_ID}: " + "; ".join(refused))


EVIDENCE = (
    "image_is_per_transaction",
    "capture_mutates_nothing",
    "image_names_enabled_state",
    "image_names_default_policies",
    "image_keeps_rule_text",
    "image_keeps_ipv4_dump",
    "image_keeps_ipv6_dump",
    "image_keeps_ufw_config",
    "image_mode_is_private",
    "existing_image_refused",
    "restore_returns_active_state",
    "restore_returns_foreign_rule",
    "restore_returns_default_policies",
    "inactive_baseline_captured",
    "restore_returns_inactive_state",
    "restore_returns_ufw_config",
    "read_back_compares_the_rules",
    "restore_is_idempotent",
    "missing_image_refused",
    "unrestorable_baseline_refused",
)


def case_panel_firewall_policy_is_preserved(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-03 on the AIO contour: the before-image run on the host it installed."""
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
        "image_names_enabled_state": facts["image_names_enabled_state"],
        "image_names_default_policies": facts["image_names_default_policies"],
        "image_keeps_rule_text": facts["image_keeps_rule_text"],
        "image_keeps_ipv4_dump": facts["image_keeps_ipv4_dump"],
        "image_keeps_ipv6_dump": facts["image_keeps_ipv6_dump"],
        "image_keeps_ufw_config": facts["image_keeps_ufw_config"],
        "image_mode_is_private": facts["image_mode_is_private"],
        "existing_image_refused": facts["existing_image_refused"],
        "restore_returns_active_state": facts["restore_returns_active_state"],
        "restore_returns_foreign_rule": facts["restore_returns_foreign_rule"],
        "restore_returns_default_policies": facts["restore_returns_default_policies"],
        "inactive_baseline_captured": facts["inactive_baseline_captured"],
        "restore_returns_inactive_state": facts["restore_returns_inactive_state"],
        "restore_returns_ufw_config": facts["restore_returns_ufw_config"],
        "read_back_compares_the_rules": facts["read_back_compares_the_rules"],
        "restore_is_idempotent": facts["restore_is_idempotent"],
        "missing_image_refused": facts["missing_image_refused"],
        "unrestorable_baseline_refused": facts["unrestorable_baseline_refused"],
    }
    _refuse(evidence)
    return evidence


def case_worker_firewall_policy_is_preserved(product: Any, run: Any) -> Dict[str, Any]:
    """OWN-03 on the multi-node contour: the before-image run on the Worker."""
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
        "image_names_enabled_state": facts["image_names_enabled_state"],
        "image_names_default_policies": facts["image_names_default_policies"],
        "image_keeps_rule_text": facts["image_keeps_rule_text"],
        "image_keeps_ipv4_dump": facts["image_keeps_ipv4_dump"],
        "image_keeps_ipv6_dump": facts["image_keeps_ipv6_dump"],
        "image_keeps_ufw_config": facts["image_keeps_ufw_config"],
        "image_mode_is_private": facts["image_mode_is_private"],
        "existing_image_refused": facts["existing_image_refused"],
        "restore_returns_active_state": facts["restore_returns_active_state"],
        "restore_returns_foreign_rule": facts["restore_returns_foreign_rule"],
        "restore_returns_default_policies": facts["restore_returns_default_policies"],
        "inactive_baseline_captured": facts["inactive_baseline_captured"],
        "restore_returns_inactive_state": facts["restore_returns_inactive_state"],
        "restore_returns_ufw_config": facts["restore_returns_ufw_config"],
        "read_back_compares_the_rules": facts["read_back_compares_the_rules"],
        "restore_is_idempotent": facts["restore_is_idempotent"],
        "missing_image_refused": facts["missing_image_refused"],
        "unrestorable_baseline_refused": facts["unrestorable_baseline_refused"],
    }
    _refuse(evidence)
    return evidence
