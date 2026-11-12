"""FW-01/FW-02: untrusted management access is denied while the trusted path works.

The Worker's control port is not simply closed: UFW allows it only from the
address the Master used during ``node add``, and the node itself demands a
client certificate on top of that. A refusal seen from one container proves
neither half — a stopped node, a route failure, or a probe sent from the
Master's own address all look the same. So the denial is measured from the
``untrusted-client`` role, every denial is paired with the product's own
working path (the Master's mTLS health answer and its pinned-key SSH command),
and the Worker's effective rules plus the source address it logged for the
attempt are required before a refusal counts as a decision by the firewall.

Nothing here re-implements a product decision. The probe attempts a real SSH
login with an identity the Worker was never told to trust and a real TCP
connection to the control port; the evidence is what those attempts made the
Worker record. SSH is deliberately attempted with host-key verification
disabled and only a public-key method offered: the question is authentication,
so making the host key the reason a login failed would answer a different one.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence

NODE_PORT = 3002
SSH_PORT = 22

# Markers are what separates "the command ran" from "the connection ended".
TRUSTED_MARKER = "GOWAVE_TRUSTED_SSH_OK"
UNTRUSTED_MARKER = "GOWAVE_UNTRUSTED_COMMAND_OK"

FIREWALL = "firewall"
AMBIGUOUS = "ambiguous"
ACCEPTED = "accepted"

PROBE_TIMEOUT_SECONDS = 120
SSH_TIMEOUT_SECONDS = 60
WORKER_REPORT_TIMEOUT_SECONDS = 120
SSHD_OBSERVATION_TIMEOUT_SECONDS = 30

# The client the probe and the operator's command use, named by absolute path
# because both run inside the target container rather than on this host: the
# harness itself never opens an SSH connection.
SSH_CLIENT = "/usr/bin/ssh"
SSH_KEYGEN = "/usr/bin/ssh-keygen"

_UNTRUSTED_PROBE = r'''#!/usr/bin/env bash
# The clean target image has bash, coreutils, and an SSH client, but no Python:
# the product installs Python on the hosts it manages, and this role never ran
# the product. So the probe is shell, and it prints one key=value per fact.
set -u

WORKER="__WORKER_IP__"
NODE_PORT="__NODE_PORT__"
SSH_PORT="__SSH_PORT__"
MARKER="__MARKER__"
SSH_CLIENT="__SSH_CLIENT__"
SSH_KEYGEN="__SSH_KEYGEN__"

printf 'worker=%s\n' "$WORKER"
printf 'node_port=%s\n' "$NODE_PORT"

# The management plane first: this is the port the Worker's firewall scopes to
# the Master, so any answer other than a refused or dropped connection means the
# allowlist is not in force. bash's /dev/tcp performs a real TCP handshake.
detail=$(WORKER="$WORKER" PORT="$NODE_PORT" timeout 10 bash -c 'exec 3<>/dev/tcp/$WORKER/$PORT' 2>&1)
rc=$?
# One fact per line: a multi-line reason would be read as several keys.
detail=$(printf '%s' "$detail" | tr '\n' ' ')
if [ "$rc" -eq 0 ]; then
    printf 'management=CONNECTED\n'
elif [ "$rc" -eq 124 ]; then
    printf 'management=TIMEOUT\n'
    printf 'management_detail=no answer within 10s\n'
elif printf '%s' "$detail" | grep -qi 'refused'; then
    printf 'management=REFUSED\n'
    printf 'management_detail=%s\n' "$detail"
else
    printf 'management=UNREACHABLE\n'
    printf 'management_detail=%s\n' "${detail:-no route}"
fi

# Then SSH as an identity the Worker has never been told about. Host-key
# verification is skipped on purpose: with it enabled a login could fail before
# authentication is even attempted, which is a different finding.
keydir=$(mktemp -d)
if [ -n "${keydir:-}" ]; then
    chmod 0700 "$keydir"
fi
if [ -z "${keydir:-}" ] || ! "$SSH_KEYGEN" -q -t ed25519 -N '' -f "$keydir/id_ed25519" >/dev/null 2>&1; then
    printf 'ssh_outcome=NO_CLIENT\n'
    printf 'ssh_detail=%s\n' "ssh-keygen is unavailable"
    exit 0
fi

timeout 40 "$SSH_CLIENT" -T -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o GlobalKnownHostsFile=/dev/null \
    -o PreferredAuthentications=publickey \
    -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no \
    -o ConnectTimeout=10 \
    -o LogLevel=ERROR \
    -i "$keydir/id_ed25519" \
    "root@$WORKER" "printf $MARKER" \
    >"$keydir/out" 2>"$keydir/err"
rc=$?

if grep -qF "$MARKER" "$keydir/out" 2>/dev/null; then
    printf 'ssh_command_output=1\n'
else
    printf 'ssh_command_output=0\n'
fi
if [ "$rc" -eq 124 ]; then
    printf 'ssh_outcome=TIMEOUT\n'
elif [ "$rc" -ne 0 ]; then
    printf 'ssh_outcome=REJECTED\n'
else
    printf 'ssh_outcome=ACCEPTED\n'
fi
printf 'ssh_returncode=%s\n' "$rc"
printf 'ssh_stderr=%s\n' "$(tail -n 1 "$keydir/err" 2>/dev/null)"
rm -rf "$keydir"
exit 0
'''

_WORKER_FIREWALL = r'''
import json, subprocess

PORT = __NODE_PORT__

report = {"node_port": PORT}


def run(*argv):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


code, out, err = run("ufw", "status", "verbose")
report["ufw_returncode"] = code
report["ufw"] = [line.rstrip() for line in out.splitlines() if line.strip()]

code, out, err = run("iptables", "-S")
report["iptables_returncode"] = code
report["iptables_error"] = (err or out).strip()[-400:]
report["iptables"] = [line.rstrip() for line in out.splitlines() if line.strip()]

code, out, err = run("iptables", "-L", "-v", "-n", "-x")
report["counters_returncode"] = code
report["counters"] = [
    line.rstrip() for line in out.splitlines() if ("dpt:%d" % PORT) in line
]

print(json.dumps(report))
'''

_SSHD_OBSERVATION = r'''
import json, os, subprocess

NEEDLE = __NEEDLE__

lines = []


def collect(*argv):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.SubprocessError):
        return
    lines.extend((proc.stdout or "").splitlines())


collect("journalctl", "-q", "--no-pager", "-n", "800", "-o", "cat")
collect("dmesg")
for path in ("/var/log/auth.log", "/var/log/secure"):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines.extend(handle.read().splitlines()[-800:])
    except OSError:
        continue

matches = [
    line.strip() for line in lines
    if NEEDLE in line and "sshd" in line.lower()
]
print(json.dumps({"count": len(matches), "matches": matches[-5:]}))
'''


def untrusted_probe_script(
    worker_ip: str, node_port: int = NODE_PORT, ssh_port: int = SSH_PORT,
) -> str:
    """The probe the untrusted role runs: a real control-plane and SSH attempt."""
    return (
        _UNTRUSTED_PROBE
        .replace("__WORKER_IP__", worker_ip)
        .replace("__NODE_PORT__", str(node_port))
        .replace("__SSH_PORT__", str(ssh_port))
        .replace("__MARKER__", UNTRUSTED_MARKER)
        .replace("__SSH_CLIENT__", SSH_CLIENT)
        .replace("__SSH_KEYGEN__", SSH_KEYGEN)
    )


def trusted_ssh_command(worker_ip: str, ssh_port: int = SSH_PORT) -> str:
    """The operator's own SSH path: pinned host key, authorized identity."""
    return (
        "umask 077\n"
        f"{SSH_CLIENT} -T -o BatchMode=yes -o StrictHostKeyChecking=yes "
        f"-o UserKnownHostsFile=/root/.ssh/known_hosts -o ConnectTimeout=10 "
        f"-p {ssh_port} root@{worker_ip} 'printf {TRUSTED_MARKER}'\n"
        f"printf ' rc=%s\\n' \"$?\"\n"
    )


def worker_firewall_script(node_port: int = NODE_PORT) -> str:
    """What the Worker's own firewall says, in the product's own rule set."""
    return _WORKER_FIREWALL.replace("__NODE_PORT__", str(node_port))


def sshd_observation_script(needle: str) -> str:
    """Every recent log line that names one source address."""
    return _SSHD_OBSERVATION.replace("__NEEDLE__", json.dumps(needle))


def _json_object(output: str) -> Dict[str, Any]:
    for line in reversed((output or "").splitlines()):
        stripped = line.strip()
        if not (stripped.startswith("{") and stripped.endswith("}")):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def parse_untrusted_probe(output: str) -> Dict[str, Any]:
    """The probe's key=value report, shaped as the two attempts it made.

    An empty report means the probe never reached a verdict: the case that reads
    it blocks rather than accepting "no output" as a refusal.
    """
    values: Dict[str, str] = {}
    for line in (output or "").splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        values[key.strip()] = value.strip()
    outcome = values.get("management")
    if not outcome:
        return {}
    returncode = values.get("ssh_returncode", "")
    report: Dict[str, Any] = {
        "management": {"outcome": outcome},
        "ssh_login": {
            "outcome": values.get("ssh_outcome", ""),
            "returncode": int(returncode) if returncode.lstrip("-").isdigit() else None,
            "command_output": values.get("ssh_command_output") == "1",
            "stderr": values.get("ssh_stderr", ""),
        },
    }
    for key in ("management_detail", "ssh_detail"):
        if values.get(key):
            target = report["management"] if key == "management_detail" else report["ssh_login"]
            target["detail"] = values[key]
    if values.get("worker"):
        report["worker"] = values["worker"]
    return report


def parse_trusted_ssh(output: str) -> Dict[str, Any]:
    """The pinned-key SSH command's marker and exit code."""
    text = output or ""
    codes = re.findall(r"^\s*rc=(\d+)\s*$", text, flags=re.MULTILINE)
    return {
        "marker": TRUSTED_MARKER in text,
        "returncode": int(codes[-1]) if codes else None,
    }


def parse_sshd_observation(output: str) -> List[str]:
    """The lines the Worker logged that name the probed source address."""
    report = _json_object(output)
    matches = report.get("matches") or []
    return [str(line) for line in matches if isinstance(line, str)]


def parse_node_rules(rules: Sequence[str], node_port: int = NODE_PORT) -> Dict[str, Any]:
    """The effective rules for the node port, split by what they do to a packet."""
    allows: List[Dict[str, str]] = []
    blocks: List[Dict[str, str]] = []
    for line in rules:
        fields = line.split()
        if "--dport" not in fields:
            continue
        index = fields.index("--dport")
        if index + 1 >= len(fields) or fields[index + 1] != str(node_port):
            continue
        target = fields[fields.index("-j") + 1] if "-j" in fields else ""
        source = ""
        if "-s" in fields:
            source = fields[fields.index("-s") + 1].split("/")[0]
        entry = {"target": target, "source": source, "line": line.strip()}
        if target in ("ACCEPT", "RETURN"):
            allows.append(entry)
        else:
            blocks.append(entry)
    return {"allows": allows, "blocks": blocks}


def parse_ssh_rules(rules: Sequence[str], ssh_port: int = SSH_PORT) -> Dict[str, Any]:
    """Whether the operator's SSH port is open to every source.

    It has to be: the Master reaches the Worker over SSH from one address, but a
    product that also let SSH in from anywhere would make the authentication
    denial this case measures the only thing standing between an untrusted host
    and the Worker - which is exactly what makes the finding meaningful.
    """
    anywhere = False
    scoped: List[str] = []
    for line in rules:
        fields = line.split()
        if "--dport" not in fields:
            continue
        index = fields.index("--dport")
        if index + 1 >= len(fields) or fields[index + 1] != str(ssh_port):
            continue
        if "-j" not in fields or fields[fields.index("-j") + 1] != "ACCEPT":
            continue
        if "-s" in fields:
            scoped.append(fields[fields.index("-s") + 1].split("/")[0])
        else:
            anywhere = True
    return {"anywhere": anywhere, "scoped_sources": sorted(set(scoped))}


def parse_counters(lines: Sequence[str], node_port: int = NODE_PORT) -> List[Dict[str, Any]]:
    """The packet counters of every rule that mentions the node port.

    ``iptables -L -v -n -x`` prints packets and bytes first, then the verdict,
    the protocol, and the addresses, so the address that is not the destination
    wildcard is the rule's source.
    """
    entries: List[Dict[str, Any]] = []
    for line in lines:
        if f"dpt:{node_port}" not in line:
            continue
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        source = ""
        for token in fields[3:]:
            candidate = token.split("/")[0]
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", candidate) and candidate != "0.0.0.0":
                source = candidate
                break
        entries.append({
            "packets": int(fields[0]),
            "bytes": int(fields[1]) if fields[1].isdigit() else None,
            "target": fields[2],
            "source": source,
        })
    return entries


def parse_worker_firewall(
    report: Dict[str, Any], node_port: int = NODE_PORT, ssh_port: int = SSH_PORT,
) -> Dict[str, Any]:
    """The Worker's firewall as the cases need it: policy, allowlist, counters."""
    rules = [str(line) for line in report.get("iptables") or []]
    node = parse_node_rules(rules, node_port)
    ssh = parse_ssh_rules(rules, ssh_port)
    policy = ""
    for line in rules:
        if line.startswith("-P INPUT "):
            policy = line.split()[2]
    ufw = [str(line) for line in report.get("ufw") or []]
    unscoped = [entry for entry in node["allows"] if not entry["source"]]
    return {
        "active": any(line.strip() == "Status: active" for line in ufw),
        "input_policy": policy,
        "node_allows": node["allows"],
        "node_blocks": node["blocks"],
        "node_allow_sources": sorted({entry["source"] for entry in node["allows"] if entry["source"]}),
        "unscoped_allows": unscoped,
        "ssh_anywhere": ssh["anywhere"],
        "ssh_scoped_sources": ssh["scoped_sources"],
        "counters": parse_counters(report.get("counters") or [], node_port),
        "iptables_returncode": report.get("iptables_returncode"),
        "iptables_error": report.get("iptables_error") or "",
    }


def classify_denial(
    *,
    management_outcome: str,
    positive_control: bool,
    worker_rule_scoped: bool,
    observed_source: Optional[str],
    allowed_source: str,
) -> tuple[str, str]:
    """Decide what a refusal is evidence of, and refuse to call it a policy win alone.

    Order matters: an accepted connection is a finding on its own, and only then
    does each missing support turn the refusal into INCOMPLETE rather than PASS.
    """
    if management_outcome == "CONNECTED":
        return ACCEPTED, (
            "the untrusted source completed a TCP connection to the Worker's control "
            "port, so the source allowlist is not in force"
        )
    if management_outcome not in ("REFUSED", "TIMEOUT"):
        return AMBIGUOUS, (
            f"the untrusted probe ended {management_outcome!r}, which is neither the "
            "Worker's decision nor a measured refusal"
        )
    if not positive_control:
        return AMBIGUOUS, (
            "the Master's own authenticated control-plane call did not succeed, so the "
            "refusal says the control plane was down rather than that this source was denied"
        )
    if not worker_rule_scoped:
        return AMBIGUOUS, (
            "the Worker's effective rules do not show the control port allowed from the "
            "Master and denied everywhere else, so the refusal is not attributable to a policy"
        )
    if not observed_source:
        return AMBIGUOUS, (
            "the Worker recorded no source address for the attempt, so the vantage that was "
            "denied is unproven"
        )
    if observed_source == allowed_source:
        return AMBIGUOUS, (
            f"the probe arrived from {observed_source}, the address the Worker allows, so the "
            "refusal is not about this vantage"
        )
    return FIREWALL, (
        f"the Worker denied {observed_source} while allowing {allowed_source}, with its own "
        "rules and log naming both"
    )


def run_untrusted_probe(
    podman: Any, container: str, worker_ip: str,
    timeout: int = PROBE_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Run both attempts from the untrusted role and return its own report."""
    result = podman.exec_bash(
        container, untrusted_probe_script(worker_ip),
        check=False, timeout=timeout,
    )
    report = parse_untrusted_probe(result.stdout or "")
    report.setdefault("returncode", result.returncode)
    if not report.get("management"):
        report["detail"] = (result.stderr or result.stdout or "").strip()[-600:]
    return report


def run_trusted_ssh(
    podman: Any, container: str, worker_ip: str,
    timeout: int = SSH_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Run the operator's pinned-key SSH command from the Master."""
    result = podman.exec_bash(
        container, trusted_ssh_command(worker_ip), check=False, timeout=timeout,
    )
    facts = parse_trusted_ssh(result.stdout or "")
    facts["stderr"] = (result.stderr or "").strip()[-400:]
    facts["returncode"] = result.returncode if facts["returncode"] is None else facts["returncode"]
    return facts


def worker_firewall(
    podman: Any, container: str, node_port: int = NODE_PORT,
    timeout: int = WORKER_REPORT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """The Worker's effective firewall rules and counters."""
    result = podman.exec(
        container, ["python3", "-c", worker_firewall_script(node_port)],
        check=False, timeout=timeout,
    )
    report = _json_object(result.stdout or "")
    facts = parse_worker_firewall(report, node_port)
    facts["returncode"] = result.returncode
    facts["detail"] = (result.stderr or "").strip()[-400:]
    return facts


def sshd_observation(
    podman: Any, container: str, needle: str,
    timeout: int = WORKER_REPORT_TIMEOUT_SECONDS,
) -> List[str]:
    """The Worker's log lines naming one source address, read in one pass."""
    result = podman.exec(
        container, ["python3", "-c", sshd_observation_script(needle)],
        check=False, timeout=timeout,
    )
    return parse_sshd_observation(result.stdout or "")
