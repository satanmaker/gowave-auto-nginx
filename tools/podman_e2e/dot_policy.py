"""What an unusable encrypted resolver path does to each DNS-over-TLS policy.

`DOT-853` and `DOT-RESTORE` are the two halves of the requirement a host's
security report is only as good as: an optional control may degrade, but the
degradation must be visible, readiness must survive it only when the previous
resolver is proven to work again, and an unproven restoration must stop every
policy instead of being rounded into a pass.

Both cases run on an installed host rather than against a stubbed toolchain:
the encrypted path is closed with a real firewall rule on the host's own
outbound chain, the product's own `--prepare-dns` is what fails, and the verdict
is read from the product's own `--security-report`. The host is left exactly as
the install had it — the case compares the firewall rule set with the snapshot
it took before the first rule and re-establishes the installed policy at the end.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from tools.podman_e2e import topology
from tools.podman_e2e.runner import require

DOT_BLOCKED_CASE_ID = "DOT-853"
DOT_RESTORE_CASE_ID = "DOT-RESTORE"
DOT_CASE_TIMEOUT_SECONDS = 900

_MANAGED = f"{topology.REPO_IN_CONTAINER}/assets/security/managed.py"
# The chain the cases own, so the rules they add are removed as a unit: a
# case that edited the host's own chains would leave the next readback of the
# managed policy with an exception nobody applied.
_CHAIN = "GOWAVE-DOT-CASE"
# A blocked encrypted path is the shape a censored network produces: the TCP
# port a TLS resolver listens on is refused, everything else answers.
_ENCIPHERED_PORT = "853"
# getent's second call is the rollback's own proof that DNS works again. The
# wrapper below lets the first call through — the preflight the step makes
# before it touches the host — and refuses the proof, which is what an upstream
# that died during the run looks like from inside the product.
_GETENT_SHIM = "/run/gowave-dot-case/bin/getent"


def _normalised_rules(product: Any, container: str, case_id: str, stage: str) -> Dict[str, str]:
    """The host's rule set without the counters that move on their own."""
    facts: Dict[str, str] = {}
    for tool in ("iptables-save", "ip6tables-save"):
        result = product.podman.exec_bash(container, f"{tool} 2>/dev/null", check=False, timeout=60)
        require(case_id,
                result.returncode == 0 and result.stdout.strip(),
                f"{stage}: {tool} answered nothing on {container}, so the case cannot prove "
                f"the rule set it started with came back")
        kept = [line for line in result.stdout.splitlines() if not line.startswith("#")]
        facts[tool] = "\n".join(line.replace("[0:0]", "") for line in kept)
    return facts


def _open_chain(product: Any, container: str, case_id: str) -> None:
    """Close the encrypted path on the host's own outbound chain."""
    rules = [
        f"iptables -N {_CHAIN}",
        f"iptables -I OUTPUT 1 -j {_CHAIN}",
        f"iptables -A {_CHAIN} -p tcp --dport {_ENCIPHERED_PORT} -j REJECT",
        f"iptables -A {_CHAIN} -p udp --dport {_ENCIPHERED_PORT} -j REJECT",
        f"ip6tables -N {_CHAIN}",
        f"ip6tables -I OUTPUT 1 -j {_CHAIN}",
        f"ip6tables -A {_CHAIN} -p tcp --dport {_ENCIPHERED_PORT} -j REJECT",
        f"ip6tables -A {_CHAIN} -p udp --dport {_ENCIPHERED_PORT} -j REJECT",
    ]
    script = "set -Eeuo pipefail\n" + "\n".join(rules) + "\nresolvectl flush-caches >/dev/null 2>&1 || true\n"
    result = product.podman.exec_bash(container, script, check=False, timeout=120)
    require(case_id,
            result.returncode == 0,
            f"the case could not close the encrypted path on {container}: "
            f"{(result.stderr or result.stdout or '')[-400:]}")


def _close_chain(product: Any, container: str) -> None:
    """Best-effort removal, safe to call whether or not the rules were added."""
    script = "set -u\n" + "\n".join([
        f"iptables -D OUTPUT -j {_CHAIN} 2>/dev/null || true",
        f"iptables -F {_CHAIN} 2>/dev/null || true",
        f"iptables -X {_CHAIN} 2>/dev/null || true",
        f"ip6tables -D OUTPUT -j {_CHAIN} 2>/dev/null || true",
        f"ip6tables -F {_CHAIN} 2>/dev/null || true",
        f"ip6tables -X {_CHAIN} 2>/dev/null || true",
        "resolvectl flush-caches >/dev/null 2>&1 || true",
        "true",
    ]) + "\n"
    product.podman.exec_bash(container, script, check=False, timeout=120)


def _install_getent_shim(product: Any, container: str, case_id: str) -> None:
    """Make the rollback's own resolution proof fail, and only that proof."""
    script = f"""set -Eeuo pipefail
mkdir -p /run/gowave-dot-case/bin /run/gowave-dot-case/count
cat > {_GETENT_SHIM} <<'SHIM'
#!/usr/bin/env bash
# The step asks getent once before it touches the host and once after the
# rollback; the second answer is the one a dead upstream would swallow.
count=/run/gowave-dot-case/count/calls
calls=0
[ -f "$count" ] && calls=$(cat "$count")
calls=$((calls + 1))
printf '%s\\n' "$calls" > "$count"
if [ "$calls" -ge 2 ] && [ "$1" = ahosts ]; then
    echo "getent: Temporary failure in name resolution" >&2
    exit 2
fi
exec /usr/bin/getent "$@"
SHIM
chmod 0755 {_GETENT_SHIM}
"""
    result = product.podman.exec_bash(container, script, check=False, timeout=120)
    require(case_id, result.returncode == 0,
            f"the case could not install its resolution probe: "
            f"{(result.stderr or result.stdout or '')[-400:]}")


def _remove_getent_shim(product: Any, container: str) -> None:
    product.podman.exec_bash(container, "rm -rf /run/gowave-dot-case; true", check=False, timeout=60)


def _reset_getent_shim(product: Any, container: str) -> None:
    """Start one arm's own count: the wrapper refuses everything after the first."""
    product.podman.exec_bash(
        container, "rm -f /run/gowave-dot-case/count/calls; true", check=False, timeout=60)


def _dot_step(product: Any, container: str, case_id: str, policy: str,
              shimmed: bool = False) -> Dict[str, Any]:
    """Run the product's own DoT preparation and return its verdict."""
    prefix = f"PATH=/run/gowave-dot-case/bin:$PATH " if shimmed else ""
    script = (f"{prefix}GOWAVE_DOT_POLICY={policy} python3 {_MANAGED} --prepare-dns "
              f"</dev/null 2>/dev/null")
    result = product.podman.exec_bash(container, script, check=False, timeout=420)
    try:
        facts = json.loads(result.stdout or "")
    except json.JSONDecodeError:
        facts = {}
    require(case_id,
            isinstance(facts, dict) and facts.get('status'),
            f"the {policy} DNS step printed no verdict on {container}: "
            f"stdout={result.stdout[-300:]!r} stderr={result.stderr[-300:]!r}")
    return facts


def _has_ipv6(product: Any, container: str, case_id: str) -> bool:
    """The same decision the install makes, read the same way it reads it.

    `[[ -s /proc/net/if_inet6 ]]` answers "empty" on a dual-stack host, because
    procfs reports a zero inode size however many addresses the table prints —
    the product reads the table and the sysctl instead, and a case that took the
    shortcut would hand the report a policy the host was never given.
    """
    result = product.podman.exec_bash(
        container,
        "if [ -f /proc/net/if_inet6 ] && grep -q '[^[:space:]]' /proc/net/if_inet6 2>/dev/null; then\n"
        "    disabled=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo 0)\n"
        "    if [ \"$disabled\" = 1 ]; then echo false; else echo true; fi\n"
        "else\n"
        "    echo false\n"
        "fi",
        check=False, timeout=60,
    )
    answer = (result.stdout or "").strip().splitlines()
    require(case_id, result.returncode == 0 and answer and answer[-1] in ("true", "false"),
            f"could not read the host's IPv6 decision on {container}: "
            f"{(result.stderr or result.stdout or '')[-300:]!r}")
    return answer[-1] == "true"


def _node_port(product: Any, container: str, case_id: str) -> int:
    """The Node API port this host actually runs, so the report reads its own policy.

    The report re-derives the firewall policy from the role and this port; a
    hard-coded one would verify a policy no host was given as soon as a plan
    changes the port, and the case would fail on the report instead of on DoT.
    """
    result = product.podman.exec_bash(
        container,
        "systemctl show gowave-node.service -p Environment --value 2>/dev/null "
        "| tr ' ' '\\n' | sed -n 's/^NODE_PORT=//p' | head -1",
        check=False, timeout=60,
    )
    reported = (result.stdout or "").strip()
    require(case_id, not reported or reported.isdigit(),
            f"the host reports a Node API port that is not a number: {reported!r}")
    port = int(reported) if reported else 3002
    require(case_id, 1 <= port <= 65535,
            f"the host reports an unusable Node API port: {port}")
    return port


def _report(product: Any, container: str, case_id: str, policy: str,
            recovery: str, ipv6: bool, port: int) -> Dict[str, Any]:
    """Read the host's own report under the policy the step was asked for.

    The verdict comes from `--security-report`, and the document it wrote is
    read back with it: the readiness is the reduction, but the per-control
    status and recovery are what the Panel stores, and a report that conflated
    them would still reduce to the same word.
    """
    request = json.dumps({
        "role": "aio",
        "node_port": port,
        "master_sources": [],
        "ipv6": ipv6,
        "dot_recovery": recovery,
    })
    script = f"""set -Eeuo pipefail
verdict=''
rc=0
verdict=$(printf '%s' '{request}' | GOWAVE_DOT_POLICY={policy} python3 {_MANAGED} --security-report) || rc=$?
printf '%s\\n' "$verdict"
path=$(printf '%s' "$verdict" | python3 -c 'import json,sys
print(json.load(sys.stdin).get("report", ""))' 2>/dev/null || true)
if [ -n "$path" ] && [ -f "$path" ]; then
    printf '%s\\n' "--- report ---"
    cat "$path"
fi
"""
    result = product.podman.exec_bash(container, script, check=False, timeout=300)
    verdict_text, _, document_text = (result.stdout or "").partition("--- report ---")
    try:
        facts = json.loads(verdict_text or "")
    except json.JSONDecodeError:
        facts = {}
    require(case_id,
            isinstance(facts, dict) and facts.get('readiness'),
            f"the {policy} report printed no verdict on {container}: "
            f"stdout={result.stdout[-400:]!r} stderr={result.stderr[-400:]!r}")
    try:
        document = json.loads(document_text or "")
    except json.JSONDecodeError:
        document = {}
    require(case_id,
            isinstance(document, dict) and 'controls' in document,
            f"the {policy} report was not written where its own verdict named it on "
            f"{container}, so its per-control outcome cannot be read")
    facts['document'] = document
    return facts


def _require_warning(case_id: str, facts: Dict[str, Any], needle: str, stage: str) -> None:
    warnings = " ".join(str(item) for item in facts.get("warnings") or [])
    require(case_id, needle in warnings,
            f"{stage}: the step did not name {needle!r} among its warnings, so this is a "
            f"different failure than the one the case is about: {warnings[-500:]!r}")


def _restore_installed_policy(product: Any, container: str, case_id: str,
                              ipv6: bool, port: int) -> Dict[str, Any]:
    """Put back what the install had and prove it with the product's own report."""
    restored = _dot_step(product, container, case_id, "best-effort")
    require(case_id,
            restored.get('status') == 'configured',
            f"the host was not left with the installed DNS-over-TLS policy: {restored!r}")
    report = _report(product, container, case_id, "best-effort",
                     str(restored.get('recovery') or 'not-needed'), ipv6, port)
    require(case_id,
            report.get('readiness') == 'ready',
            f"the restored host is not ready: {report.get('readiness')} "
            f"controls={report.get('controls')} warnings={(report.get('warnings') or [''])[0][:300]}")
    return restored


def case_blocked_encrypted_path(product: Any) -> Dict[str, Any]:
    """DOT-853: a blocked TLS resolver degrades best-effort and stops required."""
    case_id = DOT_BLOCKED_CASE_ID
    host = product.require_installed()
    container = host.target_name
    ipv6 = _has_ipv6(product, container, case_id)
    port = _node_port(product, container, case_id)
    before = _normalised_rules(product, container, case_id, "before the case")
    _close_chain(product, container)
    _open_chain(product, container, case_id)
    try:
        optional = _dot_step(product, container, case_id, "best-effort")
        require(case_id,
                optional.get('status') == 'failed_rolled_back' and optional.get('recovery') == 'verified',
                f"with the encrypted path closed the optional policy reported "
                f"{optional.get('status')!r}/{optional.get('recovery')!r}, so either DoT was "
                f"called delivered while it could not be, or the previous resolver was not "
                f"proven: {optional.get('warnings')}")
        _require_warning(case_id, optional, "DNS-over-TLS verification",
                         "the optional run failed somewhere other than the TLS check")
        optional_report = _report(product, container, case_id, "best-effort",
                                  str(optional['recovery']), ipv6, port)
        require(case_id,
                optional_report.get('readiness') == 'ready-with-warnings',
                f"a failed optional control with a proven rollback must be a warning, not "
                f"{optional_report.get('readiness')!r}")
        dot = (optional_report.get('controls') or {}).get('dot')
        require(case_id, dot == 'failed',
                f"the report does not call the optional DoT control failed: {dot!r}")
        dot_control = (optional_report['document'].get('controls') or {}).get('dot') or {}
        require(case_id,
                (dot_control.get('status'), dot_control.get('recovery'), dot_control.get('policy'))
                == ('failed', 'verified', 'best-effort'),
                f"the report conflates the optional control with its recovery: {dot_control!r}")

        required = _dot_step(product, container, case_id, "required")
        require(case_id,
                required.get('status') == 'failed_rolled_back' and required.get('recovery') == 'verified',
                f"the required policy reported {required.get('status')!r}/"
                f"{required.get('recovery')!r} with the same blocked path")
        required_report = _report(product, container, case_id, "required",
                                  str(required['recovery']), ipv6, port)
        require(case_id,
                required_report.get('readiness') == 'failed',
                f"a failed required control with a proven rollback must block readiness, not "
                f"{required_report.get('readiness')!r}")
        require(case_id,
                (required_report.get('controls') or {}).get('dot') == 'failed',
                f"the required report does not call the DoT control failed: "
                f"{required_report.get('controls')}")
        required_control = (required_report['document'].get('controls') or {}).get('dot') or {}
        require(case_id,
                (required_control.get('status'), required_control.get('recovery'))
                == ('failed', 'verified'),
                f"the required report conflates the control with its recovery: {required_control!r}")
    finally:
        _close_chain(product, container)
    _restore_installed_policy(product, container, case_id, ipv6, port)
    after = _normalised_rules(product, container, case_id, "after the case")
    for key, value in before.items():
        require(case_id, after.get(key) == value,
                f"{key} changed across the case, so the host was not left as it was found")
    return {"optional": "failed_rolled_back/verified",
            "required": "failed_rolled_back/verified",
            "readiness": ["ready-with-warnings", "failed"],
            "rules": "unchanged"}


def case_unverifiable_restoration(product: Any) -> Dict[str, Any]:
    """DOT-RESTORE: an unproven restoration stops every policy.

    The encrypted path is closed for real, as in `DOT-853`. What makes the
    restoration unverifiable here is the state a dying upstream leaves behind:
    the rollback puts the previous resolver files back, restarts the service,
    and then cannot prove that names resolve — the step's own post-rollback
    probe is the one its shim refuses. The case therefore drives the product's
    real rollback, and only the answer that proves the rollback is withheld.
    Nothing on the host is left broken: the shim is a directory under `/run`
    that the case removes, and the plaintext resolver stays reachable so the
    preflight the step makes before it touches the host still answers.
    """
    case_id = DOT_RESTORE_CASE_ID
    host = product.require_installed()
    container = host.target_name
    ipv6 = _has_ipv6(product, container, case_id)
    port = _node_port(product, container, case_id)
    before = _normalised_rules(product, container, case_id, "before the case")
    _close_chain(product, container)
    _remove_getent_shim(product, container)
    _install_getent_shim(product, container, case_id)
    _open_chain(product, container, case_id)
    try:
        for policy in ("best-effort", "required"):
            # Each arm starts its own count: the wrapper lets the first call
            # through and refuses the proof after it, and an arm that inherited
            # the previous arm's count would be refused before it ever touched
            # the host — a preflight failure, not the rollback this case is about.
            _reset_getent_shim(product, container)
            step = _dot_step(product, container, case_id, policy, shimmed=True)
            require(case_id,
                    step.get('status') == 'failed_unverified' and step.get('recovery') == 'failed',
                    f"the {policy} policy reported {step.get('status')!r}/"
                    f"{step.get('recovery')!r} while the restoration could not be proven, "
                    f"so an unverified rollback was rounded into a pass: {step.get('warnings')}")
            _require_warning(case_id, step, "rollback", "the step did not report its rollback")
            report = _report(product, container, case_id, policy, str(step['recovery']),
                             ipv6, port)
            require(case_id,
                    report.get('readiness') == 'failed',
                    f"the {policy} report is {report.get('readiness')!r} although the "
                    f"restoration is unproven")
            require(case_id,
                    (report.get('controls') or {}).get('dot') == 'failed',
                    f"the {policy} report does not call the DoT control failed: "
                    f"{report.get('controls')}")
    finally:
        _close_chain(product, container)
        _remove_getent_shim(product, container)
    _restore_installed_policy(product, container, case_id, ipv6, port)
    after = _normalised_rules(product, container, case_id, "after the case")
    for key, value in before.items():
        require(case_id, after.get(key) == value,
                f"{key} changed across the case, so the host was not left as it was found")
    return {"best-effort": "failed_unverified/failed",
            "required": "failed_unverified/failed",
            "readiness": "failed",
            "rules": "unchanged"}
