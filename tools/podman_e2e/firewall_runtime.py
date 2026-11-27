"""The ingress contract under the two events that can silently undo it.

`FW-01`…`FW-06` prove the rules that exist once the policy has been applied.
They cannot see the two things an operator actually cares about afterwards: that
the mutation did not cut the control path it was running over, and that a later
reload of the firewall or of the web server does not quietly replace the policy
with something else. Both are ordinary production events — a reload happens on
every certificate renewal — so a suite that stops at "the rules were applied"
has proven the least interesting moment.
"""

from __future__ import annotations

from typing import Any, Dict

from tools.podman_e2e.runner import require

RULES_SURVIVE_RELOAD_CASE_ID = "FW-08"
SSH_SURVIVES_CASE_ID = "FW-07"
RELOAD_TIMEOUT_SECONDS = 420

# The chains the product owns. Reading them is the point: `ufw reload` and a
# web-server reload must leave the same rules in the same order, because a
# reload that reorders or drops one turns a managed policy into an unmanaged
# one without any command failing.
_RULES = ("iptables-save", "ip6tables-save")
_LISTENERS = "ss -ltn"


def _snapshot(product: Any, container: str, case_id: str, stage: str) -> Dict[str, str]:
    facts: Dict[str, str] = {}
    for tool in _RULES:
        result = product.podman.exec_bash(container, f"{tool} 2>/dev/null", check=False, timeout=60)
        require(case_id,
                result.returncode == 0 and result.stdout.strip(),
                f"{stage}: {tool} answered nothing on {container}, so a reload cannot be compared")
        # Packet and byte counters move on their own; the rules themselves are
        # what a reload must preserve.
        facts[tool] = "\n".join(
            line for line in result.stdout.splitlines() if not line.startswith("[")
        ).replace("[0:0]", "")
    listeners = product.podman.exec_bash(container, _LISTENERS, check=False, timeout=60)
    require(case_id, listeners.returncode == 0,
            f"{stage}: could not read the listening sockets on {container}")
    facts["listeners"] = "\n".join(
        sorted(" ".join(line.split()[3:5]) for line in listeners.stdout.splitlines()[1:]
               if len(line.split()) >= 4)
    )
    return facts


def _reload(product: Any, container: str, case_id: str, stage: str, command: str) -> None:
    result = product.podman.exec_bash(container, command, check=False, timeout=120)
    require(case_id, result.returncode == 0,
            f"{stage}: {command!r} exited {result.returncode}: "
            f"{(result.stderr or result.stdout or '')[-400:]}")


def case_rules_survive_reload(product: Any) -> Dict[str, Any]:
    """FW-08: a firewall and a web-server reload change neither rules nor listeners."""
    case_id = RULES_SURVIVE_RELOAD_CASE_ID
    master = product.require_installed().target_name
    before = _snapshot(product, master, case_id, "before the reload")

    _reload(product, master, case_id, "ufw reload", "ufw reload")
    _reload(product, master, case_id, "nginx reload", "systemctl reload nginx.service")
    # A restart, not only a reload: the product's own apply path restarts the
    # unit, and a rule that only survives `reload` is not durable.
    _reload(product, master, case_id, "nginx restart", "systemctl restart nginx.service")

    after = _snapshot(product, master, case_id, "after the reload")
    for key, value in before.items():
        require(case_id, after.get(key) == value,
                f"{key} changed across a reload on {master}:\n"
                f"before:\n{value[-800:]}\nafter:\n{(after.get(key) or '')[-800:]}")
    return {"rules": "unchanged", "listeners": "unchanged",
            "events": ["ufw reload", "nginx reload", "nginx restart"]}


def case_ssh_survives_firewall(product: Any) -> Dict[str, Any]:
    """FW-07: re-applying the Worker policy does not cut an established session."""
    case_id = SSH_SURVIVES_CASE_ID
    host = product.require_worker()
    master = host.target_name
    worker = host.plan.worker_ip
    control = "/tmp/gowave-fw07.sock"

    # One multiplexed session stands in for the operator's own connection: the
    # question is not whether a *new* login is accepted (the policy allows the
    # Master) but whether the connection that already exists is torn down.
    opened = product.podman.exec_bash(
        master,
        f"ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "
        f"-o ControlMaster=yes -o ControlPath={control} -o ControlPersist=10m "
        f"-fN root@{worker} && ssh -o ControlPath={control} -O check root@{worker}",
        check=False, timeout=90,
    )
    require(case_id, opened.returncode == 0,
            f"could not open the control session to the Worker: "
            f"{(opened.stderr or opened.stdout)[-400:]}")

    try:
        # The same policy the installer applies, run over the transport the
        # session uses: if the mutation closed it, this call dies with the
        # connection rather than returning a refusal.
        reapplied = product.podman.exec_bash(
            master,
            f"ssh -o ControlPath={control} root@{worker} "
            "'ufw allow from 10.0.0.0/8 to any port 22 proto tcp >/dev/null 2>&1; "
            "ufw reload'",
            check=False, timeout=180,
        )
        require(case_id, reapplied.returncode == 0,
                f"the mutation did not complete over the established session: "
                f"{(reapplied.stderr or reapplied.stdout)[-400:]}")

        still = product.podman.exec_bash(
            master,
            f"ssh -o ControlPath={control} -O check root@{worker} 2>&1; "
            f"ssh -o ControlPath={control} root@{worker} 'systemctl is-active ssh.service "
            "2>/dev/null || systemctl is-active ssh.socket' 2>&1",
            check=False, timeout=90,
        )
        require(case_id, "Master running" in still.stdout or "master running" in still.stdout,
                f"the control session is gone after the firewall reload: {still.stdout[-400:]!r}")
        # `inactive` contains `active`, so the unit state is compared as a line
        # of its own rather than as a substring: a session that answers while the
        # transport underneath is stopped must not pass.
        states = {line.strip() for line in still.stdout.splitlines()}
        require(case_id, "active" in states,
                f"the session answers but ssh reports {still.stdout[-200:]!r}")
    finally:
        product.podman.exec_bash(
            master, f"ssh -o ControlPath={control} -O exit root@{worker} 2>/dev/null; true",
            check=False, timeout=30,
        )
    return {"session": "survived", "mutation": "firewall reload over the session"}
