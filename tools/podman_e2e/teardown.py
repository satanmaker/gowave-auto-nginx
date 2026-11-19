"""Teardown is a validated policy: refused before the run, or never reported as a pass.

``openspec/specs/live-vps-e2e/spec.md`` §Teardown Policy Enforcement describes
two policies a run may end in and one it may not. ``PRESERVE`` leaves both hosts
as the run left them and is recorded as ``PASS``. ``RESTORE_SNAPSHOT`` hands a
versioned request to a digest-pinned external hook and may only be ``PASS`` once
both hosts are back on the manifest the run captured before it installed
anything. ``DESTROY`` does not exist in v1. ``GATE-TEARDOWN`` runs the product's
own configuration preflight and its own teardown against a real mode-0600
configuration and real hook programs, so each of those sentences is a refusal
this case watched rather than a sentence it repeats.

No container and no VPS are involved: the two hosts are replaced by a temp
directory, a configuration file each and a hook that records what it was
handed. Everything the sentence is actually about is real — ``load_config``
rejects the configuration, ``execute_teardown`` decides the status, and the
hook is a Python program rather than a shell script, which is how the case knows
it was executed as a program instead of being handed to ``sh -c``. What is not
real is ``collect_remote_baseline``: it needs an SSH client, so the two
post-restore manifests are supplied by the case, and the comparison, the
disposable gate and the status they produce are the product's own.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest import mock

from tools.live_vps import teardown as live_teardown
from tools.live_vps.config import LiveVPSConfig, load_config
from tools.live_vps.reporting import write_junit_report
from tools.podman_e2e import topology
from tools.podman_e2e.runner import RunContext

TEARDOWN_CASE_ID = "GATE-TEARDOWN"
RUN_ID = "podman-{topology}-teardown-00000000"

#: Preflight accepts only a globally routable address, and this suite spells
#: exactly one such block: the data plane's, a step beside RFC 5737 so
#: ``ipaddress`` calls it global while no provider owns it. The case never binds
#: either address — it opens no socket — so it takes its two hosts from that
#: block instead of adding a third public literal the fixture-isolation guard
#: would have to learn to allow.
_ADDRESS_BLOCK = topology.DATA_PREFIX_CANDIDATES[0].rsplit(".", 1)[0]
MASTER_ADDRESS = f"{_ADDRESS_BLOCK}.{topology.TARGET_OFFSET}"
WORKER_ADDRESS = f"{_ADDRESS_BLOCK}.{topology.WORKER_OFFSET}"

#: A hook name a shell would tear apart. The path reaches the hook whole because
#: ``execute_teardown`` passes it as the program, and the hook records it as its
#: own ``argv[0]``: a rewritten path there is a path that went through a shell.
HOOK_NAME = "restore hook;touch pwned.sh"

#: The hook is Python, not POSIX shell. ``sh -c <path>`` cannot run a file it
#: cannot parse and ``sh <path>`` would refuse the shebang, so a hook that answers
#: at all proves the file itself was exec'd. Its reply is a sibling file rather
#: than an argument, so one pinned hook can answer differently per clause without
#: its digest changing: only a rewrite of the hook itself moves the digest, which
#: is what the tampering clause measures.
HOOK_BODY = '''\
#!/usr/bin/env python3
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "handed.json"), "w", encoding="utf-8") as record:
    json.dump(
        {"program": sys.argv[0], "arguments": sys.argv[1:], "stdin": json.load(sys.stdin)},
        record,
    )
with open(os.path.join(here, "reply.json"), "r", encoding="utf-8") as reply:
    sys.stdout.write(reply.read())
'''

#: The manifest a restored host is compared against: every field
#: ``BASELINE_COMPARISON_KEYS`` names, plus the tools the disposable gate wants.
#: It is a clean host — nothing GoWave left behind, none of the eleven ports the
#: install needs already bound, ``tcpdump`` and ``timeout`` present.
CLEAN_BASELINE: Dict[str, Any] = {
    "os_kernel": "Linux restored 6.8.0-45-generic #45-Ubuntu SMP",
    "running_services": ["ssh.service", "systemd-journald.service"],
    "tcp_listeners_raw": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
    "listening_ports": [22],
    "existing_gowave_dirs": [],
    "firewall_status": "Status: active",
    "swap_info": "",
    "key_packages": "openssh-server=1:9.6p1-3ubuntu13",
    "required_tools": {"tcpdump": "ok", "timeout": "ok"},
}


class _Uncontactable:
    """An SSH client the policy must not reach; reading it is the failure."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(
            f"the PRESERVE policy used the host: it read .{name} from an SSH client, so "
            "teardown touched a VPS it was told to leave exactly as the run left it"
        )


def _values(directory: Path, **overrides: str) -> Dict[str, str]:
    """A complete configuration for two hosts, with the caller's lines applied.

    The addresses are global because preflight refuses a documentation range —
    the same rule a live run meets — and the four domains are distinct because
    one domain serving two roles is refused too.
    """
    key = directory / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    key.chmod(0o600)
    known = directory / "known_hosts"
    known.write_text("", encoding="utf-8")
    values = {
        "MASTER_IP": MASTER_ADDRESS,
        "WORKER_IP": WORKER_ADDRESS,
        "MASTER_PANEL_DOMAIN": "panel.teardown.test",
        "MASTER_REALITY_DOMAIN": "reality.teardown.test",
        "WORKER_DOMAIN": "worker.teardown.test",
        "WORKER_REALITY_DOMAIN": "worker-reality.teardown.test",
        "MASTER_SSH_KEY_PATH": str(key),
        "WORKER_SSH_KEY_PATH": str(key),
        "MASTER_KNOWN_HOSTS_PATH": str(known),
        "WORKER_KNOWN_HOSTS_PATH": str(known),
        "GOWAVE_PANEL_VERSION": "latest",
        "GOWAVE_NODE_VERSION": "latest",
        "XRAY_SERVER_VERSION": "latest",
        "XRAY_CLIENT_VERSION": "latest",
        "MIHOMO_CLIENT_VERSION": "latest",
        "GOWAVE_NODE_INSTALLER_COMMIT": "0" * 40,
        "GOWAVE_NODE_INSTALLER_SHA256": "0" * 64,
    }
    values.update(overrides)
    return values


def _write(directory: Path, name: str, values: Dict[str, str]) -> Path:
    path = directory / name
    path.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _restore_values(directory: Path, hook: Path, **overrides: str) -> Dict[str, str]:
    """A ``RESTORE_SNAPSHOT`` configuration whose digest is the hook's own bytes."""
    values = _values(
        directory,
        TEST_TEARDOWN_POLICY="RESTORE_SNAPSHOT",
        MASTER_SNAPSHOT_ID="snap-master-1",
        WORKER_SNAPSHOT_ID="snap-worker-1",
        SNAPSHOT_RESTORE_HOOK=str(hook),
        SNAPSHOT_RESTORE_HOOK_SHA256=hashlib.sha256(hook.read_bytes()).hexdigest(),
    )
    values.update(overrides)
    return values


def _restore(directory: Path, hook: Path, name: str, **overrides: str) -> LiveVPSConfig:
    return load_config(_write(directory, name, _restore_values(directory, hook, **overrides)))


def _refused(path: Path) -> str:
    """The message preflight refuses ``path`` with; a failure if it accepts it."""
    try:
        load_config(path)
    except (ValueError, PermissionError, FileNotFoundError) as error:
        return str(error)
    raise AssertionError(
        f"{path.name} was accepted by configuration preflight: a policy, a snapshot ID or "
        "a hook the sentence refuses reached the hosts instead of failing the run"
    )


def _hook(directory: Path, reply: Any = None) -> Path:
    """A pinned hook that answers with ``reply``; the default is the conforming one."""
    directory.mkdir(parents=True, exist_ok=True)
    hook = directory / HOOK_NAME
    hook.write_text(HOOK_BODY, encoding="utf-8")
    hook.chmod(0o755)
    _answer(directory, _reply() if reply is None else reply)
    return hook


def _answer(directory: Path, reply: Any) -> None:
    """What the hook prints. A string is written verbatim, which is how a
    non-JSON or non-object reply is produced without touching the hook."""
    text = reply if isinstance(reply, str) else json.dumps(reply)
    (directory / "reply.json").write_text(text, encoding="utf-8")


def _reply(master_id: str = "snap-master-1", worker_id: str = "snap-worker-1",
           **overrides: Any) -> Dict[str, Any]:
    """The documented answer: both hosts, each with the id it was asked for.

    ``overrides`` replaces a whole top-level key, which is how the refusals are
    produced — a host that answered another id, or one that reported itself
    unrestored, is the same document with one member changed.
    """
    body: Dict[str, Any] = {
        "schema_version": 1,
        "status": "RESTORED",
        "master": {"snapshot_id": master_id, "restored": True},
        "worker": {"snapshot_id": worker_id, "restored": True},
    }
    body.update(overrides)
    return body


def _handed(directory: Path) -> Dict[str, Any]:
    """What the hook recorded: its own program name, its arguments and stdin."""
    return json.loads((directory / "handed.json").read_text(encoding="utf-8"))


def _script(directory: Path, body: str, mode: int) -> Path:
    """A shell hook of the given mode, for the shapes preflight has to refuse."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "hook.sh"
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def _execute(
    config: LiveVPSConfig,
    run_id: str,
    post_master: Dict[str, Any] = CLEAN_BASELINE,
    post_worker: Dict[str, Any] = CLEAN_BASELINE,
) -> Dict[str, Any]:
    """Run the real teardown with both hosts' post-restore manifests supplied.

    ``collect_remote_baseline`` is the one call this case cannot make: it needs an
    SSH client, and inventing one would be inventing the evidence. The manifests
    are arguments because the sentence is about what teardown does with them —
    the comparison, the disposable gate and the status are the product's own.
    ``time`` is likewise stood in for, so the five seconds teardown waits for a
    snapshot instance to boot is not spent six times over.
    """
    with mock.patch.object(
        live_teardown, "collect_remote_baseline",
        side_effect=[dict(post_master), dict(post_worker)],
    ), mock.patch.object(live_teardown, "time"):
        return live_teardown.execute_teardown(
            config, run_id,
            master_ssh=object(), worker_ssh=object(),
            pre_baseline_master=dict(CLEAN_BASELINE),
            pre_baseline_worker=dict(CLEAN_BASELINE),
        )


def case_teardown_policy(context: RunContext) -> Dict[str, Any]:
    """``GATE-TEARDOWN``: what preflight refuses, what the hook is handed, and what a broken restore may not become."""
    run_id = RUN_ID.format(topology=context.topology)
    with tempfile.TemporaryDirectory(prefix=f"gowave-teardown-{context.topology}-") as directory:
        root = Path(directory)
        hook_dir = root / "good"
        hook = _hook(hook_dir)

        # TD-01: destruction is refused while the configuration is being read, so
        # no host can have been touched, and the message says which policy it
        # refused and that v1 has no such policy. An invented verb is refused the
        # same way, naming the two that exist.
        destroy = _refused(_write(root, "destroy.conf", _values(root, TEST_TEARDOWN_POLICY="DESTROY")))
        assert "DESTROY" in destroy and "unsupported in v1" in destroy, (
            f"TEST_TEARDOWN_POLICY=DESTROY was refused with {destroy!r}, which does not name "
            "the destruction it refused or the version that does not have one"
        )
        invented = _refused(_write(root, "reimage.conf", _values(root, TEST_TEARDOWN_POLICY="REIMAGE")))
        assert "REIMAGE" in invented and "PRESERVE" in invented and "RESTORE_SNAPSHOT" in invented, (
            f"an unknown teardown policy was refused with {invented!r}: a refusal that does "
            "not name the value and the ones that exist leaves the operator guessing"
        )

        # TD-02: PRESERVE answers PASS without consulting a host. The clients raise
        # on any attribute read, so a policy that reconnects to collect diagnostics
        # cannot produce this status, and the record carries no verdict about the
        # run it ran after — teardown is reported separately from the result.
        preserve = load_config(_write(root, "preserve.conf", _values(root, TEST_TEARDOWN_POLICY="PRESERVE")))
        untouched = live_teardown.execute_teardown(
            preserve, run_id, master_ssh=_Uncontactable(), worker_ssh=_Uncontactable(),
        )
        assert untouched["status"] == "PASS", (
            f"PRESERVE reported {untouched['status']!r} rather than PASS: the policy that "
            "changes nothing cannot fail on the run it preserved"
        )
        assert untouched["policy"] == "PRESERVE", f"PRESERVE recorded the policy {untouched['policy']!r}"
        assert set(untouched) == {
            "status", "policy", "message", "residual_state",
            "restored_baseline", "clean_baseline_eligible",
        }, (
            f"the PRESERVE record carries {sorted(untouched)}: a teardown record that restates "
            "the test outcome makes a preserved host look like a verdict about the run"
        )
        # TD-02b: a preserved host is not a clean baseline. The packages the run
        # installed stay installed, the record says it did not restore the
        # baseline, and the host is not eligible for another clean-baseline run.
        assert untouched["restored_baseline"] is False, (
            f"PRESERVE reported restored_baseline={untouched['restored_baseline']!r}: "
            "a policy that changes nothing cannot have restored an OS baseline"
        )
        assert untouched["clean_baseline_eligible"] is False, (
            "PRESERVE called the host eligible for another clean-baseline run, so the next "
            "run would measure a host this one already changed"
        )
        residual = untouched["residual_state"]
        assert residual["retained"] is True, (
            f"PRESERVE reported retained={residual.get('retained')!r}: the state it kept is "
            "residual by definition"
        )
        assert residual["packages"]["inventory"] == "unrecorded", (
            "a teardown handed no package record claimed to know the package change: "
            f"it reported {residual['packages']}"
        )
        assert "not eligible for another clean-baseline run" in untouched["message"], (
            f"the PRESERVE message {untouched['message']!r} does not say the host may not be "
            "used as a clean baseline again"
        )

        # TD-03: every declared precondition of RESTORE_SNAPSHOT fails preflight, and
        # the ones the hook itself carries are checked against the file, not the text.
        link_dir = root / "symlink"
        link_dir.mkdir()
        link = link_dir / "hook.sh"
        link.symlink_to(hook)
        as_directory = root / "directory-hook"
        as_directory.mkdir()
        absent = root / "absent" / "hook.sh"
        noexec = _script(root / "noexec", "#!/bin/sh\nexit 0\n", 0o600)
        writable = _script(root / "writable", "#!/bin/sh\nexit 0\n", 0o777)
        refusals: List[Tuple[str, Dict[str, str], str]] = [
            ("no master snapshot id", {"MASTER_SNAPSHOT_ID": ""}, "MASTER_SNAPSHOT_ID is mandatory"),
            ("no worker snapshot id", {"WORKER_SNAPSHOT_ID": ""}, "WORKER_SNAPSHOT_ID is mandatory"),
            ("no hook path", {"SNAPSHOT_RESTORE_HOOK": ""}, "SNAPSHOT_RESTORE_HOOK is mandatory"),
            ("no hook digest", {"SNAPSHOT_RESTORE_HOOK_SHA256": ""}, "SNAPSHOT_RESTORE_HOOK_SHA256 is mandatory"),
            ("a relative hook", {"SNAPSHOT_RESTORE_HOOK": "hook.sh"}, "must be an absolute path"),
            ("a symlinked hook", {"SNAPSHOT_RESTORE_HOOK": str(link)}, "must not be a symlink"),
            ("a directory as the hook", {"SNAPSHOT_RESTORE_HOOK": str(as_directory)},
             "regular executable file not found"),
            ("an absent hook", {"SNAPSHOT_RESTORE_HOOK": str(absent)},
             "regular executable file not found"),
            ("a non-executable hook",
             {"SNAPSHOT_RESTORE_HOOK": str(noexec),
              "SNAPSHOT_RESTORE_HOOK_SHA256": hashlib.sha256(noexec.read_bytes()).hexdigest()},
             "is not executable"),
            ("a group-writable hook",
             {"SNAPSHOT_RESTORE_HOOK": str(writable),
              "SNAPSHOT_RESTORE_HOOK_SHA256": hashlib.sha256(writable.read_bytes()).hexdigest()},
             "must not be group or world writable"),
            ("a malformed digest", {"SNAPSHOT_RESTORE_HOOK_SHA256": "abc"}, "Must be 64-hex SHA256"),
        ]
        for label, overrides, fragment in refusals:
            values = _restore_values(root, hook)
            values.update(overrides)
            message = _refused(_write(root, "refusal.conf", values))
            assert fragment in message, (
                f"{label}: preflight said {message!r}, which does not name {fragment!r}"
            )

        # The owner clause can only be probed by a process that can hand a file to
        # another user, so it is probed where that is true and recorded as unrun
        # everywhere else rather than claimed.
        foreign_owner = "unrun: creating a foreign-owned hook needs root"
        if os.geteuid() == 0:
            foreign = _script(root / "foreign", "#!/bin/sh\nexit 0\n", 0o755)
            os.chown(foreign, 65534, 65534)
            message = _refused(_write(root, "foreign.conf", _restore_values(root, foreign)))
            assert "must be owned by current user or root" in message, (
                f"a hook owned by another user was accepted or refused with {message!r}: the "
                "sentence admits only the runner's user and root"
            )
            foreign_owner = "refused: uid 65534"

        # The digest is checked again immediately before execution, not only when
        # the file was read: a hook replaced between preflight and teardown is a
        # hook nobody pinned, and it must not be what restores the hosts.
        tamper_dir = root / "tamper"
        tamper_hook = _hook(tamper_dir)
        tamper = _restore(root, tamper_hook, "tamper.conf")
        tamper_hook.write_text(HOOK_BODY + "# replaced after preflight\n", encoding="utf-8")
        replaced = _execute(tamper, run_id)
        assert replaced["status"] == "TEARDOWN_FAILED", (
            f"a hook whose bytes changed after preflight reported {replaced['status']!r}: the "
            "digest before execution is the only thing that makes the pin mean anything"
        )
        assert "SHA-256 mismatch" in replaced["error"], (
            f"the replaced hook was refused with {replaced['error']!r}, which does not say the "
            "digest is what stopped it"
        )

        # TD-04 and TD-07: the real configuration object reaches the real hook, which
        # records the program name it was executed as, the arguments it was given and
        # the request it read from stdin.
        good = _restore(root, hook, "restore.conf")
        assert good.restore_hook_path == str(hook), (
            f"the configuration resolved the hook as {good.restore_hook_path!r}: a runner that "
            "reads RESTORE_HOOK_PATH finds nothing, because the key is SNAPSHOT_RESTORE_HOOK"
        )
        assert good.restore_hook_sha256 == hashlib.sha256(hook.read_bytes()).hexdigest(), (
            "the configuration did not resolve SNAPSHOT_RESTORE_HOOK_SHA256, so no digest is pinned"
        )
        restored = _execute(good, run_id)
        handed = _handed(hook_dir)
        request = handed["stdin"]
        assert handed["program"] == str(hook), (
            f"the hook was executed as {handed['program']!r} rather than as its own path: a "
            "path a shell has rewritten is a path nobody reviewed"
        )
        assert handed["arguments"] == [], (
            f"the hook was handed {handed['arguments']!r} in argv: the request belongs on "
            "stdin, where a process listing cannot read it"
        )
        assert {"schema_version", "action", "test_run_id", "master", "worker"} <= set(request), (
            f"the request carries {sorted(request)}: a hook written against the documented "
            "protocol reads fields this request does not send"
        )
        assert request["schema_version"] == 1 and request["action"] == "restore", (
            f"the request declares {request['schema_version']!r}/{request['action']!r}, not 1/restore"
        )
        assert request["test_run_id"] == run_id, (
            f"the request names the run {request['test_run_id']!r}, not {run_id!r}: a provider "
            "hook cannot tie a restore to the run that asked for it"
        )
        for host, address, snapshot in (
            ("master", good.master_ip, "snap-master-1"),
            ("worker", good.worker_ip, "snap-worker-1"),
        ):
            assert request[host] == {"address": address, "snapshot_id": snapshot}, (
                f"the {host} object reads {request[host]!r}, not the address and the snapshot "
                "the run asked to be restored"
            )

        # The reply is a contract as well: an answer that omits the version, the id or
        # the confirmation is not a restored host, and it may not be read as one.
        assert restored["status"] == "INCOMPLETE", (
            f"a conforming hook and two matching manifests reported {restored['status']!r}: "
            "teardown may not pass while a lock pair and a complete ownership comparison "
            "are still unimplemented"
        )
        assert restored["captured_baseline_comparison"] == "MATCHED", (
            f"the comparison reported {restored['captured_baseline_comparison']!r} for two "
            "identical manifests"
        )
        assert restored["pair_lock_reacquisition"] == "NOT_IMPLEMENTED", (
            f"the record claims {restored['pair_lock_reacquisition']!r} for the pair lock: a "
            "status that says implemented is a status that stopped being INCOMPLETE for free"
        )
        assert restored["complete_resource_ownership_comparison"] == "NOT_IMPLEMENTED", (
            f"the record claims {restored['complete_resource_ownership_comparison']!r} for the "
            "ownership comparison, which no case here performs"
        )

        answers = (
            ("no schema version",
             {key: value for key, value in _reply().items() if key != "schema_version"},
             "schema_version"),
            ("a later schema version", _reply(schema_version=2), "schema_version"),
            ("no master object", {k: v for k, v in _reply().items() if k != "master"},
             "no master object"),
            ("a host that was not restored",
             _reply(master={"snapshot_id": "snap-master-1", "restored": False}),
             "did not report the master as restored"),
            ("an id the run did not ask for", _reply(master_id="snap-master-2"),
             "snapshot IDs mismatch"),
        )
        for label, answer, fragment in answers:
            _answer(hook_dir, answer)
            refused = _execute(good, run_id)
            assert refused["status"] == "TEARDOWN_FAILED", (
                f"{label}: the hook answer was accepted with {refused['status']!r}"
            )
            assert fragment in refused["error"], (
                f"{label}: the answer was refused with {refused['error']!r}, which does not "
                f"name {fragment!r}"
            )

        # TD-07's other half: a host that came back different is a host that was not
        # restored, and the difference is named rather than summarised.
        _answer(hook_dir, _reply())
        drifted = _execute(good, run_id, post_master={**CLEAN_BASELINE, "swap_info": "1024M swap"})
        assert drifted["status"] == "TEARDOWN_FAILED", (
            f"a Master that came back with swap enabled reported {drifted['status']!r}"
        )
        assert drifted["master"]["changed_fields"] == ["swap_info"], (
            f"the baseline difference was recorded as {drifted['master']['changed_fields']!r}, "
            "which does not name the field that differs"
        )

        # TD-08: four ways a hook fails to restore both hosts, plus a host that came
        # back unclean. Each is TEARDOWN_FAILED, which is not PASS.
        broken = _restore(root, _script(root / "non-zero", "#!/bin/sh\nexit 7\n", 0o755), "nonzero.conf")
        # `exec` so the shell is the sleep: a child left holding the pipe would keep
        # `subprocess.run` reading after the timeout killed the shell.
        slow = _restore(
            root, _script(root / "slow", "#!/bin/sh\nexec sleep 30\n", 0o755), "slow.conf",
            RESTORE_TIMEOUT="1",
        )
        failures: List[Tuple[str, Dict[str, Any], str]] = []

        nonzero = _execute(broken, run_id)
        failures.append(("a hook that exited nonzero", nonzero, "exited with code 7"))

        _answer(hook_dir, "not-json")
        non_json = _execute(good, run_id)
        failures.append(("a hook that answered non-JSON", non_json, "non-JSON output"))

        _answer(hook_dir, "[1, 2]")
        non_object = _execute(good, run_id)
        failures.append(("a hook that answered JSON but not an object", non_object,
                         "must be an object"))

        timed_out = _execute(slow, run_id)
        failures.append(("a hook that outlived RESTORE_TIMEOUT", timed_out,
                         "timed out after 1s"))

        _answer(hook_dir, _reply())
        unclean = _execute(
            good, run_id,
            post_worker={**CLEAN_BASELINE, "existing_gowave_dirs": ["/opt/gowave"]},
        )
        failures.append(("a host that came back with the install still on it", unclean,
                         "disposable gate failed"))

        for label, result, fragment in failures:
            assert result["status"] == "TEARDOWN_FAILED", (
                f"{label}: teardown reported {result['status']!r} rather than TEARDOWN_FAILED"
            )
            assert fragment in result["error"], (
                f"{label}: the failure was recorded as {result['error']!r}, which does not "
                f"name {fragment!r}"
            )

        # The status may not be read as green anywhere a reader looks: the report
        # writer of the contour this failure belongs to carries TEARDOWN_FAILED as a
        # JUnit <error> beside a passing acceptance case.
        report = root / "report"
        junit = write_junit_report(report, [
            {"name": "acceptance", "classname": "teardown", "status": "PASS"},
            {"name": "teardown", "classname": "teardown", "status": unclean["status"],
             "message": unclean["error"]},
        ])
        suite = ET.parse(junit).getroot()
        assert suite.get("errors") == "1", (
            f"a run whose acceptance case passed and whose teardown failed reports "
            f"errors={suite.get('errors')!r}: a CI reader sees only what this file says"
        )
        assert len(suite.findall("testcase/error")) == 1, (
            "the teardown failure is not a JUnit <error>, so nothing in the report says the "
            "hosts are in an unknown state"
        )

    return {
        "destroy_refusal": destroy,
        "invented_policy_refusal": invented,
        "preserve_status": untouched["status"],
        "preflight_refusals": len(refusals),
        "foreign_owner_probe": foreign_owner,
        "digest_at_execution": replaced["error"],
        "hook_program": Path(handed["program"]).name,
        "hook_arguments": len(handed["arguments"]),
        "request_keys": ",".join(sorted(request)),
        "request_schema_version": request["schema_version"],
        "reply_refusals": len(answers),
        "restored_status": restored["status"],
        "baseline_comparison": restored["captured_baseline_comparison"],
        "pair_lock_reacquisition": restored["pair_lock_reacquisition"],
        "ownership_comparison": restored["complete_resource_ownership_comparison"],
        "baseline_change_named": ",".join(drifted["master"]["changed_fields"]),
        "hook_failures": len(failures),
        "teardown_result_status": unclean["status"],
        "teardown_junit_errors": suite.get("errors"),
    }
