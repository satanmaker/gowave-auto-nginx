"""Vision is two optional domains: what the configuration accepts, and which host owes the gate.

``openspec/specs/live-vps-e2e/spec.md`` §Independent Optional Vision Domains
states that ``MASTER_VISION_DOMAIN`` and ``WORKER_VISION_DOMAIN`` are configured
independently, that every configured name is distinct from every other name the
run carries, and that only the host whose own name is configured is required to
keep the Vision ports free. Two of those sentences are decided before a single
packet leaves the control machine, and both are decided by code this suite can
run: ``load_config`` is the whitelist parser the runner reads its configuration
with, and ``evaluate_preflight_eligibility`` is the function that hands each
host's own baseline to the disposable gate.

So ``VIS-CONFIG`` writes real mode-0600 configuration files and reads them back
through the parser, and ``VIS-GATE`` hands two real manifests to the runner's own
eligibility decision. Neither case starts a container, and neither reaches a
host: what they prove is the refusal, and a refusal that needs a VPS to be
observed is not the refusal the sentence describes.

``endpoint_contract`` is the third layer and the one that does need a cluster:
the endpoint total the Panel declares, the hosts that publish it, and the runtime
cases the matrix owes for the same combination.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from tools.live_vps.config import LiveVPSConfig, load_config
from tools.podman_e2e import topology
from tools.podman_e2e.runner import RunContext, require

CONFIG_CASE_ID = "VIS-CONFIG"
GATE_CASE_ID = "VIS-GATE"
RUN_ID = "podman-{topology}-vision-00000000"

#: Preflight accepts only a globally routable address and this suite spells
#: exactly one such block — the data plane's, a step beside RFC 5737. Neither
#: case binds either address; they are the two hosts the configuration names, and
#: the gate is handed their manifests rather than connecting to them.
_ADDRESS_BLOCK = topology.DATA_PREFIX_CANDIDATES[0].rsplit(".", 1)[0]
MASTER_ADDRESS = f"{_ADDRESS_BLOCK}.{topology.TARGET_OFFSET}"
WORKER_ADDRESS = f"{_ADDRESS_BLOCK}.{topology.WORKER_OFFSET}"

#: The two ports the optional contour adds. They are the whole difference between
#: the port set a configured host owes and the one an unconfigured host owes, so
#: the gate clause names both rather than a count.
VISION_PORTS = (8444, 9444)
#: One port of the default set, used to prove that the host which owes no Vision
#: ports is still evaluated against something.
DEFAULT_PORT = 443

#: The four names every run carries plus the two optional ones, all distinct, so
#: a duplicate can be produced by pointing one key at another's value.
PANEL_DOMAIN = "panel.vision.test"
REALITY_DOMAIN = "reality.vision.test"
WORKER_DOMAIN = "worker.vision.test"
WORKER_REALITY_DOMAIN = "worker-reality.vision.test"
MASTER_VISION_DOMAIN = "master-vision.vision.test"
WORKER_VISION_DOMAIN = "worker-vision.vision.test"


def _values(
    directory: Path,
    *,
    master_vision: Optional[str] = None,
    worker_vision: Optional[str] = None,
    panel_domain: str = PANEL_DOMAIN,
    reality_domain: str = REALITY_DOMAIN,
    worker_domain: str = WORKER_DOMAIN,
    worker_reality_domain: str = WORKER_REALITY_DOMAIN,
    master_ip: str = MASTER_ADDRESS,
    worker_ip: str = WORKER_ADDRESS,
) -> Dict[str, str]:
    """A complete configuration for two hosts, with the caller's names applied.

    The addresses are global because preflight refuses a documentation range, and
    the key and known-hosts files exist because the parser refuses a path it
    cannot resolve — neither is read, which is the point: nothing here connects.
    """
    key = directory / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    key.chmod(0o600)
    known = directory / "known_hosts"
    known.write_text("", encoding="utf-8")
    values = {
        "MASTER_IP": master_ip,
        "WORKER_IP": worker_ip,
        "MASTER_PANEL_DOMAIN": panel_domain,
        "MASTER_REALITY_DOMAIN": reality_domain,
        "WORKER_DOMAIN": worker_domain,
        "WORKER_REALITY_DOMAIN": worker_reality_domain,
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
    if master_vision:
        values["MASTER_VISION_DOMAIN"] = master_vision
    if worker_vision:
        values["WORKER_VISION_DOMAIN"] = worker_vision
    return values


def _write(directory: Path, name: str, values: Dict[str, str]) -> Path:
    path = directory / name
    path.write_text(
        "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def _accepted(directory: Path, name: str, **overrides: Any) -> LiveVPSConfig:
    """The configuration the parser accepts, or a failure naming what it refused."""
    path = _write(directory, name, _values(directory, **overrides))
    try:
        return load_config(path)
    except (ValueError, PermissionError, FileNotFoundError) as error:
        raise AssertionError(
            f"{name} was refused by the whitelist parser: {error}. A configuration the "
            "operator can write and the runner cannot read is a topology the product "
            "documents and never provisions"
        ) from error


def _refused(path: Path) -> str:
    """The message the parser refuses ``path`` with; a failure if it accepts it."""
    try:
        load_config(path)
    except (ValueError, PermissionError, FileNotFoundError) as error:
        return str(error)
    raise AssertionError(
        f"{path.name} was accepted by the whitelist parser: a duplicate Vision domain "
        "reached the hosts instead of failing preflight"
    )


def deployment_document(
    *,
    panel_domain: str,
    reality_domain: str,
    worker_domain: str,
    worker_reality_domain: str,
    master_vision: Optional[str],
    worker_vision: Optional[str],
    master_ip: str = MASTER_ADDRESS,
    worker_ip: str = WORKER_ADDRESS,
) -> LiveVPSConfig:
    """The configuration of one deployment, read back through the parser.

    The document carries the deployment's own four names and its optional two, so
    a case that reads it is asking the parser the question the operator asked,
    and the answer is the object the runner would have carried into preflight.

    The addresses default to the one global block this suite spells rather than to
    the hosts the caller runs on: a Podman topology addresses its containers
    privately, and the parser refuses a private address before it looks at any
    name — the acceptance check is about the names, and ``VIS-CONFIG`` is where
    the addresses' own refusal is read.
    """
    with tempfile.TemporaryDirectory(prefix="gowave-vision-document-") as directory:
        root = Path(directory)
        path = _write(root, "deployment.conf", _values(
            root,
            master_vision=master_vision,
            worker_vision=worker_vision,
            panel_domain=panel_domain,
            reality_domain=reality_domain,
            worker_domain=worker_domain,
            worker_reality_domain=worker_reality_domain,
            master_ip=master_ip,
            worker_ip=worker_ip,
        ))
        return load_config(path)


def case_config_contract(context: RunContext) -> Dict[str, Any]:
    """``VIS-CONFIG``: which Vision subsets the parser accepts, and what it refuses.

    The four combinations are the ones the suite runs, so all four have to be
    readable. The refusals are the sentence's second half: every configured name
    differs from every other configured name and from all four mandatory ones, so
    each duplicate class is produced by pointing one key at another key's value
    and the message has to name what collided. The last clause runs the runner
    itself on a duplicate, which is how "before SSH or remote modification" is
    observed rather than assumed: the process exits during configuration load and
    no run directory is ever created for it.
    """
    run_id = RUN_ID.format(topology=context.topology)
    with tempfile.TemporaryDirectory(prefix=f"gowave-vision-config-{context.topology}-") as directory:
        root = Path(directory)

        combinations: Dict[str, Tuple[Optional[str], Optional[str]]] = {
            "neither": (None, None),
            "master-only": (MASTER_VISION_DOMAIN, None),
            "worker-only": (None, WORKER_VISION_DOMAIN),
            "both": (MASTER_VISION_DOMAIN, WORKER_VISION_DOMAIN),
        }
        accepted: Dict[str, Dict[str, Any]] = {}
        for label, (master, worker) in combinations.items():
            config = _accepted(root, f"{label}.conf", master_vision=master, worker_vision=worker)
            assert config.master_vision_domain == master, (
                f"the {label} configuration parsed MASTER_VISION_DOMAIN as "
                f"{config.master_vision_domain!r} instead of {master!r}"
            )
            assert config.worker_vision_domain == worker, (
                f"the {label} configuration parsed WORKER_VISION_DOMAIN as "
                f"{config.worker_vision_domain!r} instead of {worker!r}"
            )
            accepted[label] = {
                "master": config.master_vision_domain,
                "worker": config.worker_vision_domain,
            }

        duplicates: List[Tuple[str, Dict[str, Any], str]] = [
            ("the two Vision names are equal",
             {"master_vision": MASTER_VISION_DOMAIN, "worker_vision": MASTER_VISION_DOMAIN},
             "globally distinct"),
            ("a Vision name repeats the Master Panel name",
             {"master_vision": PANEL_DOMAIN}, "MASTER_VISION_DOMAIN must differ"),
            ("a Vision name repeats the Master REALITY name",
             {"master_vision": REALITY_DOMAIN}, "MASTER_VISION_DOMAIN must differ"),
            ("a Vision name repeats the Worker name",
             {"worker_vision": WORKER_DOMAIN}, "WORKER_VISION_DOMAIN must differ"),
            ("a Vision name repeats the Worker REALITY name",
             {"worker_vision": WORKER_REALITY_DOMAIN}, "WORKER_VISION_DOMAIN must differ"),
            ("the Master Vision name is the Worker's name",
             {"master_vision": WORKER_DOMAIN}, "globally distinct"),
            ("the Worker Vision name is the Master Panel name",
             {"worker_vision": PANEL_DOMAIN}, "globally distinct"),
            ("the same name in two letter cases",
             {"master_vision": MASTER_VISION_DOMAIN,
              "worker_vision": MASTER_VISION_DOMAIN.upper()},
             "globally distinct"),
        ]
        refusals: Dict[str, str] = {}
        for label, overrides, fragment in duplicates:
            path = _write(root, "duplicate.conf", _values(root, **overrides))
            message = _refused(path)
            assert fragment in message, (
                f"{label}: the parser said {message!r}, which does not name {fragment!r}"
            )
            refusals[label] = message

        # The runner's own entrypoint, on the same duplicate: it exits while the
        # configuration is being read and never creates the run directory it would
        # have filled with preflight evidence, so no host was contacted.
        duplicate = _write(root, "cli.conf", _values(
            root, master_vision=MASTER_VISION_DOMAIN, worker_vision=MASTER_VISION_DOMAIN,
        ))
        entrypoint = Path(__file__).resolve().parents[2] / "tools" / "test_live_vps.py"
        done = subprocess.run(
            [sys.executable, str(entrypoint), "--config", str(duplicate),
             "--mode", "preflight", "--run-id", run_id],
            capture_output=True, text=True, timeout=120,
        )
        artifact_dir = Path(__file__).resolve().parents[2] / "artifacts" / "live-vps" / run_id
        assert done.returncode != 0, (
            f"the runner accepted a duplicate Vision domain and exited {done.returncode}"
        )
        assert "Config parse error" in (done.stderr or ""), (
            f"the runner refused the duplicate with {(done.stderr or '').strip()[-600:]!r}, "
            "which does not report it as a configuration error"
        )
        assert not artifact_dir.exists(), (
            f"the runner created {artifact_dir} for a configuration it refused: a run "
            "directory is evidence that preflight began, and this refusal precedes it"
        )

    return {
        "combinations": len(accepted),
        "master_only_vision": str(accepted["master-only"]["master"]),
        "worker_only_vision": str(accepted["worker-only"]["worker"]),
        "neither_master_vision": "absent" if accepted["neither"]["master"] is None else
                                  str(accepted["neither"]["master"]),
        "duplicate_classes": len(refusals),
        "duplicate_message": refusals["the two Vision names are equal"],
        "cross_node_message": refusals["the Master Vision name is the Worker's name"],
        "runner_returncode": done.returncode,
        "runner_message": (done.stderr or "").strip().splitlines()[-1] if done.stderr else "",
        "runner_artifact_dir": artifact_dir.name,
    }


def _baseline(**overrides: Any) -> Dict[str, Any]:
    """A disposable host's manifest: clean, with every tool the traffic phase wants."""
    manifest: Dict[str, Any] = {
        "existing_gowave_dirs": [],
        "running_services": ["ssh.service"],
        "listening_ports": [22],
        "required_tools": {"tcpdump": "ok", "timeout": "ok"},
    }
    manifest.update(overrides)
    return manifest


def _gate(
    config: LiveVPSConfig, master: Dict[str, Any], worker: Dict[str, Any],
) -> Dict[str, Any]:
    """The runner's own eligibility decision over two manifests and one configuration."""
    from tools.test_live_vps import evaluate_preflight_eligibility

    return evaluate_preflight_eligibility(
        config,
        tools_ok=True,
        master_trust_ok=True,
        worker_trust_ok=True,
        dns_ok=True,
        master_root_ok=True,
        worker_root_ok=True,
        master_baseline=master,
        worker_baseline=worker,
    )


def case_port_gate(context: RunContext) -> Dict[str, Any]:
    """``VIS-GATE``: the Vision ports belong to the host whose own domain is configured.

    Each host is handed its own manifest, and the question is which of the two is
    evaluated against the port set that includes ``8444`` and ``9444``. The clause
    that separates a correct pairing from a run-wide switch is the one where both
    hosts hold the Vision ports and only one of them is refused — a gate that
    widened the set to both hosts would fail that, and a gate that never widened
    it would fail the master-only clause. The default set is asked separately, so
    the host that owes no Vision ports is still evaluated against something.
    """
    with tempfile.TemporaryDirectory(prefix=f"gowave-vision-gate-{context.topology}-") as directory:
        root = Path(directory)
        configs = {
            "neither": _accepted(root, "neither.conf"),
            "master-only": _accepted(root, "master-only.conf", master_vision=MASTER_VISION_DOMAIN),
            "worker-only": _accepted(root, "worker-only.conf", worker_vision=WORKER_VISION_DOMAIN),
            "both": _accepted(
                root, "both.conf",
                master_vision=MASTER_VISION_DOMAIN, worker_vision=WORKER_VISION_DOMAIN,
            ),
        }

        vision_ports = _baseline(listening_ports=[22, *VISION_PORTS])
        clean = _baseline()

        both_held = {
            label: _gate(configs[label], vision_ports, vision_ports)
            for label in ("master-only", "worker-only", "both", "neither")
        }
        assert both_held["master-only"]["master_gate_ok"] is False, (
            "the Master holds 8444 and 9444 while its own Vision domain is configured and "
            "the disposable gate accepted it"
        )
        assert both_held["master-only"]["worker_gate_ok"] is True, (
            f"the Worker owes no Vision ports, but the gate refused it: "
            f"{both_held['master-only']['worker_gate_errors']}"
        )
        assert both_held["worker-only"]["worker_gate_ok"] is False, (
            "the Worker holds 8444 and 9444 while its own Vision domain is configured and "
            "the disposable gate accepted it"
        )
        assert both_held["worker-only"]["master_gate_ok"] is True, (
            f"the Master owes no Vision ports, but the gate refused it: "
            f"{both_held['worker-only']['master_gate_errors']}"
        )
        assert both_held["both"]["master_gate_ok"] is False and \
            both_held["both"]["worker_gate_ok"] is False, (
            "both hosts hold the Vision ports and both are configured, yet the gate "
            f"accepted {both_held['both']['master_gate_ok']!r}/"
            f"{both_held['both']['worker_gate_ok']!r}"
        )
        assert both_held["neither"]["master_gate_ok"] is True and \
            both_held["neither"]["worker_gate_ok"] is True, (
            "no Vision domain is configured and the gate still demanded the Vision ports: "
            f"{both_held['neither']['master_gate_errors']} "
            f"{both_held['neither']['worker_gate_errors']}"
        )
        for label, wanted in (("master-only", "8444"), ("worker-only", "9444")):
            errors = (
                both_held[label]["master_gate_errors"] if label == "master-only"
                else both_held[label]["worker_gate_errors"]
            )
            assert any(wanted in error for error in errors), (
                f"the {label} refusal does not name port {wanted}: {errors}"
            )
        assert both_held["master-only"]["status"] == "FAIL", (
            f"a host that holds a port its own Vision domain needs reported "
            f"{both_held['master-only']['status']!r} rather than FAIL"
        )

        # The sharp clause: both hosts hold the Vision ports and only the Worker's
        # own domain is configured, so neither gate may refuse. A gate widened to
        # the run rather than to the host fails here.
        quiet = _gate(configs["master-only"], clean, vision_ports)
        assert quiet["master_gate_ok"] is True and quiet["worker_gate_ok"] is True, (
            "the Master's Vision domain is configured, only the Worker holds 8444/9444, and "
            f"the gate refused {quiet['master_gate_ok']!r}/{quiet['worker_gate_ok']!r}: the "
            "port set was widened to a host that owes nothing"
        )
        assert quiet["status"] == "PASS", (
            f"a clean pair of hosts reported {quiet['status']!r} rather than PASS"
        )

        # The default set still applies to the host that owes no Vision ports.
        default_held = _baseline(listening_ports=[22, DEFAULT_PORT])
        default = _gate(configs["master-only"], clean, default_held)
        assert default["worker_gate_ok"] is False, (
            f"the Worker holds {DEFAULT_PORT} and the gate accepted it: a host exempt from "
            "the Vision ports is not exempt from the default set"
        )
        assert any(str(DEFAULT_PORT) in error for error in default["worker_gate_errors"]), (
            f"the default-set refusal does not name port {DEFAULT_PORT}: "
            f"{default['worker_gate_errors']}"
        )
        assert default["master_gate_ok"] is True, (
            "the Master holds none of the required ports and the gate refused it"
        )

    return {
        "combinations": len(configs),
        "master_only_master_gate": both_held["master-only"]["master_gate_ok"],
        "master_only_worker_gate": both_held["master-only"]["worker_gate_ok"],
        "worker_only_master_gate": both_held["worker-only"]["master_gate_ok"],
        "worker_only_worker_gate": both_held["worker-only"]["worker_gate_ok"],
        "both_gates": f"{both_held['both']['master_gate_ok']}/{both_held['both']['worker_gate_ok']}",
        "neither_gates": f"{both_held['neither']['master_gate_ok']}/"
                         f"{both_held['neither']['worker_gate_ok']}",
        "vision_ports_named": ",".join(str(port) for port in VISION_PORTS),
        "master_only_status": both_held["master-only"]["status"],
        "unowed_vision_ports_status": quiet["status"],
        "default_port_status": default["status"],
        "default_port_named": str(DEFAULT_PORT),
    }


def cluster_document(case_id: str, facts: Dict[str, Any]) -> Dict[str, Any]:
    """The cluster structure a Panel probe reported, refused by name when absent.

    ``panel_surface.py --scope cluster`` prints its report under a ``cluster``
    key, beside the login it used: the outer mapping is the probe's own envelope,
    and a case that read node records from it would find none and call a cluster
    empty.
    """
    cluster = facts.get("cluster")
    require(
        case_id,
        isinstance(cluster, dict),
        f"the Panel probe returned no cluster structure; observed {sorted(facts)}",
    )
    return cluster


def endpoint_contract(
    case_id: str,
    cluster: Dict[str, Any],
    expected: Sequence[Tuple[str, Optional[str], int]],
    clients: int,
    runtime_cases: int,
) -> Dict[str, Any]:
    """The endpoint total a Vision combination owes, as the Panel and the matrix state it.

    The count is the combination's own arithmetic — four core inbounds per node
    plus one where the node's Vision domain is configured — so a node carrying its
    neighbour's endpoint, or a host publishing an inbound its node does not run,
    changes a number this contract reads. ``runtime_cases`` is the same total
    times the clients the matrix declares: a run whose case list disagrees with
    its own inbounds is the drift the count exists to catch.
    """
    nodes = (cluster.get("nodes") or {})
    require(
        case_id,
        nodes.get("status") == 200,
        f"GET /api/nodes returned {nodes.get('status')!r}",
    )
    records = [record for record in nodes.get("records") or [] if isinstance(record, dict)]
    require(
        case_id,
        len(records) == len(expected),
        f"the Panel reports {len(records)} nodes, and this deployment has {len(expected)}",
    )
    hosts_section = cluster.get("hosts") or {}
    require(
        case_id,
        hosts_section.get("status") == 200,
        f"GET /api/hosts returned {hosts_section.get('status')!r}",
    )
    hosts = [host for host in hosts_section.get("records") or [] if isinstance(host, dict)]

    by_name = {str(record.get("name") or ""): record for record in records}
    evidence: Dict[str, Any] = {}
    total = 0
    for label, name, expected_inbounds in expected:
        if name is None:
            require(
                case_id,
                len(records) == 1,
                f"{label}: the deployment names one node, the Panel reports {len(records)}",
            )
            record = records[0]
        else:
            record = by_name.get(name)
            require(
                case_id,
                isinstance(record, dict),
                f"the Panel reports no node {name!r}; observed {sorted(by_name)}",
            )
        # Counted the way CLUS-03 counts them, so a record this contract refuses is
        # one the cluster case refuses for the same reason rather than a stricter
        # reading of the same list.
        inbounds = list(record.get("inbounds") or [])
        require(
            case_id,
            len(inbounds) == expected_inbounds,
            f"{label} runs {len(inbounds)} inbounds, expected {expected_inbounds} for this "
            "Vision combination"
        )
        uuid = str(record.get("uuid") or "")
        published = [host for host in hosts if uuid and uuid in (host.get("nodes") or [])]
        require(
            case_id,
            len(published) == expected_inbounds,
            f"{label} publishes {len(published)} hosts, expected one per inbound "
            f"({expected_inbounds})",
        )
        stray = [host for host in published if host.get("inbound") not in inbounds]
        require(
            case_id,
            not stray,
            f"{len(stray)} of {label}'s hosts publish an inbound the node does not run: "
            f"{[host.get('inbound') for host in stray]}",
        )
        evidence[f"{label}_inbounds"] = len(inbounds)
        evidence[f"{label}_hosts"] = len(published)
        total += len(inbounds)

    require(
        case_id,
        total == sum(count for _label, _name, count in expected),
        f"the two nodes declare {total} endpoints, which is not the sum of their own inbounds",
    )
    require(
        case_id,
        runtime_cases == total * clients,
        f"the matrix owes {runtime_cases} runtime case(s) for {total} endpoint(s) and "
        f"{clients} client(s), which do not multiply to it",
    )
    evidence["endpoints"] = total
    evidence["clients"] = clients
    evidence["runtime_cases"] = runtime_cases
    return evidence
