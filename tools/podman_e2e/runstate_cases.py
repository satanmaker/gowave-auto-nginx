"""The run's own record decides what a phase may do, and a case can read it.

``openspec/specs/live-vps-e2e/spec.md`` §Durable Run State for Partial CLI
Modes makes two promises a container can witness without a VPS: a run id cannot
name a directory outside ``artifacts/live-vps/``, and a partial phase resumes
only the run that wrote the record it was handed. Both are the product's own
functions — ``tools/live_vps/runstate.py`` reads them, and
``tools/test_live_vps.py`` calls them before it creates a directory, opens an
SSH client, or starts a phase.

What is real here is the whole of every clause: the artifact root is a real
directory, the hostile ids are real strings handed to the real validator, the
record is written by the product's own ``save_run_state`` at mode 0600 and read
back by its own ``load_run_state``, and the baselines are the product's manifest
shape. What is not real is a pair of VPS — no case here opens a connection, and
the source-order guards say the CLI cannot have reached one before the answer
it got.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from tools.live_vps.runstate import (
    ResumeVerdict,
    RunIdRejected,
    artifact_path,
    baseline_drift,
    resume_gate,
    validate_run_id,
)
from tools.podman_e2e.runner import RunContext

REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "tools" / "test_live_vps.py"

RUN_ID_CASE_ID = "RUNID-01"
RESUME_CASE_ID = "RESUME-01"

#: The sentence every malformed id gets. A refusal that named only the character
#: it disliked would leave an operator guessing what the accepted shape is.
_RULE = "run-id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63} and must not be '.' or '..'"


def _order(path: Path, *anchors: str, unique: bool = True) -> List[int]:
    """Where each anchor sits in a file, refusing an anchor that is not unique.

    ``unique=False`` reads the first occurrence instead, for an anchor the file
    legitimately repeats: the runner validates a run id on both the fresh-run
    path and the resume path, and what bounds directory creation is the earliest
    of them, which is also the answer a moved validation would fail.
    """
    text = path.read_text(encoding="utf-8")
    offsets = []
    for anchor in anchors:
        count = text.count(anchor)
        if count == 0 or (unique and count != 1):
            raise AssertionError(
                f"{path.name} carries {count} occurrences of {anchor!r}, so the source "
                "order this case reads cannot be attributed"
            )
        offsets.append(text.index(anchor))
    return offsets


def _manifest(**overrides: Any) -> Dict[str, Any]:
    """A baseline in the shape ``collect_remote_baseline`` returns."""
    manifest: Dict[str, Any] = {
        "os_kernel": "Linux 6.8.0-45-generic",
        "running_services": ["cron.service", "ssh.service", "systemd-journald.service"],
        "tcp_listeners_raw": "LISTEN 0 128 0.0.0.0:22",
        "listening_ports": [22],
        "existing_gowave_dirs": [],
        "firewall_status": "Status: inactive",
        "swap_info": "",
        "disk_usage": "Filesystem Size Used Avail Use% Mounted on",
        "key_packages": "",
        "required_tools": {"tcpdump": "ok", "timeout": "ok"},
    }
    manifest.update(overrides)
    return manifest


def case_run_id_root(context: RunContext) -> Dict[str, Any]:
    """``STATE-01``: a run id names a directory below the artifact root or nothing."""
    del context
    with tempfile.TemporaryDirectory(prefix="gowave-runid-") as directory:
        root = Path(directory) / "artifacts" / "live-vps"
        root.mkdir(parents=True)
        elsewhere = Path(directory) / "elsewhere"
        elsewhere.mkdir()
        # The two shapes a pattern cannot see: an existing entry that is a link,
        # and a link planted between validation and creation in an earlier run.
        (root / "linked").symlink_to(elsewhere)
        (root / "run-1").mkdir()
        before = sorted(os.listdir(root))

        hostile = {
            "parent traversal": "..",
            "traversal with a name": "../escape",
            "separator": "run/1",
            "encoded separator": "run\\1",
            "NUL": "run\x00-1",
            "dot only": ".",
            "empty": "",
            "leading dash": "-run-1",
            "over 64 characters": "r" + "x" * 64,
            "symlinked component": "linked",
        }
        refusals: Dict[str, str] = {}
        for label, value in hostile.items():
            try:
                artifact_path(root, value)
            except RunIdRejected as error:
                refusals[label] = str(error)
            else:
                raise AssertionError(
                    f"{label} ({value!r}) was accepted as a run id, so a run could write "
                    f"outside {root}"
                )
        for label, sentence in refusals.items():
            expected = (
                "run-id must not contain a NUL byte"
                if label == "NUL"
                else "run-id artifact path must not be a symlink"
                if label == "symlinked component"
                else _RULE
            )
            if sentence != expected:
                raise AssertionError(
                    f"{label} was refused with {sentence!r} rather than {expected!r}: a "
                    "refusal has to name the rule the id broke"
                )
        after = sorted(os.listdir(root))
        assert after == before, (
            f"a refused run id changed the artifact root: {after!r} instead of {before!r}"
        )

        accepted = {
            "the printed shape": "run-20261116-120000-abcdef",
            "one character": "r",
            "64 characters": "r" + "x" * 63,
            "dots and dashes": "run-1.2_3-4",
        }
        for label, value in accepted.items():
            assert validate_run_id(value) == value, (
                f"{label} ({value!r}) was refused although it matches the accepted shape"
            )
            candidate = artifact_path(root, value)
            assert candidate.parent == root and candidate.name == value, (
                f"{label} resolved to {candidate}, which is not a directory named below {root}"
            )
            assert not candidate.exists(), (
                f"validating {label} created {candidate}; the caller creates the directory "
                "only after the id is accepted"
            )
        try:
            artifact_path(root, "r" + "x" * 64)
        except RunIdRejected:
            pass
        else:
            raise AssertionError("a 65-character run id was accepted, so the bound is not 64")

    # The CLI has to ask before it creates anything or addresses a host, or the
    # refusal above would be a property of the helper and not of the run.
    validate_at, mkdir_at, ssh_at = _order(
        RUNNER,
        "artifact_dir = artifact_path(artifact_root, run_id)",
        'artifact_dir.mkdir(parents=True, mode=0o700)',
        "master_ssh = SSHClient(",
        unique=False,
    )
    assert validate_at < mkdir_at, (
        "the runner creates the artifact directory before it validates the run id"
    )
    assert validate_at < ssh_at, (
        "the runner opens an SSH client before it validates the run id, so a hostile id "
        "would have reached a host"
    )

    return {
        "rejected_ids": len(refusals),
        "refusals": json.dumps(refusals, sort_keys=True),
        "accepted_ids": len(accepted),
        "accepted_max_length": 64,
        "root_entries_unchanged": True,
        "validated_before_mkdir": validate_at < mkdir_at,
        "validated_before_ssh_client": validate_at < ssh_at,
    }


def _record(root: Path, **overrides: Any) -> Dict[str, Any]:
    """Write a state through the product's own writer and read it back."""
    from tools import test_live_vps

    state: Dict[str, Any] = {
        "test_run_id": "run-20261116-120000-abcdef",
        "repository_commit": "a" * 40,
        "created_at": "2026-11-16T12:00:00+00:00",
        "config_fingerprint": "f" * 64,
        "trust": {"acme_mode": "staging"},
        "results": {},
        "overall": "RUNNING",
    }
    state.update(overrides)
    directory = root / state["test_run_id"]
    test_live_vps.save_run_state(directory, state)
    return test_live_vps.load_run_state(directory)


def case_resume_gate(context: RunContext) -> Dict[str, Any]:
    """``STATE-02``: a partial phase resumes its own run, its own state, and no other."""
    del context
    with tempfile.TemporaryDirectory(prefix="gowave-resume-") as directory:
        root = Path(directory)
        matching = _record(root, results={
            "preflight": {
                "status": "PASS",
                "master_baseline": _manifest(),
                "worker_baseline": _manifest(listening_ports=[22]),
            },
            "install": {"status": "PASS"},
            "verify": {"status": "PASS"},
        })
        identity = {
            "run_id": matching["test_run_id"],
            "commit": matching["repository_commit"],
            "config_fingerprint": matching["config_fingerprint"],
        }

        record_file = root / matching["test_run_id"] / "run-state.json"
        mode = stat.S_IMODE(record_file.stat().st_mode)
        assert mode == 0o600, (
            f"the run state is mode {oct(mode)}; a record that names a run and its phases "
            "is not world readable"
        )

        accepted = resume_gate(matching, phase="traffic", **identity)
        assert isinstance(accepted, ResumeVerdict) and accepted.ok, (
            f"a phase whose prerequisites all reported PASS was refused: {accepted.error!r}"
        )
        teardown_ok = resume_gate(matching, phase="teardown", **identity)
        assert teardown_ok.ok, (
            f"teardown was refused although both preflight baselines are recorded: "
            f"{teardown_ok.error!r}"
        )

        refused: Dict[str, str] = {}

        def refusal(label: str, state: Dict[str, Any], **overrides: Any) -> None:
            arguments: Dict[str, Any] = {"phase": "install"}
            arguments.update(identity)
            arguments.update(overrides)
            verdict = resume_gate(state, **arguments)
            assert not verdict.ok, f"{label} was accepted as a resumable phase"
            refused[label] = verdict.error

        refusal(
            "another run id",
            matching,
            run_id="run-20261116-120000-000000",
        )
        refusal(
            "another commit",
            dict(matching, repository_commit="b" * 40),
        )
        refusal(
            "another configuration identity",
            dict(matching, config_fingerprint="0" * 64),
        )
        refusal("a phase that already reported", matching, phase="install")
        refusal(
            "verify without an installed Master",
            dict(matching, results={"preflight": {"status": "PASS"}}),
            phase="verify",
        )
        refusal(
            "traffic without a verification",
            dict(matching, results={"install": {"status": "PASS"}}),
            phase="traffic",
        )
        refusal(
            "negative without an installed environment",
            dict(matching, results={"preflight": {"status": "PASS"}}),
            phase="negative",
        )
        refusal(
            "install without a passing preflight",
            dict(matching, results={"preflight": {"status": "FAIL"}}),
            phase="install",
        )
        refusal(
            "teardown without both baselines",
            dict(matching, results={"preflight": {"status": "PASS", "master_baseline": _manifest()}}),
            phase="teardown",
        )

        expected = {
            "another run id": "run-id does not match persisted state identity",
            "another commit": "State repository commit mismatch: " + "b" * 40,
            "another configuration identity": "Non-secret configuration identity mismatch",
            "a phase that already reported": "already has a terminal result",
            "verify without an installed Master": "Prerequisite install is not PASS",
            "traffic without a verification": "Prerequisite verify is not PASS",
            "negative without an installed environment": "Prerequisite install is not PASS",
            "install without a passing preflight": "Prerequisite preflight is not PASS",
            "teardown without both baselines": "baselines for both VPS are missing",
        }
        for label, fragment in expected.items():
            assert fragment in refused[label], (
                f"{label} was refused with {refused[label]!r}, which does not say "
                f"{fragment!r}"
            )

        # Install re-collects the baseline under both locks. The comparison is the
        # gate's own view of the manifest: a gate fact that moved is a drift, and a
        # field no gate reads is not, or every install would be refused for its own
        # disk usage.
        preflight = matching["results"]["preflight"]
        steady = baseline_drift(
            preflight, _manifest(disk_usage="Filesystem Size Used Avail Use% Mounted on /dev/vda1 40G 12G 26G 32% /"),
            _manifest(os_kernel="Linux 6.8.0-46-generic", swap_info="NAME TYPE SIZE USED PRIO"),
        )
        assert steady == "", (
            f"a baseline whose volatile fields moved was reported as drift: {steady!r}"
        )
        drifted = baseline_drift(
            preflight, _manifest(), _manifest(existing_gowave_dirs=["/opt/gowave"]),
        )
        assert "worker" in drifted and "existing_gowave_dirs" in drifted, (
            f"a Worker that grew a GoWave directory since preflight was not reported as "
            f"drift on that host: {drifted!r}"
        )
        blocked = baseline_drift(
            preflight,
            _manifest(listening_ports=[22, 443]),
            _manifest(listening_ports=[22]),
        )
        assert "master" in blocked and "required_ports" in blocked, (
            f"a Master that started listening on a required port since preflight was not "
            f"reported as drift: {blocked!r}"
        )
        no_tools = baseline_drift(
            preflight, _manifest(), _manifest(required_tools={"tcpdump": "missing", "timeout": "ok"}),
        )
        assert "worker" in no_tools and "required_tools" in no_tools, (
            f"a Worker that lost a tool the traffic phase needs was not reported as drift: "
            f"{no_tools!r}"
        )
        missing_snapshot = baseline_drift({"master_baseline": _manifest()}, _manifest(), _manifest())
        assert "worker" in missing_snapshot, (
            f"a preflight snapshot with no Worker baseline was compared anyway: "
            f"{missing_snapshot!r}"
        )

    drift_at, prep_at = _order(
        RUNNER,
        "drift = baseline_drift(",
        "prep_ok = prepare_master_repository(",
    )
    assert drift_at < prep_at, (
        "the runner copies the repository to the Master before it re-checks the baseline, "
        "so an install would modify a host that had stopped being disposable"
    )

    return {
        "refused_phases": len(refused),
        "refusals": json.dumps(refused, sort_keys=True),
        "accepted_phases": 2,
        "state_mode": oct(mode),
        "volatile_fields_tolerated": steady == "",
        "worker_drift": drifted,
        "master_port_drift": blocked,
        "missing_tool_drift": no_tools,
        "drift_checked_before_repository_copy": drift_at < prep_at,
    }
