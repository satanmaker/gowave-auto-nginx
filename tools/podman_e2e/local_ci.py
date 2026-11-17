#!/usr/bin/env python3
"""Repository CI runs the runner unit tests with no target credentials.

``openspec/changes/podman-full-e2e/specs/podman-e2e/spec.md`` §Local-only live VPS
credential handling says repository CI executes the runner unit tests without
requiring VPS target credentials or GitHub Environment secrets. The workflow is
``.github/workflows/live-vps-unit.yml`` and the claim has three halves, each read
from the thing that decides it:

* the workflow declares read-only repository permission, no ``secrets.``
  expression and no ``environment:`` gate — read from the parsed YAML and from
  the file's own bytes;
* the command it runs is the one this case runs: ``unittest discover`` over
  ``tools/tests``, with the dependency file the repository ships;
* that command succeeds in an environment emptied of everything a credential
  could arrive in — no ``GOWAVE_*``, no ``SSH_AUTH_SOCK``, no ``~/.ssh`` — which
  is what "without requiring VPS target credentials" means when nothing is
  supplied.

The suite takes seconds, so the case runs it rather than quoting it. It starts no
container and reads no host.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import yaml

from tools.podman_e2e.runner import require

LOCAL_CASE_ID = "LOCAL-01"

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "live-vps-unit.yml"
REQUIREMENTS = REPO / "tools" / "requirements-live-vps.txt"

#: The command the workflow runs, spelled as the step spells it.
DISCOVERY = ["python3", "-m", "unittest", "discover", "-s", "tools/tests", "-p", "test_*.py"]

#: How long the discovery may take before the case reports a hung suite instead of
#: a verdict about CI. The suite runs in seconds on a quiet machine.
DISCOVERY_TIMEOUT_SECONDS = 300

#: Names that carry a credential. The scrubbed environment is asserted to hold
#: none of them, so a test that needed one would fail here rather than pass on
#: the workstation's own configuration.
CREDENTIAL_PREFIXES = ("GOWAVE_", "VPS_", "AWS_", "GITHUB_TOKEN", "SSH_AUTH_SOCK")

#: What a requirement line may not name: a package that would carry a secret.
SECRET_WORDS = ("token", "password", "secret", "credential", "apikey", "api-key")


def _workflow() -> Dict[str, Any]:
    require(LOCAL_CASE_ID, WORKFLOW.is_file(), f"{WORKFLOW} is missing, so CI has no job here")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _steps(job: Dict[str, Any]) -> List[str]:
    return [str(step.get("run", "")) for step in job.get("steps", []) if step.get("run")]


def case_ci_needs_no_credentials(product: Any, context: Any) -> Dict[str, Any]:
    """``LOCAL-01``: the CI job proves the runner unit tests need no target secrets."""
    document = _workflow()
    text = WORKFLOW.read_text(encoding="utf-8")
    require(
        LOCAL_CASE_ID,
        document.get("permissions") == {"contents": "read"},
        f"the workflow declares permissions {document.get('permissions')!r}, not read-only "
        "repository access",
    )
    references = re.findall(r"secrets\.[A-Za-z0-9_]+", text)
    require(
        LOCAL_CASE_ID,
        references == [],
        f"the workflow interpolates {references}, so the job it runs is not one that needs no "
        "secrets",
    )
    jobs = document.get("jobs") or {}
    require(LOCAL_CASE_ID, len(jobs) == 1, f"the workflow declares {len(jobs)} jobs, not one")
    job_name, job = next(iter(jobs.items()))
    require(
        LOCAL_CASE_ID,
        "environment" not in job,
        f"the job {job_name!r} runs in a GitHub Environment, which is where an Environment "
        "secret would be supplied",
    )
    steps = _steps(job)
    installs = [step for step in steps if "-r tools/requirements-live-vps.txt" in step]
    require(
        LOCAL_CASE_ID,
        len(installs) == 1,
        f"the job installs its dependencies in {len(installs)} steps, not one, so the file this "
        "case reads is not the one CI uses",
    )
    require(
        LOCAL_CASE_ID,
        any("unittest discover -s tools/tests" in step for step in steps),
        f"the job runs no unittest discovery over tools/tests: {steps}",
    )
    require(
        LOCAL_CASE_ID,
        REQUIREMENTS.is_file(),
        f"{REQUIREMENTS.relative_to(REPO)} is missing, so the install step names a file that "
        "does not exist",
    )
    requirements = [
        line.strip() for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    named = [line for line in requirements if any(word in line.lower() for word in SECRET_WORDS)]
    require(
        LOCAL_CASE_ID,
        requirements and not named,
        f"the dependency file names {named or 'nothing'}, so the install step is not one a "
        "credential-free job could run",
    )

    with tempfile.TemporaryDirectory(prefix="gowave-local-01-") as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir(mode=0o700)
        tmp = root / "tmp"
        tmp.mkdir(mode=0o700)
        # Nothing a credential could arrive in: no inherited variables, no agent
        # socket, no home directory that could hold a key.
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        leaked = sorted(
            name for name in os.environ
            if name.startswith(CREDENTIAL_PREFIXES)
        )
        completed = subprocess.run(
            DISCOVERY, cwd=str(REPO), env=environment,
            capture_output=True, text=True, timeout=DISCOVERY_TIMEOUT_SECONDS,
        )
        output = completed.stdout + completed.stderr
        ran = [line for line in output.splitlines() if line.startswith("Ran ")]
        require(
            LOCAL_CASE_ID,
            completed.returncode == 0,
            f"the discovery the workflow runs exited {completed.returncode} with no credential "
            f"in the environment:\n{output[-3000:]}",
        )
        require(
            LOCAL_CASE_ID,
            ran and "OK" in output,
            f"the discovery printed no summary line ({ran}) or did not end OK:\n{output[-2000:]}",
        )
        require(
            LOCAL_CASE_ID,
            not (home / ".ssh").exists(),
            "the scrubbed home grew a .ssh directory, so the run wrote a credential path",
        )
        summary = ran[-1].strip()

    return {
        "workflow": str(WORKFLOW.relative_to(REPO)),
        "job": job_name,
        "permissions": ",".join(f"{key}={value}" for key, value in document["permissions"].items()),
        "secrets_references": len(references),
        "environment_gated": "environment" in job,
        "requirements": len(requirements),
        "credential_variables_inherited": ",".join(leaked),
        "suite_exit": completed.returncode,
        "suite_summary": summary,
        "suite_ok": "OK" in output,
    }
