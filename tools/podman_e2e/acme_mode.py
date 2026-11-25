"""``ACME-REJECT-ARB``: an arbitrary ACME directory is refused on both sides.

``modules/nginx.sh`` carries ``validate_acme_server`` for the Master and
``gowave-node-auto.sh`` carries two copies of the same function inside its
payload heredocs, so "Master and Worker both" is a statement about three
bodies. The case does two things: it runs the Master copy in bash against a
table of inputs — an arbitrary URL outside the test-only opt-in, the same URL
inside it, the pinned fixture endpoint without the opt-in, the fixture endpoint
with an unpinned CA, the two Let's Encrypt directories in both modes, and the
empty value — and it proves the Worker's two copies are the same text, so one
run speaks for all three.

What is real: the function, its sentences, ``sha256sum`` as the pin check, and
bash's exit status. What is not: no certbot runs and no ACME order is placed, so
this case decides the refusal, not an issuance — the fixture endpoint is only
accepted, never contacted.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.podman_e2e.runner import require

CASE_ID = "ACME-REJECT-ARB"

MASTER = Path(__file__).resolve().parent.parent.parent / "modules" / "nginx.sh"
WORKER = Path(__file__).resolve().parent.parent.parent / "gowave-node-auto.sh"

FIXTURE = "https://pebble.testbed.internal:14000/dir"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
ARBITRARY = "https://acme.attacker.example/directory"

FUNCTION = re.compile(r"^validate_acme_server\(\) \{.*?^\}", re.MULTILINE | re.DOTALL)

MASTER_SENTENCE = "Only 'https://acme-staging-v02.api.letsencrypt.org/directory'"
TEST_MODE_SENTENCE = "test-only ACME mode accepts only the pinned fixture endpoint"
OPT_IN_SENTENCE = "the local ACME fixture endpoint is accepted only with GOWAVE_ACME_TEST_MODE=1"
PIN_SENTENCE = "test-only ACME mode requires GOWAVE_ACME_TEST_CA_FILE and GOWAVE_ACME_TEST_CA_SHA256."


def _copies() -> List[Tuple[str, str]]:
    """The three function bodies, named by the file each one lives in."""
    found: List[Tuple[str, str]] = []
    for path in (MASTER, WORKER):
        text = path.read_text(encoding="utf-8")
        for match in FUNCTION.finditer(text):
            found.append((path.name, match.group(0)))
    return found


def _run(directory: Path, server: str, *, test_mode: bool = False,
         ca_file: Path | None = None, ca_sha256: str = "") -> Tuple[int, str]:
    """Call the Master copy with ``server`` and return its status and message."""
    script = "\n".join(
        [
            "set -Eeuo pipefail",
            f"source {MASTER} >/dev/null 2>&1",
            'export GOWAVE_ACME_SERVER="$1"',
            f"export GOWAVE_ACME_TEST_MODE={'1' if test_mode else '0'}",
            'export GOWAVE_ACME_TEST_CA_FILE="${2:-}"',
            'export GOWAVE_ACME_TEST_CA_SHA256="${3:-}"',
            'validate_acme_server "$GOWAVE_ACME_SERVER"',
        ]
    )
    completed = subprocess.run(
        ["bash", "-c", script, "acme", server, str(ca_file or ""), ca_sha256],
        capture_output=True, text=True, timeout=60, check=False,
    )
    return completed.returncode, (completed.stderr or "").strip()


def _mint_ca(directory: Path, name: str) -> Tuple[Path, str]:
    key = directory / f"{name}.key"
    certificate = directory / f"{name}.pem"
    created = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(certificate), "-days", "2",
         "-subj", "/CN=probe-acme-test-authority",
         "-addext", "basicConstraints=critical,CA:TRUE"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    require(
        CASE_ID,
        created.returncode == 0 and certificate.is_file(),
        f"the probe could not mint the pinned CA it needs: {created.stderr[-400:]!r}",
    )
    digest = hashlib.sha256(certificate.read_bytes()).hexdigest()
    return certificate, digest


def case_arbitrary_directory_is_refused(product: Any, context: Any) -> Dict[str, Any]:
    """``ACME-REJECT-ARB``: only the pinned fixture and the allowlist pass."""
    copies = _copies()
    require(
        CASE_ID,
        len(copies) == 3,
        f"the product carries {len(copies)} validate_acme_server bod(ies) "
        f"({', '.join(name for name, _ in copies)}), not the Master's one and the Worker's two",
    )
    distinct = {body for _name, body in copies}
    require(
        CASE_ID,
        len(distinct) == 1,
        "the Master and the Worker no longer validate the ACME directory with the same function, "
        f"so a run of one copy says nothing about the other: {len(distinct)} distinct bodies",
    )

    with tempfile.TemporaryDirectory(prefix="gowave-acme-arb-") as directory:
        root = Path(directory)
        ca_file, digest = _mint_ca(root, "pinned")
        unrelated, _unrelated_digest = _mint_ca(root, "unrelated")

        arbitrary_outside = _run(root, ARBITRARY)
        arbitrary_inside = _run(root, ARBITRARY, test_mode=True)
        fixture_outside = _run(root, FIXTURE)
        fixture_unpinned = _run(root, FIXTURE, test_mode=True,
                                ca_file=unrelated, ca_sha256=digest)
        fixture_missing = _run(root, FIXTURE, test_mode=True)
        fixture_pinned = _run(root, FIXTURE, test_mode=True,
                              ca_file=ca_file, ca_sha256=digest)
        staging = _run(root, STAGING)
        production = _run(root, PRODUCTION)
        staging_inside = _run(root, STAGING, test_mode=True)
        production_inside = _run(root, PRODUCTION, test_mode=True)
        empty = _run(root, "")

    refusals = {
        "arbitrary_outside": arbitrary_outside,
        "arbitrary_inside": arbitrary_inside,
        "fixture_outside": fixture_outside,
        "fixture_unpinned": fixture_unpinned,
        "fixture_missing_ca": fixture_missing,
    }
    for label, (code, message) in refusals.items():
        require(
            CASE_ID,
            code != 0,
            f"{label} was accepted (exit {code}) with {message!r}, so an arbitrary or unpinned "
            "ACME directory would reach certbot",
        )
    require(
        CASE_ID,
        MASTER_SENTENCE in arbitrary_outside[1],
        f"an arbitrary URL outside the opt-in was refused with {arbitrary_outside[1]!r}, which does "
        "not name the two Let's Encrypt directories the product allows",
    )
    require(
        CASE_ID,
        TEST_MODE_SENTENCE in arbitrary_inside[1] and ARBITRARY in arbitrary_inside[1],
        f"an arbitrary URL inside the opt-in was refused with {arbitrary_inside[1]!r}, which does "
        "not say that test mode narrows the choice to the pinned endpoint",
    )
    require(
        CASE_ID,
        OPT_IN_SENTENCE in fixture_outside[1],
        f"the fixture endpoint without the opt-in was refused with {fixture_outside[1]!r}, which "
        "does not say the endpoint needs GOWAVE_ACME_TEST_MODE=1",
    )
    require(
        CASE_ID,
        PIN_SENTENCE in fixture_missing[1],
        f"the fixture endpoint with no CA was refused with {fixture_missing[1]!r}, which does not "
        "name the two variables the pin needs",
    )
    require(
        CASE_ID,
        "digest mismatch" in fixture_unpinned[1],
        f"the fixture endpoint with a mismatched pin was refused with {fixture_unpinned[1]!r}, "
        f"not by the digest check (the pinned digest was {digest[:12]}… and the file's was "
        f"{_unrelated_digest[:12]}…)",
    )

    accepted = {
        "fixture_pinned": fixture_pinned,
        "staging": staging,
        "production": production,
        "staging_inside": staging_inside,
        "production_inside": production_inside,
        "empty": empty,
    }
    for label, (code, message) in accepted.items():
        require(
            CASE_ID,
            code == 0,
            f"{label} was refused (exit {code}) with {message!r}, so the allowlist or the pinned "
            "fixture endpoint is no longer accepted",
        )

    return {
        "refused_inputs": ",".join(sorted(refusals)),
        "accepted_inputs": ",".join(sorted(accepted)),
        "arbitrary_outside_sentence": arbitrary_outside[1],
        "arbitrary_inside_sentence": arbitrary_inside[1],
        "fixture_without_optin_sentence": fixture_outside[1],
        "unpinned_ca_sentence": fixture_unpinned[1],
        "missing_ca_sentence": fixture_missing[1],
        "pinned_endpoint": FIXTURE,
        "allowlisted_directories": f"{STAGING},{PRODUCTION}",
        "function_copies": len(copies),
        "worker_copies_identical": str(len(distinct) == 1),
    }
