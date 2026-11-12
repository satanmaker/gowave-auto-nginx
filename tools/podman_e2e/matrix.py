"""The versioned protocol/client matrix, enumerated as executable tuples.

``tests/cases/matrix.yaml`` is the checked-in contract: which inbounds an
install carries, which clients must traverse each of them, the stable case id
per tuple, and how many positive cases each topology/configuration owes. The
suite builds its data-plane cases from this module, so a case id cannot drift
from the matrix and a matrix edit cannot silently add a case the harness never
runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = REPO_ROOT / "tests" / "cases" / "matrix.yaml"

# The inbound the optional Vision domain adds; it is present only when the
# operator was given a third domain, which is what makes the All-in-One matrix
# 8 or 10 tuples rather than a fixed list.
VISION_INBOUND = "VISION"

AIO = "aio"
MULTI_NODE = "multi-node"


def load(path: Path = MATRIX_PATH) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def inbounds(data: Dict[str, Any], vision: bool) -> List[Dict[str, Any]]:
    """The inbounds an install of the selected Vision configuration carries.

    Matrix order is preserved: it is the order the cases are declared and run.
    """
    selected = []
    for inbound in data.get("inbounds") or []:
        if bool(inbound.get("optional")) and not vision:
            continue
        selected.append(inbound)
    return selected


def inbound(data: Dict[str, Any], inbound_id: str) -> Dict[str, Any]:
    for candidate in data.get("inbounds") or []:
        if candidate.get("id") == inbound_id:
            return candidate
    raise KeyError(f"the matrix declares no inbound {inbound_id!r}")


def clients(data: Dict[str, Any]) -> List[str]:
    return [str(client["id"]) for client in data.get("clients") or []]


def tuples(data: Dict[str, Any], vision: bool) -> List[Tuple[Dict[str, Any], str]]:
    """Every (inbound, client) pair the selected configuration must exercise."""
    return [
        (candidate, client)
        for candidate in inbounds(data, vision)
        for client in clients(data)
    ]


def case_id(data: Dict[str, Any], topology: str, inbound_id: str, client: str, node: str = "") -> str:
    """The stable case id the matrix declares for one tuple."""
    pattern = str((data.get("topologies") or {}).get(topology, {}).get("case_id_pattern") or "")
    if not pattern:
        raise KeyError(f"the matrix declares no case id pattern for {topology!r}")
    values = {"node": node, "inbound": inbound_id, "client": client}
    try:
        return pattern.format(**values)
    except KeyError as exc:
        raise KeyError(f"the {topology} case id pattern needs {exc} which the tuple does not carry")


def combination(topology: str, vision: bool = False, worker_vision: bool = False) -> str:
    """The matrix key that names the selected per-node Vision configuration.

    The All-in-One topology has one node, so it has two configurations. The
    Multi-Node topology configures Vision per node, so the same two flags give
    four: neither, master-only, worker-only and both.
    """
    if topology == AIO:
        if worker_vision:
            raise KeyError("the AIO topology has no Worker to configure Vision on")
        return "enabled" if vision else "disabled"
    if topology == MULTI_NODE:
        if vision and worker_vision:
            return "both"
        if vision:
            return "master-only"
        if worker_vision:
            return "worker-only"
        return "neither"
    raise KeyError(f"no Vision combination is defined for {topology!r} yet")


def positive_count(
    data: Dict[str, Any], topology: str, vision: bool = False, worker_vision: bool = False,
) -> int:
    """How many positive cases the matrix owes for the selected configuration."""
    counts = (data.get("topologies") or {}).get(topology, {}).get("positive_case_counts") or {}
    key = combination(topology, vision, worker_vision)
    if key not in counts:
        raise KeyError(f"the matrix declares no positive case count for {topology}/{key}")
    return int(counts[key])
