"""The negative matrix is a table of rows, and every row is a case that runs.

``NEG-01`` and ``NEG-04`` are not verdicts a run can produce: both are
conjunctions over the same fifteen-row table that the spec prints inside the
sentence itself — a fault, the component it is injected into, and the boundary
the run has to stop at. "All fifteen terminate at their designated boundaries"
is therefore a property of the suite's case list, and the case list is what these
two cases read.

Each row here names the container case that witnesses that boundary, and the
contour able to produce it: a Worker observed offline by the Panel needs a second
node, and a closed SSH daemon needs a host whose daemon this suite can stop. The
witness does not have to live under the same requirement — ``NEG-13``'s
interrupted deploy is the boundary ``NEG-03`` (the partial-deployment journal
case) already proves — so the table records the id, not the requirement.

What the cases check, in order:

* the sentence still prints fifteen rows, one per scenario id, and each row's
  component cell still names the component this table names;
* the live runner still defines one ``run_neg_NN_*`` function per row, so the
  matrix the table describes is the matrix the product still carries;
* every witness is a ``Case`` the suite builds for the contour the row names,
  read from ``catalog.driver_registry()`` — the same registry the catalog is
  generated from, so a witness removed from the code fails here rather than
  quietly emptying a catalog entry.

What it cannot check is that a witness asserts the right boundary: the mapping
from row to case is a judgement the source cannot make, which is why it is
written out row by row with a sentence saying what each witness proves.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Tuple

from tools.podman_e2e import catalog
from tools.podman_e2e.runner import require

MATRIX_CASE_ID = "NEG-01"
TEN_CASE_ID = "NEG-04"

NEGATIVE_RUNNER = catalog.REPO_ROOT / "tools" / "live_vps" / "negative.py"

#: The rows the two sentences are conjunctions over. ``NEG-04`` is the first ten.
TOTAL_ROWS = 15
TEN_ROWS = 10


@dataclass(frozen=True)
class Row:
    """One line of the normative table, and the case that stops at its boundary."""

    scenario: str
    component: str
    topology: str
    case_id: str
    witness: str


#: Fifteen rows, in the order the spec prints them.
MATRIX: Tuple[Row, ...] = (
    Row("NEG-01", "Preflight SSH", "aio", "PRE-01",
        "PRE-01 refuses a host whose key is absent from the configured known_hosts "
        "before the first remote command."),
    Row("NEG-02", "Preflight SSH", "multi-node", "MN-SSH-DOWN",
        "MN-SSH-DOWN stops the Worker's ssh daemon and reads the transport refusal "
        "before the remote command runs."),
    Row("NEG-03", "Preflight DNS", "aio", "PRE-02",
        "PRE-02 gives a domain an A record for an address that is not the configured "
        "one and requires the refusal before any mutation."),
    Row("NEG-04", "Preflight DNS", "aio", "PRE-05",
        "PRE-05 requires a missing AAAA to fail preflight when IPv6 is enabled."),
    Row("NEG-05", "ACME Install", "aio", "ACME-02",
        "ACME-02 closes the port 80 challenge webroot and requires the renewal to exit "
        "non-zero while the working leaf keeps being served."),
    Row("NEG-06", "NGINX Config", "aio", "NGX-05",
        "NGX-05 hands the deploy hook a snippet that fails `nginx -t` and requires the "
        "hook not to reload NGINX."),
    Row("NEG-07", "Worker Node", "multi-node", "MN-OUTAGE",
        "MN-OUTAGE stops gowave-node on the Worker and requires the Panel to report that "
        "node offline while the Master stays connected."),
    Row("NEG-08", "Worker Node", "multi-node", "MN-OUTAGE",
        "The same case starts the unit again and requires the node to reconnect and carry "
        "the captured payload once more."),
    Row("NEG-09", "Subscription", "aio", "SUB-UA-ABSENT",
        "SUB-UA-ABSENT sends a subscription request with no User-Agent at all and "
        "requires the Panel's own refusal code for every representation."),
    Row("NEG-10", "mTLS Control", "multi-node", "MTLS-04",
        "MTLS-04 presents a self-signed client certificate and requires the Worker to "
        "reject it during the handshake, before any HTTP handler."),
    Row("NEG-11", "Backup Restore", "multi-node", "MN-BACKUP-BAD",
        "MN-BACKUP-BAD feeds the product's own restore an archive it did not write and "
        "requires the refusal before a live file is replaced."),
    Row("NEG-12", "Backup Restore", "multi-node", "MN-BACKUP-BAD",
        "The same case ships a checksum-valid archive whose SQLite database does not open, "
        "so the integrity gate is the only thing left to refuse it."),
    Row("NEG-13", "Worker Deploy", "aio", "NEG-03",
        "NEG-03 interrupts a Worker deployment and requires the recovery journal never to "
        "reach COMMITTED."),
    Row("NEG-14", "Worker Deploy", "multi-node", "MN-DUP-ADD",
        "MN-DUP-ADD pins a second address, claims the committed pair's name there, and "
        "requires the refusal to name the address the record holds, before the Panel client exists."),
    Row("NEG-15", "Panel API Auth", "aio", "AIO-AUTH-NEG",
        "AIO-AUTH-NEG sends forged and expired tokens and requires the Panel's 401."),
)


@lru_cache(maxsize=1)
def _registry() -> Dict[str, Dict[str, Dict[str, Any]]]:
    return catalog.driver_registry()


@lru_cache(maxsize=1)
def _runner_scenarios() -> Tuple[str, ...]:
    """The ``run_neg_NN_*`` functions the live runner still defines, in file order."""
    tree = ast.parse(NEGATIVE_RUNNER.read_text(encoding="utf-8"))
    return tuple(
        f"NEG-{node.name.split('_')[2]}"
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("run_neg_")
    )


def _assertion(case_id: str) -> str:
    for case in catalog.load_catalog()["cases"]:
        if case["id"] == case_id:
            return case["assertion"]
    raise AssertionError(f"{case_id}: the catalog defines no such case")


def _checked(
    case_id: str, rows: Tuple[Row, ...], *, printed_table: bool,
) -> Dict[str, Any]:
    """The shared body: the sentence, the runner, and the witnesses, in that order."""
    text = _assertion(case_id)
    if printed_table:
        printed = text.count("| **NEG-")
        require(
            case_id,
            printed == len(rows),
            f"the sentence prints {printed} matrix row(s) and this table names {len(rows)}, "
            "so one of the two describes a matrix the other does not",
        )
    else:
        # This sentence names its scope rather than printing the table: the ten ids
        # are the ones it says it covers, so the scope itself is asserted beside the
        # ordering check below, and the two together say the same thing the printed
        # table says on the other sentence.
        printed = len(rows)
        require(
            case_id,
            f"NEG-01 through NEG-{TEN_ROWS:02d}" in text,
            f"the sentence no longer states the scope 'NEG-01 through NEG-{TEN_ROWS:02d}', "
            "so the ten rows this case reads are no longer the ten it describes",
        )
    require(
        case_id,
        [row.scenario for row in rows] == [f"NEG-{index:02d}" for index in range(1, len(rows) + 1)],
        "the table's scenario ids are not NEG-01..NEG-%02d in order" % len(rows),
    )

    missing_cells: List[str] = []
    if printed_table:
        for row in rows:
            marker = f"| **{row.scenario}**"
            require(
                case_id,
                marker in text,
                f"{row.scenario} is not a row of the sentence's own table, so the matrix this "
                "case reads is not the matrix the sentence prints",
            )
            cell = text.split(marker, 1)[1][:120]
            if row.component not in cell:
                missing_cells.append(f"{row.scenario}:{row.component}")
        require(
            case_id,
            not missing_cells,
            f"the sentence's row names a different component than this table does for "
            f"{', '.join(missing_cells)}",
        )

    defined = _runner_scenarios()
    absent = [row.scenario for row in rows if row.scenario not in defined]
    require(
        case_id,
        not absent,
        f"the live runner defines no scenario for {', '.join(absent)}, so the matrix the "
        "table describes is not the one the product carries",
    )

    registry = _registry()
    unwitnessed: List[str] = []
    for row in rows:
        drivers = registry.get(row.case_id, {})
        if row.topology not in drivers:
            unwitnessed.append(
                f"{row.scenario} -> {row.case_id} ({row.topology}: "
                f"{'not built' if not drivers else 'built only for ' + ','.join(sorted(drivers))})"
            )
    require(
        case_id,
        not unwitnessed,
        "a matrix row has no case that runs at its boundary in the contour it names: "
        + "; ".join(unwitnessed),
    )

    return {
        "matrix_rows": len(rows),
        "rows_in_sentence": printed,
        "scenario_ids": ",".join(row.scenario for row in rows),
        "components": ",".join(row.component for row in rows),
        "live_scenarios_defined": len(defined),
        "witnesses": ",".join(f"{row.scenario}={row.case_id}" for row in rows),
        "witnessed_contours": ",".join(
            f"{row.scenario}={row.topology}" for row in rows),
        "aio_rows": sum(1 for row in rows if row.topology == "aio"),
        "multi_node_rows": sum(1 for row in rows if row.topology == "multi-node"),
        "unwitnessed_rows": 0,
    }


def case_fifteen_rows_are_witnessed(product: Any, context: Any) -> Dict[str, Any]:
    """``NEG-01``: each of the fifteen rows is a case this suite builds and runs."""
    evidence = _checked(MATRIX_CASE_ID, MATRIX, printed_table=True)
    return evidence


def case_ten_rows_are_witnessed(product: Any, context: Any) -> Dict[str, Any]:
    """``NEG-04``: the first ten rows of the same matrix are witnessed as well."""
    evidence = _checked(TEN_CASE_ID, MATRIX[:TEN_ROWS], printed_table=False)
    return evidence
