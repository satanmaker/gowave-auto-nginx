"""The Panel-only product E2E.

``gowave-auto.sh install --panel-only`` deploys the Panel and the static
camouflage site and leaves the host without a traffic plane: no GoWave Node, no
Xray, and no inbound listener. This module owns the cases that prove that shape
from inside the disposable host, the Panel API and ``state.json`` an install
leaves behind, and the squad a later ``node add`` has to create.

They are added as tasks 6.2-6.5 of ``openspec/changes/interactive-setup-wizard``
land. Until the first one exists the suite refuses to run instead of returning
an empty list, because a run of zero cases reports a green acceptance result
that proved nothing.
"""
from __future__ import annotations

from typing import Any, List

from .runner import Case


class SuiteNotDeclared(RuntimeError):
    """The topology has no case yet, so no run may claim its acceptance."""


def cases(podman: Any, distribution: str = "ubuntu-24.04") -> List[Case]:
    """The Panel-only cases in run order."""
    raise SuiteNotDeclared(
        "the Panel-only topology declares no case yet: the host, API, squad and "
        "catalog cases arrive in tasks 6.2-6.5, and an empty suite would report a "
        "green acceptance run that proves nothing"
    )
