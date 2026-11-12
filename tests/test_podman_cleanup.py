#!/usr/bin/env python3
"""Suite nonroot: stale-run reclamation for the Podman E2E (label ownership only)."""
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e.podman import STALE_AFTER_SECONDS, Podman  # noqa: E402
from tools.podman_e2e.runner import RunContext  # noqa: E402


class StubPodman(Podman):
    """Records commands and returns canned listings instead of touching a host."""

    def __init__(self, context: RunContext, listings: dict) -> None:
        self.context = context
        self.binary = "podman"
        self._built_images = set()
        self._started_epoch = int(time.time())
        self.listings = listings
        self.commands = []

    def _run(self, args, check=True, input_text=None):
        self.commands.append(list(args))
        payload = []
        if args[:2] == ["ps", "-a"]:
            payload = self.listings.get("containers", [])
        elif args[:2] == ["volume", "ls"]:
            payload = self.listings.get("volumes", [])
        elif args[:2] == ["network", "ls"]:
            payload = self.listings.get("networks", [])
        return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")


def labelled(run_id, started):
    return {"gowave.e2e.run": run_id, "gowave.e2e.started": str(started), "gowave.e2e.topology": "aio"}


class TestPodmanStaleRunRecovery(unittest.TestCase):
    def context(self) -> RunContext:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        return RunContext(
            "aio", Path(self.tmp.name), budget_seconds=60,
            run_id="podman-aio-current-11112222",
        )

    def stub(self, now: int) -> StubPodman:
        context = self.context()
        old = now - STALE_AFTER_SECONDS - 60
        young = now - 60
        listings = {
            "containers": [
                {"Id": "old-container", "Names": ["old"], "Labels": labelled("run-old", old)},
                {"Id": "young-container", "Names": ["young"], "Labels": labelled("run-young", young)},
                {"Id": "current-container", "Names": ["current"], "Labels": labelled(context.run_id, old)},
                {"Id": "foreign", "Names": ["foreign"], "Labels": {"com.example.owner": "someone"}},
            ],
            "volumes": [
                {"Name": "old-volume", "Labels": labelled("run-old", old)},
                {"Name": "young-volume", "Labels": labelled("run-young", young)},
            ],
            "networks": [
                {"id": "old-network", "name": "old", "labels": labelled("run-old", old)},
                {"id": "foreign-network", "name": "foreign", "labels": {}},
            ],
        }
        return StubPodman(context, listings)

    def test_only_old_foreign_runs_are_classified_as_stale(self):
        now = 2_000_000_000
        podman = self.stub(now)
        stale = podman.stale_run_resources(now=now)
        self.assertEqual(set(stale), {"run-old"})
        self.assertEqual(
            stale["run-old"],
            ["container:old-container", "volume:old-volume", "network:old-network"],
        )

    def test_unreadable_age_label_is_left_alone(self):
        now = 2_000_000_000
        podman = self.stub(now)
        podman.listings["containers"].append(
            {"Id": "no-age", "Names": ["no-age"], "Labels": {"gowave.e2e.run": "run-unknown"}}
        )
        self.assertNotIn("run-unknown", podman.stale_run_resources(now=now))

    def test_reclaim_removes_containers_before_volumes_and_networks(self):
        now = 2_000_000_000
        podman = self.stub(now)
        removed = podman.remove_stale_runs(now=now)
        self.assertEqual(
            removed,
            ["container:old-container", "volume:old-volume", "network:old-network"],
        )
        removals = [command for command in podman.commands if "rm" in command]
        self.assertEqual(
            removals,
            [["rm", "-f", "old-container"], ["volume", "rm", "-f", "old-volume"], ["network", "rm", "-f", "old-network"]],
        )

    def test_recent_runs_are_never_reclaimed(self):
        now = 2_000_000_000
        podman = self.stub(now)
        podman.listings["containers"] = [
            {"Id": "recent", "Names": ["recent"], "Labels": labelled("run-recent", now - 120)}
        ]
        podman.listings["volumes"] = []
        podman.listings["networks"] = []
        self.assertEqual(podman.remove_stale_runs(now=now), [])


if __name__ == "__main__":
    unittest.main()
