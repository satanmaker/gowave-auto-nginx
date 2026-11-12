#!/usr/bin/env python3
"""Unit tests for the pre-deployment acceptance gate live-run check."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from check_acceptance_gate import verify_live_staging_run


RUNNER_RESULT = {
    "test_run_id": "run-20261111-234949-6736a352",
    "overall": "PASS",
    "trust": {"acme_mode": "staging"},
    "results": {"teardown": {"status": "PASS"}},
}

LEGACY_RESULT = {
    "run_id": "run-legacy",
    "overall_status": "PASS",
    "acme_mode": "staging",
    "phases": {"teardown": {"status": "PASS"}},
}


def _write_run(root: Path, name: str, payload: dict) -> None:
    run_dir = root / name
    run_dir.mkdir(parents=True)
    (run_dir / "result.json").write_text(json.dumps(payload), encoding="utf-8")


class TestAcceptanceGate(unittest.TestCase):
    def test_accepts_the_runner_result_schema(self):
        with tempfile.TemporaryDirectory() as td:
            _write_run(Path(td), "run-pass", RUNNER_RESULT)
            ok, message = verify_live_staging_run(Path(td))
        self.assertTrue(ok, message)
        self.assertIn("run-20261111-234949-6736a352", message)

    def test_accepts_the_legacy_result_schema(self):
        with tempfile.TemporaryDirectory() as td:
            _write_run(Path(td), "run-legacy", LEGACY_RESULT)
            ok, message = verify_live_staging_run(Path(td))
        self.assertTrue(ok, message)
        self.assertIn("run-legacy", message)

    def test_rejects_a_production_acme_run(self):
        payload = dict(RUNNER_RESULT, trust={"acme_mode": "production"})
        with tempfile.TemporaryDirectory() as td:
            _write_run(Path(td), "run-prod", payload)
            ok, message = verify_live_staging_run(Path(td))
        self.assertFalse(ok)
        self.assertIn("No completed run", message)

    def test_rejects_a_failed_teardown(self):
        payload = dict(RUNNER_RESULT, results={"teardown": {"status": "FAIL"}})
        with tempfile.TemporaryDirectory() as td:
            _write_run(Path(td), "run-teardown", payload)
            ok, _ = verify_live_staging_run(Path(td))
        self.assertFalse(ok)

    def test_rejects_an_incomplete_overall_status(self):
        payload = dict(RUNNER_RESULT, overall="INCOMPLETE")
        with tempfile.TemporaryDirectory() as td:
            _write_run(Path(td), "run-incomplete", payload)
            ok, _ = verify_live_staging_run(Path(td))
        self.assertFalse(ok)

    def test_ignores_runs_without_a_result_file(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "run-empty").mkdir()
            (Path(td) / "result.json").write_text("{}", encoding="utf-8")
            ok, _ = verify_live_staging_run(Path(td))
        self.assertFalse(ok)

    def test_reports_a_missing_artifacts_directory(self):
        with tempfile.TemporaryDirectory() as td:
            ok, message = verify_live_staging_run(Path(td) / "absent")
        self.assertFalse(ok)
        self.assertIn("No artifacts/live-vps directory", message)


if __name__ == "__main__":
    unittest.main()
