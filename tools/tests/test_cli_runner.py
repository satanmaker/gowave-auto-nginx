#!/usr/bin/env python3
"""Integration and CLI runner tests for Live VPS E2E:
Validates preflight eligibility, run-state persistence, ACME directory mappings,
and the fail-closed status gates used by the Live VPS runner.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.deployment import ACME_MODE_URLS
from live_vps.negative import run_negative_suite
from live_vps.traffic import evaluate_traffic_suite_status
from test_live_vps import (
    load_run_state, save_run_state, build_config_fingerprint,
    evaluate_preflight_eligibility, get_git_head_commit,
    build_test_cases_from_state,
)


class TestCLIRunnerAndIntegration(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.artifact_dir = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _evaluate_preflight(self, config, **overrides):
        baseline = {
            "existing_gowave_dirs": [],
            "running_services": [],
            "listening_ports": [],
            "required_tools": {"tcpdump": "ok", "timeout": "ok"},
        }
        arguments = {
            "tools_ok": True,
            "master_trust_ok": True,
            "worker_trust_ok": True,
            "dns_ok": True,
            "master_root_ok": True,
            "worker_root_ok": True,
            "master_baseline": baseline,
            "worker_baseline": baseline,
        }
        arguments.update(overrides)
        return evaluate_preflight_eligibility(config, **arguments)

    def test_acme_mode_exact_mappings(self):
        # Exactly two official directories allowed
        self.assertEqual(
            ACME_MODE_URLS.get("staging"),
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        )
        self.assertEqual(
            ACME_MODE_URLS.get("production"),
            "https://acme-v02.api.letsencrypt.org/directory",
        )
        self.assertIsNone(ACME_MODE_URLS.get("custom"))
        self.assertIsNone(ACME_MODE_URLS.get("http://arbitrary-acme.org"))

    def test_config_fingerprint_covers_all_parsed_values(self):
        base = {"MASTER_IP": "93.184.216.34", "GOWAVE_PANEL_VERSION": "0.4.0",
                "XRAY_SERVER_VERSION": "25.10.15", "TEST_NEGATIVE_SUITE": True}
        original = SimpleNamespace(values=dict(base))
        reordered = SimpleNamespace(values=dict(reversed(list(base.items()))))
        changed = SimpleNamespace(values={**base, "GOWAVE_PANEL_VERSION": "0.4.1"})

        self.assertEqual(build_config_fingerprint(original), build_config_fingerprint(reordered))
        self.assertNotEqual(build_config_fingerprint(original), build_config_fingerprint(changed))

    def test_preflight_supports_independent_vision_topologies(self):
        topologies = (
            ("master-vision.example.com", None, True),
            (None, "worker-vision.example.com", True),
            (None, None, False),
        )
        for master_domain, worker_domain, requested in topologies:
            with self.subTest(master=master_domain, worker=worker_domain):
                result = self._evaluate_preflight(SimpleNamespace(
                    master_vision_domain=master_domain,
                    worker_vision_domain=worker_domain,
                ))
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(result["vision_requested"], requested)
                self.assertTrue(result["vision_supported"])

    def test_preflight_fails_closed_when_any_required_prerequisite_fails(self):
        config = SimpleNamespace(master_vision_domain=None, worker_vision_domain=None)
        required_gates = (
            "tools_ok",
            "master_trust_ok",
            "worker_trust_ok",
            "dns_ok",
            "master_root_ok",
            "worker_root_ok",
        )
        for gate in required_gates:
            with self.subTest(gate=gate):
                result = self._evaluate_preflight(config, **{gate: False})
                self.assertEqual(result["status"], "FAIL")

    def test_preflight_fails_closed_when_either_host_is_not_disposable(self):
        config = SimpleNamespace(master_vision_domain=None, worker_vision_domain=None)
        occupied_baseline = {
            "existing_gowave_dirs": ["/opt/gowave"],
            "running_services": ["ssh.service"],
            "listening_ports": [22],
        }
        for host in ("master", "worker"):
            with self.subTest(host=host):
                result = self._evaluate_preflight(
                    config, **{f"{host}_baseline": occupied_baseline}
                )
                self.assertEqual(result["status"], "FAIL")
                self.assertFalse(result[f"{host}_gate_ok"])

    @patch("test_live_vps.subprocess.run")
    def test_git_head_rejects_dirty_worktree(self, run):
        run.return_value = MagicMock(returncode=0, stdout=" M tools/test_live_vps.py\n")
        self.assertEqual(get_git_head_commit(), "dirty_worktree")
        run.assert_called_once()

    def test_live_e2e_uses_local_operator_not_github_secret_inputs(self):
        workflow = REPO_ROOT / ".github" / "workflows" / "live-vps-e2e.yml"
        self.assertFalse(workflow.exists())
        operator = (REPO_ROOT / "tools" / "live_vps" / "operator.py").read_text(encoding="utf-8")
        self.assertIn("getpass.getpass", operator)
        self.assertIn("Type the complete fingerprint to confirm this host", operator)
        self.assertIn("systemctl enable --now", operator)
        self.assertNotIn("MASTER_SSH_PASSWORD", operator)
        self.assertNotIn("WORKER_SSH_PASSWORD", operator)

    def test_non_vision_preflight_passes_with_integrated_pair_lock(self):
        config = SimpleNamespace(
            master_vision_domain=None,
            worker_vision_domain=None,
        )
        result = self._evaluate_preflight(config)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["remote_pair_lock_supported"])
        self.assertTrue(result["transactional_restore_supported"])

    def test_run_state_load_rejects_symlink(self):
        target = self.artifact_dir / "target.json"
        target.write_text("{}")
        (self.artifact_dir / "run-state.json").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            load_run_state(self.artifact_dir)

    def test_run_state_save_and_load(self):
        state = {
            "test_run_id": "run-test-1",
            "repository_commit": "abcdef123456",
            "config_fingerprint": {"master_ip": "198.51.100.1", "worker_ip": "198.51.100.2"},
            "results": {"preflight": {"status": "PASS"}},
            "overall": "RUNNING",
        }
        save_run_state(self.artifact_dir, state)

        loaded = load_run_state(self.artifact_dir)
        self.assertEqual(loaded["test_run_id"], "run-test-1")
        self.assertEqual(loaded["results"]["preflight"]["status"], "PASS")

        # Mode 0600 on run-state.json
        st = (self.artifact_dir / "run-state.json").stat()
        self.assertEqual(st.st_mode & 0o777, 0o600)

    def test_negative_suite_disabled_gate_produces_incomplete(self):
        config = SimpleNamespace(test_negative_suite=False)
        res = run_negative_suite(config)
        self.assertEqual(res["status"], "INCOMPLETE")
        self.assertEqual(res["skipped_count"], 15)

    def test_traffic_verification_disabled_gate_produces_incomplete(self):
        # Even if all cases pass, test_traffic_verification=False forces INCOMPLETE
        status = evaluate_traffic_suite_status(
            test_traffic_verification=False,
            xray_results=[{"status": "PASS"}],
            mihomo_results={"status": "PASS"},
        )
        self.assertEqual(status, "INCOMPLETE")

    def test_report_builder_fails_closed_on_missing_phase_and_case_status(self):
        cases = build_test_cases_from_state({
            "results": {
                "verify": {},
                "traffic": {
                    "xray_results": [{"tag": "xray-master"}],
                    "mihomo_results": {"results": [{"proxy": "mihomo-worker"}]},
                },
                "negative": {"scenarios": [{"id": "NEG-01"}]},
            }
        })
        by_name = {case["name"]: case for case in cases}
        self.assertEqual(by_name["phase_verify"]["status"], "INCOMPLETE")
        self.assertEqual(by_name["traffic_xray_xray-master"]["status"], "INCOMPLETE")
        self.assertEqual(by_name["traffic_mihomo_mihomo-worker"]["status"], "INCOMPLETE")
        self.assertEqual(by_name["negative_NEG-01"]["status"], "INCOMPLETE")

    def test_report_builder_uses_mihomo_proxy_name_instead_of_unknown(self):
        cases = build_test_cases_from_state({
            "results": {
                "traffic": {
                    "status": "PASS",
                    "xray_results": [{"tag": "master-reality", "status": "PASS"}],
                    "mihomo_results": {
                        "status": "PASS",
                        "results": [{"proxy": "worker-vision", "status": "PASS"}],
                    },
                }
            }
        })
        names = {case["name"] for case in cases}
        self.assertIn("traffic_mihomo_worker-vision", names)
        self.assertNotIn("traffic_mihomo_unknown", names)


if __name__ == "__main__":
    unittest.main()
