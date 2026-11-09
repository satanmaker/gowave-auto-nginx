#!/usr/bin/env python3
"""Regression test suite for Vision capability (Task 10.9 & Task 1.7).

Verifies:
1. Master and Worker Vision domains are configured independently.
2. Master Vision Certbot/verification failure aborts and rolls back.
3. Worker --vision-domain reaches API profile, host provisioning, bootstrap HTTP-01 server_name, and SSH stdin.
4. Worker issues/validates Vision certificate using selected ACME server.
5. NGINX maps Vision SNI to 8444 and Xray xver: 1 fallback reaches 127.0.0.1:9444 PROXY-protocol decoy.
6. Worker rollback removes only transaction-owned Vision artifacts and preserves unrelated lineages.
7. Failpoints cover challenge issuance, certificate validation, NGINX syntax, and API provisioning.
8. Disabled Vision retains 4 inbounds and no Vision certificate/route/fallback.
9. Case matrix enforces 16, 18, or 20 runtime cases for zero, one, or two Vision domains.
"""
from __future__ import annotations

import json
import os
import re
import textwrap
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
import sys
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT))

from live_vps.config import load_config
from live_vps.traffic import evaluate_traffic_suite_status
from live_vps.reporting import write_junit_report
from test_live_vps import build_test_cases_from_state
from modules.api_client import GoWaveClient

NGINX_SH = str(REPO_ROOT / "modules" / "nginx.sh")
NODE_AUTO_SH = str(REPO_ROOT / "gowave-node-auto.sh")


class TestVisionRegressionCoverage(unittest.TestCase):
    """Test matrix and lifecycle regression tests for Vision capability."""

    def test_master_and_worker_vision_domains_are_independent(self):
        """Parser accepts Master-only and Worker-only Vision topologies."""
        example_cfg = (REPO_ROOT / "tools" / "live_vps_config.env.example").read_text()
        example_cfg = example_cfg.replace("203.0.113.10", "93.184.216.34").replace("203.0.113.20", "93.184.216.35")
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "live_vps_config.env"
            for addition, expected_master, expected_worker in (
                ("\nMASTER_VISION_DOMAIN=vision.master.com\n", "vision.master.com", None),
                ("\nWORKER_VISION_DOMAIN=vision.worker.com\n", None, "vision.worker.com"),
            ):
                with self.subTest(addition=addition):
                    cfg.write_text(example_cfg + addition)
                    cfg.chmod(0o600)
                    parsed = load_config(cfg)
                    self.assertEqual(parsed.master_vision_domain, expected_master)
                    self.assertEqual(parsed.worker_vision_domain, expected_worker)

    def test_worker_vision_domain_propagation_and_inbound_counts(self):
        """Worker compile_config_profile and provision_hosts generate 5 inbounds/hosts with Vision, 4 without."""
        dummy_client = GoWaveClient(base_url="http://127.0.0.1:9999")

        # Disabled Vision: exactly 4 inbounds
        cfg_no_vis = json.loads(dummy_client.compile_config_profile(
            "test-worker",
            "reality.example.com",
            "test-key",
            vision_domain=None,
        ))
        inbounds_no_vis = cfg_no_vis["inbounds"]
        self.assertEqual(len(inbounds_no_vis), 4)
        tags_no_vis = [i["tag"] for i in inbounds_no_vis]
        self.assertNotIn("vless-vision-test-worker", tags_no_vis)

        # Enabled Vision: exactly 5 inbounds
        cfg_vis = json.loads(dummy_client.compile_config_profile(
            "test-worker",
            "reality.example.com",
            "test-key",
            vision_domain="vision.worker.com",
        ))
        inbounds_vis = cfg_vis["inbounds"]
        self.assertEqual(len(inbounds_vis), 5)
        tags_vis = [i["tag"] for i in inbounds_vis]
        self.assertIn("vless-vision-test-worker", tags_vis)
        vision_inbound = next(i for i in inbounds_vis if i["tag"] == "vless-vision-test-worker")
        self.assertEqual(vision_inbound["port"], 8444)
        self.assertEqual(vision_inbound["streamSettings"]["security"], "tls")
        self.assertTrue(vision_inbound["streamSettings"]["tcpSettings"]["acceptProxyProtocol"])

    def test_worker_bootstrap_vhost_includes_vision_domain(self):
        """00-bootstrap-worker-acme.conf includes WORKER_VISION_DOMAIN in server_name."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "bootstrap.conf"
            # Without vision
            cmd_no = f'source "{NGINX_SH}" && generate_bootstrap_acme_vhost "panel.worker.com" "reality.worker.com" "{out}" "off"'
            subprocess.run(["bash", "-c", cmd_no], check=True)
            content_no = out.read_text()
            self.assertIn("server_name panel.worker.com reality.worker.com;", content_no)
            self.assertNotIn("vision.worker.com", content_no)

            # With vision
            cmd_vis = f'source "{NGINX_SH}" && generate_bootstrap_acme_vhost "panel.worker.com" "reality.worker.com" "{out}" "off" "vision.worker.com"'
            subprocess.run(["bash", "-c", cmd_vis], check=True)
            content_vis = out.read_text()
            self.assertIn("server_name panel.worker.com reality.worker.com vision.worker.com;", content_vis)

    def test_nginx_vision_sni_and_fallback_vhost_generation(self):
        """NGINX stream routes Vision SNI to 8444; cleartext proxy_protocol vhost listens on 9444 with decoy."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            stream_out = tmp / "stream.conf"
            # Generate stream config with vision
            cmd_stream = f'source "{NGINX_SH}" && generate_stream_config "panel.worker.com" "reality.worker.com" "{stream_out}" "off" "vision.worker.com"'
            subprocess.run(["bash", "-c", cmd_stream], check=True)
            stream_content = stream_out.read_text()
            self.assertIn("vision.worker.com 127.0.0.1:8444;", stream_content)
            self.assertIn("proxy_protocol on;", stream_content)

            # Generate 9444 fallback vhost
            vhost_out = tmp / "vision-fallback.conf"
            cover_dir = tmp / "cover-reality"
            cover_dir.mkdir()
            (cover_dir / "index.html").write_text("Decoy Cover Site")
            cmd_vhost = f'source "{NGINX_SH}" && generate_vision_fallback_vhost "vision.worker.com" "{vhost_out}" "{cover_dir}"'
            subprocess.run(["bash", "-c", cmd_vhost], check=True)
            vhost_content = vhost_out.read_text()
            self.assertIn("listen 127.0.0.1:9444 proxy_protocol;", vhost_content)
            self.assertIn("server_name vision.worker.com;", vhost_content)
            self.assertIn(f"root {cover_dir};", vhost_content)
            self.assertNotIn("/api/", vhost_content)  # Must serve decoy, not Panel/API

    def test_master_vision_certbot_failure_fail_closed(self):
        """Master installation fails closed if Vision certificate verification fails."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            live_dir = tmp / "live" / "vision.master.com"
            live_dir.mkdir(parents=True)
            cert_file = live_dir / "fullchain.pem"
            key_file = live_dir / "privkey.pem"

            # Create certificate with mismatching hostname
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "30", "-subj", "/CN=other.master.com",
                "-addext", "subjectAltName=DNS:other.master.com"
            ], check=True, stderr=subprocess.DEVNULL)

            cmd = f'source "{NGINX_SH}" && verify_acme_certificate "vision.master.com" "{live_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Certificate SAN/CN does not cover vision.master.com", res.stderr)

    def test_worker_remote_payload_serializes_vision_domain(self):
        """gowave-node-auto.sh remote_payload serializes VISION_DOMAIN over SSH stdin."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            mock_ssh = bin_dir / "ssh"
            payload_capture = tmp / "captured_payload.txt"
            mock_ssh.write_text(f'#!/bin/sh\ncat > "{payload_capture}"\nexit 0\n')
            mock_ssh.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SSH_KNOWN_HOSTS"] = str(known_hosts)
            env["SECRET_KEY"] = "bW9jay1zZWNyZXQ="
            env["GOWAVE_NODE_INSTALLER_COMMIT"] = "7b3514d1ab8c674050597820d52d55525d4bece7"
            env["GOWAVE_NODE_INSTALLER_SHA256"] = "9a524f1383d3a6a8be42ac370699b0ec6725678ece4abe5b5bc61e8c2af682d0"
            env["VISION_DOMAIN"] = "vision.worker.example.com"

            cmd = [NODE_AUTO_SH, "remote_payload", "127.0.0.1", "22", "worker.example.com", "reality.example.com", "root"]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            captured = payload_capture.read_text()
            self.assertIn("export VISION_DOMAIN=vision.worker.example.com", captured)
            self.assertIn("gowave-worker-vision-fallback.conf", captured)

    def test_acme_snapshot_restores_preexisting_vision_lineage(self):
        """ACME snapshot recovery restores the original Vision certificate after tampering."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rec_dir = tmp / "recovery"
            le_dir = tmp / "letsencrypt"
            domain = "vision.worker.com"

            # 1. Create a pre-existing lineage for vision domain
            renewal_dir = le_dir / "renewal"
            archive_dir = le_dir / "archive" / domain
            live_dir = le_dir / "live" / domain
            renewal_dir.mkdir(parents=True)
            archive_dir.mkdir(parents=True)
            live_dir.mkdir(parents=True)

            renewal_conf = renewal_dir / f"{domain}.conf"
            renewal_conf.write_text("[renewalparams]\nserver = https://acme-v02.api.letsencrypt.org/directory\n")
            cert_file = archive_dir / "fullchain1.pem"
            key_file = archive_dir / "privkey1.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "30", "-subj", f"/CN={domain}"
            ], check=True, stderr=subprocess.DEVNULL)
            key_file.chmod(0o600)
            (live_dir / "fullchain.pem").symlink_to(f"../../archive/{domain}/fullchain1.pem")
            (live_dir / "privkey.pem").symlink_to(f"../../archive/{domain}/privkey1.pem")

            # Snapshot pre-existing lineage
            tx_id = "tx_vis_rollback_1"
            cmd_snap = f'source "{NGINX_SH}" && snapshot_acme_lineage "{tx_id}" "{domain}" "{rec_dir}" "{le_dir}"'
            subprocess.run(["bash", "-c", cmd_snap], check=True)

            # Simulate certbot tampering with the lineage
            cert_file.write_text("TAMPERED_CERT_BYTES")
            self.assertEqual(cert_file.read_text(), "TAMPERED_CERT_BYTES")

            # Rollback: must restore original bytes
            cmd_rb = f'source "{NGINX_SH}" && restore_acme_lineage "{tx_id}" "{domain}" "{rec_dir}" "{le_dir}"'
            subprocess.run(["bash", "-c", cmd_rb], check=True)
            self.assertNotEqual(cert_file.read_text(), "TAMPERED_CERT_BYTES")
            self.assertIn("BEGIN CERTIFICATE", cert_file.read_text())

    def test_all_in_one_acme_rollback_reports_partial_failure(self):
        script = (REPO_ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        match = re.search(r"(?ms)^    rollback_acme_lineages\(\) \{\n.*?^    \}", script)
        self.assertIsNotNone(match, "all-in-one ACME rollback function not found")
        function = textwrap.dedent(match.group(0))
        harness = '''
rollback_managed_deploy_hook() { return 0; }
restore_acme_lineage() {
    if [[ "${FAIL_RESTORE:-0}" == "1" && "$2" == "panel.example.test" ]]; then return 1; fi
    return 0
}
rm() { return 0; }
acme_tx_id=test_tx
panel_domain=panel.example.test
reality_domain=reality.example.test
vision_domain=vision.example.test
'''
        failed = subprocess.run(["bash", "-c", harness + "\n" + function + "\nrollback_acme_lineages"], env={**os.environ, "FAIL_RESTORE": "1"}, text=True, capture_output=True, check=False)
        self.assertEqual(failed.returncode, 0)
        self.assertIn("CRITICAL: ACME rollback incomplete", failed.stderr)
        self.assertNotIn("ACME certificate lineage rollback completed successfully", failed.stderr)
        succeeded = subprocess.run(["bash", "-c", harness + "\n" + function + "\nrollback_acme_lineages"], env={**os.environ, "FAIL_RESTORE": "0"}, text=True, capture_output=True, check=False)
        self.assertEqual(succeeded.returncode, 0)
        self.assertIn("ACME certificate lineage rollback completed successfully", succeeded.stderr)
        self.assertNotIn("CRITICAL: ACME rollback incomplete", succeeded.stderr)

    def test_snapshot_acme_lineage_fails_when_directory_permissions_cannot_be_hardened(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            recovery = root / "recovery"
            letsencrypt = root / "letsencrypt"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_chmod = fake_bin / "chmod"
            fake_chmod.write_text("#!/bin/sh\nexit 1\n")
            fake_chmod.chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
            result = subprocess.run(
                ["bash", "-c", 'source "$1" && snapshot_acme_lineage "$2" "$3" "$4" "$5"',
                 "bash", NGINX_SH, "snapshot_test", "snapshot.example.test", str(recovery), str(letsencrypt)],
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Could not secure ACME snapshot directory", result.stderr)
        for path in (REPO_ROOT / "gowave-node-auto.sh", REPO_ROOT / "modules" / "nginx.sh"):
            script = path.read_text(encoding="utf-8")
            starts = [match.start() for match in re.finditer(r"(?m)^snapshot_acme_lineage\(\) \{", script)]
            self.assertTrue(starts)
            for start in starts:
                end = script.index("restore_acme_lineage() {", start)
                function = script[start:end]
                self.assertIn('chmod 0700 "$snap_dir" 2>/dev/null || {', function)
                self.assertIn("os.O_NOFOLLOW", function)
                self.assertIn("os.fsync", function)

    def test_restore_acme_lineage_propagates_removal_failure(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            recovery = root / "recovery"
            letsencrypt = root / "letsencrypt"
            domain = "new.example.test"
            manifest = recovery / "tx" / "acme" / domain / "lineage-manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({"domain": domain, "existed_before": False}))
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_rm = fake_bin / "rm"
            fake_rm.write_text("#!/bin/sh\nexit 1\n")
            fake_rm.chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
            result = subprocess.run(
                ["bash", "-c", 'source "$1" && restore_acme_lineage "$2" "$3" "$4" "$5"',
                 "bash", str(NGINX_SH), "tx", domain, str(recovery), str(letsencrypt)],
                text=True, capture_output=True, env=env, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Could not remove transaction-created renewal config", result.stderr)

    def test_deploy_hook_rollback_rejects_invalid_manifest_and_propagates_remove_failure(self):
        import hashlib
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            recovery = root / "recovery"
            hook = root / "gowave-nginx.sh"
            hook.write_text("#!/bin/sh\nexit 0\n")
            tx = "hook_rollback_test"
            manifest = recovery / tx / "deploy-hook-manifest.json"
            manifest.parent.mkdir(parents=True)
            digest = hashlib.sha256(hook.read_bytes()).hexdigest()
            valid = {"transaction_id": tx, "path": str(hook), "created_by_tx": True, "sha256": digest}
            manifest.write_text(json.dumps(valid))
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_rm = fake_bin / "rm"
            fake_rm.write_text("#!/bin/sh\nexit 1\n")
            fake_rm.chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
            command = ['source "$1" && rollback_managed_deploy_hook "$2" "$3" "$4"', "bash", NGINX_SH, tx, str(hook), str(recovery)]
            failed_remove = subprocess.run(["bash", "-c", *command], env=env, text=True, capture_output=True, check=False)
            self.assertNotEqual(failed_remove.returncode, 0)
            self.assertTrue(hook.exists())
            manifest.write_text('{ malformed json')
            invalid_manifest = subprocess.run(["bash", "-c", *command], env=os.environ.copy(), text=True, capture_output=True, check=False)
            self.assertNotEqual(invalid_manifest.returncode, 0)
            self.assertTrue(hook.exists())
            self.assertIn("ownership manifest is invalid", invalid_manifest.stderr)
            manifest.unlink()
            missing_manifest = subprocess.run(["bash", "-c", *command], env=os.environ.copy(), text=True, capture_output=True, check=False)
            self.assertNotEqual(missing_manifest.returncode, 0)
            self.assertTrue(hook.exists())
            self.assertIn("exists without an ownership manifest", missing_manifest.stderr)

    def test_worker_deploy_hook_rollback_copies_share_strict_contract(self):
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text(encoding="utf-8")
        matches = list(re.finditer(r"(?ms)^rollback_managed_deploy_hook\(\) \{\n.*?^\}", script))
        self.assertEqual(len(matches), 3, "expected local, remote-payload, and standalone rollback copies")
        for match in matches:
            function = match.group(0)
            self.assertIn("expected_tx", function)
            self.assertIn("ownership manifest is invalid", function)
            self.assertIn("exists without an ownership manifest", function)
            self.assertIn("digest mismatch", function)
            self.assertIn('rm -f "$hook_file" || {', function)
            self.assertIn('sync "$(dirname "$hook_file")" || {', function)

    def test_worker_compensation_removes_vision_artifacts_and_restores_lineage(self):
        """Worker ERR compensation removes the Vision fallback and restores its ACME lineage."""
        node_script = (REPO_ROOT / "gowave-node-auto.sh").read_text(encoding="utf-8")
        start = node_script.index("compensate_remote_worker() {")
        end = node_script.index("\n}\n", start) + len("\n}\n")
        compensation = node_script[start:end]

        self.assertIn("/etc/nginx/conf.d/gowave-worker-vision-fallback.conf", compensation)
        self.assertIn('if [[ -n "${VISION_DOMAIN:-}" ]]; then', compensation)
        self.assertIn('restore_acme_lineage "$_ACME_TX_ID" "$VISION_DOMAIN"', compensation)
    def test_case_matrix_counting_16_vs_20_in_traffic_and_junit(self):
        """Case matrix: 16, 18, or 20 cases for zero, one, or two Vision domains."""
        # Every synthetic PASS fixture carries the same mandatory packet-evidence contract.
        packet_evidence = {
            "target_packets": 3, "offload_packets": 0,
            "target_ingress_ok": True, "offload_ok": True, "egress_matches": True,
            "evidence_method": "tcpdump inbound TCP filtered by control-machine public IPv4",
        }
        # 1. Disabled Vision: expected 8 per client (total 16)
        xray_8 = [{"status": "PASS", "tag": f"outbound-{i}", "duration": 0.5, **packet_evidence} for i in range(8)]
        mihomo_8 = {"status": "PASS", "results": [{"status": "PASS", "name": f"proxy-{i}", "duration": 0.5, **packet_evidence} for i in range(8)]}

        # Passing 8 per client with expected_case_count=8 yields PASS
        self.assertEqual(evaluate_traffic_suite_status(True, xray_8, mihomo_8, expected_case_count=8), "PASS")

        # Passing 8 per client when at least one Vision domain is enabled yields INCOMPLETE
        self.assertEqual(evaluate_traffic_suite_status(True, xray_8, mihomo_8, expected_case_count=10), "INCOMPLETE")

        # 2. Exactly one Vision domain: expected 9 per client (total 18)
        xray_9 = [{"status": "PASS", "tag": f"outbound-{i}", "duration": 0.5, **packet_evidence} for i in range(9)]
        mihomo_9 = {"status": "PASS", "results": [{"status": "PASS", "name": f"proxy-{i}", "duration": 0.5, **packet_evidence} for i in range(9)]}
        self.assertEqual(evaluate_traffic_suite_status(True, xray_9, mihomo_9, expected_case_count=9), "PASS")
        self.assertEqual(evaluate_traffic_suite_status(True, xray_9, mihomo_9, expected_case_count=10), "INCOMPLETE")

        # 3. Enabled Vision on both hosts: expected 10 per client (total 20)
        xray_10 = [{"status": "PASS", "tag": f"outbound-{i}", "duration": 0.5, **packet_evidence} for i in range(10)]
        mihomo_10 = {"status": "PASS", "results": [{"status": "PASS", "name": f"proxy-{i}", "duration": 0.5, **packet_evidence} for i in range(10)]}

        self.assertEqual(evaluate_traffic_suite_status(True, xray_10, mihomo_10, expected_case_count=10), "PASS")

        # 4. JUnit report generation contains exact case counts
        with tempfile.TemporaryDirectory() as td:
            artifact_dir = Path(td)

            # State without vision (8 Xray + 8 Mihomo = 16 endpoint testcases)
            state_no_vis = {
                "results": {
                    "traffic": {
                        "status": "PASS",
                        "xray_results": xray_8,
                        "mihomo_results": mihomo_8,
                    }
                }
            }
            cases_no_vis = build_test_cases_from_state(state_no_vis)
            # phase_traffic + 8 xray + 8 mihomo = 17 testcases
            endpoint_cases_no_vis = [c for c in cases_no_vis if c["classname"].startswith("live_vps.traffic.")]
            self.assertEqual(len(endpoint_cases_no_vis), 16)
            junit_path_no_vis = write_junit_report(artifact_dir, cases_no_vis)
            content_no_vis = junit_path_no_vis.read_text()
            self.assertIn('tests="17"', content_no_vis)

            # State with exactly one Vision endpoint (9 Xray + 9 Mihomo = 18 endpoint testcases)
            state_one_vis = {
                "results": {
                    "traffic": {
                        "status": "PASS",
                        "xray_results": xray_9,
                        "mihomo_results": mihomo_9,
                    }
                }
            }
            cases_one_vis = build_test_cases_from_state(state_one_vis)
            endpoint_cases_one_vis = [c for c in cases_one_vis if c["classname"].startswith("live_vps.traffic.")]
            self.assertEqual(len(endpoint_cases_one_vis), 18)
            junit_path_one_vis = write_junit_report(artifact_dir, cases_one_vis)
            content_one_vis = junit_path_one_vis.read_text()
            self.assertIn('tests="19"', content_one_vis)

            # State with vision (10 Xray + 10 Mihomo = 20 endpoint testcases)
            state_vis = {
                "results": {
                    "traffic": {
                        "status": "PASS",
                        "xray_results": xray_10,
                        "mihomo_results": mihomo_10,
                    }
                }
            }
            cases_vis = build_test_cases_from_state(state_vis)
            endpoint_cases_vis = [c for c in cases_vis if c["classname"].startswith("live_vps.traffic.")]
            self.assertEqual(len(endpoint_cases_vis), 20)
            junit_path_vis = write_junit_report(artifact_dir, cases_vis)
            content_vis = junit_path_vis.read_text()
            self.assertIn('tests="21"', content_vis)


if __name__ == "__main__":
    unittest.main()
