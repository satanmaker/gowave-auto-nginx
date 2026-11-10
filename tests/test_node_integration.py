#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_SH = REPO_ROOT / "modules" / "node.sh"


class TestNodeIntegration(unittest.TestCase):
    def test_vendored_upstream_installer_matches_pinned_commit_digest(self):
        installer = REPO_ROOT / "sources" / "gowave-node" / "install.sh"
        self.assertTrue(installer.is_file(), "Pinned GoWave Node installer must be vendored")
        config = REPO_ROOT / "tools" / "live_vps_config.env.example"
        values = {}
        for line in config.read_text(encoding="utf-8").splitlines():
            if line and not line.lstrip().startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        commit = values.get("GOWAVE_NODE_INSTALLER_COMMIT", "")
        expected_digest = values.get("GOWAVE_NODE_INSTALLER_SHA256", "")
        self.assertRegex(commit, r"^[0-9a-fA-F]{40}$")
        self.assertRegex(expected_digest, r"^[0-9a-fA-F]{64}$")
        actual_digest = hashlib.sha256(installer.read_bytes()).hexdigest()
        self.assertEqual(actual_digest, expected_digest)

    def test_extract_secret_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            mock_server = tmp / "gowave-server"
            fake_secret = base64.b64encode(b'{"caCertPem":"CA","jwtPublicKey":"JWT","nodeCertPem":"CERT","nodeKeyPem":"KEY"}').decode()
            mock_server.write_text(f'#!/bin/sh\nif [ "$1" = "rescue" ] && [ "$2" = "--print-secret-key-raw" ]; then echo "{fake_secret}"; fi\n')
            mock_server.chmod(0o755)

            cmd = f'source "{NODE_SH}" && extract_secret_key "{tmp}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertEqual(res.stdout, fake_secret)

    def test_configure_node_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_secret = "c2VjcmV0LWtleS1kYXRh"
            cmd = f'source "{NODE_SH}" && configure_node_env "{tmp}" "{fake_secret}" 3002'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            env_file = tmp / ".env"
            self.assertTrue(env_file.exists())
            mode = oct(env_file.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")

            content = env_file.read_text()
            self.assertIn(f"SECRET_KEY={fake_secret}", content)
            self.assertIn("NODE_PORT=3002", content)
            self.assertIn("SNI_VERIFICATION=true", content)

    def test_verify_node_mtls_payload(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ca_key = tmp / "ca.key"
            ca_crt = tmp / "ca.crt"
            node_key = tmp / "node.key"
            node_csr = tmp / "node.csr"
            node_crt = tmp / "node.crt"
            jwt_key = tmp / "jwt.key"
            jwt_pub = tmp / "jwt.pub"

            # 1. Generate real ECDSA P-256 CA
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)],
                           check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(ca_key), "-out", str(ca_crt),
                            "-days", "365", "-subj", "/CN=TestGoWaveCA"], check=True, stderr=subprocess.DEVNULL)

            # 2. Generate real ECDSA P-256 Node keypair signed by CA
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(node_key)],
                           check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "req", "-new", "-key", str(node_key), "-out", str(node_csr),
                            "-subj", "/CN=TestNode"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "x509", "-req", "-in", str(node_csr), "-CA", str(ca_crt),
                            "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(node_crt), "-days", "365"],
                           check=True, stderr=subprocess.DEVNULL)

            # 3. Generate real RSA 2048 JWT public key
            subprocess.run(["openssl", "genrsa", "-out", str(jwt_key), "2048"], check=True, stderr=subprocess.DEVNULL)
            subprocess.run(["openssl", "rsa", "-in", str(jwt_key), "-pubout", "-out", str(jwt_pub)],
                           check=True, stderr=subprocess.DEVNULL)

            valid_payload = {
                "caCertPem": ca_crt.read_text(),
                "jwtPublicKey": jwt_pub.read_text(),
                "nodeCertPem": node_crt.read_text(),
                "nodeKeyPem": node_key.read_text(),
            }
            valid_b64 = base64.b64encode(json.dumps(valid_payload).encode()).decode()

            # Test crypto-only verification passes with real keys and derives SNI
            cmd = f'source "{NODE_SH}" && verify_node_mtls_health "{valid_b64}" 3002 127.0.0.1 crypto-only'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Derived HKDF SNI (rw-v1):", res.stdout)
            self.assertIn("Payload cryptographic verification PASSED", res.stdout)

            # Test incomplete payload rejection
            bad_payload = {"caCertPem": "CA"}
            bad_b64 = base64.b64encode(json.dumps(bad_payload).encode()).decode()
            cmd_bad = f'source "{NODE_SH}" && verify_node_mtls_health "{bad_b64}" 3002 127.0.0.1 crypto-only'
            res_bad = subprocess.run(["bash", "-c", cmd_bad], capture_output=True, text=True)
            self.assertNotEqual(res_bad.returncode, 0)
            self.assertIn("Missing or empty required cryptographic field", res_bad.stderr)

            # Test corrupted base64 rejection
            cmd_corrupt = f'source "{NODE_SH}" && verify_node_mtls_health "not-a-valid-base64!!!" 3002 127.0.0.1 crypto-only'
            res_corrupt = subprocess.run(["bash", "-c", cmd_corrupt], capture_output=True, text=True)
            self.assertNotEqual(res_corrupt.returncode, 0)
            self.assertIn("Failed to decode base64", res_corrupt.stderr)

            # Test mismatched certificate/key rejection
            other_key = tmp / "other.key"
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other_key)],
                           check=True, stderr=subprocess.DEVNULL)
            mismatched_payload = dict(valid_payload)
            mismatched_payload["nodeKeyPem"] = other_key.read_text()
            mismatch_b64 = base64.b64encode(json.dumps(mismatched_payload).encode()).decode()
            cmd_mismatch = f'source "{NODE_SH}" && verify_node_mtls_health "{mismatch_b64}" 3002 127.0.0.1 crypto-only'
            res_mismatch = subprocess.run(["bash", "-c", cmd_mismatch], capture_output=True, text=True)
            self.assertNotEqual(res_mismatch.returncode, 0)
            self.assertIn("Cryptographic mismatch", res_mismatch.stderr)

    def test_deploy_node_systemd_dropins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            cmd = f'source "{NODE_SH}" && deploy_node_systemd_dropins 3002 "{tmp}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            conf_file = tmp / "10-port.conf"
            self.assertTrue(conf_file.exists())
            content = conf_file.read_text()
            self.assertIn('Environment="NODE_PORT=3002"', content)
            self.assertIn("sport = :3002", content)
            self.assertNotIn("curl -k", content)

    def test_worker_payload_contains_automated_compensation(self):
        """Worker deployment must include automated compensating rollback on error."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("compensate_remote_worker", worker_script)
        self.assertIn("trap 'exit_code=$?; compensate_remote_worker \"$exit_code\"; exit \"$exit_code\"' ERR", worker_script)
        self.assertIn("systemctl stop gowave-node.service", worker_script)
        self.assertIn("rm -rf /etc/systemd/system/gowave-node.service.d", worker_script)
        self.assertIn("certbot delete --cert-name \"$WORKER_DOMAIN\"", worker_script)
        self.assertIn("swapoff /swapfile", worker_script)
        self.assertIn("ufw delete allow proto tcp from \"$PANEL_IP\"", worker_script)

    def test_worker_standalone_remote_rollback_defined(self):
        """gowave-node-auto.sh must provide standalone remote_rollback command."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("remote_rollback()", worker_script)
        self.assertIn("remote_rollback|rollback)", worker_script)
        self.assertIn("SSH host key for $host_key is not pre-pinned", worker_script)

    def test_worker_remote_payload_serializes_acme_server(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            mock_ssh = bin_dir / "ssh"
            payload_capture = tmp / "captured_payload.txt"
            mock_ssh.write_text(f'#!/bin/sh\ncat > "{payload_capture}"\nexit 0\n')
            mock_ssh.chmod(0o755)

            node_auto_sh = REPO_ROOT / "gowave-node-auto.sh"
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SSH_KNOWN_HOSTS"] = str(known_hosts)
            env["SECRET_KEY"] = "bW9jay1zZWNyZXQ="
            env["GOWAVE_ACME_SERVER"] = "https://acme-staging-v02.api.letsencrypt.org/directory"

            cmd = [str(node_auto_sh), "remote_payload", "127.0.0.1", "22", "worker.example.com", "reality.example.com", "root"]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"stdout: {res.stdout}, stderr: {res.stderr}")
            captured = payload_capture.read_text()
            self.assertIn("export GOWAVE_ACME_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory", captured)
            self.assertIn('--server "$GOWAVE_ACME_SERVER"', captured)

    def test_node_installer_e2e_gate_bundled_required(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_installer = tmp / "install.sh"
            fake_installer.write_text("#!/bin/sh\nexit 0\n")
            fake_installer.chmod(0o755)
            import hashlib
            real_sha = hashlib.sha256(fake_installer.read_bytes()).hexdigest()

            # Case 1: Missing installer when required
            cmd_missing = f'source "{NODE_SH}" && GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1 GOWAVE_NODE_INSTALLER_SHA256="{real_sha}" install_local_node "secret" 3002 "{tmp}/nonexistent.sh"'
            res_missing = subprocess.run(["bash", "-c", cmd_missing], capture_output=True, text=True)
            self.assertNotEqual(res_missing.returncode, 0)
            self.assertIn("bundled installer is absent", res_missing.stderr)

            # Case 2: Missing SHA256 env var when required
            cmd_nosha = f'source "{NODE_SH}" && GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1 GOWAVE_NODE_INSTALLER_SHA256="" install_local_node "secret" 3002 "{fake_installer}"'
            res_nosha = subprocess.run(["bash", "-c", cmd_nosha], capture_output=True, text=True)
            self.assertNotEqual(res_nosha.returncode, 0)
            self.assertIn("GOWAVE_NODE_INSTALLER_SHA256 is not set", res_nosha.stderr)

            # Case 3: Mismatched SHA256
            cmd_badsha = f'source "{NODE_SH}" && GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER=1 GOWAVE_NODE_INSTALLER_SHA256="0000000000000000000000000000000000000000000000000000000000000000" install_local_node "secret" 3002 "{fake_installer}"'
            res_badsha = subprocess.run(["bash", "-c", cmd_badsha], capture_output=True, text=True)
            self.assertNotEqual(res_badsha.returncode, 0)
            self.assertIn("Bundled installer SHA256 mismatch", res_badsha.stderr)

    def test_worker_remote_payload_validates_and_serializes_installer_pins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            mock_ssh = bin_dir / "ssh"
            payload_capture = tmp / "captured_payload.txt"
            mock_ssh.write_text(f'#!/bin/sh\ncat > "{payload_capture}"\nexit 0\n')
            mock_ssh.chmod(0o755)

            node_auto_sh = REPO_ROOT / "gowave-node-auto.sh"
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SSH_KNOWN_HOSTS"] = str(known_hosts)
            env["SECRET_KEY"] = "bW9jay1zZWNyZXQ="

            # Invalid commit (not 40-hex)
            env["GOWAVE_NODE_INSTALLER_COMMIT"] = "invalid_commit"
            cmd = [str(node_auto_sh), "remote_payload", "127.0.0.1", "22", "worker.example.com", "reality.example.com", "root"]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("GOWAVE_NODE_INSTALLER_COMMIT must be a 40-character hex commit SHA", res.stderr)

            # Invalid SHA256 (not 64-hex)
            env["GOWAVE_NODE_INSTALLER_COMMIT"] = "7b3514d1ab8c674050597820d52d55525d4bece7"
            env["GOWAVE_NODE_INSTALLER_SHA256"] = "bad_sha"
            res2 = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertNotEqual(res2.returncode, 0)
            self.assertIn("GOWAVE_NODE_INSTALLER_SHA256 must be a 64-character hex SHA-256 digest", res2.stderr)

            # Valid commit and SHA256 serialized
            env["GOWAVE_NODE_INSTALLER_SHA256"] = "9a524f1383d3a6a8be42ac370699b0ec6725678ece4abe5b5bc61e8c2af682d0"
            res3 = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res3.returncode, 0, f"stdout: {res3.stdout}, stderr: {res3.stderr}")
            captured = payload_capture.read_text()
            self.assertIn("export GOWAVE_NODE_INSTALLER_COMMIT=7b3514d1ab8c674050597820d52d55525d4bece7", captured)
            self.assertIn("export GOWAVE_NODE_INSTALLER_SHA256=9a524f1383d3a6a8be42ac370699b0ec6725678ece4abe5b5bc61e8c2af682d0", captured)
            self.assertIn("upstream installer SHA256 mismatch", captured)

    def test_worker_vision_domain_serialization_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            mock_ssh = bin_dir / "ssh"
            payload_capture = tmp / "captured_payload.txt"
            mock_ssh.write_text(f'#!/bin/sh\ncat > "{payload_capture}"\nexit 0\n')
            mock_ssh.chmod(0o755)

            node_auto_sh = REPO_ROOT / "gowave-node-auto.sh"
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SSH_KNOWN_HOSTS"] = str(known_hosts)
            env["SECRET_KEY"] = "bW9jay1zZWNyZXQ="
            env["GOWAVE_NODE_INSTALLER_COMMIT"] = "7b3514d1ab8c674050597820d52d55525d4bece7"
            env["GOWAVE_NODE_INSTALLER_SHA256"] = "9a524f1383d3a6a8be42ac370699b0ec6725678ece4abe5b5bc61e8c2af682d0"
            env["VISION_DOMAIN"] = "vision.worker.example.com"

            # 1. remote_payload with VISION_DOMAIN
            cmd = [str(node_auto_sh), "remote_payload", "127.0.0.1", "22", "worker.example.com", "reality.example.com", "root"]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            captured = payload_capture.read_text()
            self.assertIn("export VISION_DOMAIN=vision.worker.example.com", captured)
            self.assertIn("gowave-worker-vision-fallback.conf", captured)
            self.assertIn("127.0.0.1:9444 proxy_protocol", captured)

            # 2. remote_rollback with VISION_DOMAIN
            cmd_rb = [str(node_auto_sh), "remote_rollback", "127.0.0.1", "22", "worker.example.com", "reality.example.com", "root"]
            res_rb = subprocess.run(cmd_rb, env=env, capture_output=True, text=True)
            self.assertEqual(res_rb.returncode, 0, res_rb.stderr)
            captured_rb = payload_capture.read_text()
            self.assertIn("export VISION_DOMAIN=vision.worker.example.com", captured_rb)
            self.assertIn("gowave-worker-vision-fallback.conf", captured_rb)

    def test_lock_helper_canonical_path_and_reentrant_lease(self):
        lock_sh = REPO_ROOT / "modules" / "lock.sh"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            lock_file = tmp / "test-mutation.lock"
            lease_file = tmp / "test-lease.json"

            # Direct acquisition when free
            cmd_direct = f'source "{lock_sh}" && MUTATION_LOCK_FILE="{lock_file}" MUTATION_LEASE_FILE="{lease_file}" acquire_mutation_lock'
            res = subprocess.run(["bash", "-c", cmd_direct], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(lock_file.is_file())

            # Path validation rejects symlinks
            sym_dir = tmp / "sym_dir"
            sym_dir.symlink_to(tmp)
            bad_lock = sym_dir / "bad.lock"
            cmd_sym = f'source "{lock_sh}" && validate_lock_path "{bad_lock}"'
            res_sym = subprocess.run(["bash", "-c", cmd_sym], capture_output=True, text=True)
            self.assertNotEqual(res_sym.returncode, 0)
            self.assertIn("Lock directory", res_sym.stderr)

    def _runner_functions(self, target: Path) -> Path:
        """Extract the remote payload helper functions so they can run locally."""
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text(encoding="utf-8")
        marker = "cat <<'RUNNER_FUNCS'\n"
        start = script.index(marker) + len(marker)
        end = script.index("\nRUNNER_FUNCS\n", start)
        target.write_text(script[start:end] + "\n", encoding="utf-8")
        return target

    @staticmethod
    def _fake_core_tools(tmp: Path, install_rc: int, rewrite_version: bool) -> tuple[Path, Path, Path]:
        """Build a fake goave-node launcher and a fake rw-core that reports a version file."""
        version_file = tmp / "core-version.txt"
        version_file.write_text("25.10.15\n", encoding="utf-8")
        install_log = tmp / "install-calls.txt"
        node_bin = tmp / "gowave-node"
        node_bin.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{install_log}"\n'
            f"[[ {install_rc} -eq 0 ]] || exit {install_rc}\n"
            + (f'printf "26.11.9\\n" > "{version_file}"\n' if rewrite_version else "")
            + "exit 0\n",
            encoding="utf-8",
        )
        node_bin.chmod(0o755)
        core_bin = tmp / "rw-core"
        core_bin.write_text(
            "#!/bin/sh\n"
            f'printf "Xray %s (Xray, Penetrates Everything.) test-build (go1.27.3 linux/amd64)\\n" "$(cat "{version_file}")"\n',
            encoding="utf-8",
        )
        core_bin.chmod(0o755)
        return node_bin, core_bin, install_log

    def _run_pinned_core(self, tmp: Path, node_bin: Path, core_bin: Path, version: str = "26.11.9"):
        funcs = self._runner_functions(tmp / "runner_funcs.sh")
        cmd = (
            f'source "{funcs}" && XRAY_SERVER_VERSION="{version}" '
            f'ensure_pinned_xray_core "{node_bin}" "{core_bin}"'
        )
        return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)

    def test_pinned_core_crash_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Failed to install requested Xray server version 26.11.9", res.stderr)
            calls = install_log.read_text(encoding="utf-8")
            # Both version spellings are attempted before failing closed.
            self.assertIn("--version v26.11.9", calls)
            self.assertIn("--version 26.11.9", calls)

    def test_pinned_core_silent_noop_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, _ = self._fake_core_tools(tmp, install_rc=0, rewrite_version=False)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("version mismatch after installation", res.stderr)
            self.assertIn("expected 26.11.9, got Xray 25.10.15", res.stderr)

    def test_pinned_core_version_token_must_match_exactly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=0, rewrite_version=False)
            core_bin.write_text(
                '#!/bin/sh\nprintf "Xray 26.11.90 (Xray, Penetrates Everything.) test-build\\n"\n',
                encoding="utf-8",
            )
            core_bin.chmod(0o755)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("version mismatch after installation", res.stderr)
            self.assertTrue(install_log.exists(), "26.11.90 must not satisfy a 26.11.9 pin")

    def test_pinned_core_already_matching_skips_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            (tmp / "core-version.txt").write_text("26.11.9\n", encoding="utf-8")
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(install_log.exists())

    def test_pinned_core_install_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=0, rewrite_version=True)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Installing explicit Xray server version 26.11.9", res.stdout)
            self.assertIn("--version v26.11.9", install_log.read_text(encoding="utf-8"))

    def test_pinned_core_disabled_without_pin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            res = self._run_pinned_core(tmp, node_bin, core_bin, version="")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(install_log.exists())


if __name__ == "__main__":
    unittest.main()
