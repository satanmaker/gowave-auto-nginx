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
        self.assertIn("local rollback_failed=0", worker_script)
        self.assertIn("compensating rollback incomplete; one or more cleanup operations failed", worker_script)
        self.assertIn('if [[ "$swap_is_inactive" -eq 1 ]]; then', worker_script)
        self.assertIn('active_swaps=$(swapon --noheadings --raw --output NAME 2>/dev/null)', worker_script)

        self.assertNotIn("Compensating rollback completed on worker host.", worker_script)
        self.assertIn('restore_acme_lineage "$_ACME_TX_ID" "$WORKER_DOMAIN" 2>/dev/null || rollback_failed=1', worker_script)

    def test_standalone_remote_rollback_reports_non_acme_cleanup_failures(self):
        """Standalone rollback must fail if service, NGINX, hook, or scratch cleanup is incomplete."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        remote_start = worker_script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        remote_end = worker_script.index("\nROLLBACK_REMOTE_SCRIPT", remote_start)
        rollback_script = worker_script[remote_start:remote_end]

        self.assertIn("rollback_failed=0", rollback_script)
        self.assertIn('systemctl stop "$unit" 2>/dev/null || rollback_failed=1', rollback_script)
        self.assertIn('rollback_managed_deploy_hook', rollback_script)
        self.assertIn('rm -f "$hook_file" || {', rollback_script)
        self.assertIn('sync "$(dirname "$hook_file")" || {', rollback_script)
        self.assertIn('type(created) is not bool', rollback_script)
        self.assertIn(') || {', rollback_script)
        self.assertIn("nginx -t >/dev/null 2>&1", rollback_script)
        self.assertIn('systemctl reload nginx 2>/dev/null || rollback_failed=1', rollback_script)
        self.assertIn('rm -f /etc/sysctl.d/99-gowave-node.conf || rollback_failed=1', rollback_script)
        self.assertIn('sysctl --system 2>/dev/null || rollback_failed=1', rollback_script)
        self.assertIn("one or more cleanup or restoration operations failed", rollback_script)
        self.assertIn('ufw status numbered 2>/dev/null', rollback_script)
        self.assertIn('ufw delete allow 80/tcp 2>/dev/null || rollback_failed=1', rollback_script)
        self.assertIn('awk \'$3 == "80/tcp" { found=1 } END { exit !found }\'', rollback_script)
        self.assertIn('awk \'$3 == "443/tcp" { found=1 } END { exit !found }\'', rollback_script)
        self.assertNotIn("rollback_restore_failed", rollback_script)

    def test_node_add_pre_dispatch_failures_stay_inside_api_rollback_boundary(self):
        """Resolve local prerequisites early and persist VERIFYING inside the guarded API transaction."""
        worker_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        secret_index = worker_script.index('if ! secret_key=$(extract_secret_key "$GOWAVE_DIR")')
        api_index = worker_script.index("if ! PYTHONPATH=", secret_index)
        dispatch_index = worker_script.index('if ! ACME_TX_ID="$acme_tx_id" PANEL_IP="$panel_ip" PANEL_IPV6="$panel_ipv6" NODE_PORT="$node_port" SECRET_KEY="$secret_key"', api_index)
        self.assertLess(secret_index, api_index)
        self.assertLess(api_index, dispatch_index)

        transaction_block = worker_script[api_index:dispatch_index]
        self.assertIn('journal["state"] = "NODE_ADD_VERIFYING"', transaction_block)
        self.assertIn("write_journal_atomically(journal_path, journal)", transaction_block)
        self.assertNotIn("jdata['state'] = 'NODE_ADD_VERIFYING'", worker_script)
        self.assertNotIn("extract_secret_key", transaction_block)

    def test_worker_rollback_uses_the_original_acme_snapshot_transaction(self):
        """The controller and remote payload must share the snapshot ID; missing IDs must never delete unknown certs."""
        main_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn('local acme_tx_id="worker_install_${name}_$(date +%s)_${BASHPID}"', main_script)
        self.assertIn('ACME_TX_ID="$acme_tx_id"', main_script)
        self.assertIn('printf \'export ACME_TX_ID=%q\\n\' "${ACME_TX_ID:-}"', worker_script)
        self.assertIn('_ACME_TX_ID="${ACME_TX_ID:-worker_install_$(date +%s)}"', worker_script)

        remote_start = worker_script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        remote_end = worker_script.index("\nROLLBACK_REMOTE_SCRIPT", remote_start)
        rollback_script = worker_script[remote_start:remote_end]
        acme_start = rollback_script.index("# 3. Clean ACME certificates")
        acme_end = rollback_script.index("# 4. Remove UFW rules", acme_start)
        acme_cleanup = rollback_script[acme_start:acme_end]
        self.assertIn('restore_acme_lineage "$ACME_TX_ID" "$WORKER_DOMAIN"', acme_cleanup)
        self.assertIn("ACME_TX_ID missing; preserving unknown certificate lineage", acme_cleanup)
        self.assertNotIn("certbot delete", acme_cleanup)
        self.assertIn("rollback_failed=1", acme_cleanup)

    def test_worker_standalone_remote_rollback_defined(self):
        """gowave-node-auto.sh must provide standalone remote_rollback command."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("remote_rollback()", worker_script)
        self.assertIn("remote_rollback|rollback)", worker_script)
        self.assertIn("SSH host key for $host_key is not pre-pinned", worker_script)

    def test_standalone_remote_rollback_aborts_when_mutation_lock_is_held(self):
        """A failed nonblocking lock acquisition must stop rollback before destructive commands."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            marker = tmp / "destructive-command-called"
            lock_file = tmp / "mutation.lock"
            lock_file.touch()

            fake_ssh_keygen = bin_dir / "ssh-keygen"
            fake_ssh_keygen.write_text("#!/bin/sh\nexit 0\n")
            fake_ssh_keygen.chmod(0o755)

            fake_ssh = bin_dir / "ssh"
            fake_ssh.write_text("#!/bin/sh\nexec bash -s\n")
            fake_ssh.chmod(0o755)

            fake_id = bin_dir / "id"
            fake_id.write_text("#!/bin/sh\necho 0\n")
            fake_id.chmod(0o755)

            fake_flock = bin_dir / "flock"
            fake_flock.write_text("#!/bin/sh\nexit 1\n")
            fake_flock.chmod(0o755)

            fake_chmod = bin_dir / "chmod"
            fake_chmod.write_text("#!/bin/sh\nexit 0\n")
            fake_chmod.chmod(0o755)

            for command in ("systemctl", "rm", "sed", "nginx", "certbot", "ufw", "sysctl", "rmdir"):
                fake = bin_dir / command
                fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{command}' >> '{marker}'\nexit 0\n")
                fake.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SSH_KNOWN_HOSTS"] = str(known_hosts)
            env["MUTATION_LOCK_FILE"] = str(lock_file)

            cmd = [
                str(REPO_ROOT / "gowave-node-auto.sh"),
                "remote_rollback",
                "127.0.0.1",
                "22",
                "worker.example.com",
                "reality.example.com",
                "root",
            ]
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("Refusing remote rollback without the mutation lock", result.stderr)
            self.assertFalse(marker.exists(), "destructive commands ran without owning the mutation lock")

    def test_standalone_acme_restore_fails_closed_on_missing_or_malformed_manifest(self):
        """Missing or invalid lineage metadata must never be interpreted as 'no prior certificate'."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        remote_start = worker_script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        function_start = worker_script.index("restore_acme_lineage() {", remote_start)
        function_end = worker_script.index("\n}\n\nacquire_mutation_lock", function_start) + 2
        self.assertGreater(function_start, remote_start)
        self.assertGreater(function_end, function_start)
        restore_function = worker_script[function_start:function_end]

        for manifest_kind in ("missing", "malformed-json", "invalid-boolean"):
            with self.subTest(manifest_kind=manifest_kind), tempfile.TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                recovery = root / "recovery"
                letsencrypt = root / "letsencrypt"
                domain = "worker.example.com"
                snap_dir = recovery / "txn-1" / "acme" / domain
                snap_dir.mkdir(parents=True)
                renewal_dir = letsencrypt / "renewal"
                live_dir = letsencrypt / "live" / domain
                archive_dir = letsencrypt / "archive" / domain
                renewal_dir.mkdir(parents=True)
                live_dir.mkdir(parents=True)
                archive_dir.mkdir(parents=True)
                renewal = renewal_dir / f"{domain}.conf"
                live_cert = live_dir / "fullchain.pem"
                archive_cert = archive_dir / "cert1.pem"
                renewal.write_text("existing renewal configuration")
                live_cert.write_text("existing live certificate")
                archive_cert.write_text("existing archived certificate")

                manifest = snap_dir / "lineage-manifest.json"
                if manifest_kind == "malformed-json":
                    manifest.write_text("{not-json")
                elif manifest_kind == "invalid-boolean":
                    manifest.write_text(json.dumps({
                        "domain": domain,
                        "existed_before": "false",
                    }))

                command = (
                    restore_function
                    + "\nrestore_acme_lineage "
                    + '"txn-1" "'
                    + domain
                    + '" "'
                    + str(recovery)
                    + '" "'
                    + str(letsencrypt)
                    + '"'
                )
                result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertTrue(renewal.exists(), "renewal configuration was deleted on invalid manifest")
                self.assertEqual(live_cert.read_text(), "existing live certificate")
                self.assertEqual(archive_cert.read_text(), "existing archived certificate")

    def test_standalone_acme_restore_accepts_certbot_archive_relative_symlinks(self):
        """A valid Certbot-style relative link must resolve inside the archive and pass identity checks."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        remote_start = worker_script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        function_start = worker_script.index("restore_acme_lineage() {", remote_start)
        function_end = worker_script.index("\n}\n\nacquire_mutation_lock", function_start) + 2
        restore_function = worker_script[function_start:function_end]

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            recovery = root / "recovery"
            letsencrypt = root / "letsencrypt"
            domain = "worker.example.com"
            snap_dir = recovery / "txn-1" / "acme" / domain
            snapshot_archive = snap_dir / "archive"
            snapshot_live = snap_dir / "live"
            snapshot_archive.mkdir(parents=True)
            snapshot_live.mkdir(parents=True)

            generated_cert = root / "fullchain.pem"
            generated_key = root / "privkey.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(generated_key), "-out", str(generated_cert),
                "-subj", f"/CN={domain}", "-days", "1",
            ], check=True, capture_output=True, text=True)

            (snapshot_archive / "cert1.pem").write_bytes(generated_cert.read_bytes())
            (snapshot_archive / "privkey1.pem").write_bytes(generated_key.read_bytes())
            (snapshot_live / "fullchain.pem.target").write_text(f"../../archive/{domain}/cert1.pem")
            (snapshot_live / "privkey.pem.target").write_text(f"../../archive/{domain}/privkey1.pem")

            serial = subprocess.check_output(
                ["openssl", "x509", "-in", str(generated_cert), "-noout", "-serial"], text=True
            ).strip()
            fingerprint = subprocess.check_output(
                ["openssl", "x509", "-in", str(generated_cert), "-noout", "-fingerprint", "-sha256"], text=True
            ).strip()
            (snap_dir / "lineage-manifest.json").write_text(json.dumps({
                "domain": domain,
                "existed_before": True,
                "serial": serial,
                "fingerprint": fingerprint,
            }))

            command = (
                restore_function
                + "\nrestore_acme_lineage "
                + '"txn-1" "'
                + domain
                + '" "'
                + str(recovery)
                + '" "'
                + str(letsencrypt)
                + '"'
            )
            result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            restored_fullchain = letsencrypt / "live" / domain / "fullchain.pem"
            restored_privkey = letsencrypt / "live" / domain / "privkey.pem"
            self.assertTrue(restored_fullchain.is_symlink())
            self.assertTrue(restored_privkey.is_symlink())
            self.assertEqual(restored_fullchain.resolve(), (letsencrypt / "archive" / domain / "cert1.pem").resolve())
            self.assertEqual(restored_privkey.resolve(), (letsencrypt / "archive" / domain / "privkey1.pem").resolve())

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


if __name__ == "__main__":
    unittest.main()
