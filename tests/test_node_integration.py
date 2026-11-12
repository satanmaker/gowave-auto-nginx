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
    def test_recovery_directory_is_created_private_and_owned_by_caller(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recovery_dir = Path(tmpdir) / "recovery"
            env = os.environ.copy()
            env["RECOVERY_DIR"] = str(recovery_dir)
            result = subprocess.run(
                ["bash", "-c", 'source "$1/modules/recovery.sh"; ensure_recovery_dir', "test", str(REPO_ROOT)],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            metadata = recovery_dir.stat()
            self.assertEqual(metadata.st_uid, os.geteuid())
            self.assertEqual(metadata.st_mode & 0o777, 0o700)

    def test_recovery_directory_refuses_filesystem_root(self):
        root_mode = Path("/").stat().st_mode & 0o777
        env = os.environ.copy()
        env["RECOVERY_DIR"] = "/"
        result = subprocess.run(
            ["bash", "-c", 'source "$1/modules/recovery.sh"; ensure_recovery_dir', "test", str(REPO_ROOT)],
            env=env, capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dedicated 'recovery' directory", result.stderr)
        self.assertEqual(Path("/").stat().st_mode & 0o777, root_mode)

    def test_recovery_directory_does_not_chmod_foreign_owned_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            recovery_dir = root / "recovery"
            recovery_dir.mkdir(mode=0o755)
            recovery_dir.chmod(0o755)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            chmod_marker = root / "chmod-called"
            fake_stat = bin_dir / "stat"
            fake_stat.write_text("#!/bin/sh\necho 65534:755\n")
            fake_stat.chmod(0o755)
            fake_chmod = bin_dir / "chmod"
            fake_chmod.write_text(f"#!/bin/sh\ntouch '{chmod_marker}'\nexit 0\n")
            fake_chmod.chmod(0o755)

            env = os.environ.copy()
            env["RECOVERY_DIR"] = str(recovery_dir)
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", 'source "$1/modules/recovery.sh"; ensure_recovery_dir', "test", str(REPO_ROOT)],
                env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must be owned by the current user", result.stderr)
            self.assertFalse(chmod_marker.exists(), "chmod must not mutate a foreign-owned directory")
            self.assertEqual(recovery_dir.stat().st_mode & 0o777, 0o755)
    def test_recovery_directory_rejects_symlink_path_components(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real_parent = root / "real"
            real_parent.mkdir()
            real_parent.chmod(0o755)
            linked_parent = root / "linked"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            recovery_dir = linked_parent / "recovery"
            env = os.environ.copy()
            env["RECOVERY_DIR"] = str(recovery_dir)
            result = subprocess.run(
                ["bash", "-c", 'source "$1/modules/recovery.sh"; ensure_recovery_dir', "test", str(REPO_ROOT)],
                env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("recovery directory path contains a symlink", result.stderr)
            self.assertFalse((real_parent / "recovery").exists())
            self.assertEqual(real_parent.stat().st_mode & 0o777, 0o755)

    def test_recovery_directory_permission_failure_aborts_snapshot_setup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            recovery_dir = root / "recovery"
            bin_dir = root / "bin"
            bin_dir.mkdir()
            fake_chmod = bin_dir / "chmod"
            fake_chmod.write_text("#!/bin/sh\nexit 1\n")
            fake_chmod.chmod(0o755)
            env = os.environ.copy()
            env["RECOVERY_DIR"] = str(recovery_dir)
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", 'source "$1/modules/recovery.sh"; ensure_recovery_dir', "test", str(REPO_ROOT)],
                env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot enforce private recovery directory permissions", result.stderr)

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

    def test_worker_keeps_port_80_acme_vhost_for_renewal(self):
        """Worker port-80 ACME vhost must survive issuance; deleting it makes renewal 404."""
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        funcs_start = script.index("cat <<'RUNNER_FUNCS'")
        payload = script[funcs_start:script.index("\nRUNNER_FUNCS\n", funcs_start)]

        start = payload.index("configure_edge_nginx() {")
        end = payload.index("\n}\n", start) + len("\n}\n")
        body = payload[start:end]

        vhost = "/etc/nginx/conf.d/00-worker-acme-challenge.conf"
        self.assertIn(f"cat > {vhost}", body)
        self.assertIn("location /.well-known/acme-challenge/ {", body)
        self.assertIn("root /var/www/gowave-acme;", body)
        self.assertNotIn(f"rm -f {vhost}", body)

        rollback_start = payload.index("compensate_remote_worker() {")
        self.assertIn(vhost, payload[rollback_start:])

        uninstall_start = script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        uninstall = script[uninstall_start:script.index("\nROLLBACK_REMOTE_SCRIPT", uninstall_start)]
        self.assertIn(vhost, uninstall)

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

    def _run_worker_dot(self, body: str) -> subprocess.CompletedProcess:
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        start = script.index("configure_worker_dot() {")
        end = script.index("\n}\n", start) + len("\n}\n")
        prelude = (
            "set -euo pipefail\n"
            "log_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            + script[start:end]
            + "\n"
        )
        return subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True)

    def test_worker_host_security_enables_strict_dot(self):
        """Worker hardening must run the DoT helper and track ownership of the drop-in."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        security_start = worker_script.index("configure_host_security() {")
        security_end = worker_script.index("\nconfigure_firewall() {", security_start)
        self.assertIn("configure_worker_dot", worker_script[security_start:security_end])

        with tempfile.TemporaryDirectory() as tmpdir:
            dropin = Path(tmpdir) / "90-gowave-auto-nginx.conf"
            body = (
                'configure_dot() { return 0; }\n'
                f'configure_worker_dot "{dropin}"\n'
                'echo "flag=${_DOT_CREATED_BY_US:-unset}"\n'
            )
            res = self._run_worker_dot(body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("flag=1", res.stdout)

            dropin.write_text("# Managed by GoWave Auto NGINX: VPS Security\n")
            res = self._run_worker_dot(body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("flag=0", res.stdout)

    def test_worker_dot_failure_is_non_fatal_and_not_owned(self):
        """A DoT failure must warn instead of aborting, and must not claim the drop-in."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dropin = Path(tmpdir) / "90-gowave-auto-nginx.conf"
            body = (
                'configure_dot() { return 1; }\n'
                f'configure_worker_dot "{dropin}"\n'
                'echo "flag=${_DOT_CREATED_BY_US:-unset}"\n'
            )
            res = self._run_worker_dot(body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("flag=0", res.stdout)
            self.assertIn("remains unhardened", res.stderr)

    def test_worker_payload_ships_security_helper_for_dot(self):
        """The Worker never receives the project checkout, so managed.py must travel with the payload."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("export SECURITY_HELPER_B64", worker_script)
        self.assertIn('$SCRIPT_DIR/assets/security/managed.py', worker_script)

        funcs_start = worker_script.index("cat <<'RUNNER_FUNCS'")
        payload = worker_script[funcs_start:worker_script.index("\nRUNNER_FUNCS\n", funcs_start)]
        self.assertIn("configure_dot() {", payload)
        self.assertIn("--prepare-dns", payload)

    def _run_payload_function(self, function: str, body: str, exports: str = "") -> subprocess.CompletedProcess:
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        funcs_start = script.index("cat <<'RUNNER_FUNCS'")
        payload = script[funcs_start:script.index("\nRUNNER_FUNCS\n", funcs_start)]
        start = payload.index(function + "() {")
        end = payload.index("\n}\n", start) + len("\n}\n")
        prelude = (
            "set -euo pipefail\n"
            "log_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            + exports
            + payload[start:end]
            + "\n"
        )
        return subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True)

    def test_worker_payload_dot_runs_shipped_security_helper(self):
        helper = "import json, sys\nprint(json.dumps({'status': 'configured'}))\nsys.exit(0)\n"
        exports = "export SECURITY_HELPER_B64=%s\n" % base64.b64encode(helper.encode()).decode()
        temp_helper = Path("/tmp/gowave-managed-security.py")
        try:
            res = self._run_payload_function("configure_dot", "configure_dot\n", exports)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn('"status": "configured"', res.stdout)
            self.assertFalse(temp_helper.exists(), "the streamed helper must not be left behind")
        finally:
            temp_helper.unlink(missing_ok=True)

    def test_worker_payload_dot_propagates_helper_failure(self):
        helper = "import json, sys\nprint(json.dumps({'status': 'failed'}))\nsys.exit(1)\n"
        exports = "export SECURITY_HELPER_B64=%s\n" % base64.b64encode(helper.encode()).decode()
        res = self._run_payload_function("configure_dot", "configure_dot\n", exports)
        self.assertEqual(res.returncode, 1)
        self.assertIn('"status": "failed"', res.stdout)

    def test_worker_payload_dot_warns_when_helper_not_delivered(self):
        res = self._run_payload_function("configure_dot", "configure_dot\n")
        self.assertEqual(res.returncode, 1)
        self.assertIn("was not delivered", res.stderr)

    def test_worker_rollbacks_remove_only_project_owned_dns_drop_in(self):
        """Both rollback paths must gate DNS drop-in removal on the project marker."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        marker_guard = "grep -qF 'Managed by GoWave Auto NGINX: VPS Security' /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf"
        self.assertEqual(worker_script.count(marker_guard), 2)
        self.assertEqual(
            worker_script.count("rm -f /etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf || rollback_failed=1"),
            2,
        )

    def test_initial_provision_persists_applying_state_at_first_api_mutation(self):
        auto_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        prepared_at = auto_script.index('"state": "PROVISION_PREPARED"')
        callback_at = auto_script.index("def persist_transaction_entities(entities):", prepared_at)
        callback_end = auto_script.index("\nclient.transaction_callback", callback_at)
        callback = auto_script[callback_at:callback_end]
        self.assertIn('journal["state"] = "PROVISION_APPLYING"', callback)
        self.assertIn('journal["entities"] = list(entities)', callback)
        self.assertLess(
            auto_script.index("client.transaction_callback = persist_transaction_entities", callback_at),
            auto_script.index('client.provision_config_profile("GoWave MVP Unified Profile - local-node"', callback_at),
        )

    def test_node_add_persists_applying_state_before_first_api_create(self):
        auto_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        prepared_at = auto_script.index('"state": "NODE_ADD_PREPARED"')
        callback_at = auto_script.index("def persist_transaction_entities(entities):", prepared_at)
        callback_end = auto_script.index("\nclient.transaction_callback", callback_at)
        callback = auto_script[callback_at:callback_end]
        self.assertIn('journal["state"] = "NODE_ADD_APPLYING"', callback)
        self.assertIn('journal["entities"] = list(entities)', callback)
        self.assertLess(
            auto_script.index("client.transaction_callback = persist_transaction_entities", callback_at),
            auto_script.index('client.provision_config_profile(f"GoWave Worker {name} Profile"', callback_at),
        )

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

    def test_node_add_commit_record_failure_compensates_both_sides(self):
        """A failed durable commit after remote success must roll back Worker and Panel API state."""
        worker_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        commit_start = worker_script.index("# 5. Commit transaction")
        commit_end = worker_script.index('echo "Worker \'$name\' successfully added and deployed."', commit_start)
        commit_block = worker_script[commit_start:commit_end]
        self.assertIn("if ! python3 -c", commit_block)
        self.assertIn('ACME_TX_ID="$acme_tx_id"', commit_block)
        self.assertIn('remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"', commit_block)
        self.assertIn("rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE')", commit_block)
        self.assertIn("return 1", commit_block)

    def test_worker_acme_snapshot_is_retained_until_controller_commit(self):
        """The remote payload must preserve its ACME before-image until the controller commits."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        main_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        success_start = worker_script.index("# Disable ERR compensation trap on verified success")
        success_end = worker_script.index("GoWave Edge Worker deployment complete", success_start)
        self.assertNotIn("cleanup_acme_snapshot", worker_script[success_start:success_end])
        self.assertIn("remote_finalize()", worker_script)
        self.assertIn("remote_finalize)", worker_script)
        self.assertIn('rm -rf -- "$transaction_dir"', worker_script)
        self.assertIn("Delete the ACME snapshot only after every rollback action has succeeded", worker_script)
        rollback_script_start = worker_script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        rollback_cleanup_index = worker_script.index("Delete the ACME snapshot only after every rollback action has succeeded", rollback_script_start)
        rollback_sysctl_index = worker_script.index("sysctl --system 2>/dev/null || rollback_failed=1", rollback_script_start)
        self.assertGreater(rollback_cleanup_index, rollback_sysctl_index)

        commit_index = main_script.index("# 5. Commit transaction")
        finalize_index = main_script.index("remote_finalize \"$ip\" \"$ssh_port\" \"$ssh_user\"", commit_index)
        self.assertGreater(finalize_index, commit_index)
        self.assertIn('if [[ ! "$_ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]', worker_script)
        self.assertIn('if [[ -n "${ACME_TX_ID:-}" && ! "$ACME_TX_ID" =~ ^worker_install_[A-Za-z0-9._-]{1,100}$ ]]', worker_script)
        self.assertIn('( -e "$lock_file" && ! -f "$lock_file" )', worker_script)
        self.assertIn("snapshot could not be finalized; snapshot retained", main_script[finalize_index:])

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

    def test_standalone_remote_rollback_reports_service_stop_failure(self):
        """A failed service stop must make standalone remote rollback fail, not report success."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            log = tmp / "commands.log"

            scripts = {
                "ssh-keygen": "#!/bin/sh\nexit 0\n",
                "ssh": "#!/bin/sh\nexec bash -s\n",
                "id": "#!/bin/sh\necho 0\n",
                "flock": "#!/bin/sh\nexit 0\n",
                "chmod": "#!/bin/sh\nexit 0\n",
                "systemctl": (
                    "#!/bin/sh\n"
                    "printf '%s\\n' \"$*\" >> '" + str(log) + "'\n"
                    "case \"$1\" in\n"
                    "  list-unit-files) echo 'gowave-node.service enabled enabled'; exit 0;;\n"
                    "  stop) exit 1;;\n"
                    "  *) exit 0;;\n"
                    "esac\n"
                ),
                "nginx": "#!/bin/sh\nexit 0\n",
                "ufw": "#!/bin/sh\nexit 0\n",
                "sysctl": "#!/bin/sh\nexit 0\n",
                "rm": "#!/bin/sh\nexit 0\n",
                "rmdir": "#!/bin/sh\nexit 0\n",
                "sed": "#!/bin/sh\nexit 0\n",
                "certbot": "#!/bin/sh\nexit 0\n",
            }
            for name, content in scripts.items():
                executable = bin_dir / name
                executable.write_text(content)
                executable.chmod(0o755)

            lock_file = tmp / "mutation.lock"
            lock_file.touch()
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
            self.assertIn("Remote worker compensation teardown incomplete", result.stderr)
            self.assertNotIn("Remote worker compensation teardown finished", result.stderr)
            self.assertIn("stop gowave-node.service", log.read_text())

    def test_standalone_remote_rollback_reports_service_cleanup_failure(self):
        """A failed stop/disable operation must make standalone rollback fail explicitly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            known_hosts = tmp / "known_hosts"
            known_hosts.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n")
            bin_dir = tmp / "bin"
            bin_dir.mkdir()

            def fake(name, body):
                path = bin_dir / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(0o755)

            fake("ssh-keygen", "exit 0")
            fake("ssh", "exec bash -s")
            fake("id", "echo 0")
            fake("flock", "exit 0")
            log = tmp / "systemctl.log"
            fake("systemctl", (
                "printf '%s\\n' \"$*\" >> '" + str(log) + "'\n"
                "case \"$1\" in\n"
                "    list-unit-files) echo 'gowave-node.service enabled'; exit 0;;\n"
                "    is-active) exit 3;;\n"
                "    stop) exit 0;;\n"
                "    disable) exit 7;;\n"
                "    *) exit 0;;\n"
                "esac"
            ))
            for command in ("rm", "sed", "nginx", "certbot", "ufw", "sysctl", "rmdir", "chmod"):
                fake(command, "exit 0")

            lock_file = tmp / "mutation.lock"
            lock_file.touch()
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            env["SSH_KNOWN_HOSTS"] = str(known_hosts)
            env["MUTATION_LOCK_FILE"] = str(lock_file)

            result = subprocess.run(
                [
                    str(REPO_ROOT / "gowave-node-auto.sh"),
                    "remote_rollback", "127.0.0.1", "22",
                    "worker.example.com", "reality.example.com", "root",
                ],
                env=env, capture_output=True, text=True,
            )

            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("Remote worker compensation teardown incomplete", result.stderr)
            self.assertNotIn("Remote worker compensation teardown finished.", result.stderr)
            self.assertIn("disable gowave-node.service", log.read_text())

    def test_standalone_rollback_preserves_unowned_deploy_hook_without_transaction_id(self):
        """Without an ACME transaction ID, an existing deploy hook has unknown ownership."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        remote_start = worker_script.index(
            "cat <<'ROLLBACK_REMOTE_SCRIPT'",
            worker_script.index("remote_rollback() {"),
        )
        function_start = worker_script.index("rollback_managed_deploy_hook() {", remote_start)
        function_end = worker_script.index("\n}\n\nrestore_acme_lineage", function_start) + 2
        self.assertGreater(function_end, function_start)
        function = worker_script[function_start:function_end]

        with tempfile.TemporaryDirectory() as tmpdir:
            hook_file = Path(tmpdir) / "gowave-nginx.sh"
            hook_file.write_text("#!/bin/sh\necho operator-owned\n")
            recovery_root = Path(tmpdir) / "recovery"

            command = function + '\nrollback_managed_deploy_hook "" "$1" "$2"'
            result = subprocess.run(
                ["bash", "-c", command, "bash", str(hook_file), str(recovery_root)],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("transaction ID is missing", result.stderr)
            self.assertTrue(hook_file.is_file(), "unknown-ownership deploy hook must be preserved")

            hook_file.unlink()
            absent = subprocess.run(
                ["bash", "-c", command, "bash", str(hook_file), str(recovery_root)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(absent.returncode, 0, absent.stderr)

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

    def _run_node_sh_pinned_core(self, node_bin: Path, core_bin: Path, version: str = "26.11.9"):
        cmd = (
            f'source "{NODE_SH}" && XRAY_SERVER_VERSION="{version}" '
            f'ensure_pinned_xray_core "{node_bin}" "{core_bin}"'
        )
        return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)

    def test_node_sh_pinned_core_crash_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            res = self._run_node_sh_pinned_core(node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Failed to install requested Xray server version 26.11.9", res.stderr)
            self.assertIn("--version v26.11.9", install_log.read_text(encoding="utf-8"))

    def test_node_sh_pinned_core_silent_noop_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, _ = self._fake_core_tools(tmp, install_rc=0, rewrite_version=False)
            res = self._run_node_sh_pinned_core(node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("version mismatch after installation", res.stderr)

    def test_node_sh_pinned_core_version_token_must_match_exactly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=0, rewrite_version=False)
            core_bin.write_text(
                '#!/bin/sh\nprintf "Xray 26.11.90 (Xray, Penetrates Everything.) test-build\\n"\n',
                encoding="utf-8",
            )
            core_bin.chmod(0o755)
            res = self._run_node_sh_pinned_core(node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertTrue(install_log.exists(), "26.11.90 must not satisfy a 26.11.9 pin")

    def test_node_sh_pinned_core_install_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, _ = self._fake_core_tools(tmp, install_rc=0, rewrite_version=True)
            res = self._run_node_sh_pinned_core(node_bin, core_bin)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Installing explicit Xray server version 26.11.9", res.stdout)


if __name__ == "__main__":
    unittest.main()
