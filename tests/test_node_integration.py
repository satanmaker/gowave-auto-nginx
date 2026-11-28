#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NODE_SH = REPO_ROOT / "modules" / "node.sh"
XRAY_CORE_SH = REPO_ROOT / "modules" / "xray_core.sh"
OS_SH = REPO_ROOT / "modules" / "os.sh"
PANEL_SH = REPO_ROOT / "modules" / "panel.sh"
ARTIFACT_SH = REPO_ROOT / "modules" / "artifact.sh"
PREFLIGHT_SH = REPO_ROOT / "modules" / "preflight.sh"
NGINX_PACKAGE_SH = REPO_ROOT / "modules" / "nginx_package.sh"
NODE_AUTO_SH = REPO_ROOT / "gowave-node-auto.sh"
MATRIX_YAML = REPO_ROOT / "tests" / "cases" / "matrix.yaml"


def node_sh_without_bundle(directory: Path) -> Path:
    """Copy the Node module so its SCRIPT_DIR carries no local installer bundle."""
    copy = directory / "repo" / "modules" / "node.sh"
    copy.parent.mkdir(parents=True)
    copy.write_bytes(NODE_SH.read_bytes())
    return copy


def capture_remote_script(directory, *command, extra_env=None) -> str:
    """Run a remote-* subcommand against a mock ssh and return the streamed script."""
    directory = Path(directory)
    known_hosts = directory / "known_hosts"
    known_hosts.write_text(
        "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGMockKeyMockKeyMockKeyMockKeyMockKeyMockKey\n"
    )
    bin_dir = directory / "bin"
    bin_dir.mkdir()
    capture = directory / "payload.sh"
    mock_ssh = bin_dir / "ssh"
    mock_ssh.write_text(f'#!/bin/sh\ncat > "{capture}"\nexit 0\n')
    mock_ssh.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["SSH_KNOWN_HOSTS"] = str(known_hosts)
    env["SECRET_KEY"] = "bW9jay1zZWNyZXQ="
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [str(REPO_ROOT / "gowave-node-auto.sh"), *command],
        env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise AssertionError(f"stdout: {result.stdout}, stderr: {result.stderr}")
    return capture.read_text()


#: Takes the Worker's mutation lock the way the live runner's `RemotePairLock`
#: does — an exclusive `flock` with the lease naming the holder published beside
#: the lock — and then runs the finalizer in a process of its own. The holder
#: stays the finalizer's parent so both live in one user namespace: a process in
#: a child namespace cannot read the descriptor targets of one outside it, which
#: would make the validator's own check fail for a reason the Worker never sees.
LOCK_HOLDER_DRIVER = """
import fcntl, json, os, subprocess, sys
lock_path, lease_path, holder_token, finalizer, result_path = sys.argv[1:6]
fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
with open(lease_path, "w", encoding="utf-8") as stream:
    json.dump({"run_id": "run-test", "host": "127.0.0.1",
               "holder_pid": os.getpid(), "lease_token": holder_token}, stream)
result = subprocess.run(["bash", finalizer], capture_output=True, text=True)
with open(result_path, "w", encoding="utf-8") as stream:
    json.dump({"returncode": result.returncode, "stdout": result.stdout,
               "stderr": result.stderr}, stream)
"""


def run_rendered_finalizer(directory, transaction, lease_token, holder_token=None):
    """Run the finalize script the product streams while a real holder owns the lock.

    `lease_token` is what the rendered script presents; `holder_token` is what the
    live lease names, so the two differ when another run's lease is borrowed.
    """
    directory = Path(directory)
    render_dir = directory / "render"
    render_dir.mkdir()
    script = capture_remote_script(
        render_dir, "remote_finalize", "127.0.0.1", "22", "root",
        extra_env={
            "ACME_TX_ID": transaction.name,
            "GOWAVE_WORKER_LEASE_TOKEN": lease_token,
        },
    )
    root_line = 'recovery_root="/var/lib/gowave-auto-nginx/recovery"'
    if script.count(root_line) != 1:
        raise AssertionError("the streamed finalizer no longer names one recovery root")
    finalizer = render_dir / "finalize.sh"
    finalizer.write_text(
        script.replace(root_line, f'recovery_root="{transaction.parent}"'), encoding="utf-8"
    )

    lock = directory / "gowave-managed-mutation.lock"
    lease = directory / "gowave-mutation-lease.json"
    result_path = directory / "finalizer-result.json"
    env = os.environ.copy()
    env["MUTATION_LOCK_FILE"] = str(lock)
    env["MUTATION_LEASE_FILE"] = str(lease)
    command = [
        sys.executable, "-c", LOCK_HOLDER_DRIVER,
        str(lock), str(lease), holder_token or lease_token, str(finalizer), str(result_path),
    ]
    if os.geteuid() != 0:
        # The root guard is part of what the Worker runs, so the script is not
        # relaxed for the test: holder and finalizer both run as uid 0 in a user
        # namespace, which keeps the validator's owner, liveness and descriptor
        # checks meaningful.
        unshare = shutil.which("unshare")
        if not unshare or subprocess.run(
            [unshare, "-r", "true"], capture_output=True
        ).returncode != 0:
            raise unittest.SkipTest("this host cannot grant the finalizer its root guard")
        command = [unshare, "-r", "--", *command]
    driver = subprocess.run(command, env=env, capture_output=True, text=True)
    if not result_path.exists():
        raise AssertionError(f"the finalizer never ran: {driver.stdout}{driver.stderr}")
    recorded = json.loads(result_path.read_text(encoding="utf-8"))
    return subprocess.CompletedProcess(command, recorded["returncode"],
                                       recorded["stdout"], recorded["stderr"])


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

    def test_the_upstream_node_installer_is_pinned_not_vendored(self):
        tracked = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "--", "sources/gowave-node/install.sh"],
            capture_output=True, text=True,
        )
        if tracked.returncode == 0:
            self.assertEqual(
                tracked.stdout.strip(), "",
                "the upstream Node installer must stay out of git; the commit pin is the authority",
            )
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
        # The ERR trap is the same guarded handler as a signal, because the
        # compensator returns the exit code it was given: called straight from
        # the trap it would re-enter and roll the host back twice.
        self.assertIn("trap 'handle_error \"$?\"' ERR", worker_script)
        # Both units are cleaned up by name from a loop that skips a unit the host
        # does not have, so the assertion names the loop rather than one stop line.
        self.assertIn("for unit in gowave-node.service xray.service; do", worker_script)
        self.assertIn('systemctl stop "$unit" 2>/dev/null || rollback_failed=1', worker_script)
        # The service directory is no longer removed by a blanket rm: it comes
        # back from the transaction's before-image, so a path this install did
        # not write is not deleted by a rollback that never owned it.
        self.assertIn('restore_worker_targets_before_image \\\n'
                      '        "$host_root" "$(worker_targets_before_image "$state_root" '
                      '"$_ACME_TX_ID")" ||\n'
                      '        rollback_failed=1\n',
                      worker_script)
        self.assertNotIn("rm -rf /etc/systemd/system/gowave-node.service.d", worker_script)
        self.assertIn("certbot delete --cert-name \"$worker_lineage\"", worker_script)
        self.assertIn("swapoff /swapfile", worker_script)
        self.assertIn("ufw delete allow proto tcp from \"$PANEL_IP\"", worker_script)
        self.assertIn("local rollback_failed=0", worker_script)
        self.assertIn("compensating rollback incomplete; one or more cleanup operations failed", worker_script)
        self.assertIn('if [[ "$swap_is_inactive" -eq 1 ]]; then', worker_script)
        self.assertIn('active_swaps=$(swapon --noheadings --raw --output NAME 2>/dev/null)', worker_script)

        self.assertNotIn("Compensating rollback completed on worker host.", worker_script)
        self.assertIn(
            'restore_acme_lineage "$_ACME_TX_ID" "${_WORKER_LINEAGE:-$WORKER_DOMAIN}" '
            '"$state_root/recovery" "$host_root/etc/letsencrypt" 2>/dev/null || rollback_failed=1',
            worker_script,
        )

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
        self.assertIn("return 301 https://\\$host\\$request_uri;", body)

        inventory_start = payload.index("worker_mutation_targets() {")
        inventory_end = payload.index("\n}\n", inventory_start) + len("\n}\n")
        self.assertIn(vhost, payload[inventory_start:inventory_end])
        rollback_start = payload.index("compensate_remote_worker() {")
        self.assertIn('restore_worker_targets_before_image \\\n'
                      '        "$host_root" "$(worker_targets_before_image "$state_root" '
                      '"$_ACME_TX_ID")" ||\n'
                      '        rollback_failed=1\n',
                      payload[rollback_start:])

        uninstall_start = script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        uninstall = script[uninstall_start:script.index("\nROLLBACK_REMOTE_SCRIPT", uninstall_start)]
        self.assertIn(vhost, uninstall)

    def test_worker_edge_https_vhost_pins_its_own_tls_versions(self):
        """Worker Edge HTTPS must state ssl_protocols; inheriting a platform default
        would make the same product accept different versions per distribution."""
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        funcs_start = script.index("cat <<'RUNNER_FUNCS'")
        payload = script[funcs_start:script.index("\nRUNNER_FUNCS\n", funcs_start)]

        start = payload.index("configure_edge_nginx() {")
        # The function writes several vhosts whose heredocs own top-level braces,
        # so the slice ends at the next function rather than at the first "\n}\n".
        end = payload.index("\ncore_version_matches() {", start)
        body = payload[start:end]

        self.assertIn("cat > /etc/nginx/conf.d/gowave-worker-https.conf", body)
        vhost_start = body.index("cat > /etc/nginx/conf.d/gowave-worker-https.conf")
        https = body[vhost_start:body.index("\nEOF\n", vhost_start)]
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", https)
        self.assertIn("ssl_ciphers HIGH:!aNULL:!MD5;", https)
        self.assertIn("ssl_certificate $worker_live/fullchain.pem;", https)
        self.assertNotIn("ssl_protocols TLSv1.3;", https)

    def test_worker_edge_https_serves_cover_and_denies_management(self):
        """The Worker primary is an ordinary website: the root and every known
        asset are the rendered cover site, an unknown path keeps the brand's own
        404 page, and no management or subscription path reaches a transport."""
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        funcs_start = script.index("cat <<'RUNNER_FUNCS'")
        payload = script[funcs_start:script.index("\nRUNNER_FUNCS\n", funcs_start)]

        start = payload.index("configure_edge_nginx() {")
        end = payload.index("\ncore_version_matches() {", start)
        body = payload[start:end]
        vhost_start = body.index("cat > /etc/nginx/conf.d/gowave-worker-https.conf")
        https = body[vhost_start:body.index("\nEOF\n", vhost_start)]

        self.assertIn("root /var/www/gowave-auto-nginx/cover-reality;", https)
        self.assertIn("index index.html;", https)
        self.assertIn("error_page 404 /404.html;", https)
        self.assertIn("location ^~ /api/ {\n        return 444;\n    }", https)
        self.assertIn("location / {\n        try_files \\$uri \\$uri/ =404;\n    }", https)
        self.assertNotIn("return 404;", https)
        for transport in ("location ^~ /xhttp-down/ {", "location = /ws {",
                          "location /trojan-grpc {"):
            self.assertIn(transport, https)
        xhttp = https.split("location ^~ /xhttp-down/ {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("grpc_pass grpc://127.0.0.1:10001;", xhttp)
        self.assertIn('grpc_set_header Connection "";', xhttp)
        self.assertNotIn("proxy_pass", xhttp)

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
        # A file the install did not write is not removed by its rollback: the
        # drop-in goes only when it carries the marker that says this install
        # wrote it, and never on an unguarded ``rm -f``.
        self.assertIn(
            "if [[ -f /etc/sysctl.d/99-gowave-node.conf ]] &&\n"
            "    grep -qxF '# Managed by GoWave Auto NGINX' "
            "/etc/sysctl.d/99-gowave-node.conf; then\n"
            "    rm -f /etc/sysctl.d/99-gowave-node.conf || rollback_failed=1\n"
            "fi\n",
            rollback_script,
        )
        self.assertNotIn(
            "# 5. Clean sysctl, project-owned DNS drop-in and scratch\n"
            "rm -f /etc/sysctl.d/99-gowave-node.conf || rollback_failed=1\n",
            rollback_script,
        )
        self.assertIn('sysctl --system 2>/dev/null || rollback_failed=1', rollback_script)
        self.assertIn("one or more cleanup or restoration operations failed", rollback_script)
        self.assertIn('ufw status numbered 2>/dev/null', rollback_script)
        self.assertIn('ufw delete allow 80/tcp 2>/dev/null || rollback_failed=1', rollback_script)
        self.assertIn('awk \'$3 == "80/tcp" { found=1 } END { exit !found }\'', rollback_script)
        self.assertIn('awk \'$3 == "443/tcp" { found=1 } END { exit !found }\'', rollback_script)
        self.assertNotIn("rollback_restore_failed", rollback_script)

    def _run_worker_dot(self, body: str, env=None) -> subprocess.CompletedProcess:
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        start = script.index("configure_worker_dot() {")
        end = script.index("\n}\n", start) + len("\n}\n")
        prelude = (
            "set -euo pipefail\n"
            "log_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            + script[start:end]
            + "\n"
        )
        return subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True,
                              env=env)

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

    def test_worker_dot_failure_stops_the_installation(self):
        """Only a configured policy or a verified rollback may finish a Worker.

        `configure_dot` returns 0 in those two cases, so a non-zero result is a
        `required` failure or an unproven rollback in either mode. The
        ownership flag stays as computed, which is what lets the compensating
        rollback remove a drop-in the failed attempt left behind.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            dropin = Path(tmpdir) / "90-gowave-auto-nginx.conf"
            body = (
                'configure_dot() { return 1; }\n'
                f'if configure_worker_dot "{dropin}"; then echo "rc=0"; else echo "rc=$?"; fi\n'
                'echo "flag=${_DOT_CREATED_BY_US:-unset}"\n'
            )
            res = self._run_worker_dot(body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("rc=1", res.stdout)
            self.assertIn("flag=1", res.stdout)
            self.assertIn("stopping the Worker installation", res.stderr)

            res = self._run_worker_dot(body, env={**os.environ, "GOWAVE_DOT_POLICY": "required"})
            self.assertIn("rc=1", res.stdout)

    def test_worker_dot_without_the_helper_only_passes_when_it_is_not_required(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dropin = Path(tmpdir) / "90-gowave-auto-nginx.conf"
            body = (
                f'configure_worker_dot "{dropin}"\n'
                'echo "flag=${_DOT_CREATED_BY_US:-unset}"\n'
            )
            res = self._run_worker_dot(body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("remains unhardened", res.stderr)
            self.assertIn("flag=0", res.stdout)

            res = self._run_worker_dot(body, env={**os.environ, "GOWAVE_DOT_POLICY": "required"})
            self.assertEqual(res.returncode, 1)
            self.assertIn("Required DNS-over-TLS cannot even be attempted", res.stderr)

    def test_worker_dot_success_does_not_warn(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dropin = Path(tmpdir) / "90-gowave-auto-nginx.conf"
            res = self._run_worker_dot(
                'configure_dot() { return 0; }\n' f'configure_worker_dot "{dropin}"\n')
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn("remains unhardened", res.stderr)

    def test_worker_payload_ships_security_helper_for_dot(self):
        """The Worker never receives the project checkout, so managed.py must travel with the payload."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertIn("export SECURITY_HELPER_B64", worker_script)
        self.assertIn('$SCRIPT_DIR/assets/security/managed.py', worker_script)

        funcs_start = worker_script.index("cat <<'RUNNER_FUNCS'")
        payload = worker_script[funcs_start:worker_script.index("\nRUNNER_FUNCS\n", funcs_start)]
        self.assertIn("configure_dot() {", payload)
        self.assertIn("--prepare-dns", payload)

    def _payload_function(self, payload: str, function: str) -> str:
        start = payload.index(function + "() {")
        end = payload.index("\n}\n", start) + len("\n}\n")
        return payload[start:end]

    def _run_payload_function(self, function: str, body: str, exports: str = "",
                              env=None, stubs: str = "") -> subprocess.CompletedProcess:
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        funcs_start = script.index("cat <<'RUNNER_FUNCS'")
        payload = script[funcs_start:script.index("\nRUNNER_FUNCS\n", funcs_start)]
        target = self._payload_function(payload, function)
        # The payload defines both functions side by side, so a case that runs
        # one must carry the helper the other calls.
        needed = [function]
        if "materialize_security_helper" in target:
            needed.insert(0, "materialize_security_helper")
        prelude = (
            "set -euo pipefail\n"
            "log_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
            + exports
            + "".join(self._payload_function(payload, name) for name in needed)
            # Stubs come last: they replace the payload's own collaborators that
            # a slice cannot carry (the policy deriviver, the streamed helper).
            + stubs
            + "\n"
        )
        return subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True,
                              env=env)

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

    def test_worker_payload_dot_continues_after_a_verified_best_effort_rollback(self):
        helper = ("import json, sys\n"
                  "print(json.dumps({'status': 'failed_rolled_back', 'recovery': 'verified'}))\n"
                  "sys.exit(1)\n")
        exports = "export SECURITY_HELPER_B64=%s\n" % base64.b64encode(helper.encode()).decode()
        res = self._run_payload_function("configure_dot", "configure_dot\n", exports,
                                         env={**os.environ, "GOWAVE_DOT_POLICY": "best-effort"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("restored and verified", res.stderr)
        self.assertIn('"status": "failed_rolled_back"', res.stdout)

    def test_worker_payload_dot_stops_on_a_required_failure(self):
        helper = ("import json, sys\n"
                  "print(json.dumps({'status': 'failed_rolled_back', 'recovery': 'verified'}))\n"
                  "sys.exit(1)\n")
        exports = "export SECURITY_HELPER_B64=%s\n" % base64.b64encode(helper.encode()).decode()
        res = self._run_payload_function("configure_dot", "configure_dot\n", exports,
                                         env={**os.environ, "GOWAVE_DOT_POLICY": "required"})
        self.assertEqual(res.returncode, 1)
        self.assertIn("rollback was not verified", res.stderr)

    def test_worker_payload_dot_warns_when_helper_not_delivered(self):
        res = self._run_payload_function("configure_dot", "configure_dot\n")
        self.assertEqual(res.returncode, 1)
        self.assertIn("was not delivered", res.stderr)

    def test_kernel_has_ipv6_reads_the_address_table_rather_than_measuring_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            table = Path(tmpdir) / "if_inet6"
            body = (
                f'table="{table}"\n'
                'if kernel_has_ipv6 "$table"; then echo present; else echo absent; fi\n'
            )
            table.write_text("")
            res = self._run_payload_function("kernel_has_ipv6", body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("absent", res.stdout)

            table.write_text("   \n")
            res = self._run_payload_function("kernel_has_ipv6", body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("absent", res.stdout)

            table.write_text(
                "00000000000000000000000000000001 01 80 10 80       lo\n"
            )
            res = self._run_payload_function("kernel_has_ipv6", body)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("present", res.stdout)

    def test_the_worker_firewall_declares_the_same_ipv6_branch_it_renders(self):
        """The distro default must not outvote the host decision the listeners use."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        self.assertEqual(worker_script.count("kernel_has_ipv6() {"), 1,
                         "the host decision must be defined once")
        for function, next_function in (
            ('worker_firewall_policy_json', 'configure_firewall'),
            ('configure_firewall', 'unpack_cover_reality'),
        ):
            start = worker_script.index(f'{function}() {{')
            end = worker_script.index(f'\n{next_function}() {{', start)
            self.assertIn('kernel_has_ipv6', worker_script[start:end],
                          f'{function} must use the shared host decision')
        listen_at = worker_script.index('local listen_v6=""')
        listen = worker_script[listen_at:worker_script.index("\n    fi", listen_at)]
        self.assertIn("kernel_has_ipv6", listen)
        self.assertNotIn("/proc/net/if_inet6", listen)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            calls = root / "ufw.log"
            calls.write_text("")
            ufw = fake_bin / "ufw"
            ufw.write_text(
                "#!/usr/bin/env bash\n"
                f'printf \'%s\\n\' "$*" >> "{calls}"\n'
                'if [[ "$*" == "status" ]]; then echo "Status: active"; fi\n'
            )
            ufw.chmod(0o755)
            declaration = root / "ufw-default"
            helper = root / "helper.py"
            helper.write_text(
                'import json, sys\n'
                'sys.stdin.read()\n'
                'if sys.argv[1] == "--firewall-preflight":\n'
                '    print(json.dumps({"status": "success", "preserved_exceptions": []}))\n'
                'else:\n'
                '    print(json.dumps({"status": "success"}))\n',
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            def run(decision: int) -> str:
                declaration.write_text("# configured by the distribution\nIPV6=yes\n")
                exports = (
                    "kernel_has_ipv6() { return %d; }\n"
                    # The before-image is taken by a helper outside this slice; the
                    # subject here is the IPv6 branch the function renders.
                    "record_firewall_before_image() { return 0; }\n"
                    'export PANEL_IP="10.89.0.10"\nexport SSH_PORT=22\nexport NODE_PORT=3002\n'
                    % decision
                )
                policy_text = ('{"status": "ok", "policy": {"commands": '
                               '[["default", "deny", "incoming"], ["allow", "22/tcp"]]}}')
                stubs = (
                    "worker_firewall_policy_json() { printf '%s' '" + policy_text + "'; }\n"
                    # The function under test deletes the helper it materialized,
                    # exactly as it does on a host; a shared file would vanish
                    # between two runs of the same slice.
                    "materialize_security_helper() {\n"
                    "    local copy\n"
                    "    copy=$(mktemp /tmp/gowave-test-helper.XXXXXX) || return 1\n"
                    "    cp \"$STUB_HELPER\" \"$copy\" || return 1\n"
                    "    printf '%s\\n' \"$copy\"\n"
                    "}\n"
                )
                res = self._run_payload_function(
                    "configure_firewall", f'configure_firewall "{declaration}"\n', exports,
                    env={**environment, "STUB_HELPER": str(helper)}, stubs=stubs,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                return declaration.read_text()

            self.assertIn("IPV6=no", run(1))
            self.assertNotIn("IPV6=yes", run(1))
            self.assertIn("IPV6=yes", run(0))
            self.assertIn("--force enable", calls.read_text())

    def test_the_worker_claims_no_cover_apex(self):
        """A Worker owns no apex: its camouflage site is served under its own
        camouflage name, so the payload carries no apex decision, no apex route,
        no apex SAN and no `www` alias a shared zone could have lent the Master."""
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        payload = script[script.index("cat <<'RUNNER_FUNCS'"):]
        payload = payload[:payload.index("\nRUNNER_FUNCS\n")]

        for function in ("derive_cover_domain", "cover_domains_resolve_here",
                         "cover_domains_not_resolving", "cover_domain_for"):
            with self.subTest(function=function):
                self.assertNotIn(f"{function}() {{", script)

        start = payload.index("configure_edge_nginx() {")
        body = payload[start:payload.index("\ncore_version_matches() {", start)]

        stream_start = body.index("cat > /etc/nginx/stream-enabled/gowave-worker-stream.conf")
        stream = body[stream_start:body.index("\nEOF\n", stream_start)]
        self.assertNotIn("9443", stream)
        self.assertIn("$REALITY_DOMAIN 127.0.0.1:8443;", stream)

        decoy_start = body.index("cat > /etc/nginx/conf.d/gowave-worker-decoy.conf")
        decoy = body[decoy_start:body.index("\nEOF\n", decoy_start)]
        self.assertIn("server_name $REALITY_DOMAIN;", decoy)

        self.assertIn(
            r'''    run_certbot certonly --webroot -w /var/www/gowave-acme \
        -d "$REALITY_DOMAIN" --cert-name "$reality_lineage" \
''',
            body,
        )
        self.assertNotIn("--expand", body)
        self.assertIn('    render_cover_site "/var/www/gowave-auto-nginx/cover-reality" '
                      '"$REALITY_DOMAIN" || return 1', body)

    def test_worker_port_80_redirects_managed_names_and_refuses_other_hosts(self):
        """Port 80 is the renewal path: every name this Worker manages keeps an
        ordinary HTTPS visit, an unmanaged host is closed, and no cover name the
        Worker does not own is answered here."""
        script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        start = script.index("cat > /etc/nginx/conf.d/00-worker-acme-challenge.conf")
        vhost = script[start:script.index("\nEOF\n", start)]
        prefix = script[:start]

        self.assertIn(
            r'managed_http_regex="${WORKER_DOMAIN//./\\.}|${REALITY_DOMAIN//./\\.}"',
            prefix,
        )
        self.assertIn(r'managed_http_regex+="|${VISION_DOMAIN//./\\.}"', prefix)
        self.assertIn("server_name $WORKER_DOMAIN $REALITY_DOMAIN ${VISION_DOMAIN:-};", vhost)
        self.assertIn("root /var/www/gowave-acme;", vhost)
        self.assertIn(
            r"""        if (\$host ~* ^(${managed_http_regex})\$) {
            return 301 https://\$host\$request_uri;
        }
        return 444;
""",
            vhost,
        )

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
            auto_script.index("client.provision_config_profile(PROFILE_NAME", callback_at),
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

    def test_node_add_refuses_a_foreign_name_before_the_first_panel_write(self):
        """A name another server holds is refused before the journal, not adopted."""
        script = (REPO_ROOT / "gowave-auto.sh").read_text()
        guard_at = script.index("for held in client.list_nodes():")
        login_at = script.rindex("client.login(admin_user, admin_password)", 0, guard_at)
        journal_at = script.index('"state": "NODE_ADD_PREPARED"', guard_at)
        profile_at = script.index(
            'client.provision_config_profile(f"GoWave Worker {name} Profile"', journal_at
        )
        self.assertLess(login_at, guard_at)
        self.assertLess(guard_at, journal_at, "the inventory check must precede the journal")
        self.assertLess(journal_at, profile_at)
        guard = script[guard_at:journal_at]
        # The retry of this very node is not a collision; a different address is.
        self.assertIn('str(held.get("address") or "") == address', guard)
        self.assertIn("raise SystemExit(3)", guard)

    def test_a_refused_worker_name_returns_without_a_rollback(self):
        """Exit 3 means nothing was written, so no rollback may be attempted."""
        script = (REPO_ROOT / "gowave-auto.sh").read_text()
        branch_at = script.index("if (( register_rc == 3 )); then")
        returned_at = script.index("return 1", branch_at)
        rollback_at = script.index("rollback_provisioning(", returned_at)
        self.assertLess(returned_at, rollback_at, "a name refusal reached the rollback")
        self.assertIn("not changed", script[branch_at:returned_at])

    def test_node_add_pre_dispatch_failures_stay_inside_api_rollback_boundary(self):
        """Resolve local prerequisites early and persist VERIFYING inside the guarded API transaction."""
        worker_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        secret_index = worker_script.index('if ! secret_key=$(extract_secret_key "$GOWAVE_DIR")')
        api_index = worker_script.index(
            "# 2. Register the node using argv for data and FD 3 for the password.", secret_index
        )
        # The add branch's dispatch opens with the interactive-deployment flag so
        # the payload streams through the stage-heartbeat reader; the reapply
        # branch keeps the plain `if ! ACME_TX_ID=` form. Anchoring on the add
        # branch's own first line is what keeps the transaction window from
        # spilling into reapply and its later secret extraction.
        dispatch_index = worker_script.index(
            'GOWAVE_WORKER_INTERACTIVE_DEPLOYMENT="$interactive_deployment"', api_index
        )
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
        acme_end = rollback_script.index("# 4. Restore the UFW before-image", acme_start)
        acme_cleanup = rollback_script[acme_start:acme_end]
        # The snapshot names the lineage, not the requested name: an adopted
        # suffixed lineage (`cover2.example.net-0001`) has no manifest under the
        # plain name, and a rollback that asks for the plain name restores nothing
        # while reporting itself complete. The recovery script therefore restores
        # every snapshot directory the transaction wrote.
        self.assertIn('acme_snapshot_root="/var/lib/gowave-auto-nginx/recovery/$ACME_TX_ID/acme"',
                      acme_cleanup)
        self.assertIn('restore_acme_lineage "$ACME_TX_ID" "$(basename -- "$acme_snapshot")"',
                      acme_cleanup)
        self.assertIn('echo "[ROLLBACK] ERROR: transaction $ACME_TX_ID has no ACME snapshot to restore."',
                      acme_cleanup)
        self.assertIn("ACME_TX_ID missing; preserving unknown certificate lineage", acme_cleanup)
        self.assertNotIn("certbot delete", acme_cleanup)
        self.assertIn("rollback_failed=1", acme_cleanup)

    def test_worker_compensation_restarts_a_service_it_found_serving(self):
        """A failed re-apply must leave the Worker serving, not silent.

        The compensation is written for a first install: it stops and disables
        the unit whose paths it is about to remove. A re-apply over a Worker the
        Panel still lists is not that — if the run dies after the stop, the
        cluster keeps a registered member that answers nothing, which is exactly
        what an unreachable vendor repository produced. The unit is therefore
        disabled only when it was not serving before the run, and the restored
        unit is started again after the before-image is put back.
        """
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        start = worker_script.index("compensate_remote_worker() {")
        block = worker_script[start:worker_script.index('compensate_remote_worker "$exit_code"', start)]
        self.assertIsNotNone(
            re.search(r'if \[\[ "\$\{_NODE_SERVICE_WAS_ACTIVE:-0\}" -ne 1 \]\]; then\s*\n\s*'
                      r'systemctl disable "\$unit"', block),
            "the compensation disables the node unit unconditionally, so a failed re-apply "
            "takes a serving Worker offline")
        restart = re.search(r'if \[\[ "\$\{_NODE_SERVICE_WAS_ACTIVE:-0\}" -eq 1 \]\] && '
                            r'\[\[ "\$rollback_failed" -eq 0 \]\]; then', block)
        self.assertIsNotNone(restart, "nothing puts back the service the run found active")
        after_restart = block[restart.end():]
        self.assertIn('systemctl start gowave-node.service', after_restart)
        self.assertIn('systemctl is-active --quiet gowave-node.service', after_restart)
        # The answer is read before the first mutation, or it would describe the
        # host this run already changed.
        self.assertLess(worker_script.index("_NODE_SERVICE_WAS_ACTIVE=1"),
                        worker_script.index('record_worker_transaction_journal "$_ACME_TX_ID" || return 1'))

    def test_node_add_commit_record_failure_compensates_both_sides(self):
        """A failed durable commit after remote success must roll back Worker and Panel API state."""
        worker_script = (REPO_ROOT / "gowave-auto.sh").read_text()
        commit_start = worker_script.index("# 5. Commit transaction")
        commit_end = worker_script.index('echo "Worker \'$name\' successfully added and deployed."', commit_start)
        commit_block = worker_script[commit_start:commit_end]
        self.assertIn("if ! python3 -c", commit_block)
        self.assertIn('ACME_TX_ID="$acme_tx_id"', commit_block)
        # Both sides are compensated by the one finalizer the two failure paths
        # share, so the block names that call and the finalizer holds the two
        # compensations: a copy here would be a second place to forget a side.
        self.assertIn('finalize_failed_node_add "$name" "$ip" "$ssh_port"', commit_block)
        finalizer_start = worker_script.index("finalize_failed_node_add() {")
        finalizer = worker_script[finalizer_start:worker_script.index("\ncmd_node() {", finalizer_start)]
        self.assertIn('remote_rollback "$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"', finalizer)
        self.assertIn("rollback_provisioning('$JOURNAL_FILE', '$STATE_FILE', '$CREDENTIALS_FILE')", finalizer)
        self.assertIn("return 1", commit_block)

    def test_the_rendered_finalizer_accepts_the_lock_lease_of_the_run_that_owns_it(self):
        """The streamed finalize script honours the pair lock's lease.

        Measured on the live pair: `remote_finalize` took `flock` directly while the
        run that installed the Worker held that same lock through `RemotePairLock`,
        so the finalizer answered "Another process currently holds the mutation
        lock", the verified install kept its snapshot, and every later install on
        the Worker was refused as an unfinalized transaction.

        The script under test is the one the product renders (a mock `ssh` captures
        the stream) with only its recovery root rewritten into a temporary
        directory; the root guard, the lock paths and the lease check are what the
        Worker receives. The lock is taken by a real holder that publishes a real
        lease, so the validator's owner, liveness and descriptor checks all run
        against a live process, and the finalizer still fails its own `flock`.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            token = "lease-token-of-the-owning-run"
            transaction = root / "recovery" / "worker_install_test_1_1"
            transaction.mkdir(parents=True)
            result = run_rendered_finalizer(root, transaction, lease_token=token)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Worker ACME recovery snapshot finalized", result.stderr)
            self.assertFalse(transaction.exists())

    def test_the_rendered_finalizer_refuses_another_runs_lease(self):
        """A lease that names a different run buys the finalizer nothing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            transaction = root / "recovery" / "worker_install_test_1_1"
            transaction.mkdir(parents=True)
            result = run_rendered_finalizer(
                root, transaction,
                lease_token="a-borrowed-token",
                holder_token="the-owning-runs-token",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Another process currently holds the mutation lock", result.stderr)
            self.assertTrue(transaction.exists())

    def test_every_finalize_call_hands_over_the_runs_lease(self):
        """A finalize call that drops the token is refused by the lock it must honour.

        The Worker-side fix is only reachable if the controller passes the lease
        into `remote_finalize`; `node add` and `node reapply` each hold a session
        that already carries it, and an inherited environment is not a contract.
        """
        lines = (REPO_ROOT / "gowave-auto.sh").read_text().splitlines()
        call_sites = [
            index for index, line in enumerate(lines)
            if 'gowave-node-auto.sh" remote_finalize' in line
        ]
        self.assertEqual(len(call_sites), 2, call_sites)
        for index in call_sites:
            handed = "\n".join(lines[max(0, index - 3):index + 1])
            self.assertIn(
                'GOWAVE_WORKER_LEASE_TOKEN="${GOWAVE_WORKER_LEASE_TOKEN:-}"', handed,
                f"the finalize call at line {index + 1} does not pass the run's lease",
            )

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
        lock_at = worker_script.index("\nacquire_mutation_lock\n", function_start)
        function_end = worker_script.rindex("\n}", function_start, lock_at) + 2
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
        lock_at = worker_script.index("\nacquire_mutation_lock\n", function_start)
        function_end = worker_script.rindex("\n}", function_start, lock_at) + 2
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

    def test_standalone_acme_restore_removes_a_lineage_that_did_not_exist_before(self):
        """A snapshot of an absent lineage restores to "absent", not to a refused rollback."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        remote_start = worker_script.index("cat <<'ROLLBACK_REMOTE_SCRIPT'")
        function_start = worker_script.index("restore_acme_lineage() {", remote_start)
        lock_at = worker_script.index("\nacquire_mutation_lock\n", function_start)
        function_end = worker_script.rindex("\n}", function_start, lock_at) + 2
        restore_function = worker_script[function_start:function_end]

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            recovery = root / "recovery"
            letsencrypt = root / "letsencrypt"
            domain = "worker-two.example.com"
            snap_dir = recovery / "txn-1" / "acme" / domain
            snap_dir.mkdir(parents=True)
            # The snapshot writer records an absent lineage with an empty serial
            # and fingerprint, which is what the live rollback reads back.
            (snap_dir / "lineage-manifest.json").write_text(json.dumps({
                "domain": domain,
                "existed_before": False,
                "serial": "",
                "fingerprint": "",
            }))
            renewal_dir = letsencrypt / "renewal"
            live_dir = letsencrypt / "live" / domain
            archive_dir = letsencrypt / "archive" / domain
            renewal_dir.mkdir(parents=True)
            live_dir.mkdir(parents=True)
            archive_dir.mkdir(parents=True)
            renewal = renewal_dir / f"{domain}.conf"
            renewal.write_text("transaction-created renewal configuration")
            (live_dir / "fullchain.pem").write_text("transaction-created live certificate")
            (archive_dir / "cert1.pem").write_text("transaction-created archived certificate")

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
            self.assertNotIn("invalid field count", result.stderr)
            self.assertFalse(renewal.exists(), "the transaction's own renewal configuration survived")
            self.assertFalse(live_dir.exists(), "the transaction's own live directory survived")
            self.assertFalse(archive_dir.exists(), "the transaction's own archive survived")

    def test_worker_rollback_treats_an_absent_unit_as_clean_and_a_failed_stop_as_incomplete(self):
        """Xray is supervised by gowave-node, so a host without xray.service is clean."""
        worker_script = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        payload_start = worker_script.index("cat <<'RUNNER_FUNCS'")
        function_start = worker_script.index("compensate_remote_worker() {", payload_start)
        loop_start = worker_script.index("        for unit in gowave-node.service xray.service; do", function_start)
        loop_end = worker_script.index("\n        done\n", loop_start) + len("\n        done\n")
        loop = worker_script[loop_start:loop_end]

        def run_loop(stop_status):
            with tempfile.TemporaryDirectory() as tmpdir:
                bin_dir = Path(tmpdir) / "bin"
                bin_dir.mkdir()
                systemctl = bin_dir / "systemctl"
                # The stub owns the same unit table the host would: gowave-node is
                # installed, xray is not, and stopping a unit that is not installed
                # fails the way systemd fails it.
                systemctl.write_text(f"""#!/bin/sh
installed="gowave-node.service"
case "$1" in
    list-unit-files)
        for unit in $installed; do
            [ "$unit" = "$2" ] && echo "$2"
        done
        exit 0
        ;;
    is-active)
        exit 3
        ;;
    stop|disable)
        for unit in $installed; do
            [ "$unit" = "$2" ] && exit {stop_status}
        done
        echo "Unit $2 not loaded." >&2
        exit 5
        ;;
esac
exit 0
""")
                systemctl.chmod(0o755)
                script = "set -Eeuo pipefail\nrollback_failed=0\n" + loop + '\necho "rollback_failed=$rollback_failed"\n'
                env = os.environ.copy()
                env["PATH"] = f"{bin_dir}:{env['PATH']}"
                return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

        clean = run_loop(0)
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertIn("rollback_failed=0", clean.stdout,
                      "an absent xray.service was counted as a failed cleanup")

        failed = run_loop(1)
        self.assertIn("rollback_failed=1", failed.stdout,
                      "a unit that exists and cannot be stopped was not reported")

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

            mock_timeout = bin_dir / "timeout"
            mock_timeout.write_text('#!/bin/sh\n[ "$1 $2 $3" = "--kill-after=10s 60m ssh" ] || exit 9\nexit 124\n')
            mock_timeout.chmod(0o755)
            env["GOWAVE_WORKER_INTERACTIVE_DEPLOYMENT"] = "1"
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertNotIn(env["SECRET_KEY"], result.stdout + result.stderr)

    def test_the_node_installer_gate_requires_a_pinned_verified_installer(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_installer = tmp / "install.sh"
            fake_installer.write_text("#!/bin/sh\nexit 0\n")
            fake_installer.chmod(0o755)
            real_sha = hashlib.sha256(fake_installer.read_bytes()).hexdigest()

            # Case 1: an explicitly supplied installer that does not exist is never
            # silently replaced by a download.
            cmd_missing = f'source "{NODE_SH}" && GOWAVE_NODE_REQUIRE_PINNED_INSTALLER=1 GOWAVE_NODE_INSTALLER_SHA256="{real_sha}" install_local_node "secret" 3002 "{tmp}/nonexistent.sh"'
            res_missing = subprocess.run(["bash", "-c", cmd_missing], capture_output=True, text=True)
            self.assertNotEqual(res_missing.returncode, 0)
            self.assertIn("GoWave Node installer not found", res_missing.stderr)

            # Case 2: the gate without a pinned commit fails closed before any
            # execution; the legacy flag name keeps the same guarantee.
            isolated = node_sh_without_bundle(tmp)
            for flag in ("GOWAVE_NODE_REQUIRE_PINNED_INSTALLER", "GOWAVE_NODE_REQUIRE_BUNDLED_INSTALLER"):
                with self.subTest(flag=flag):
                    cmd_unpinned = f'source "{isolated}" && {flag}=1 install_local_node "secret" 3002'
                    res_unpinned = subprocess.run(["bash", "-c", cmd_unpinned], capture_output=True, text=True)
                    self.assertNotEqual(res_unpinned.returncode, 0)
                    self.assertIn(
                        "GOWAVE_NODE_INSTALLER_COMMIT must be a 40-character hex commit SHA",
                        res_unpinned.stderr,
                    )

            # Case 3: bytes that do not match the pinned digest are rejected before
            # the installer is executed.
            cmd_badsha = f'source "{NODE_SH}" && GOWAVE_NODE_REQUIRE_PINNED_INSTALLER=1 GOWAVE_NODE_INSTALLER_SHA256="{"0" * 64}" install_local_node "secret" 3002 "{fake_installer}"'
            res_badsha = subprocess.run(["bash", "-c", cmd_badsha], capture_output=True, text=True)
            self.assertNotEqual(res_badsha.returncode, 0)
            self.assertIn("Node installer SHA256 mismatch", res_badsha.stderr)

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
        version_file.write_text("1.2.2\n", encoding="utf-8")
        install_log = tmp / "install-calls.txt"
        node_bin = tmp / "gowave-node"
        node_bin.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >> "{install_log}"\n'
            # /bin/sh is dash on Debian and Ubuntu, so the stub uses the POSIX test
            # builtin: an unhandled [[ ... ]] there fails the command, `|| exit 0`
            # fires and the rewritten version is never written.
            f"[ {install_rc} -eq 0 ] || exit {install_rc}\n"
            + (f'printf "1.2.3\\n" > "{version_file}"\n' if rewrite_version else "")
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

    def _run_pinned_core(self, tmp: Path, node_bin: Path, core_bin: Path, version: str = "1.2.3"):
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
            self.assertIn("Failed to install requested Xray server version 1.2.3", res.stderr)
            calls = install_log.read_text(encoding="utf-8")
            # Both version spellings are attempted before failing closed.
            self.assertIn("--version v1.2.3", calls)
            self.assertIn("--version 1.2.3", calls)

    def test_pinned_core_silent_noop_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, _ = self._fake_core_tools(tmp, install_rc=0, rewrite_version=False)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("version mismatch after installation", res.stderr)
            self.assertIn("expected 1.2.3, got Xray 1.2.2", res.stderr)

    def test_pinned_core_version_token_must_match_exactly(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=0, rewrite_version=False)
            core_bin.write_text(
                '#!/bin/sh\nprintf "Xray 1.2.30 (Xray, Penetrates Everything.) test-build\\n"\n',
                encoding="utf-8",
            )
            core_bin.chmod(0o755)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("version mismatch after installation", res.stderr)
            self.assertTrue(install_log.exists(), "1.2.30 must not satisfy a 1.2.3 pin")

    def test_pinned_core_already_matching_skips_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            (tmp / "core-version.txt").write_text("1.2.3\n", encoding="utf-8")
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(install_log.exists())

    def test_pinned_core_install_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=0, rewrite_version=True)
            res = self._run_pinned_core(tmp, node_bin, core_bin)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Installing explicit Xray server version 1.2.3", res.stdout)
            self.assertIn("--version v1.2.3", install_log.read_text(encoding="utf-8"))

    def test_pinned_core_disabled_without_pin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            res = self._run_pinned_core(tmp, node_bin, core_bin, version="")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(install_log.exists())

    def test_pinned_core_disabled_for_the_latest_channel(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            for channel in ("latest", "LATEST", "vlatest"):
                with self.subTest(channel=channel):
                    res = self._run_pinned_core(tmp, node_bin, core_bin, version=channel)
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertFalse(install_log.exists(), channel)

    def _run_node_sh_pinned_core(self, node_bin: Path, core_bin: Path, version: str = "1.2.3"):
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
            self.assertIn("Failed to install requested Xray server version 1.2.3", res.stderr)
            self.assertIn("--version v1.2.3", install_log.read_text(encoding="utf-8"))

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
                '#!/bin/sh\nprintf "Xray 1.2.30 (Xray, Penetrates Everything.) test-build\\n"\n',
                encoding="utf-8",
            )
            core_bin.chmod(0o755)
            res = self._run_node_sh_pinned_core(node_bin, core_bin)
            self.assertNotEqual(res.returncode, 0)
            self.assertTrue(install_log.exists(), "1.2.30 must not satisfy a 1.2.3 pin")

    def test_node_sh_pinned_core_install_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, _ = self._fake_core_tools(tmp, install_rc=0, rewrite_version=True)
            res = self._run_node_sh_pinned_core(node_bin, core_bin)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Installing explicit Xray server version 1.2.3", res.stdout)

    def test_node_sh_pinned_core_disabled_for_the_latest_channel(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            node_bin, core_bin, install_log = self._fake_core_tools(tmp, install_rc=1, rewrite_version=False)
            res = self._run_node_sh_pinned_core(node_bin, core_bin, version="latest")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse(install_log.exists())


class TestPinnedNodeInstaller(unittest.TestCase):
    """The pinned commit and digest are the installer contract, not a vendored file."""

    COMMIT = "7b3514d1ab8c674050597820d52d55525d4bece7"

    def _stub_curl(self, directory: Path, body: bytes):
        bin_dir = directory / "bin"
        bin_dir.mkdir()
        payload = directory / "upstream.sh"
        payload.write_bytes(body)
        args_log = directory / "curl-args.txt"
        curl = bin_dir / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            f'printf \'%s\\n\' "$@" >> "{args_log}"\n'
            f'while [ "$#" -gt 0 ]; do if [ "$1" = "-o" ]; then cp "{payload}" "$2"; fi; shift; done\n'
        )
        curl.chmod(0o755)
        return bin_dir, args_log

    def _fetch(self, script: Path, dest: Path, extra):
        env = os.environ.copy()
        for key in ("GOWAVE_NODE_INSTALLER_COMMIT", "GOWAVE_NODE_INSTALLER_SHA256"):
            env.pop(key, None)
        env.update(extra)
        return subprocess.run(
            ["bash", "-c", f'source "{script}" && fetch_pinned_node_installer "{dest}"'],
            env=env, capture_output=True, text=True,
        )

    def test_the_pinned_installer_is_fetched_from_the_commit_and_verified(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            body = b"#!/bin/sh\nexit 0\n"
            bin_dir, args_log = self._stub_curl(tmp, body)
            dest = tmp / "installer.sh"
            result = self._fetch(NODE_SH, dest, {
                "GOWAVE_NODE_INSTALLER_COMMIT": self.COMMIT,
                "GOWAVE_NODE_INSTALLER_SHA256": hashlib.sha256(body).hexdigest(),
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
            })
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(dest.read_bytes(), body)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o700)
            self.assertIn(
                f"https://raw.githubusercontent.com/aaaSaZaN/gowave-node/{self.COMMIT}/install.sh",
                args_log.read_text().splitlines(),
            )

    def test_the_fetched_installer_must_match_the_pinned_digest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bin_dir, _ = self._stub_curl(tmp, b"#!/bin/sh\nexit 0\n")
            dest = tmp / "installer.sh"
            result = self._fetch(NODE_SH, dest, {
                "GOWAVE_NODE_INSTALLER_COMMIT": self.COMMIT,
                "GOWAVE_NODE_INSTALLER_SHA256": "0" * 64,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
            })
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Node installer SHA256 mismatch", result.stderr)
            self.assertFalse(dest.exists(), "a mismatched download must not be left behind")

    def test_the_pin_is_validated_before_any_download(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bin_dir, args_log = self._stub_curl(tmp, b"#!/bin/sh\nexit 0\n")
            dest = tmp / "installer.sh"
            cases = (
                (
                    {"GOWAVE_NODE_INSTALLER_COMMIT": "main", "GOWAVE_NODE_INSTALLER_SHA256": "0" * 64},
                    "GOWAVE_NODE_INSTALLER_COMMIT must be a 40-character hex commit SHA",
                ),
                (
                    {"GOWAVE_NODE_INSTALLER_COMMIT": self.COMMIT, "GOWAVE_NODE_INSTALLER_SHA256": ""},
                    "GOWAVE_NODE_INSTALLER_SHA256 must be a 64-character hex SHA-256 digest",
                ),
            )
            for extra, message in cases:
                with self.subTest(message=message):
                    result = self._fetch(NODE_SH, dest, dict(extra, PATH=f"{bin_dir}:{os.environ['PATH']}"))
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
            self.assertFalse(args_log.exists(), "no download may start before the pin is validated")
            self.assertFalse(dest.exists())


class TestPinnedXrayCore(unittest.TestCase):
    """The pinned core is the bytes the harness, the product and the payload name.

    The pin names the release archive; the installed rw-core is the member
    extracted from it and has no digest of its own. The arm64 digest is confirmed
    against the release's published .dgst and has no second in-tree witness, so
    the guard checks its shape there and does not pretend to compare it to one.
    """

    VERSION = "26.11.9"
    MEMBER = "#!/bin/sh\nprintf 'Xray 26.11.9 (Xray, Penetration)\\n'\n"
    OTHER_MEMBER = "#!/bin/sh\nprintf 'Xray 1.2.3 (Xray, Penetration)\\n'\n"

    # -- fixtures ---------------------------------------------------------

    def _archive(self, directory: Path, member: str = MEMBER) -> tuple[Path, str]:
        archive = directory / "Xray.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            info = zipfile.ZipInfo("xray")
            info.external_attr = 0o755 << 16
            bundle.writestr(info, member)
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def _stub_curl(self, directory: Path, archive: Path | None, exit_code: int = 0):
        bin_dir = directory / "bin"
        bin_dir.mkdir(exist_ok=True)
        args_log = directory / "curl-args.txt"
        lines = ["#!/bin/sh", f'printf \'%s\\n\' "$@" >> "{args_log}"']
        if exit_code != 0:
            lines.append(f"exit {exit_code}")
        else:
            lines += [
                'while [ "$#" -gt 0 ]; do',
                '  if [ "$1" = "-o" ]; then',
                f'    cp "{archive}" "$2"',
                "  fi",
                "  shift",
                "done",
            ]
        curl = bin_dir / "curl"
        curl.write_text("\n".join(lines) + "\n", encoding="utf-8")
        curl.chmod(0o755)
        return bin_dir, args_log

    def _install(self, directory: Path, bin_dir: Path, digest: str, *,
                 version: str | None = None, install_dir: Path | None = None):
        env = os.environ.copy()
        env.pop("XRAY_SERVER_VERSION", None)
        if version is not None:
            env["XRAY_SERVER_VERSION"] = version
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["FIXTURE_URL"] = "https://fixture.invalid/Xray-linux-64.zip"
        env["FIXTURE_SHA"] = digest
        env["FIXTURE_DIR"] = str(install_dir or (directory / "install"))
        script = (
            f'source "{XRAY_CORE_SH}" && '
            'GOWAVE_PINNED_XRAY_AMD64_URL="$FIXTURE_URL" '
            'GOWAVE_PINNED_XRAY_AMD64_SHA256="$FIXTURE_SHA" '
            'install_pinned_xray_core "$FIXTURE_DIR"'
        )
        return subprocess.run(["bash", "-c", script], env=env,
                              capture_output=True, text=True, timeout=120)

    @staticmethod
    def _urls(args_log: Path) -> list[str]:
        if not args_log.exists():
            return []
        return [line for line in args_log.read_text(encoding="utf-8").splitlines()
                if line.startswith("https://")]

    def _installed_core(self, directory: Path) -> Path:
        return directory / "install" / "rw-core"

    # -- delivery --------------------------------------------------------

    def test_a_matching_core_is_not_downloaded_again(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive, digest = self._archive(tmp)
            bin_dir, args_log = self._stub_curl(tmp, archive)
            install = tmp / "install"
            install.mkdir()
            core = install / "rw-core"
            core.write_text(self.MEMBER, encoding="utf-8")
            core.chmod(0o755)

            result = self._install(tmp, bin_dir, digest)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self._urls(args_log), [], "a satisfied pin must not download")
            self.assertEqual(core.read_text(encoding="utf-8"), self.MEMBER)

    def test_a_foreign_core_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive, digest = self._archive(tmp)
            bin_dir, args_log = self._stub_curl(tmp, archive)
            install = tmp / "install"
            install.mkdir()
            core = install / "rw-core"
            core.write_text(self.OTHER_MEMBER, encoding="utf-8")
            core.chmod(0o755)

            result = self._install(tmp, bin_dir, digest)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(core.read_text(encoding="utf-8"), self.MEMBER)
            self.assertEqual(len(self._urls(args_log)), 1)
            self.assertEqual(core.stat().st_mode & 0o777, 0o755)

    def test_a_digest_mismatch_is_terminal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive, _ = self._archive(tmp)
            bin_dir, args_log = self._stub_curl(tmp, archive)

            result = self._install(tmp, bin_dir, "0" * 64)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("did not match the pinned SHA-256", result.stderr)
            self.assertFalse(self._installed_core(tmp).exists())
            self.assertEqual(len(self._urls(args_log)), 1,
                             "a mismatch is terminal, so only one host may be tried")

    def test_no_host_delivers_the_archive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive, digest = self._archive(tmp)
            bin_dir, _ = self._stub_curl(tmp, archive, exit_code=1)

            result = self._install(tmp, bin_dir, digest)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no artifact host delivered the archive", result.stderr)
            self.assertFalse(self._installed_core(tmp).exists())

    def test_a_member_reporting_another_version_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive, digest = self._archive(tmp, member=self.OTHER_MEMBER)
            bin_dir, _ = self._stub_curl(tmp, archive)

            result = self._install(tmp, bin_dir, digest)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("the extracted core reports", result.stderr)
            self.assertIn("Xray 1.2.3", result.stderr)
            self.assertFalse(self._installed_core(tmp).exists())

    def test_the_pin_and_its_aliases_are_delivered_once(self):
        for version in (None, "26.11.9", "v26.11.9"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                archive, digest = self._archive(tmp)
                bin_dir, args_log = self._stub_curl(tmp, archive)

                result = self._install(tmp, bin_dir, digest, version=version)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self._installed_core(tmp).read_text(encoding="utf-8"),
                                 self.MEMBER)
                self.assertEqual(len(self._urls(args_log)), 1)
                self.assertIn(f"Installed pinned Xray core {self.VERSION}", result.stdout)
                self.assertIn(digest, result.stdout)

    def test_latest_and_foreign_versions_download_nothing(self):
        for version in ("latest", "vlatest", "1.2.3", "v1.2.3"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                archive, digest = self._archive(tmp)
                bin_dir, args_log = self._stub_curl(tmp, archive)

                result = self._install(tmp, bin_dir, digest, version=version)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self._urls(args_log), [])
                self.assertFalse(self._installed_core(tmp).exists())

    def test_an_unsupported_architecture_abstains_and_names_the_opt_out(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            archive, digest = self._archive(tmp)
            bin_dir, args_log = self._stub_curl(tmp, archive)
            uname = bin_dir / "uname"
            uname.write_text("#!/bin/sh\necho riscv64\n", encoding="utf-8")
            uname.chmod(0o755)

            result = self._install(tmp, bin_dir, digest)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("riscv64", result.stderr)
            self.assertIn("XRAY_SERVER_VERSION=latest", result.stderr)
            self.assertNotIn("https://", result.stderr,
                             "no artifact exists for this architecture, so none is named")
            self.assertFalse(self._installed_core(tmp).exists())
            self.assertEqual(self._urls(args_log), [])

    # -- parity with the payload and the acceptance matrix ----------------

    @staticmethod
    def _assignments(text: str) -> dict[str, str]:
        return dict(re.findall(r'^(GOWAVE_PINNED_XRAY_[A-Z0-9_]+)="([^"]*)"$', text, re.M))

    @staticmethod
    def _matrix_artifact(text: str) -> dict[str, str]:
        start = text.index("- id: xray")
        end = text.find("\n  - id:", start)
        block = text[start:end if end != -1 else len(text)]
        url = re.search(r"^\s+url: (\S+)$", block, re.M)
        sha = re.search(r'^\s+sha256: "?([0-9a-f]{64})"?$', block, re.M)
        if url is None or sha is None:
            raise AssertionError("the matrix has no xray artifact url/sha256")
        return {"url": url.group(1), "sha256": sha.group(1)}

    def _parity_problems(self, module_text: str, payload_text: str,
                         matrix_text: str) -> list[str]:
        module = self._assignments(module_text)
        payload = self._assignments(payload_text)
        matrix = self._matrix_artifact(matrix_text)
        problems = []

        for arch in ("AMD64", "ARM64"):
            for field in ("URL", "SHA256"):
                key = f"GOWAVE_PINNED_XRAY_{arch}_{field}"
                if module.get(key) != payload.get(key):
                    problems.append(
                        f"{key}: module={module.get(key)!r} payload={payload.get(key)!r}")
        version = module.get("GOWAVE_PINNED_XRAY_VERSION")
        if payload.get("GOWAVE_PINNED_XRAY_VERSION") != version:
            problems.append("the pinned version differs between the product copies")
        if not version or f"/v{version}/" not in matrix["url"]:
            problems.append("the matrix url does not name the pinned version")
        if matrix["url"] != module.get("GOWAVE_PINNED_XRAY_AMD64_URL"):
            problems.append("the matrix url differs from the amd64 row")
        if matrix["sha256"] != module.get("GOWAVE_PINNED_XRAY_AMD64_SHA256"):
            problems.append("the matrix digest differs from the amd64 row")
        if "arm64" not in module.get("GOWAVE_PINNED_XRAY_ARM64_URL", ""):
            problems.append("the arm64 row does not name arm64")
        if not re.fullmatch(r"[0-9a-f]{64}",
                            module.get("GOWAVE_PINNED_XRAY_ARM64_SHA256", "")):
            problems.append("the arm64 row has no 64-hex digest")
        return problems

    def test_the_product_and_the_matrix_name_the_same_amd64_bytes(self):
        problems = self._parity_problems(
            XRAY_CORE_SH.read_text(encoding="utf-8"),
            NODE_AUTO_SH.read_text(encoding="utf-8"),
            MATRIX_YAML.read_text(encoding="utf-8"),
        )
        self.assertEqual(problems, [])

    def test_the_parity_guard_fails_on_its_own_damage(self):
        module_text = XRAY_CORE_SH.read_text(encoding="utf-8")
        payload_text = NODE_AUTO_SH.read_text(encoding="utf-8")
        matrix_text = MATRIX_YAML.read_text(encoding="utf-8")
        digest = self._assignments(module_text)["GOWAVE_PINNED_XRAY_AMD64_SHA256"]
        matrix_sha = self._matrix_artifact(matrix_text)["sha256"]
        flipped = ("0" if digest[0] != "0" else "1") + digest[1:]
        matrix_flipped = ("0" if matrix_sha[0] != "0" else "1") + matrix_sha[1:]

        damaged = {
            "module": (module_text.replace(digest, flipped, 1), payload_text, matrix_text),
            "payload": (module_text, payload_text.replace(digest, flipped, 1), matrix_text),
            "matrix": (module_text, payload_text,
                       matrix_text.replace(matrix_sha, matrix_flipped, 1)),
        }
        for name, texts in damaged.items():
            with self.subTest(damaged=name):
                self.assertNotEqual(self._parity_problems(*texts), [],
                                    f"a one-character change in the {name} must be caught")

    def test_detect_arch_lives_in_os_and_keeps_reaching_panel_callers(self):
        os_text = OS_SH.read_text(encoding="utf-8")
        panel_text = PANEL_SH.read_text(encoding="utf-8")
        self.assertEqual(os_text.count("detect_arch() {"), 1)
        self.assertIn("/os.sh", panel_text)
        self.assertNotIn("detect_arch() {", panel_text)

        for machine, expected in (("x86_64", "amd64"), ("aarch64", "arm64"),
                                  ("arm64", "arm64")):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                bin_dir = tmp / "bin"
                bin_dir.mkdir()
                uname = bin_dir / "uname"
                uname.write_text(f"#!/bin/sh\necho {machine}\n", encoding="utf-8")
                uname.chmod(0o755)
                env = os.environ.copy()
                env["PATH"] = f"{bin_dir}:{env['PATH']}"
                result = subprocess.run(
                    ["bash", "-c", f'source "{PANEL_SH}" && detect_arch'],
                    env=env, capture_output=True, text=True, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            uname = bin_dir / "uname"
            uname.write_text("#!/bin/sh\necho riscv64\n", encoding="utf-8")
            uname.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", f'source "{PANEL_SH}" && detect_arch'],
                env=env, capture_output=True, text=True, timeout=60,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("riscv64", result.stderr)

    # -- source order ----------------------------------------------------

    @staticmethod
    def _function_slice(text: str, header: str) -> str:
        start = text.index(header)
        end = text.index("\n}\n", start) + len("\n}\n")
        return text[start:end]

    @staticmethod
    def _order_problems(body: str, anchors: tuple[str, ...]) -> list[str]:
        call = body.find("install_pinned_xray_core")
        if call < 0:
            return ["the pinned-core call is missing"]
        problems = []
        for anchor in anchors:
            position = body.find(anchor)
            if position < 0:
                problems.append(f"anchor missing: {anchor}")
            elif position < call:
                problems.append(f"the pinned-core call follows {anchor}")
        return problems

    MODULE_ANCHORS = ("run_node_installer_with_retry",
                      "raw.githubusercontent.com/aaaSaZaN/gowave-node/main/install.sh")
    PAYLOAD_ANCHORS = ("run_node_installer_with_retry", "tmp_inst=$(mktemp")

    def test_the_module_call_precedes_both_installers_inside_the_restart_branch(self):
        body = self._function_slice(NODE_SH.read_text(encoding="utf-8"),
                                    "install_local_node() {")
        branch = body.index("if (( node_restart_required == 1 )); then")
        call = body.index("install_pinned_xray_core")
        self.assertLess(branch, call, "the call must sit inside the restart branch")
        self.assertEqual(self._order_problems(body, self.MODULE_ANCHORS), [])
        self.assertEqual(body.count("install_pinned_xray_core"), 1)

    def test_the_payload_installs_python_before_the_step_can_run(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        self.assertLess(text.index("setup_system_prereqs </dev/null"),
                        text.index("run_upstream_node_installer </dev/null"),
                        "python3 must be installed before the pinned step unpacks the archive")

    def test_the_payload_call_precedes_the_installer_and_appears_once(self):
        body = self._function_slice(NODE_AUTO_SH.read_text(encoding="utf-8"),
                                    "run_upstream_node_installer() {")
        self.assertEqual(self._order_problems(body, self.PAYLOAD_ANCHORS), [])
        self.assertEqual(body.count("install_pinned_xray_core"), 1)

    def test_the_order_guard_fails_when_the_call_moves_after_its_anchor(self):
        body = self._function_slice(NODE_SH.read_text(encoding="utf-8"),
                                    "install_local_node() {")
        moved = body.replace("install_pinned_xray_core", "# placeholder", 1)
        moved += "\ninstall_pinned_xray_core \"$GOWAVE_NODE_INSTALL_DIR\"\n"
        self.assertNotEqual(self._order_problems(moved, self.MODULE_ANCHORS), [])

    # -- the helper the payload's pinned step calls ----------------------

    @staticmethod
    def _heredoc(text: str, marker: str) -> str:
        start = text.index(f"cat <<'{marker}'\n") + len(f"cat <<'{marker}'\n")
        return text[start:text.index(f"\n{marker}\n", start)]

    def _composed_payload(self, with_artifact: bool = True) -> str:
        """The streamed Worker payload, assembled the way ``remote_payload`` does.

        The two modules travel as their own text and the runner functions and
        the entrypoint travel as heredocs, so a function the pinned step calls
        resolves only when every part of the composition is present.
        """
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        parts = [PREFLIGHT_SH.read_text(encoding="utf-8")]
        if with_artifact:
            parts.append(ARTIFACT_SH.read_text(encoding="utf-8"))
            parts.append(NGINX_PACKAGE_SH.read_text(encoding="utf-8"))
        parts += [self._heredoc(text, "RUNNER_FUNCS"), self._heredoc(text, "REMOTE_EOF")]
        return "\n".join(parts).replace(
            'main "$@" </dev/null',
            "declare -F fetch_verified_artifact install_pinned_xray_core pinned_xray_deliver",
        )

    def test_the_payload_carries_the_artifact_helper_as_its_module(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        self.assertEqual(text.count("fetch_verified_artifact() {"), 0,
                         "the payload must not carry its own copy of the helper")
        self.assertIn('artifact_module="$SCRIPT_DIR/modules/artifact.sh"', text)
        self.assertEqual(text.count('cat "$artifact_module"'), 1)

    def test_the_artifact_helper_is_defined_before_the_functions_that_call_it(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        self.assertLess(text.index('cat "$artifact_module"'),
                        text.index("cat <<'RUNNER_FUNCS'"))

    def test_the_payload_carries_the_nginx_package_module_as_its_module(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        self.assertIn('nginx_package_module="$SCRIPT_DIR/modules/nginx_package.sh"', text)
        self.assertEqual(text.count('cat "$nginx_package_module"'), 1)
        self.assertLess(text.index('cat "$nginx_package_module"'),
                        text.index("setup_system_prereqs() {"))

    def test_the_worker_prerequisite_step_installs_the_pinned_nginx(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        prereqs = text[text.index("setup_system_prereqs() {"):]
        prereqs = prereqs[:prereqs.index("\n}")]
        self.assertIn('install_pinned_nginx "$os_id" "$codename"', prereqs)
        self.assertNotIn("nginx-full libnginx-mod-stream", prereqs,
                         "the distribution nginx-full conflicts with the pinned official package")

    def test_the_composed_payload_resolves_every_function_its_pinned_step_calls(self):
        result = subprocess.run(["bash", "-s"], input=self._composed_payload(),
                                capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("fetch_verified_artifact", "install_pinned_xray_core",
                     "pinned_xray_deliver"):
            self.assertIn(name, result.stdout.split())

    def test_the_composition_guard_fails_without_the_helper(self):
        result = subprocess.run(["bash", "-s"],
                                input=self._composed_payload(with_artifact=False),
                                capture_output=True, text=True, timeout=180)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("fetch_verified_artifact", result.stdout.split())


class TestLocalNodeIdempotency(unittest.TestCase):
    """A repeated install must not restart a node that is already serving.

    The Panel pushes the Xray configuration to a node and never re-reads it: a
    restarted node reports itself alive while its core waits for a push the Panel
    only sends to a node it sees go offline. The install therefore has to leave a
    serving node alone instead of replaying the upstream installer's restart.
    """

    def _fake_tools(self, tmp: Path, status_rc: int = 0) -> Path:
        install_dir = tmp / "opt_gowave_node"
        install_dir.mkdir()
        node_bin = install_dir / "gowave-node"
        node_bin.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  version) echo "gowave-node v1.0.5" ;;\n'
            f'  status) exit {status_rc} ;;\n'
            "esac\n",
            encoding="utf-8",
        )
        node_bin.chmod(0o755)
        (install_dir / ".env").write_text("SECRET_KEY=secret\nNODE_PORT=3002\n", encoding="utf-8")

        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        systemctl = bin_dir / "systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            '[ "$1" = "is-active" ] || exit 0\n'
            '[ "${FAKE_SERVICE_ACTIVE:-1}" = "1" ]\n',
            encoding="utf-8",
        )
        systemctl.chmod(0o755)
        timeout = bin_dir / "timeout"
        timeout.write_text('#!/bin/sh\nshift\nexec "$@"\n', encoding="utf-8")
        timeout.chmod(0o755)
        # The install runs as root; the guard checks for it before claiming a node
        # is already serving, so the fixture reports a privileged caller.
        id_bin = bin_dir / "id"
        id_bin.write_text('#!/bin/sh\n[ "$1" = "-u" ] && { echo 0; exit 0; }\nexec /usr/bin/id "$@"\n', encoding="utf-8")
        id_bin.chmod(0o755)
        return install_dir

    def _run(self, tmp: Path, install_dir: Path, expected: str = "latest", active: str = "1"):
        env = os.environ.copy()
        env["PATH"] = f"{tmp / 'bin'}:{env['PATH']}"
        env["FAKE_SERVICE_ACTIVE"] = active
        cmd = (
            f'source "{NODE_SH}" && GOWAVE_NODE_INSTALL_DIR="{install_dir}" '
            f'local_node_is_serving 3002 "{expected}"'
        )
        return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env)

    def test_serving_node_is_reused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            res = self._run(tmp, self._fake_tools(tmp))
            self.assertEqual(res.returncode, 0, res.stderr)

    def test_inactive_service_is_reinstalled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            res = self._run(tmp, self._fake_tools(tmp), active="0")
            self.assertNotEqual(res.returncode, 0)

    def test_explicit_pin_must_match_the_installed_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            install_dir = self._fake_tools(tmp)
            self.assertNotEqual(self._run(tmp, install_dir, expected="v9.9.9").returncode, 0)
            self.assertEqual(self._run(tmp, install_dir, expected="v1.0.5").returncode, 0)
            self.assertEqual(self._run(tmp, install_dir, expected="1.0.5").returncode, 0)

    def test_node_without_a_serving_core_is_reinstalled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            res = self._run(tmp, self._fake_tools(tmp, status_rc=1))
            self.assertNotEqual(res.returncode, 0)

    def test_node_bound_to_another_port_is_reinstalled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            install_dir = self._fake_tools(tmp)
            (install_dir / ".env").write_text("SECRET_KEY=secret\nNODE_PORT=3099\n", encoding="utf-8")
            self.assertNotEqual(self._run(tmp, install_dir).returncode, 0)

    def test_install_local_node_guards_the_installer_and_the_restart(self):
        text = NODE_SH.read_text(encoding="utf-8")
        install = text.split("install_local_node() {", 1)[1]
        self.assertIn('if local_node_is_serving "$node_port" "$normalized_node_ver"; then', install)
        self.assertIn("node_restart_required=0", install)
        self.assertLess(install.index("if (( node_restart_required == 1 )); then"),
                        install.index('run_node_installer_with_retry "$upstream_installer"'))
        self.assertIn("if (( node_restart_required == 1 )) && "
                      '[[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then', install)


class TestNodeInstallerRetry(unittest.TestCase):
    """One slow answer from api.github.com must not end a whole deployment.

    gowave-node lists the Xray releases with a 10-second deadline and no retry of
    its own, so the installer it runs behind is the only place a transient network
    fault can be absorbed. The retry is bounded and applies to nothing else:
    repeating a configuration error would only print it twice.
    """

    def write_installer(self, tmp: Path, name: str, body: str) -> Path:
        path = tmp / f"{name}.sh"
        path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
        path.chmod(0o700)
        return path

    def run_helper(self, tmp: Path, installer: Path):
        # The delays are a module default, so the test shortens them by assignment
        # rather than through a prefix, which bash would treat as a string value.
        command = (
            f'source "{NODE_SH}" && '
            "NODE_INSTALLER_RETRY_DELAYS=(0 0)\n"
            f'run_node_installer_with_retry "{installer}" hidden-secret 3002 latest'
        )
        return subprocess.run(["bash", "-c", command], capture_output=True, text=True, cwd=tmp)

    def counting_installer(self, tmp: Path, failure: str, fail_until: int = 1) -> Path:
        count = tmp / "attempts"
        body = (
            f'count=$(cat "{count}" 2>/dev/null || echo 0)\n'
            "count=$(( count + 1 ))\n"
            f'printf "%s\\n" "$count" > "{count}"\n'
            'echo "attempt $count"\n'
            f"if (( count <= {fail_until} )); then {failure}; fi\n"
            "exit 0\n"
        )
        return self.write_installer(tmp, "counting", body)

    def test_a_network_fault_is_retried_and_the_second_attempt_decides(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            installer = self.counting_installer(
                tmp,
                "echo '[ERROR] Failed to fetch releases: Get "
                '"https://api.github.com/repos/XTLS/Xray-core/releases?per_page=100": '
                "context deadline exceeded' >&2 && exit 1",
            )
            res = self.run_helper(tmp, installer)
            attempts = (tmp / "attempts").read_text().strip()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(attempts, "2")
        self.assertIn("attempt 1", res.stdout, "the failed attempt's own output is still shown")
        self.assertIn("context deadline exceeded", res.stderr, "its stderr is replayed")
        self.assertIn("retrying in 0s (attempt 2 of 3)", res.stdout)

    def test_a_failure_that_is_not_a_network_fault_is_reported_at_once(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            installer = self.counting_installer(
                tmp, "echo 'Error: unsupported architecture: riscv64' >&2 && exit 4", fail_until=99,
            )
            res = self.run_helper(tmp, installer)
            attempts = (tmp / "attempts").read_text().strip()
        self.assertEqual(res.returncode, 4, "the installer's own exit code is preserved")
        self.assertEqual(attempts, "1", "a configuration error is not worth repeating")
        self.assertIn("unsupported architecture", res.stderr)
        self.assertNotIn("retrying", res.stdout)

    def test_repeated_network_faults_stop_at_the_declared_attempt_count(self):
        before = set(Path(tempfile.gettempdir()).glob("gowave-node-installer-*"))
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            installer = self.counting_installer(
                tmp, "echo '[ERROR] Failed to fetch releases: i/o timeout' >&2 && exit 1",
                fail_until=99,
            )
            res = self.run_helper(tmp, installer)
            attempts = (tmp / "attempts").read_text().strip()
        after = set(Path(tempfile.gettempdir()).glob("gowave-node-installer-*"))
        self.assertEqual(res.returncode, 1)
        self.assertEqual(attempts, "3")
        self.assertEqual(res.stderr.count("i/o timeout"), 3, "every attempt's evidence survives")
        self.assertEqual(after, before, "the attempt logs live in a directory the helper removes")

    def test_the_secret_travels_in_the_environment_and_never_in_the_arguments(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            seen = tmp / "env"
            argv = tmp / "argv"
            installer = self.write_installer(
                tmp,
                "env",
                f'printf "%s %s %s\\n" "$SECRET_KEY" "$NODE_PORT" "$GOWAVE_NODE_VERSION" > "{seen}"\n'
                f'tr "\\0" " " < /proc/$$/cmdline > "{argv}"\n',
            )
            res = self.run_helper(tmp, installer)
            environment = seen.read_text().strip()
            arguments = argv.read_text()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(environment, "hidden-secret 3002 latest")
        self.assertNotIn("hidden-secret", arguments)
        self.assertNotIn("hidden-secret", res.stdout + res.stderr)


class TestWorkerPayloadBootstrap(unittest.TestCase):
    """The Worker payload must provision python3 before the transaction that uses it.

    A minimal supported host has no interpreter, and the mutation lease plus the
    ACME lineage snapshots are python3 and openssl. When the payload reached them
    first, ``node add`` died at its first Python call and the compensation failed
    for the same reason, leaving the Worker half-provisioned.
    """

    def capture(self, tmp, *command):
        return capture_remote_script(tmp, *command)

    def payload(self, tmp):
        return self.capture(tmp, "remote_payload", "127.0.0.1", "22",
                            "worker.example.com", "reality.example.com", "root")

    def test_the_interpreter_arrives_before_the_lease_and_the_snapshots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = self.payload(tmpdir)
        main_body = payload.split("main() {", 1)[1]
        bootstrap_at = main_body.index("bootstrap_early_tools </dev/null")
        self.assertLess(bootstrap_at, main_body.index("acquire_mutation_lock"),
                        "the lease is python3, so it cannot come first")
        self.assertLess(bootstrap_at, main_body.index("snapshot_acme_lineage"))
        self.assertLess(bootstrap_at, main_body.index("setup_system_prereqs"))

    def test_the_payload_configures_the_managed_jail_before_the_firewall(self):
        # The Worker gets the same SSH jail as the Master, and it is mandatory:
        # a jail that only warns leaves the discovered SSH ports protected by
        # the package install alone. Running it before the firewall keeps an
        # aborting Worker from having changed its ingress already.
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = self.payload(tmpdir)
        syntax = subprocess.run(["bash", "-n"], input=payload, text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        main_body = payload.split("main() {", 1)[1]
        self.assertIn("--configure-fail2ban", payload)
        lines = [line.strip() for line in main_body.splitlines()
                 if "configure_worker_fail2ban </dev/null" in line]
        self.assertEqual(len(lines), 1, lines)
        self.assertNotIn("||", lines[0])
        self.assertLess(main_body.index(lines[0]), main_body.index("configure_firewall </dev/null"))

    def test_the_security_helper_lands_on_a_random_private_path(self):
        # A fixed name in /tmp is a file another local account can pre-create,
        # and both the DoT and the Fail2ban step write it as root.
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = self.payload(tmpdir)
        self.assertEqual(payload.count("materialize_security_helper()"), 1)
        self.assertIn("mktemp /tmp/gowave-managed-security.XXXXXX", payload)
        self.assertNotIn("/tmp/gowave-managed-security.py", payload)
        self.assertIn("/tmp/gowave-managed-security.*", payload)
        self.assertIn('chmod 0700 "$helper"', payload)

    def test_the_rollback_can_run_without_a_preinstalled_interpreter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rollback = self.capture(tmpdir, "remote_rollback", "127.0.0.1", "22",
                                    "worker.example.com", "reality.example.com", "root")
        self.assertIn("command -v python3", rollback)
        self.assertLess(rollback.rindex("command -v python3"),
                        rollback.rindex("acquire_mutation_lock"))

    def test_the_bootstrap_installs_only_what_is_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            payload = self.payload(tmp)
            script = tmp / "payload.sh"
            script.write_text(
                "\n".join(
                    line for line in payload.splitlines()
                    if not line.startswith('main "$@"')
                ) + "\n",
                encoding="utf-8",
            )
            stubs = tmp / "stubs"
            stubs.mkdir()
            calls = tmp / "apt-calls.log"
            installed = tmp / "installed"
            (stubs / "dpkg-query").write_text(
                "#!/bin/sh\n"
                "for pkg in \"$@\"; do :; done\n"
                f"if grep -qxF \"$pkg\" \"{installed}\" 2>/dev/null; then\n"
                '  echo "install ok installed"\n'
                "else\n"
                '  echo "deinstall ok config-files"\n'
                "fi\n"
            )
            (stubs / "apt-get").write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{calls}"\nexit 0\n')
            for stub in (stubs / "dpkg-query", stubs / "apt-get"):
                stub.chmod(0o755)

            def bootstrap(pretend_installed):
                installed.write_text("\n".join(pretend_installed) + "\n", encoding="utf-8")
                calls.write_text("", encoding="utf-8")
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; set +euo pipefail; bootstrap_early_tools',
                     "test", str(script)],
                    env={**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"},
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return calls.read_text()

            missing_all = bootstrap([])
            self.assertIn("update -qq", missing_all)
            install_line = [line for line in missing_all.splitlines() if line.startswith("install")]
            self.assertEqual(len(install_line), 1, missing_all)
            for package in ("python3", "openssl", "ca-certificates"):
                self.assertIn(package, install_line[0])

            self.assertEqual(bootstrap(["python3", "iproute2", "curl", "ca-certificates", "openssl"]), "",
                             "a prepared host must not be touched again")

            only_openssl = bootstrap(["python3", "iproute2", "curl", "ca-certificates"])
            self.assertIn("install", only_openssl)
            self.assertIn("openssl", only_openssl)
            self.assertNotIn("python3", only_openssl)


class TestWorkerInstallerRetry(unittest.TestCase):
    """The Worker payload absorbs the same transient fault before it rolls back.

    The payload cannot source ``modules/``, so it carries its own copy of the
    retry; running the streamed script's functions proves that copy, not the
    module's.
    """

    def payload_functions(self, tmp: Path) -> Path:
        payload = capture_remote_script(tmp, "remote_payload", "127.0.0.1", "22",
                                        "worker.example.com", "reality.example.com", "root")
        script = tmp / "payload-functions.sh"
        script.write_text(
            "\n".join(line for line in payload.splitlines() if not line.startswith('main "$@"')) + "\n",
            encoding="utf-8",
        )
        return script

    def test_a_network_fault_is_retried_inside_the_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            count = tmp / "attempts"
            installer = tmp / "install.sh"
            installer.write_text(
                "#!/usr/bin/env bash\n"
                f'count=$(cat "{count}" 2>/dev/null || echo 0)\n'
                "count=$(( count + 1 ))\n"
                f'printf "%s\\n" "$count" > "{count}"\n'
                'echo "attempt $count"\n'
                "if (( count == 1 )); then\n"
                "    echo '[ERROR] Failed to fetch releases: i/o timeout' >&2\n"
                "    exit 1\n"
                "fi\n",
                encoding="utf-8",
            )
            installer.chmod(0o700)
            driver = (
                f'source "{script}"\n'
                "NODE_INSTALLER_RETRY_DELAYS=(0)\n"
                f'run_node_installer_with_retry "{installer}" "" 3002 latest'
            )
            res = subprocess.run(["bash", "-c", driver], capture_output=True, text=True)
            attempts = count.read_text().strip()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(attempts, "2")
        self.assertIn("i/o timeout", res.stderr, "the failed attempt's stderr is replayed")
        self.assertIn("retrying in 0s (attempt 2 of 3)", res.stdout)

    def test_the_payload_installer_failure_still_reaches_the_rollback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = capture_remote_script(tmpdir, "remote_payload", "127.0.0.1", "22",
                                            "worker.example.com", "reality.example.com", "root")
        installer_body = payload.split("run_upstream_node_installer() {", 1)[1].split(
            "\ncompensate_remote_worker() {", 1)[0]
        self.assertIn("run_node_installer_with_retry", installer_body,
                      "the payload's only installer invocation must be the retrying one")
        self.assertIn('return "$installer_rc"', installer_body)


class TestWorkerLineageSelection(unittest.TestCase):
    """A Worker adopts the lineage it already serves, and serves the one it checked.

    A Worker in a shared zone can be left with `cover2.example.net-0001`: certbot
    names a lineage after `--cert-name`, so issuing the plain name beside it leaves
    one name with two certificates and a vhost pointing at whichever path the
    template happened to hardcode. The payload therefore selects the owned lineage
    before it snapshots or renders anything, and the vhosts are rendered from the
    directory that selection returned. The payload carries its own copy of the
    selector, so these cases run that copy rather than the Master's module.
    """

    @staticmethod
    def payload_functions(tmp: Path) -> Path:
        payload = capture_remote_script(tmp, "remote_payload", "127.0.0.1", "22",
                                        "worker.example.com", "reality.example.com", "root")
        script = tmp / "payload-functions.sh"
        script.write_text(
            "\n".join(line for line in payload.splitlines() if not line.startswith('main "$@"')) + "\n",
            encoding="utf-8",
        )
        return script

    @staticmethod
    def select(script: Path, name: str, root: Path, server: str):
        return subprocess.run(
            ["bash", "-c", f'source "{script}" && select_acme_lineage "{name}" "{server}" "{root}"'],
            capture_output=True, text=True,
        )

    def test_the_payload_adopts_the_suffixed_lineage_that_covers_the_name(self):
        from tests.test_nginx_routing import issue_lineage, PRODUCTION_DIRECTORY
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            root = tmp / "letsencrypt"
            issue_lineage(root, "worker.example.com-0001", ["worker.example.com"],
                          server=PRODUCTION_DIRECTORY)
            res = self.select(script, "worker.example.com", root, PRODUCTION_DIRECTORY)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), str(root / "live" / "worker.example.com-0001"))
        self.assertIn("Adopting the ACME lineage worker.example.com-0001", res.stderr)

    def test_the_payload_refuses_a_lineage_from_another_acme_directory(self):
        from tests.test_nginx_routing import issue_lineage, PRODUCTION_DIRECTORY, STAGING_DIRECTORY
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            root = tmp / "letsencrypt"
            issue_lineage(root, "worker.example.com-0001", ["worker.example.com"],
                          server=STAGING_DIRECTORY)
            res = self.select(script, "worker.example.com", root, PRODUCTION_DIRECTORY)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), "")
        self.assertIn("was not issued by", res.stderr)

    def test_the_payload_refuses_an_expired_or_unrelated_lineage(self):
        from tests.test_nginx_routing import issue_lineage, PRODUCTION_DIRECTORY
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            root = tmp / "letsencrypt"
            issue_lineage(root, "worker.example.com-0001", ["worker.example.com"],
                          server=PRODUCTION_DIRECTORY, expired=True)
            expired = self.select(script, "worker.example.com", root, PRODUCTION_DIRECTORY)
            self.assertEqual(expired.returncode, 0, expired.stderr)
            self.assertEqual(expired.stdout.strip(), "")
            self.assertIn("has expired", expired.stderr)

            other = tmp / "other"
            issue_lineage(other, "worker.example.com-0002", ["elsewhere.example.com"],
                          server=PRODUCTION_DIRECTORY)
            unrelated = self.select(script, "worker.example.com", other, PRODUCTION_DIRECTORY)
        self.assertEqual(unrelated.returncode, 0, unrelated.stderr)
        self.assertEqual(unrelated.stdout.strip(), "")
        self.assertNotIn("Adopting", unrelated.stderr)

    def test_the_install_selects_the_lineage_before_it_snapshots_or_renders(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        main = text[text.index("cat <<'REMOTE_EOF'"):]
        main = main[:main.index("\nREMOTE_EOF\n")]
        selected = main.index('_WORKER_LIVE_DIR=$(select_acme_lineage "$WORKER_DOMAIN"')
        self.assertLess(
            selected,
            main.index('snapshot_acme_lineage "$_ACME_TX_ID" "$_WORKER_LINEAGE"'),
            "the snapshot has to name the lineage the run selected",
        )
        self.assertIn('_REALITY_LIVE_DIR=$(select_acme_lineage "$REALITY_DOMAIN"', main)
        self.assertIn('_VISION_LIVE_DIR=$(select_acme_lineage "$VISION_DOMAIN"', main)
        self.assertIn('_WORKER_LIVE_DIR="${_WORKER_LIVE_DIR:-/etc/letsencrypt/live/$WORKER_DOMAIN}"',
                      main)
        self.assertIn(
            'check_acme_lineage "$WORKER_DOMAIN" "$effective_acme_server" \\\n'
            '        "/etc/letsencrypt/renewal/$_WORKER_LINEAGE.conf" "$_WORKER_LIVE_DIR"',
            main,
        )
        self.assertIn('configure_edge_nginx "$_WORKER_LIVE_DIR" "$_REALITY_LIVE_DIR" '
                      '"${_VISION_LIVE_DIR:-}" </dev/null', main)

    def test_the_edge_step_proves_every_owned_lineage_renews(self):
        """Renewal is a separate path: it runs the port-80 vhost and the hook, so
        the step that makes the production config live is the only place a dry run
        means anything, and it may name only the lineages this Worker owns."""
        script = NODE_AUTO_SH.read_text(encoding="utf-8")
        payload = script[script.index("cat <<'RUNNER_FUNCS'"):]
        payload = payload[:payload.index("\nRUNNER_FUNCS\n")]
        self.assertEqual(payload.count("verify_renewal_dry_run() {"), 1,
                         "the payload is one file; its own copy is the one that runs")
        start = payload.index("configure_edge_nginx() {")
        body = payload[start:payload.index("\ncore_version_matches() {", start)]
        dry_run = body.index('verify_renewal_dry_run "$owned_lineage"')
        self.assertLess(body.index("nginx -t"), dry_run)
        self.assertLess(body.index("systemctl reload nginx || systemctl restart nginx"), dry_run)
        self.assertLess(dry_run, body.index("_NGINX_CONFIGS_CREATED=1"),
                        "a failed dry run has to fail while the step is still rollback-owed")
        self.assertIn('for owned_lineage in "$worker_lineage" "$reality_lineage" '
                      '${vision_lineage:+"$vision_lineage"}; do', body)
        self.assertIn("renew --dry-run --cert-name", payload)
        self.assertNotIn("certonly --dry-run", payload)

    def test_the_rendered_vhosts_use_the_selected_directories(self):
        script = NODE_AUTO_SH.read_text(encoding="utf-8")
        payload = script[script.index("cat <<'RUNNER_FUNCS'"):]
        payload = payload[:payload.index("\nRUNNER_FUNCS\n")]
        start = payload.index("configure_edge_nginx() {")
        body = payload[start:payload.index("\ncore_version_matches() {", start)]
        self.assertIn('local worker_live="${1:-/etc/letsencrypt/live/$WORKER_DOMAIN}"', body)
        self.assertIn('local reality_live="${2:-/etc/letsencrypt/live/$REALITY_DOMAIN}"', body)
        self.assertIn('--cert-name "$worker_lineage"', body)
        self.assertIn('--cert-name "$reality_lineage"', body)
        self.assertIn("ssl_certificate $worker_live/fullchain.pem;", body)
        self.assertIn("ssl_certificate_key $worker_live/privkey.pem;", body)
        self.assertIn("ssl_certificate $reality_live/fullchain.pem;", body)
        self.assertNotIn("/etc/letsencrypt/live/$WORKER_DOMAIN/fullchain.pem", body)
        self.assertNotIn("/etc/letsencrypt/live/$REALITY_DOMAIN/fullchain.pem", body)


class TestWorkerEdgeMigrationGate(unittest.TestCase):
    """An installed Worker keeps the edge it serves until the controller confirms it.

    Re-applying a Worker streams the payload again, which rewrites the stream map
    and the certificate each listener references -- what every client of the host
    reaches. The payload therefore reads the identity its managed files serve,
    prints it beside the one this run would serve, and refuses a difference
    without GOWAVE_MIGRATE_EXISTING=yes, which `node reapply` sends only after its
    own preview. These cases run the payload's own copy of the gate.
    """

    STREAM = """\
# Managed by GoWave Auto NGINX: Worker Edge Stream
map $ssl_preread_server_name $worker_dest {
    worker.example.com 127.0.0.1:7443;
    reality.example.com 127.0.0.1:8443;
    vision.example.com 127.0.0.1:8444;
    default 127.0.0.1:8443;
}
"""

    @staticmethod
    def payload_functions(tmp: Path, vision: str = "vision.example.com") -> Path:
        # The payload re-exports every streamed value when it is sourced, so the
        # Vision name has to come through the controller's own input rather than
        # the test's environment.
        payload = capture_remote_script(
            tmp, "remote_payload", "127.0.0.1", "22",
            "worker.example.com", "reality.example.com", "root",
            extra_env={"VISION_DOMAIN": vision},
        )
        script = tmp / "payload-functions.sh"
        script.write_text(
            "\n".join(line for line in payload.splitlines() if not line.startswith('main "$@"')) + "\n",
            encoding="utf-8",
        )
        return script

    @staticmethod
    def write_edge(tmp: Path, worker_live: str, reality_live: str, vision_live: str = "") -> None:
        (tmp / "gowave-worker-stream.conf").write_text(TestWorkerEdgeMigrationGate.STREAM, encoding="utf-8")
        conf = tmp / "conf.d"
        conf.mkdir()
        (conf / "gowave-worker-https.conf").write_text(
            f"server {{\n    ssl_certificate {worker_live}/fullchain.pem;\n}}\n", encoding="utf-8")
        (conf / "gowave-worker-decoy.conf").write_text(
            f"server {{\n    ssl_certificate {reality_live}/fullchain.pem;\n}}\n", encoding="utf-8")
        if vision_live:
            (conf / "gowave-worker-vision-fallback.conf").write_text(
                f"server {{\n    ssl_certificate {vision_live}/fullchain.pem;\n}}\n", encoding="utf-8")

    def gate(self, script: Path, tmp: Path, worker_live: str, reality_live: str,
             vision_live: str = "", env=None):
        # The confirmation is baked into the streamed payload when it is generated,
        # so at this level it is passed to the function call itself.
        prefix = ""
        if env and "GOWAVE_MIGRATE_EXISTING" in env:
            prefix = f"GOWAVE_MIGRATE_EXISTING={env['GOWAVE_MIGRATE_EXISTING']} "
        command = (
            f'source "{script}" && {prefix}require_worker_edge_migration_confirmation '
            f'"{worker_live}" "{reality_live}" "{vision_live}" '
            f'"{tmp / "gowave-worker-stream.conf"}" "{tmp / "conf.d"}"'
        )
        merged = {
            "PATH": os.environ["PATH"],
            "HOME": os.environ.get("HOME", "/root"),
        }
        return subprocess.run(["bash", "-c", command], capture_output=True, text=True, env=merged)

    def test_a_different_identity_is_refused_without_the_controller_confirmation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            self.write_edge(tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
            res = self.gate(script, tmp, "/etc/letsencrypt/live/worker.example.com-0001",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
        self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
        self.assertIn("already serves a different edge identity", res.stderr)
        self.assertIn("GOWAVE_MIGRATE_EXISTING=yes", res.stderr)
        self.assertIn("node reapply", res.stderr)

    def test_the_preview_prints_both_identities_before_it_proceeds(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            self.write_edge(tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
            res = self.gate(script, tmp, "/etc/letsencrypt/live/worker-0001",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com",
                            env={"GOWAVE_MIGRATE_EXISTING": "yes"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Edge identity currently served by this Worker:", res.stdout)
        self.assertIn("cert worker /etc/letsencrypt/live/worker.example.com", res.stdout)
        self.assertIn("Edge identity this run will serve:", res.stdout)
        self.assertIn("cert worker /etc/letsencrypt/live/worker-0001", res.stdout)
        self.assertIn("Migration confirmed by GOWAVE_MIGRATE_EXISTING=yes.", res.stdout)

    def test_an_identical_identity_is_not_a_migration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            self.write_edge(tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
            res = self.gate(script, tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("already serves this identity", res.stdout)

    def test_a_host_with_no_managed_edge_is_a_first_install(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            res = self.gate(script, tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("nothing to migrate", res.stdout)

    def test_a_symlinked_stream_map_is_refused_instead_of_read(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script = self.payload_functions(tmp)
            self.write_edge(tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
            stream = tmp / "gowave-worker-stream.conf"
            elsewhere = tmp / "elsewhere.conf"
            stream.rename(elsewhere)
            stream.symlink_to(elsewhere)
            res = self.gate(script, tmp, "/etc/letsencrypt/live/worker.example.com",
                            "/etc/letsencrypt/live/reality.example.com",
                            "/etc/letsencrypt/live/vision.example.com")
        self.assertEqual(res.returncode, 1)
        self.assertIn("is not a regular file", res.stderr)

    def test_the_gate_runs_before_the_first_snapshot_or_before_image(self):
        text = NODE_AUTO_SH.read_text(encoding="utf-8")
        main = text[text.index("cat <<'REMOTE_EOF'"):]
        main = main[:main.index("\nREMOTE_EOF\n")]
        gate = main.index("require_worker_edge_migration_confirmation")
        self.assertLess(gate, main.index('snapshot_acme_lineage "$_ACME_TX_ID" "$_WORKER_LINEAGE"'))
        self.assertLess(gate, main.index("record_worker_targets_before_image"))
        self.assertLess(gate, main.index('configure_edge_nginx "$_WORKER_LIVE_DIR"'))

    def test_the_controller_streams_the_confirmation_over_stdin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = capture_remote_script(Path(tmpdir), "remote_payload", "127.0.0.1", "22",
                                            "worker.example.com", "reality.example.com", "root")
        self.assertIn("export GOWAVE_MIGRATE_EXISTING=no", payload)
        with tempfile.TemporaryDirectory() as tmpdir:
            confirmed = capture_remote_script(
                Path(tmpdir), "remote_payload", "127.0.0.1", "22",
                "worker.example.com", "reality.example.com", "root",
                extra_env={"GOWAVE_MIGRATE_EXISTING": "yes"},
            )
        self.assertIn("export GOWAVE_MIGRATE_EXISTING=yes", confirmed)


class TestWorkerReapply(unittest.TestCase):
    """`node reapply` reconverges a registered Worker without re-registering it.

    The Worker keeps no copy of the payload it was installed with, so the only
    way an operator can reconfigure an existing host is to stream that payload
    again. The branch therefore takes the identity from state.json, leaves the
    Panel's registration untouched, and keeps the secret out of argv.
    """

    @classmethod
    def setUpClass(cls):
        cls.text = (REPO_ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        cls.branch = cls.text.split("        reapply)", 1)[1].split("        *)", 1)[0]

    def test_it_reads_the_registered_identity_instead_of_taking_it_as_arguments(self):
        self.assertIn("$STATE_FILE", self.branch)
        for field in ("address", "port", "workerDomain", "realityDomain"):
            self.assertIn(field, self.branch)
        self.assertNotIn("associate_node", self.branch)
        self.assertNotIn("provision_config_profile", self.branch)

    def test_the_identity_is_read_by_label_so_an_empty_name_survives(self):
        # A Worker without Vision prints an empty fifth field, and command
        # substitution strips trailing empty lines, so a positional read loses
        # the name it was asked for and refuses a perfectly valid node.
        self.assertIn("while IFS='=' read -r key value", self.branch)
        self.assertIn('address) ip="$value"', self.branch)
        self.assertIn('vision_domain) vision_domain="$value"', self.branch)
        self.assertNotIn("mapfile", self.branch)

    def test_it_streams_the_shipped_payload_with_only_the_registered_identity(self):
        self.assertIn('"$SCRIPT_DIR/gowave-node-auto.sh" remote_payload', self.branch)
        call = [line for line in self.branch.splitlines() if "remote_payload" in line]
        self.assertEqual(len(call), 1, self.branch)
        self.assertIn('"$ip" "$ssh_port" "$worker_domain" "$reality_domain" "$ssh_user"', call[0])
        self.assertNotIn("$secret_key", call[0])
        self.assertNotIn("$acme_test_ca_b64", call[0])

    def test_the_secret_and_the_test_ca_travel_only_in_the_environment(self):
        self.assertIn('SECRET_KEY="$secret_key"', self.branch)
        self.assertIn('GOWAVE_ACME_TEST_CA_B64="$acme_test_ca_b64"', self.branch)

    def test_it_refuses_a_host_key_that_was_never_pinned(self):
        self.assertIn("ssh-keygen -F", self.branch)
        self.assertLess(self.branch.index("ssh-keygen -F"),
                        self.branch.index("remote_payload"))

    def test_the_cli_advertises_the_subcommand(self):
        self.assertIn("node {add|list|reapply|rollback}", self.text)


class TestWorkerDeployHookOwnership(unittest.TestCase):
    """The Worker payload must accept the deploy hook an earlier payload installed.

    A reconfiguration streams the payload again under a new ACME transaction id,
    and `remote_finalize` deletes that transaction directory once the install
    commits, taking its `deploy-hook-manifest.json` with it. The hook itself stays
    on the host on purpose, so ownership is recorded where the finalizer cannot
    reach it; otherwise the second install refuses the Worker's own hook and the
    whole reconfiguration fails.
    """

    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as tmpdir:
            payload = capture_remote_script(
                tmpdir, "remote_payload", "127.0.0.1", "22",
                "worker.example.com", "reality.example.com", "root",
            )
        start = payload.index("deploy_hook_ownership_record() {")
        end = payload.index("\nsetup_system_prereqs() {", start)
        assert end > start
        cls.functions = payload[start:end]

    def run_hook_functions(self, tmp, body):
        script = Path(tmp) / "hook-functions.sh"
        script.write_text(self.functions + "\n" + body, encoding="utf-8")
        return subprocess.run(
            ["bash", str(script), str(Path(tmp) / "renewal-hooks" / "deploy" / "gowave-nginx.sh"),
             str(Path(tmp) / "recovery")],
            capture_output=True, text=True,
        )

    def test_a_repeated_install_accepts_the_hook_after_the_snapshot_is_finalized(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.run_hook_functions(
                tmpdir,
                "\n".join((
                    "hook=\"$1\"",
                    "recovery=\"$2\"",
                    'install_managed_deploy_hook "worker_install_one" "$hook" "$recovery" || exit 10',
                    # This is what remote_finalize does once the install commits.
                    'rm -rf -- "$recovery/worker_install_one" || exit 11',
                    'install_managed_deploy_hook "worker_install_two" "$hook" "$recovery" || exit 12',
                    'rollback_managed_deploy_hook "worker_install_two" "$hook" "$recovery" || exit 13',
                )),
            )
            self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}, stderr: {result.stderr}")
            self.assertFalse((Path(tmpdir) / "renewal-hooks" / "deploy" / "gowave-nginx.sh").exists(),
                             "the rolled-back hook must not survive the transaction")
            self.assertFalse((Path(tmpdir) / "recovery" / "deploy-hook-ownership.json").exists(),
                             "ownership must be cleared with the hook it described")

    def test_the_record_names_the_file_so_an_operator_edit_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.run_hook_functions(
                tmpdir,
                "\n".join((
                    "hook=\"$1\"",
                    "recovery=\"$2\"",
                    'install_managed_deploy_hook "worker_install_one" "$hook" "$recovery" || exit 10',
                    'record="$recovery/deploy-hook-ownership.json"',
                    '[[ -f "$record" && ! -L "$record" ]] || exit 11',
                    '[[ "$(stat -c %a -- "$record")" == "600" ]] || exit 12',
                    'rm -rf -- "$recovery/worker_install_one" || exit 13',
                    "printf '#!/bin/sh\\necho hijacked\\n' > \"$hook\" || exit 14",
                    'verify_deploy_hook_preflight "$hook" "worker_install_two" "$recovery" && exit 15',
                    "exit 0",
                )),
            )
            self.assertEqual(result.returncode, 0, f"stdout: {result.stdout}, stderr: {result.stderr}")
            self.assertIn("Pre-existing unowned Certbot deploy hook found", result.stderr)


class TestWorkerFirewallPolicy(unittest.TestCase):
    """The Worker applies the shared role policy instead of a hand-written list.

    A rule list that only looks right leaves an internal port reachable while
    the install reports a hardened host. These cases drive the payload function
    with a stub policy and a recording `ufw`, and read the order back: preflight
    before any mutation, the baseline capture before the first rule, the policy
    commands verbatim, a kernel read-back, and one restoration when the read-back
    disagrees.
    """

    POLICY = json.dumps({"status": "ok", "policy": {"commands": [
        ["default", "deny", "incoming"],
        ["default", "allow", "outgoing"],
        ["allow", "22/tcp"],
        ["deny", "3000/tcp"],
        ["allow", "proto", "tcp", "from", "203.0.113.10", "to", "any", "port", "3002"],
    ]}})

    def setUp(self):
        script = NODE_AUTO_SH.read_text()
        start = script.index("cat <<'RUNNER_FUNCS'")
        self.payload = script[start:script.index("\nRUNNER_FUNCS\n", start)]
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workdir = Path(temporary.name)
        self.calls = self.workdir / "calls.txt"
        self.helper = self.workdir / "helper.py"
        self.helper.write_text(
            'import os, sys\n'
            'mode = sys.argv[1] if len(sys.argv) > 1 else ""\n'
            'document = sys.stdin.read()\n'
            'if mode == "--firewall-preflight":\n'
            '    sys.stdout.write(os.environ["STUB_PREFLIGHT"])\n'
            '    sys.exit(int(os.environ.get("STUB_PREFLIGHT_RC", "0")))\n'
            'if mode == "--firewall-verify":\n'
            '    sys.stdout.write(os.environ["STUB_VERIFY"])\n'
            '    sys.exit(int(os.environ.get("STUB_VERIFY_RC", "0")))\n'
            'if mode == "--security-report":\n'
            '    open(os.environ["STUB_REQUEST"], "w", encoding="utf-8").write(document)\n'
            '    sys.stdout.write(os.environ["STUB_REPORT"])\n'
            '    sys.exit(int(os.environ.get("STUB_REPORT_RC", "0")))\n'
            'sys.exit(2)\n',
            encoding="utf-8",
        )
        self.helper.chmod(0o700)
        self.request = self.workdir / "request.json"
        self.ufw_default = self.workdir / "ufw-default"
        self.ufw_default.write_text("IPV6=no\n", encoding="utf-8")

    def function(self, name):
        start = self.payload.index(name + "() {")
        return self.payload[start:self.payload.index("\n}\n", start) + len("\n}\n")]

    STUBS = '''
kernel_has_ipv6() { return 0; }
worker_firewall_policy_json() { printf %s "$STUB_POLICY"; }
materialize_security_helper() {
    [[ -n "${STUB_HELPER:-}" ]] || return 1
    local copy
    copy=$(mktemp /tmp/gowave-test-helper.XXXXXX) || return 1
    cp "$STUB_HELPER" "$copy" || return 1
    printf '%s\\n' "$copy"
}
record_firewall_before_image() { echo capture >> "$STUB_CALLS"; }
restore_firewall_before_image() { echo restore >> "$STUB_CALLS"; }
ufw() {
    echo "ufw $*" >> "$STUB_CALLS"
    if [[ "${STUB_UFW_FAIL:-}" == "$1" ]]; then return 1; fi
    if [[ "$1" == status ]]; then echo "Status: active"; fi
    return 0
}
'''

    def environment(self, **overrides):
        values = {**os.environ, "PANEL_IP": "203.0.113.10", "PANEL_IPV6": "",
                  "NODE_PORT": "3002", "SSH_PORT": "22", "STUB_POLICY": self.POLICY,
                  "STUB_HELPER": str(self.helper), "STUB_CALLS": str(self.calls),
                  "STUB_REQUEST": str(self.request),
                  "STUB_PREFLIGHT": '{"status": "ok", "preserved_exceptions": []}',
                  "STUB_VERIFY": '{"status": "success"}', "STUB_REPORT": '{"status": "ready"}'}
        values.update(overrides)
        return values

    def run_firewall(self, **overrides):
        prelude = ('set -euo pipefail\n'
                   'log_warn() { printf "[WARN] %s\\n" "$*" >&2; }\n'
                   + self.function("configure_firewall") + self.STUBS)
        body = ('if configure_firewall "$UFW_DEFAULT"; then echo "rc=0"; '
                'else echo "rc=$?"; fi\n'
                'printf "configured=%s\\n" "${_UFW_RULES_CONFIGURED:-0}"\n')
        return subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True,
                              env=self.environment(UFW_DEFAULT=str(self.ufw_default), **overrides))

    def recorded(self):
        return self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []

    def test_the_policy_commands_are_applied_verbatim_and_read_back(self):
        result = self.run_firewall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=0", result.stdout)
        self.assertIn("configured=1", result.stdout)
        calls = self.recorded()
        self.assertEqual(calls[0], "capture", "the baseline is captured before the first rule")
        applied = [line for line in calls if line.startswith("ufw ") and line != "ufw status"]
        self.assertEqual(applied, [
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw allow 22/tcp comment GoWave Auto NGINX",
            "ufw deny 3000/tcp comment GoWave Auto NGINX",
            "ufw allow proto tcp from 203.0.113.10 to any port 3002 comment GoWave Auto NGINX",
            "ufw --force enable",
        ])
        self.assertNotIn("restore", calls)
        self.assertIn("IPV6=yes", self.ufw_default.read_text(encoding="utf-8"))

    def test_a_preflight_conflict_is_refused_before_any_mutation(self):
        result = self.run_firewall(
            STUB_PREFLIGHT_RC="1",
            STUB_PREFLIGHT='{"error": "Existing UFW allow conflicts with managed listener isolation"}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=1", result.stdout)
        self.assertIn("Existing UFW allow conflicts", result.stderr)
        self.assertIn("conflicts with existing firewall policy", result.stderr)
        self.assertEqual(self.recorded(), [], "nothing may be captured or applied after a refusal")

    def test_a_failed_read_back_restores_the_baseline_exactly_once(self):
        result = self.run_firewall(STUB_VERIFY_RC="1",
                                   STUB_VERIFY='{"error": "Live firewall still exposes protected ports"}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=1", result.stdout)
        self.assertIn("configured=0", result.stdout)
        self.assertIn("Live firewall still exposes protected ports", result.stderr)
        self.assertEqual(self.recorded().count("restore"), 1)
        self.assertIn("baseline was restored", result.stderr)

    def test_a_rule_ufw_refuses_restores_the_baseline(self):
        result = self.run_firewall(STUB_UFW_FAIL="deny")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=1", result.stdout)
        self.assertEqual(self.recorded().count("restore"), 1)
        self.assertNotIn("ufw --force enable", self.recorded())

    def test_a_missing_helper_changes_nothing(self):
        result = self.run_firewall(STUB_HELPER="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=1", result.stdout)
        self.assertEqual(self.recorded(), [])

    def run_report(self, **overrides):
        prelude = ('set -euo pipefail\n'
                   'log_warn() { printf "[WARN] %s\\n" "$*" >&2; }\n'
                   'kernel_has_ipv6() { return 0; }\n'
                   'materialize_security_helper() { printf "%s\\n" "$STUB_HELPER"; }\n'
                   + self.function("write_worker_security_report"))
        body = ('_DOT_RECOVERY=verified\n'
                'if write_worker_security_report; then echo "rc=0"; else echo "rc=$?"; fi\n')
        return subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True,
                              env=self.environment(GOWAVE_DOT_POLICY="required", **overrides))

    def test_the_worker_report_carries_the_policy_and_the_recovery_it_observed(self):
        result = self.run_report()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=0", result.stdout)
        self.assertEqual(json.loads(self.request.read_text(encoding="utf-8")), {
            "role": "worker", "node_port": 3002, "master_sources": ["203.0.113.10"],
            "ipv6": True, "dot_policy": "required", "dot_recovery": "verified"})

    def test_a_failed_report_verdict_stops_the_worker(self):
        result = self.run_report(STUB_REPORT_RC="1", STUB_REPORT='{"status": "failed"}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rc=1", result.stdout)
        self.assertIn("not ready for deployment", result.stderr)


if __name__ == "__main__":
    unittest.main()
