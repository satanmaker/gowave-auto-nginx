#!/usr/bin/env python3
import hashlib
import http.server
import json
import os
import socket
import subprocess
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PREFLIGHT_SH = REPO_ROOT / "modules" / "preflight.sh"
PANEL_SH = REPO_ROOT / "modules" / "panel.sh"


class TestPanelDeployment(unittest.TestCase):
    def test_preflight_port_conflicts(self):
        # Bind a socket to a random port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            occupied_port = s.getsockname()[1]

            # Test check_port_availability detects occupied port
            cmd = f'source "{PREFLIGHT_SH}" && check_port_availability {occupied_port}'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn(f"Port {occupied_port} is in use", res.stderr)

    def test_preflight_managed_unit_ports_are_not_conflicts(self):
        # A repeated install finds the product itself listening on its ports.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

            with tempfile.TemporaryDirectory() as tmpdir:
                entry = Path(tmpdir) / str(os.getpid())
                entry.mkdir()
                (entry / "cgroup").write_text("0::/system.slice/gowave.service\n")

                env = os.environ.copy()
                env["PREFLIGHT_PROC_ROOT"] = tmpdir
                cmd = f'source "{PREFLIGHT_SH}" && check_port_availability {port}'
                res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env)
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertNotIn("is in use", res.stderr)

    def test_preflight_pid_classification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proc_root = Path(tmpdir)
            cases = {
                # (pid, cgroup contents): True when the listener belongs to a managed unit
                11: ("0::/system.slice/gowave.service\n", True),
                12: ("1:name=systemd:/system.slice/gowave-node.service\n", True),
                13: ("0::/system.slice/nginx.service\n", True),
                14: ("0::/system.slice/other.service\n", False),
                15: ("0::/user.slice/user-1000.slice/session-2.scope\n", False),
            }
            for pid, (cgroup, _) in cases.items():
                entry = proc_root / str(pid)
                entry.mkdir()
                (entry / "cgroup").write_text(cgroup)

            env = os.environ.copy()
            env["PREFLIGHT_PROC_ROOT"] = str(proc_root)
            for pid, (_, managed) in cases.items():
                res = subprocess.run(
                    ["bash", "-c", f'source "{PREFLIGHT_SH}" && preflight_pid_is_managed {pid}'],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertEqual(res.returncode == 0, managed, f"pid {pid}: {res.stderr}")

            missing = subprocess.run(
                ["bash", "-c", f'source "{PREFLIGHT_SH}" && preflight_pid_is_managed 999999'],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(missing.returncode, 0)

    def test_preflight_nginx_443_conflicts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nginx_dir = Path(tmpdir)

            # 1. Clean nginx directory
            cmd = f'source "{PREFLIGHT_SH}" && check_nginx_443_conflicts "{nginx_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # 2. Managed files (gowave-*.conf) should NOT trigger conflict
            (nginx_dir / "gowave-stream.conf").write_text("listen 443 so_keepalive=on;\n")
            (nginx_dir / "gowave-panel.conf").write_text("listen 127.0.0.1:7443 ssl;\n")
            cmd = f'source "{PREFLIGHT_SH}" && check_nginx_443_conflicts "{nginx_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # 3. Commented line should NOT trigger conflict
            (nginx_dir / "other.conf").write_text("# listen 443 ssl;\n")
            cmd = f'source "{PREFLIGHT_SH}" && check_nginx_443_conflicts "{nginx_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # 4. Unmanaged active listen 443 MUST trigger conflict
            (nginx_dir / "unmanaged.conf").write_text("server {\n    listen 443 ssl;\n    server_name example.com;\n}\n")
            cmd = f'source "{PREFLIGHT_SH}" && check_nginx_443_conflicts "{nginx_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Unmanaged NGINX port 443 configuration detected", res.stderr)

    def test_generate_panel_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir)
            cmd = f'source "{PANEL_SH}" && generate_panel_env "{target_dir}" "panel.example.com" "panel.example.com/api/sub" 3000 3001 stable'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            env_file = target_dir / ".env"
            self.assertTrue(env_file.exists())
            mode = oct(env_file.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o640")

            content = env_file.read_text()
            self.assertIn("APP_HOST=127.0.0.1", content)
            self.assertIn("APP_PORT=3000", content)
            self.assertIn("METRICS_PORT=3001", content)
            self.assertIn("DB_DRIVER=sqlite", content)
            self.assertIn("DATABASE_URL=gowave.db", content)
            self.assertIn("GOWAVE_PROXY=external", content)
            self.assertIn("GOWAVE_CHANNEL=stable", content)
            self.assertIn("PANEL_DOMAIN=panel.example.com", content)
            self.assertIn("SUB_PUBLIC_DOMAIN=panel.example.com/api/sub", content)

            # Check APP_SECRET length: 64 hex chars
            for line in content.splitlines():
                if line.startswith("APP_SECRET="):
                    secret = line.split("=", 1)[1]
                    self.assertEqual(len(secret), 64)

    def test_repeated_install_keeps_the_app_secret(self):
        # APP_SECRET is the key the Panel encrypts stored credentials with, so a
        # repeat install that rotates it makes every row the Panel wrote unreadable.
        with tempfile.TemporaryDirectory() as tmpdir:
            target_dir = Path(tmpdir)
            command = (
                f'source "{PANEL_SH}" && generate_panel_env "{target_dir}" '
                '"panel.example.com" "panel.example.com/api/sub" 3000 3001 stable'
            )
            first = subprocess.run(["bash", "-c", command], capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            env_file = target_dir / ".env"
            secret = next(
                line.split("=", 1)[1]
                for line in env_file.read_text().splitlines()
                if line.startswith("APP_SECRET=")
            )

            second = subprocess.run(["bash", "-c", command], capture_output=True, text=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            kept = next(
                line.split("=", 1)[1]
                for line in env_file.read_text().splitlines()
                if line.startswith("APP_SECRET=")
            )
            self.assertEqual(kept, secret)
            mode = oct(env_file.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o640")

    def test_panel_keeps_ownership_of_its_database(self):
        # The release install chowns the install directory to root; the database
        # the Panel writes has to come back to the panel account, or the running
        # Panel answers every write with "attempt to write a readonly database".
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target_dir = tmp / "opt_gowave"
            target_dir.mkdir()
            for name in ("gowave.db", "gowave.db-wal", "gowave.db-shm"):
                (target_dir / name).write_text("", encoding="utf-8")
            (target_dir / "gowave-server").write_text("", encoding="utf-8")

            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            calls = tmp / "calls.log"
            for tool in ("chown", "chmod"):
                script = bin_dir / tool
                script.write_text(
                    f'#!/bin/sh\nprintf "%s %s\\n" "{tool}" "$*" >> "{calls}"\n',
                    encoding="utf-8",
                )
                script.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            res = subprocess.run(
                ["bash", "-c", f'source "{PANEL_SH}" && retain_panel_data_ownership "{target_dir}"'],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            recorded = calls.read_text()
            for name in ("gowave.db", "gowave.db-wal", "gowave.db-shm"):
                self.assertIn(f"chown gowave:gowave {target_dir / name}", recorded)
                self.assertIn(f"chmod 0600 {target_dir / name}", recorded)
            self.assertNotIn("gowave-server", recorded)

    def test_download_panel_release_with_checksum(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target_dir = tmp / "opt_gowave"
            art_dir = tmp / "artifacts"
            art_dir.mkdir()

            # Create mock binary and frontend archive
            mock_bin = art_dir / "gowave-server"
            mock_bin.write_text("#!/bin/sh\necho mock gowave\n")

            mock_frontend_tar = art_dir / "gowave-frontend.tar.gz"
            frontend_dist = tmp / "frontend_dist"
            frontend_dist.mkdir()
            (frontend_dist / "index.html").write_text("<html>GoWave UI</html>")
            with tarfile.open(mock_frontend_tar, "w:gz") as tar:
                tar.add(frontend_dist, arcname="dist")

            # Create valid SHA256SUMS
            bin_sha = hashlib.sha256(mock_bin.read_bytes()).hexdigest()
            front_sha = hashlib.sha256(mock_frontend_tar.read_bytes()).hexdigest()

            # Detect current machine arch
            arch_res = subprocess.run(["bash", "-c", f'source "{PANEL_SH}" && detect_arch'], capture_output=True, text=True)
            arch = arch_res.stdout.strip()

            sums_file = art_dir / "SHA256SUMS"
            sums_file.write_text(f"{bin_sha}  gowave-linux-{arch}\n{front_sha}  gowave-frontend.tar.gz\n")

            # 1. Successful download with matching checksums
            env = os.environ.copy()
            env["GOWAVE_PANEL_BINARY"] = str(mock_bin)
            env["GOWAVE_FRONTEND_ARCHIVE"] = str(mock_frontend_tar)
            env["GOWAVE_SHA256SUMS"] = str(sums_file)

            cmd = f'source "{PANEL_SH}" && download_panel_release "{target_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue((target_dir / "gowave-server").exists())
            self.assertTrue((target_dir / "frontend" / "dist" / "index.html").exists())

            # 2. Corrupt checksum detection
            sums_corrupt = art_dir / "SHA256SUMS.bad"
            sums_corrupt.write_text(
                f"0000000000000000000000000000000000000000000000000000000000000000  gowave-linux-{arch}\n"
                "0000000000000000000000000000000000000000000000000000000000000000  gowave-frontend.tar.gz\n"
            )
            env["GOWAVE_SHA256SUMS"] = str(sums_corrupt)
            res_bad = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env)
            self.assertNotEqual(res_bad.returncode, 0)
            self.assertIn("Checksum mismatch", res_bad.stderr)

    def test_verify_panel_startup(self):
        # Start a local mock HTTP server on a random port
        class MockHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, format, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), MockHandler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()

        try:
            cmd = f'source "{PANEL_SH}" && verify_panel_startup 127.0.0.1 {port} 3'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn(f"listening on http://127.0.0.1:{port}", res.stdout)
        finally:
            server.shutdown()
            server.server_close()

    def test_save_credentials_bash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            creds_file = Path(tmpdir) / "gowave-credentials.txt"
            cmd = f'source "{PANEL_SH}" && save_credentials admin mysecretpass123 https://panel.example.com tok-abc "{creds_file}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertTrue(creds_file.exists())
            mode = oct(creds_file.stat().st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            content = creds_file.read_text()
            self.assertIn("PANEL_URL=https://panel.example.com", content)
            self.assertIn("ADMIN_USERNAME=admin", content)
            self.assertIn("ADMIN_PASSWORD=mysecretpass123", content)
            self.assertIn("SCOPED_API_TOKEN=tok-abc", content)


if __name__ == "__main__":
    unittest.main()
