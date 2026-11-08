#!/usr/bin/env python3
"""Suite nonroot: Linting, syntax compilation, OpenSpec validation, NGINX compilation, and archive rejection tests."""
import io
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import tarfile
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parent.parent


class TestNonrootLint(unittest.TestCase):

    def test_shell_scripts_syntax(self):
        """All shell scripts in the repository must pass syntax check (bash -n)."""
        shell_scripts = [
            REPO_ROOT / "gowave-auto.sh",
            REPO_ROOT / "gowave-node-auto.sh",
            REPO_ROOT / "assets" / "backup" / "gowave-backup.sh",
        ] + list((REPO_ROOT / "modules").glob("*.sh"))

        self.assertTrue(len(shell_scripts) >= 8, f"Found {len(shell_scripts)} shell scripts")
        for script in shell_scripts:
            self.assertTrue(script.is_file(), f"Script {script} does not exist")
            res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"Syntax error in {script.name}:\n{res.stderr}")

    def test_python_syntax_compilation(self):
        """All Python files in the repository must compile without SyntaxError."""
        py_files = list((REPO_ROOT / "modules").glob("*.py")) + \
                   list((REPO_ROOT / "assets").rglob("*.py")) + \
                   list((REPO_ROOT / "tests").glob("*.py"))
        self.assertTrue(len(py_files) >= 5, f"Found {len(py_files)} Python files")
        for py_file in py_files:
            try:
                py_compile.compile(str(py_file), doraise=True)
            except py_compile.PyCompileError as e:
                self.fail(f"Python syntax compilation failed for {py_file}: {e}")

    def test_openspec_validation(self):
        """OpenSpec validation command must pass across all specs."""
        if shutil.which("openspec") is None:
            self.skipTest("openspec CLI is not installed in the environment")
        res = subprocess.run(["openspec", "validate", "--all", "--strict"],
                             cwd=str(REPO_ROOT), capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"OpenSpec validation failed:\n{res.stdout}\n{res.stderr}")

    def test_nginx_version_detected_syntax_compilation(self):
        """Verify NGINX config generation handles legacy (listen ... ssl http2;) vs modern (http2 on;) syntax."""
        test_script = f"""
source "{REPO_ROOT}/modules/os.sh"
source "{REPO_ROOT}/modules/nginx.sh"

export NGINX_HTTP2_DIRECTIVE="ssl http2"
generate_panel_https_vhost "vpn.test.example"
generate_decoy_vhost "decoy.test.example"

cat /etc/nginx/conf.d/gowave-panel-https.conf
cat /etc/nginx/conf.d/gowave-reality-decoy.conf
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            conf_d = Path(tmp_dir) / "etc" / "nginx" / "conf.d"
            conf_d.mkdir(parents=True)
            env = dict(os.environ)
            env["PANEL_HTTPS_CONF"] = str(conf_d / "gowave-panel-https.conf")
            env["REALITY_DECOY_CONF"] = str(conf_d / "gowave-reality-decoy.conf")
            
            # Legacy test (< 1.25.1, e.g. Debian 12 1.22.1, Ubuntu 24.04 1.24.0)
            legacy_script = f"""
source "{REPO_ROOT}/modules/os.sh"
source "{REPO_ROOT}/modules/nginx.sh"
export OVERRIDE_NGINX_VERSION="1.24.0"
generate_panel_https_vhost "vpn.legacy.example" "{conf_d}/legacy-panel.conf"
generate_decoy_vhost "decoy.legacy.example" "{conf_d}/legacy-decoy.conf"
"""
            res = subprocess.run(["bash", "-c", legacy_script], env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            legacy_panel = (conf_d / "legacy-panel.conf").read_text()
            self.assertIn("listen 127.0.0.1:7443 ssl http2 proxy_protocol;", legacy_panel)
            self.assertNotIn("http2 on;", legacy_panel)

            # Modern test (>= 1.25.1, e.g. Debian 13 / Ubuntu 26.04)
            modern_script = f"""
source "{REPO_ROOT}/modules/os.sh"
source "{REPO_ROOT}/modules/nginx.sh"
export OVERRIDE_NGINX_VERSION="1.26.3"
generate_panel_https_vhost "vpn.modern.example" "{conf_d}/modern-panel.conf"
generate_decoy_vhost "decoy.modern.example" "{conf_d}/modern-decoy.conf"
"""
            res = subprocess.run(["bash", "-c", modern_script], env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            modern_panel = (conf_d / "modern-panel.conf").read_text()
            self.assertIn("listen 127.0.0.1:7443 ssl proxy_protocol;", modern_panel)
            self.assertIn("http2 on;", modern_panel)

    def test_malicious_archive_rejection(self):
        """Preflight archive validator must reject traversal, absolute paths, and dangerous files."""
        backup_script = REPO_ROOT / "assets" / "backup" / "gowave-backup.sh"

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)

            # 1. Path traversal
            bad_traversal_tar = tmp / "traversal.tar.gz"
            with tarfile.open(bad_traversal_tar, "w:gz") as tar:
                meta = b'{"format_version": 1, "backup_type": "panel", "files": []}'
                ti_m = tarfile.TarInfo("meta.json")
                ti_m.size = len(meta)
                tar.addfile(ti_m, io.BytesIO(meta))

                data = b"malicious"
                ti = tarfile.TarInfo(name="files/opt/gowave/../../etc/shadow")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))

            res = subprocess.run(["bash", str(backup_script), "verify", str(bad_traversal_tar), "panel"],
                                 capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Path traversal detected", res.stderr)

            # 2. Executable shell script inside archive
            bad_script_tar = tmp / "script.tar.gz"
            with tarfile.open(bad_script_tar, "w:gz") as tar:
                meta = b'{"format_version": 1, "backup_type": "panel", "files": []}'
                ti_m = tarfile.TarInfo("meta.json")
                ti_m.size = len(meta)
                tar.addfile(ti_m, io.BytesIO(meta))

                data = b"#!/bin/bash\necho evil"
                ti = tarfile.TarInfo(name="files/etc/letsencrypt/renewal-hooks/deploy/evil.sh")
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))

            res = subprocess.run(["bash", str(backup_script), "verify", str(bad_script_tar), "panel"],
                                 capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Forbidden", res.stderr)


if __name__ == "__main__":
    unittest.main()
