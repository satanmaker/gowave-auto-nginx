#!/usr/bin/env python3
"""Suite nonroot: Linting, syntax compilation, OpenSpec validation, NGINX compilation, and archive rejection tests."""
import io
import os
from pathlib import Path
import py_compile
import re
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


class TestShellFailurePaths(unittest.TestCase):
    """Cleanup and deletion guards must hold on the path a failed run takes."""

    def _shell_scripts(self):
        return [
            REPO_ROOT / "gowave-auto.sh",
            REPO_ROOT / "gowave-node-auto.sh",
            REPO_ROOT / "assets" / "backup" / "gowave-backup.sh",
        ] + sorted((REPO_ROOT / "modules").glob("*.sh"))

    def test_errtrace_is_part_of_strict_mode(self):
        """Every script opens with `set -Eeuo pipefail`; plain `-e` silences ERR traps in functions."""
        for script in self._shell_scripts():
            text = script.read_text()
            self.assertNotIn("set -euo pipefail", text,
                             f"{script.name} must use `set -Eeuo pipefail`")

    def test_cleanup_is_not_left_to_a_return_trap(self):
        """A RETURN trap never runs when errexit abandons a function, so it cannot clean up."""
        pattern = re.compile(r"trap\s+'[^']*'\s+RETURN")
        for script in self._shell_scripts():
            match = pattern.search(script.read_text())
            self.assertIsNone(match, f"{script.name} cleans up from a RETURN trap: {match.group(0) if match else ''}")

    def test_temp_dir_survives_an_aborted_function_only_through_the_exit_trap(self):
        """A command failing inside a function must still remove the tracked scratch directory."""
        script = """
set -Eeuo pipefail
source "$REPO/modules/tempdir.sh"
aborting() {
    local dir
    dir=$(mktemp -d /tmp/gowave-tempdir-probe.XXXXXX)
    track_temp_dir "$dir"
    printf '%s\\n' "$dir" > "$PROBE_OUT"
    false
}
aborting
printf 'unreachable\\n'
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            probe = Path(tmp_dir) / "dir.txt"
            env = dict(os.environ, REPO=str(REPO_ROOT), PROBE_OUT=str(probe))
            res = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0, "the probe must abort under errexit")
            self.assertNotIn("unreachable", res.stdout, "the function body must not continue")
            self.assertTrue(probe.is_file(), f"probe did not record the directory: {res.stderr}")
            leaked = Path(probe.read_text().strip())
            self.assertFalse(leaked.exists(), f"tracked temp directory leaked: {leaked}")

    def test_release_temp_dir_removes_the_directory_before_exit(self):
        """The success path drops the directory early instead of waiting for exit."""
        script = """
set -Eeuo pipefail
source "$REPO/modules/tempdir.sh"
dir=$(mktemp -d /tmp/gowave-tempdir-probe.XXXXXX)
track_temp_dir "$dir"
release_temp_dir "$dir"
if [[ -d "$dir" ]]; then printf 'LEAK\\n'; else printf 'GONE\\n'; fi
"""
        env = dict(os.environ, REPO=str(REPO_ROOT))
        res = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), "GONE", "release_temp_dir left the directory behind")

    def test_tree_guard_refuses_paths_outside_the_owned_root(self):
        """`realpath` guard rejects the cases `${var:?}` lets through."""
        text = (REPO_ROOT / "gowave-node-auto.sh").read_text()
        start = text.index("require_tree_under() {")
        end = text.index("\n}\n", start) + len("\n}\n")
        guard = text[start:end]

        script = guard + """
set -Eeuo pipefail
tmp=$(mktemp -d /tmp/gowave-guard-probe.XXXXXX)
mkdir -p "$tmp/live/example.test"
require_tree_under "$tmp/live/example.test" "$tmp/live" && printf 'ACCEPT-INSIDE\\n'
require_tree_under "$tmp/live" "$tmp/live" || printf 'REJECT-SELF\\n'
require_tree_under "/" "/" || printf 'REJECT-ROOT\\n'
require_tree_under "$tmp/live/../../escape" "$tmp/live" || printf 'REJECT-TRAVERSAL\\n'
require_tree_under "/etc/passwd" "$tmp/live" || printf 'REJECT-OUTSIDE\\n'
rm -rf "$tmp"
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        for marker in ("ACCEPT-INSIDE", "REJECT-SELF", "REJECT-ROOT", "REJECT-TRAVERSAL", "REJECT-OUTSIDE"):
            self.assertIn(marker, res.stdout, f"guard verdict missing: {marker}\n{res.stdout}")


if __name__ == "__main__":
    unittest.main()
