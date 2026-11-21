#!/usr/bin/env python3
"""The pinned-artifact chain: ordered hosts, digest before use, mismatch terminal.

A pinned artifact is published more than once so a single unreachable host is not
an outage. What must never become "more than once" is an answer: a host that
delivers bytes the pin does not name is a supply-chain signal, and the chain stops
there instead of asking the next host for a version it might like better.
"""
import hashlib
import http.server
import os
import shlex
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_SH = REPO_ROOT / "modules" / "artifact.sh"
NODE_SH = REPO_ROOT / "modules" / "node.sh"
PANEL_SH = REPO_ROOT / "modules" / "panel.sh"


class ArtifactServer:
    """A local release host that answers the routes it was given and 404s the rest."""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.requests = []
        routes = self.routes
        requests = self.requests

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                body = routes.get(self.path)
                if body is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        self.base = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        return self

    def __exit__(self, *_exc):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=10)
        return False

    def url(self, path):
        return self.base + path


def fetch(dest: Path, name: str, urls, digest: str):
    """Run the helper exactly as its callers do, from a shell that sourced it."""
    command = " ".join([
        f"source {shlex.quote(str(ARTIFACT_SH))} &&",
        "fetch_verified_artifact",
        shlex.quote(str(dest)),
        shlex.quote(name),
        *(shlex.quote(url) for url in urls),
        shlex.quote(digest),
    ])
    return subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=120)


def part_files(directory: Path):
    return sorted(path.name for path in directory.glob("*.part.*"))


class TestVerifiedArtifactFetch(unittest.TestCase):
    def test_a_host_that_cannot_deliver_falls_through_to_the_next(self):
        payload = b"the pinned bytes\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir, ArtifactServer({"/second": payload}) as server:
            dest = Path(tmpdir) / "installer.sh"
            result = fetch(dest, "installer", [server.url("/first"), server.url("/second")], digest)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(dest.read_bytes(), payload)
            self.assertEqual(server.requests, ["/first", "/second"])
            self.assertIn("Warning: installer was not delivered", result.stderr)
            self.assertEqual(part_files(Path(tmpdir)), [])

    def test_a_mismatch_is_terminal_and_the_next_host_is_never_asked(self):
        released = b"the pinned bytes\n"
        digest = hashlib.sha256(released).hexdigest()
        routes = {"/first": b"another version\n", "/second": released}
        with tempfile.TemporaryDirectory() as tmpdir, ArtifactServer(routes) as server:
            dest = Path(tmpdir) / "installer.sh"
            result = fetch(dest, "installer", [server.url("/first"), server.url("/second")], digest)

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(server.requests, ["/first"], "a mismatch must not fall through")
            self.assertFalse(dest.exists(), "a mismatched download must not be left behind")
            self.assertEqual(part_files(Path(tmpdir)), [])
            self.assertIn("installer SHA256 mismatch", result.stderr)
            self.assertIn("no further host is tried", result.stderr)

    def test_no_host_delivering_leaves_nothing_behind(self):
        payload = b"the pinned bytes\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir, ArtifactServer({}) as server:
            dest = Path(tmpdir) / "installer.sh"
            result = fetch(dest, "installer", [server.url("/first"), server.url("/second")], digest)

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(server.requests, ["/first", "/second"])
            self.assertFalse(dest.exists())
            self.assertEqual(part_files(Path(tmpdir)), [])
            self.assertIn("no source could deliver installer", result.stderr)

    def test_a_destination_is_replaced_only_after_its_bytes_are_verified(self):
        payload = b"the pinned bytes\n"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as tmpdir, ArtifactServer({"/only": payload}) as server:
            dest = Path(tmpdir) / "installer.sh"
            dest.write_bytes(b"the previous install\n")
            result = fetch(dest, "installer", [server.url("/only")], digest)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(dest.read_bytes(), payload)
            self.assertEqual(part_files(Path(tmpdir)), [])

    def test_an_unusable_digest_is_refused_before_any_download(self):
        payload = b"the pinned bytes\n"
        with tempfile.TemporaryDirectory() as tmpdir, ArtifactServer({"/only": payload}) as server:
            dest = Path(tmpdir) / "installer.sh"
            result = fetch(dest, "installer", [server.url("/only")], "not-a-digest")

            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(server.requests, [], "nothing may be downloaded for an unusable pin")
            self.assertIn("64-character SHA-256 digest", result.stderr)

    def test_a_missing_host_list_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "installer.sh"
            result = fetch(dest, "installer", [], hashlib.sha256(b"x").hexdigest())

            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("no source host to be fetched from", result.stderr)
            self.assertFalse(dest.exists())


class TestPinnedInstallerHosts(unittest.TestCase):
    COMMIT = "7b3514d1ab8c674050597820d52d55525d4bece7"

    def test_the_commit_is_tried_on_github_first_and_jsdelivr_second(self):
        env = os.environ.copy()
        env["GOWAVE_NODE_INSTALLER_COMMIT"] = self.COMMIT
        result = subprocess.run(
            ["bash", "-c", f"source {shlex.quote(str(NODE_SH))} && pinned_node_installer_urls"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), [
            f"https://raw.githubusercontent.com/aaaSaZaN/gowave-node/{self.COMMIT}/install.sh",
            f"https://cdn.jsdelivr.net/gh/aaaSaZaN/gowave-node@{self.COMMIT}/install.sh",
        ])


def curl_stub(directory: Path, body: bytes):
    """A curl that answers every URL with `body` and records the URL it was asked for."""
    bin_dir = directory / "bin"
    bin_dir.mkdir()
    log = directory / "curl-urls.log"
    payload = directory / "stub-body.bin"
    payload.write_bytes(body)
    stub = bin_dir / "curl"
    stub.write_text(
        "#!/bin/sh\n"
        "url=''\n"
        "target=''\n"
        'while [ "$#" -gt 0 ]; do\n'
        '  case "$1" in\n'
        '    -o) target="$2"; shift 2 ;;\n'
        '    -*) shift ;;\n'
        '    *) url="$1"; shift ;;\n'
        "  esac\n"
        "done\n"
        f'printf \'%s\\n\' "$url" >> "{log}"\n'
        f'if [ -n "$target" ]; then cp "{payload}" "$target"; fi\n'
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return bin_dir, log


class TestPanelAssetVerification(unittest.TestCase):
    """A release asset is checked against SHA256SUMS before the next URL is tried."""

    def test_a_mismatched_asset_aborts_without_falling_through(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target_dir = tmp / "opt_gowave"
            bin_dir, log = curl_stub(tmp, b"another release's bytes\n")
            arch = subprocess.run(
                ["bash", "-c", f'source "{PANEL_SH}" && detect_arch'],
                capture_output=True, text=True, timeout=60,
            ).stdout.strip()
            sums = tmp / "SHA256SUMS"
            # Well-formed digests that the stub's bytes cannot match: the refusal
            # has to come from the byte check, not from SHA256SUMS being unusable.
            sums.write_text(
                f"{'0' * 64}  gowave-linux-{arch}\n"
                f"{'0' * 64}  gowave-frontend.tar.gz\n",
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["GOWAVE_SHA256SUMS"] = str(sums)
            env["PATH"] = f"{bin_dir}:{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", f'source "{PANEL_SH}" && download_panel_release "{target_dir}" v9.9.9'],
                capture_output=True, text=True, env=env, timeout=120,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Checksum mismatch", result.stderr)
            self.assertFalse((target_dir / "gowave-server").exists())

            requested = log.read_text().splitlines()
            self.assertEqual(
                len(requested), 1,
                f"a mismatch must abort instead of trying the next URL, got {requested}",
            )
            self.assertIn(f"gowave-linux-{arch}", requested[0])
            self.assertNotIn("gowave-frontend.tar.gz", requested[0])
            self.assertFalse(
                any("api.github.com" in url for url in requested),
                "a digest mismatch must not fall back to the release API",
            )


if __name__ == "__main__":
    unittest.main()
