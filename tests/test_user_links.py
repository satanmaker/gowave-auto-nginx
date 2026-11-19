"""Tests for `gowave-auto.sh user links` output.

Regression: the CLI advertised /v2ray-json as the Xray subscription URL, but v2rayNG
and NekoBox only accept a base64 body of share links, so imports silently failed.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALLER = REPO_ROOT / "gowave-auto.sh"


class TestUserLinks(unittest.TestCase):
    def _run(self, state_file, *args):
        env = dict(os.environ)
        env["GOWAVE_STATE_FILE"] = state_file
        return subprocess.run(
            ["bash", str(INSTALLER), "user", "links", *args],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def test_prints_base64_url_for_v2rayng_first(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state.json"
            state.write_text(json.dumps({
                "panelDomain": "panel.example.com",
                "defaultUserShortUuid": "abc123token",
            }))
            res = self._run(str(state), "default-user")
            self.assertEqual(res.returncode, 0, res.stderr)
            out = res.stdout
            self.assertIn("https://panel.example.com/api/sub/abc123token\n", out)
            self.assertIn("/api/sub/abc123token/v2ray-json", out)
            self.assertIn("/api/sub/abc123token/mihomo", out)
            self.assertIn("/api/sub/abc123token/clash", out)
            self.assertIn("v2rayNG", out)
            # The base64 endpoint must be advertised before the JSON one.
            self.assertLess(out.index("/api/sub/abc123token\n"),
                            out.index("/api/sub/abc123token/v2ray-json"))

    def test_falls_back_to_identifier_without_state(self):
        res = self._run("/nonexistent/state.json", "bob")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("https://localhost/api/sub/bob\n", res.stdout)

    def test_default_user_when_argument_omitted(self):
        res = self._run("/nonexistent/state.json")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("GoWave Subscription Links for user: default-user", res.stdout)


if __name__ == "__main__":
    unittest.main()
