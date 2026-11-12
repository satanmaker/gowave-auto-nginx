#!/usr/bin/env python3
"""Podman-only Master address override contract tests."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADDRESS_SH = REPO_ROOT / "modules" / "address.sh"

ASSIGNED = "2: eth0    inet 10.89.0.5/24 brd 10.89.0.255 scope global eth0\n"


class TestPodmanAddressOverride(unittest.TestCase):
    def _run(self, override, mode, extra_env=None):
        env = os.environ.copy()
        for name in (
            "GOWAVE_PODMAN_MASTER_ADDRESS",
            "GOWAVE_PODMAN_TEST_MODE",
            "GOWAVE_PODMAN_NETWORK_CIDR",
            "GOWAVE_PODMAN_NETWORK_INTERFACE",
        ):
            env.pop(name, None)
        if override is not None:
            env["GOWAVE_PODMAN_MASTER_ADDRESS"] = override
        if mode is not None:
            env["GOWAVE_PODMAN_TEST_MODE"] = mode
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", "-c", f'source "{ADDRESS_SH}" && resolve_panel_ipv4'],
            capture_output=True, text=True, env=env,
        )

    def _fake_tool_env(self, tmpdir, tool, output):
        bin_dir = Path(tmpdir) / "bin"
        bin_dir.mkdir()
        script = bin_dir / tool
        script.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' '{output}'\n")
        script.chmod(0o755)
        return {"PATH": f"{bin_dir}:{os.environ['PATH']}"}

    def test_override_requires_explicit_test_mode(self):
        res = self._run("10.89.0.5", mode=None)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("requires GOWAVE_PODMAN_TEST_MODE=1", res.stderr)

    def test_test_mode_requires_an_explicit_address(self):
        res = self._run(None, mode="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("requires GOWAVE_PODMAN_MASTER_ADDRESS", res.stderr)

    def test_public_address_is_rejected(self):
        res = self._run("8.8.8.8", mode="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("must be a private address", res.stderr)

    def test_address_must_be_assigned_on_this_host(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self._fake_tool_env(tmpdir, "ip", ASSIGNED.strip())

            assigned = self._run("10.89.0.5", mode="1", extra_env=env)
            self.assertEqual(assigned.returncode, 0, assigned.stderr)
            self.assertEqual(assigned.stdout.strip(), "10.89.0.5")

            unassigned = self._run("10.89.0.6", mode="1", extra_env=env)
            self.assertNotEqual(unassigned.returncode, 0)
            self.assertIn("is not assigned to this host", unassigned.stderr)

    def test_network_membership_is_enforced_when_a_cidr_is_given(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self._fake_tool_env(tmpdir, "ip", ASSIGNED.strip())

            inside = self._run("10.89.0.5", mode="1", extra_env={**env, "GOWAVE_PODMAN_NETWORK_CIDR": "10.89.0.0/24"})
            self.assertEqual(inside.returncode, 0, inside.stderr)

            outside = self._run("10.89.0.5", mode="1", extra_env={**env, "GOWAVE_PODMAN_NETWORK_CIDR": "10.90.0.0/24"})
            self.assertNotEqual(outside.returncode, 0)
            self.assertIn("outside the run-scoped network", outside.stderr)

    def test_interface_membership_is_enforced_when_named(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self._fake_tool_env(tmpdir, "ip", ASSIGNED.strip())

            on_interface = self._run(
                "10.89.0.5", mode="1",
                extra_env={**env, "GOWAVE_PODMAN_NETWORK_INTERFACE": "eth0"},
            )
            self.assertEqual(on_interface.returncode, 0, on_interface.stderr)

            wrong_interface = self._run(
                "10.89.0.5", mode="1",
                extra_env={**env, "GOWAVE_PODMAN_NETWORK_INTERFACE": "eth1"},
            )
            self.assertNotEqual(wrong_interface.returncode, 0)
            self.assertIn("run-scoped interface eth1", wrong_interface.stderr)

    def test_invalid_address_is_rejected(self):
        res = self._run("not-an-address", mode="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Invalid Podman Master address", res.stderr)

    def test_public_path_is_untouched_outside_podman_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env = self._fake_tool_env(tmpdir, "curl", "203.0.113.9")
            res = self._run(None, mode=None, extra_env=env)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "203.0.113.9")

    def test_ipv6_is_suppressed_in_podman_mode(self):
        env = os.environ.copy()
        env["GOWAVE_PODMAN_TEST_MODE"] = "1"
        res = subprocess.run(
            ["bash", "-c", f'source "{ADDRESS_SH}" && resolve_panel_ipv6'],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout, "")


if __name__ == "__main__":
    unittest.main()
