#!/usr/bin/env python3
"""Suite nonroot: privilege scope contract for the Podman E2E gate."""
import sys
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import preconditions  # noqa: E402
from tools.podman_e2e.podman import PodmanUnavailable  # noqa: E402


class TestPodmanPrivilegeScopes(unittest.TestCase):
    def test_unknown_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            preconditions.scope("rootless-but-magical")

    def test_rootless_scope_claims_only_self_checks(self):
        selected = preconditions.scope("rootless")
        self.assertFalse(selected.rootful)
        self.assertEqual(selected.checks, preconditions.ROOTLESS_CHECKS)
        self.assertNotIn("product-suite", selected.checks)

    def test_rootless_scope_is_available_without_root(self):
        self.assertEqual(preconditions.assert_scope_available("rootless").name, "rootless")

    def test_rootful_scope_fails_closed_for_unprivileged_invocation(self):
        with self.assertRaises(PodmanUnavailable) as raised:
            preconditions.assert_scope_available("rootful")
        self.assertIn("requires rootful Podman", str(raised.exception))

    def test_matrix_declares_the_same_scopes_as_the_code(self):
        matrix = yaml.safe_load((REPO_ROOT / "tests" / "cases" / "matrix.yaml").read_text(encoding="utf-8"))
        declared = matrix["privilege_scopes"]
        self.assertEqual(set(declared), set(preconditions.SCOPES))
        self.assertEqual(
            tuple(declared["rootless"]["checks"]),
            preconditions.ROOTLESS_CHECKS,
        )
        self.assertEqual(
            tuple(declared["rootful"]["required_for"]),
            preconditions.ROOTFUL_ONLY_REASONS,
        )
        self.assertEqual(declared["rootful"]["claim"], "product acceptance")
        self.assertEqual(declared["rootless"]["claim"], "static self-checks only")


if __name__ == "__main__":
    unittest.main()
