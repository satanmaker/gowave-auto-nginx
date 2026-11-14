"""Sentinel-based proof that no secret reaches a retained artifact.

A redaction filter is only as good as the last writer: the artifact tree is
retained and shared, so a single path that forgets ``redact()`` leaks a working
credential. These tests plant unique sentinels, drive the writers the suite
actually uses, and then read the tree back as bytes — a sentinel that survives
anywhere is a failure, whether it sits in an evidence file, ``result.json`` or
``junit.xml``.
"""
import json
import tempfile
import unittest
from pathlib import Path

from tools.live_vps.redaction import clear_secrets, redact, register_secret
from tools.podman_e2e import diagnostics
from tools.podman_e2e.runner import FAIL, PASS, Case, RunContext, Runner

PASSWORD = "AdminPassword-SENTINEL-4f2c9d"
PEM_BODY = "SENTINELPRIVATEKEYBODY7b1e"
PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    f"{PEM_BODY}\n"
    "-----END PRIVATE KEY-----"
)
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJzZW50aW5lbCJ9"
    ".c2VudGluZWwtc2lnbmF0dXJlLXZhbHVl"
)


class TestRedactionFilter(unittest.TestCase):
    """What the filter removes, and the one trade-off it makes on purpose."""

    def setUp(self):
        clear_secrets()
        self.addCleanup(clear_secrets)

    def test_a_registered_secret_never_survives(self):
        register_secret(PASSWORD)
        self.assertEqual(redact(f'credentials: password="{PASSWORD}"'), 'credentials: password="[REDACTED]"')

    def test_the_longest_registered_secret_wins(self):
        register_secret("sentinel-secret")
        register_secret("sentinel-secret-longer")
        self.assertEqual(redact("sentinel-secret-longer and sentinel-secret"), "[REDACTED] and [REDACTED]")

    def test_a_private_key_block_is_removed_whole(self):
        redacted = redact(f"before\n{PRIVATE_KEY}\nafter")
        self.assertNotIn(PEM_BODY, redacted)
        self.assertNotIn("BEGIN PRIVATE KEY", redacted)
        self.assertIn("before", redacted)
        self.assertIn("after", redacted)

    def test_a_jwt_is_removed(self):
        self.assertNotIn(JWT, redact(f"Authorization: Bearer {JWT}"))

    def test_a_three_character_value_is_not_registered(self):
        # Redacting every short value would shred ordinary prose, so the registry
        # only takes values of four characters or more. The cost is named here
        # rather than discovered later.
        register_secret("abc")
        self.assertEqual(redact("abc"), "abc")

    def test_redaction_is_idempotent(self):
        register_secret(PASSWORD)
        once = redact(f"{PASSWORD} {PRIVATE_KEY}")
        self.assertEqual(redact(once), once)

    def test_ordinary_prose_is_untouched(self):
        register_secret(PASSWORD)
        text = "the panel route answered 502 while the data plane kept carrying payload"
        self.assertEqual(redact(text), text)


class TestArtifactTreeHoldsNoSentinel(unittest.TestCase):
    """The tree the operator keeps, read back as bytes."""

    def setUp(self):
        clear_secrets()
        self.addCleanup(clear_secrets)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def context(self) -> RunContext:
        context = RunContext("aio", self.root, budget_seconds=60, run_id="podman-aio-redaction-abcdef12")
        self.addCleanup(context.run_cleanup)
        return context

    def tree_bytes(self, context: RunContext):
        for path in sorted(context.artifact_dir.rglob("*")):
            if path.is_file():
                yield path, path.read_bytes()

    def result(self, context: RunContext):
        return json.loads((context.artifact_dir / "result.json").read_text())

    def test_every_writer_scrubs_its_output(self):
        context = self.context()
        context.write_secret("admin-password", PASSWORD)

        def evidence(ctx):
            ctx.evidence_text("install.log", f"password={PASSWORD}\n{PRIVATE_KEY}\nBearer {JWT}\n")
            return {"observed": True}

        runner = Runner(context)
        runner.add(Case("AIO-EVIDENCE", "aio", evidence))
        runner.add(Case("AIO-FAILED", "aio", lambda ctx: (_ for _ in ()).throw(AssertionError(f"login failed with {PASSWORD}"))))
        self.assertEqual(runner.execute(), 1)

        for sentinel in (PASSWORD, PEM_BODY, JWT):
            for path, blob in self.tree_bytes(context):
                self.assertNotIn(
                    sentinel.encode(), blob,
                    f"{path.relative_to(context.artifact_dir)} still holds a planted secret",
                )
        self.assertIn("[REDACTED]", (context.artifact_dir / "evidence" / "install.log").read_text())
        report = self.result(context)
        self.assertIn("[REDACTED]", report["cases"][1]["message"])
        self.assertIn("[REDACTED]", (context.artifact_dir / "junit.xml").read_text())

    def test_the_secret_store_is_outside_the_artifact_tree(self):
        context = self.context()
        path = context.write_secret("admin-password", PASSWORD)
        self.assertNotIn(context.artifact_dir, path.parents)
        self.assertEqual(path.read_text(), PASSWORD)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual([p for p, _ in self.tree_bytes(context)], [])

    def test_a_secret_name_cannot_be_a_path(self):
        context = self.context()
        for name in ("../../escape", ".hidden", "nested/name"):
            with self.assertRaises(ValueError):
                context.write_secret(name, PASSWORD)

    def test_a_writer_that_skips_the_filter_fails_the_run(self):
        context = self.context()
        context.write_secret("admin-password", PASSWORD)

        def leaky(ctx):
            # Exactly the mistake the audit exists to catch: a writer that talks
            # to the artifact directory without passing its text through redact().
            (ctx.artifact_dir / "leak.txt").write_text(f"password={PASSWORD}\n")
            return {}

        runner = Runner(context)
        runner.add(Case("AIO-LEAKY", "aio", leaky))
        self.assertEqual(runner.execute(), 1)
        report = self.result(context)
        self.assertEqual(report["overall"], FAIL)
        self.assertEqual(report["environment"]["redaction_audit"]["offences"], ["leak.txt"])
        redaction_case = [case for case in report["cases"] if case["id"] == "REDACTION"]
        self.assertEqual(len(redaction_case), 1)
        self.assertEqual(redaction_case[0]["status"], FAIL)
        self.assertIn("leak.txt", redaction_case[0]["message"])
        self.assertNotIn(PASSWORD, (context.artifact_dir / "leak.txt").read_text())
        for path, blob in self.tree_bytes(context):
            self.assertNotIn(PASSWORD.encode(), blob, f"{path.name} still holds the secret after the scrub")

    def test_a_clean_run_records_what_it_audited(self):
        context = self.context()

        def evidence(ctx):
            ctx.evidence_text("probe.txt", "listeners: 443 nginx\n")
            return {}

        runner = Runner(context)
        runner.add(Case("AIO-CLEAN", "aio", evidence))
        self.assertEqual(runner.execute(), 0)
        audit = self.result(context)["environment"]["redaction_audit"]
        self.assertEqual(audit["offences"], [])
        self.assertEqual(audit["skipped_non_utf8"], [])
        self.assertGreaterEqual(audit["files"], 3)

    def test_a_non_utf8_artifact_is_named_instead_of_assumed_clean(self):
        context = self.context()

        def binary(ctx):
            (ctx.artifact_dir / "capture.bin").write_bytes(b"\xff\xfe\x00binary")
            return {}

        runner = Runner(context)
        runner.add(Case("AIO-BINARY", "aio", binary))
        self.assertEqual(runner.execute(), 0)
        audit = self.result(context)["environment"]["redaction_audit"]
        self.assertEqual(audit["skipped_non_utf8"], ["capture.bin"])
        self.assertEqual(audit["offences"], [])


class TestDiagnosticsNeverPrintValues(unittest.TestCase):
    """The failure bundle may read an environment file, but only for its keys."""

    def test_the_operator_probe_lists_environment_keys_only(self):
        operator = next(area for area in diagnostics.AREAS if area.name == "operator")
        for line in operator.script.splitlines():
            if ".env" in line:
                self.assertIn(
                    "sed -n 's/^", line,
                    "an environment file must be read for its key names, never dumped",
                )

    def test_no_probe_dumps_a_key_material_path(self):
        for area in diagnostics.AREAS:
            for line in area.script.splitlines():
                for marker in ("cat /etc/letsencrypt/live/", "cat /root/gowave-credentials.txt"):
                    self.assertNotIn(marker, line, f"{area.name} must not print key material")


if __name__ == "__main__":
    unittest.main()
