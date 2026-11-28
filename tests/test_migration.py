#!/usr/bin/env python3
"""An installed deployment is migrated, not re-derived.

A host installed before the explicit ownership record has no `domainOwnership`
in its state. The installer must not guess a cover apex from the transport name
and must not overwrite the record it does hold: it reads what the host actually
serves, prints that beside any ambiguity, and waits for the operator's own word.
Nothing in the inspection writes, so a declined preview leaves the host exactly
as it was.
"""
import json
import os
import pty
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

MIGRATION_SH = REPO_ROOT / "modules" / "migration.sh"
GOWAVE_AUTO = REPO_ROOT / "gowave-auto.sh"

LEGACY_STATE = {
    "schemaVersion": 2,
    "installationMode": "all-in-one",
    "panelDomain": "panel.example.com",
    "realityDomain": "cdn.example.com",
    "localNodeUuid": "node-uuid-1",
    "profileUuid": "profile-uuid-1",
    "nodes": [{"name": "local-node", "uuid": "node-uuid-1", "hostUuids": ["host-1", "host-2"]}],
}

EXPLICIT_STATE = dict(
    LEGACY_STATE,
    domainOwnership={
        "role": "master",
        "names": {
            "panel": "panel.example.com",
            "reality": "cdn.example.com",
            "cover": "cover.example.com",
            "coverAlias": "www.cover.example.com",
        },
        "sans": {"panel": ["panel.example.com"], "reality": ["cdn.example.com", "cover.example.com"]},
    },
    certificateLineages={
        "panel": "/etc/letsencrypt/live/panel.example.com",
        "reality": "/etc/letsencrypt/live/cdn.example.com",
    },
)

DECOY_VHOST = """\
# Managed by GoWave Auto NGINX: REALITY Fallback Camouflage Decoy
server {
    listen 127.0.0.1:9443 ssl http2 proxy_protocol;
    server_name cdn.example.com cover.example.com www.cover.example.com;
    ssl_certificate /etc/letsencrypt/live/cdn.example.com/fullchain.pem;
}
"""

PANEL_VHOST = """\
server {
    listen 443 ssl;
    server_name panel.example.com;
    ssl_certificate /etc/letsencrypt/live/panel.example.com/fullchain.pem;
}
"""


def write_state(directory, state):
    path = Path(directory) / "state.json"
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return path


def write_conf_dir(directory, decoy=DECOY_VHOST, panel=PANEL_VHOST, vision=None):
    conf = Path(directory) / "conf.d"
    conf.mkdir(parents=True, exist_ok=True)
    if decoy is not None:
        (conf / "gowave-decoy.conf").write_text(decoy, encoding="utf-8")
    if panel is not None:
        (conf / "gowave-panel.conf").write_text(panel, encoding="utf-8")
    if vision is not None:
        (conf / "gowave-vision-fallback.conf").write_text(vision, encoding="utf-8")
    return conf


def run(function, *args, stdin="", env=None, extra_source=""):
    """Source the module and call one function the way the installer does."""
    command = f'source {shlex.quote(str(MIGRATION_SH))}\n{extra_source}{function}'
    for argument in args:
        command += " " + shlex.quote(str(argument))
    merged = {key: value for key, value in os.environ.items() if key != "GOWAVE_MIGRATE_EXISTING"}
    if env:
        merged.update(env)
    return subprocess.run(
        ["bash", "-c", command], input=stdin, capture_output=True, text=True, env=merged,
    )


def run_with_terminal(command, answer, env=None):
    """Run a command with a real terminal on stdin, so the prompt path is reachable."""
    merged = {key: value for key, value in os.environ.items() if key != "GOWAVE_MIGRATE_EXISTING"}
    if env:
        merged.update(env)
    master, slave = pty.openpty()
    process = subprocess.Popen(
        ["bash", "-c", command], stdin=slave, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, env=merged,
    )
    os.close(slave)
    try:
        try:
            os.write(master, answer.encode())
        except OSError:
            pass
        output, _ = process.communicate(timeout=60)
    finally:
        os.close(master)
    return subprocess.CompletedProcess(process.args, process.returncode, output, output)


class TestMigrationState(unittest.TestCase):
    """What the installer may believe about the host it finds itself on."""

    def test_a_missing_state_is_a_first_install_not_a_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = write_conf_dir(directory)
            result = run("migration_inspect_state", Path(directory) / "state.json", conf)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("state=absent", result.stdout)
        self.assertIn("action=none", result.stdout)
        self.assertIn("reason=no deployment state on this host", result.stdout)

    def test_a_fresh_host_reads_its_absence_before_python3_exists(self):
        # The inspection runs before `bootstrap_early_tools` installs python3, so
        # a host with no state file must be classified without the interpreter. A
        # python3 that is present but refuses every call proves whether the absent
        # path still depends on it: on the unfixed code the stub is invoked and
        # the run fails instead of reporting a first install.
        with tempfile.TemporaryDirectory() as directory:
            stub_dir = Path(directory) / "bin"
            stub_dir.mkdir()
            stub = stub_dir / "python3"
            stub.write_text("#!/bin/sh\necho PYTHON3_CALLED >&2\nexit 127\n", encoding="utf-8")
            stub.chmod(0o755)
            conf = write_conf_dir(directory)
            env = {"PATH": f"{stub_dir}:{os.environ['PATH']}"}
            result = run("migration_inspect_state", Path(directory) / "state.json", conf, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("state=absent", result.stdout)
        self.assertIn("action=none", result.stdout)
        self.assertNotIn("PYTHON3_CALLED", result.stderr)

    def test_a_symlinked_state_is_refused_instead_of_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            real = write_state(directory, LEGACY_STATE)
            link = Path(directory) / "linked.json"
            link.symlink_to(real)
            result = run("migration_state_facts", link)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not a regular file", result.stderr)

    def test_an_unreadable_state_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("{not json", encoding="utf-8")
            result = run("migration_state_facts", path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot read", result.stderr)

    def test_a_state_this_installer_is_older_than_blocks_the_run(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = write_conf_dir(directory)
            state = write_state(directory, dict(LEGACY_STATE, schemaVersion=3))
            result = run("migration_inspect_state", state, conf)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("action=block", result.stdout)
        self.assertIn("schema 3 is newer", result.stdout)

    def test_legacy_state_is_classified_for_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = write_conf_dir(directory)
            state = write_state(directory, LEGACY_STATE)
            result = run("migration_inspect_state", state, conf)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("ownership=legacy", result.stdout)
        self.assertIn("action=confirm", result.stdout)
        self.assertIn("legacy state records no explicit cover ownership", result.stdout)

    def test_an_explicit_record_needs_no_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = write_conf_dir(directory)
            state = write_state(directory, EXPLICIT_STATE)
            result = run("migration_inspect_state", state, conf)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ownership=explicit", result.stdout)
        self.assertIn("action=none", result.stdout)

    def test_the_registered_identity_is_counted_before_it_is_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            conf = write_conf_dir(directory)
            state = write_state(directory, LEGACY_STATE)
            result = run("migration_inspect_state", state, conf)
        self.assertIn("recorded.nodes=1", result.stdout)
        self.assertIn("recorded.node_uuids=1", result.stdout)
        self.assertIn("recorded.host_uuids=1", result.stdout)


class TestCoverCandidate(unittest.TestCase):
    """The cover apex is adopted only when the host itself names it."""

    def inspect(self, state, **vhosts):
        with tempfile.TemporaryDirectory() as directory:
            write_state(directory, state)
            conf = write_conf_dir(directory, **vhosts)
            return run("migration_inspect_state", Path(directory) / "state.json", conf)

    def test_the_decoy_apex_and_its_alias_are_adopted(self):
        result = self.inspect(LEGACY_STATE)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("candidate_cover=cover.example.com", result.stdout)
        self.assertIn("candidate_alias=www.cover.example.com", result.stdout)
        self.assertIn("ambiguity=\n", result.stdout)

    def test_two_apexes_are_an_ambiguity_and_nothing_is_adopted(self):
        decoy = DECOY_VHOST.replace(
            "server_name cdn.example.com cover.example.com www.cover.example.com;",
            "server_name cdn.example.com cover.example.com second.example.com;",
        )
        result = self.inspect(LEGACY_STATE, decoy=decoy)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("candidate_cover=\n", result.stdout)
        self.assertIn("more than one cover apex", result.stdout)
        self.assertIn("cover.example.com second.example.com", result.stdout)

    def test_an_alias_without_an_apex_is_an_ambiguity(self):
        decoy = DECOY_VHOST.replace(
            "server_name cdn.example.com cover.example.com www.cover.example.com;",
            "server_name cdn.example.com www.cover.example.com;",
        )
        result = self.inspect(LEGACY_STATE, decoy=decoy)
        self.assertIn("candidate_cover=\n", result.stdout)
        self.assertIn("only an alias", result.stdout)

    def test_a_decoy_that_names_only_transport_names_proves_no_apex(self):
        decoy = DECOY_VHOST.replace(
            "server_name cdn.example.com cover.example.com www.cover.example.com;",
            "server_name cdn.example.com;",
        )
        result = self.inspect(LEGACY_STATE, decoy=decoy)
        self.assertIn("candidate_cover=\n", result.stdout)
        self.assertIn("names no cover apex", result.stdout)

    def test_a_token_that_is_not_a_dns_name_is_not_adopted(self):
        decoy = DECOY_VHOST.replace(
            "server_name cdn.example.com cover.example.com www.cover.example.com;",
            "server_name cdn.example.com local;",
        )
        result = self.inspect(LEGACY_STATE, decoy=decoy)
        self.assertIn("candidate_cover=\n", result.stdout)
        self.assertIn("not a DNS name", result.stdout)

    def test_a_symlinked_managed_vhost_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, LEGACY_STATE)
            conf = Path(directory) / "conf.d"
            conf.mkdir()
            target = Path(directory) / "elsewhere.conf"
            target.write_text(DECOY_VHOST, encoding="utf-8")
            (conf / "gowave-decoy.conf").symlink_to(target)
            result = run("migration_inspect_state", state, conf)
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not a regular file", result.stderr)

    def test_a_listener_serving_another_path_than_recorded_is_reported_as_drift(self):
        state = dict(
            EXPLICIT_STATE,
            certificateLineages={
                "panel": "/etc/letsencrypt/live/panel.example.com-0001",
                "reality": "/etc/letsencrypt/live/cdn.example.com",
            },
        )
        result = self.inspect(state)
        self.assertIn(
            "rendered.conflict=the Panel listener serves /etc/letsencrypt/live/panel.example.com "
            "but state records /etc/letsencrypt/live/panel.example.com-0001",
            result.stdout,
        )


class TestMigrationConfirmation(unittest.TestCase):
    """Silence is not consent: a legacy host changes only on an explicit answer."""

    def test_without_a_terminal_the_run_stops_and_names_the_confirmation_input(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, LEGACY_STATE)
            conf = write_conf_dir(directory)
            before = state.read_bytes(), sorted(path.name for path in conf.iterdir())
            result = run("migration_confirm_existing", state, conf, stdin="y\n")
            after = state.read_bytes(), sorted(path.name for path in conf.iterdir())
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("needs an explicit migration confirmation", result.stderr)
        self.assertIn("GOWAVE_MIGRATE_EXISTING=yes", result.stderr)
        self.assertEqual(before, after, "the inspection wrote to the host")

    def test_a_declined_preview_changes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, LEGACY_STATE)
            conf = write_conf_dir(directory)
            before = state.read_bytes()
            command = (
                f"source {shlex.quote(str(MIGRATION_SH))} && "
                f"migration_confirm_existing {shlex.quote(str(state))} {shlex.quote(str(conf))}"
            )
            result = run_with_terminal(command, "n\n")
            after = state.read_bytes()
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn("Migration declined. The existing deployment is unchanged.", result.stdout)
        self.assertEqual(before, after, "a declined migration wrote to the host")

    def test_a_confirmed_preview_proceeds(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, LEGACY_STATE)
            conf = write_conf_dir(directory)
            command = (
                f"source {shlex.quote(str(MIGRATION_SH))} && "
                f"migration_confirm_existing {shlex.quote(str(state))} {shlex.quote(str(conf))}"
            )
            result = run_with_terminal(command, "y\n")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Migration confirmed.", result.stdout)

    def test_the_environment_confirmation_proceeds_without_a_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, LEGACY_STATE)
            conf = write_conf_dir(directory)
            result = run("migration_confirm_existing", state, conf,
                         env={"GOWAVE_MIGRATE_EXISTING": "yes"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("confirmed by GOWAVE_MIGRATE_EXISTING=yes", result.stdout)

    def test_an_explicit_record_is_not_asked_about(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, EXPLICIT_STATE)
            conf = write_conf_dir(directory)
            result = run("migration_confirm_existing", state, conf)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_the_preview_names_the_identity_and_the_records_it_keeps(self):
        with tempfile.TemporaryDirectory() as directory:
            state = write_state(directory, LEGACY_STATE)
            conf = write_conf_dir(directory)
            result = run("migration_confirm_existing", state, conf)
        self.assertIn("Recorded panel name:   panel.example.com", result.stdout)
        self.assertIn("Recorded REALITY name: cdn.example.com", result.stdout)
        self.assertIn("Cover apex to adopt:   cover.example.com", result.stdout)
        self.assertIn("Panel certificate:     /etc/letsencrypt/live/panel.example.com", result.stdout)
        self.assertIn("Registered identity:   1 node(s), 1 with a UUID, 1 with Host records", result.stdout)

    def test_the_cover_is_adopted_only_for_a_legacy_host(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy = write_state(directory, LEGACY_STATE)
            conf = write_conf_dir(directory)
            adopted = run("migration_adopted_cover", legacy, conf)
            explicit = write_state(directory, EXPLICIT_STATE)
            kept = run("migration_adopted_cover", explicit, conf)
        self.assertEqual(adopted.returncode, 0, adopted.stderr)
        self.assertEqual(adopted.stdout.strip(), "cover.example.com")
        self.assertEqual(kept.stdout.strip(), "",
                         "an explicit record must not be re-adopted over this run's own selection")


class TestNodeEdgeMigration(unittest.TestCase):
    """Re-applying a Worker rewrites its edge; the operator says so first."""

    ARGS = ("node-02", "worker.example.com", "reality.example.com", "vision.example.com", "3002")

    def preview(self, stdin="", env=None):
        return run("node_confirm_edge_migration", *self.ARGS, stdin=stdin, env=env)

    def test_the_preview_names_every_identity_and_the_records_it_reuses(self):
        result = self.preview()
        self.assertIn("Edge migration preview for Worker node-02:", result.stdout)
        self.assertIn("worker.example.com -> 127.0.0.1:7443", result.stdout)
        self.assertIn("reality.example.com -> 127.0.0.1:8443", result.stdout)
        self.assertIn("vision.example.com -> 127.0.0.1:8444", result.stdout)
        self.assertIn("Node API stays on 3002", result.stdout)
        self.assertIn("node UUID, profile and Host records are reused", result.stdout)

    def test_a_worker_without_vision_shows_no_vision_line(self):
        result = run("node_confirm_edge_migration", "node-02", "worker.example.com",
                     "reality.example.com", "", "3002")
        self.assertNotIn("vision.example.com", result.stdout)

    def test_without_a_terminal_it_refuses_and_names_the_reapply_path(self):
        result = self.preview()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no terminal to confirm it on", result.stderr)
        self.assertIn("node reapply", result.stderr)

    def test_the_environment_confirmation_proceeds(self):
        result = self.preview(env={"GOWAVE_MIGRATE_EXISTING": "yes"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("confirmed by GOWAVE_MIGRATE_EXISTING=yes", result.stdout)

    def test_a_declined_preview_opens_nothing(self):
        command = (
            f"source {shlex.quote(str(MIGRATION_SH))} && node_confirm_edge_migration "
            "node-02 worker.example.com reality.example.com '' 3002"
        )
        result = run_with_terminal(command, "n\n")
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn("Migration declined. The Worker is unchanged.", result.stdout)


class TestMigrationWiring(unittest.TestCase):
    """The gate sits where it can stop the run, not after something has changed."""

    @classmethod
    def setUpClass(cls):
        cls.text = GOWAVE_AUTO.read_text(encoding="utf-8")
        cls.install = cls.text[cls.text.index("cmd_install() {"):cls.text.index("\ncmd_node() {")]
        cls.reapply = cls.text.split("        reapply)", 1)[1].split("        *)", 1)[0]

    def test_the_install_inspects_before_it_changes_anything(self):
        gate = self.install.index("migration_confirm_existing")
        for later in ("select_acme_lineage", "record_certificate_lineages",
                      "record_domain_ownership", "bootstrap_early_tools"):
            self.assertLess(gate, self.install.index(later), later)

    def test_a_declined_migration_returns_before_the_next_step(self):
        branch = self.install[self.install.index("migration_confirm_existing"):]
        declined = branch.index("3)")
        self.assertIn("Existing deployment left unchanged.", branch[declined:declined + 200])
        self.assertLess(declined, branch.index("preflight_require_direct_dns"))

    def test_the_selected_cover_is_never_overridden_by_the_adopted_one(self):
        guarded = self.install.index('${GOWAVE_COVER_DOMAIN+set}')
        adopted = self.install.index("migration_adopted_cover")
        self.assertLess(guarded, adopted)

    def test_reapply_confirms_before_it_streams_the_payload(self):
        confirm = self.reapply.index("node_confirm_edge_migration")
        self.assertLess(confirm, self.reapply.index("remote_payload"))
        self.assertIn("GOWAVE_MIGRATE_EXISTING=yes", self.reapply)
        # A declined preview is the operator's answer, not a failed re-apply: the
        # branch returns success without opening a session.
        declined = self.reapply[self.reapply.index("migrate_rc"):]
        self.assertIn("if (( migrate_rc == 3 )); then", declined)
        self.assertLess(declined.index("return 0"), declined.index("remote_payload"))

    def test_the_module_is_sourced_by_the_installer(self):
        self.assertIn('source "$SCRIPT_DIR/modules/migration.sh"', self.text)


if __name__ == "__main__":
    unittest.main()
