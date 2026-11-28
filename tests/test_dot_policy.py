#!/usr/bin/env python3
"""Suite nonroot: the DoT policy is parsed, applied per policy and reported honestly.

The helper owns three policy values: `off` writes no managed document,
`best-effort` writes an `opportunistic` drop-in that may degrade to plain DNS,
and `required` writes `yes` and must be read back as strict. `prepare_dns`
reports the applied policy, the control result and the recovery outcome
separately, so a caller can tell "DoT is on" from "DoT failed and the original
resolver was restored".

Each case runs a disposable host: a temporary root holding the drop-in,
`/etc/resolv.conf` and `/etc/os-release`, with every command the helper calls
answered by a recorder. The last group runs the shell wrapper in
`modules/security.sh` against a stub helper, which is where the policy becomes
a continue-or-stop decision.
"""
from datetime import datetime, timezone
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from modules import security_report as reports
from modules.deployment_state import StateError

REPO_ROOT = Path(__file__).resolve().parent.parent
MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
SECURITY_SH = REPO_ROOT / "modules" / "security.sh"
DROPIN = "etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf"
SERVERS = "1.1.1.1#one.one.one.one 1.0.0.1#one.one.one.one 8.8.8.8#dns.google 8.8.4.4#dns.google"
RESOLV_DNS = f"Global: {SERVERS}\n"


def load_managed():
    spec = importlib.util.spec_from_file_location("managed_dot", str(MANAGED_PY))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHost:
    """Answers the commands `prepare_dns` uses; no host state is touched.

    `tls_blocked` stands in for a network that drops the encrypted path: the
    resolver accepts the configuration but every uncached query fails, which is
    what the helper has to notice instead of trusting the mode it wrote.
    """

    def __init__(self, mode='s "opportunistic"', dns=RESOLV_DNS, fail_getent_after=0, tls_blocked=False):
        self.mode = mode
        self.dns = dns
        self.fail_getent_after = fail_getent_after
        self.tls_blocked = tls_blocked
        self.getent = 0
        self.calls = []

    def names(self):
        return [args[0] for args in self.calls]

    def __call__(self, *args, check=True):
        self.calls.append(args)
        name, rest = args[0], args[1:]
        if name == 'busctl':
            return self.mode
        if name == 'resolvectl':
            if rest[:1] == ('query',) and self.tls_blocked:
                raise ValueError('query failed (encrypted path blocked)')
            return self.dns if rest[:1] == ('dns',) else ''
        if name == 'getent':
            self.getent += 1
            if self.fail_getent_after and self.getent > self.fail_getent_after:
                raise ValueError('name resolution failed')
            return ''
        if name == 'apt-get':
            return ''
        if name == 'systemctl':
            if rest[:1] == ('is-active',):
                return 'inactive' if '--quiet' in rest else 'active'
            if rest[:1] == ('is-enabled',):
                return 'enabled'
            return ''
        raise AssertionError(f"unexpected command: {args}")


class DotHost:
    """A disposable root; the subclass supplies the TestCase base."""
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8")
        self.resolv = self.root / "etc/resolv.conf"
        self.resolv.write_text('nameserver 192.0.2.53\n', encoding="utf-8")

    def prepare(self, host, policy=None, state=None):
        managed = load_managed()
        # This root was created by the suite's own user, so it stands in for the
        # root-owned tree a real install meets. The unpatched owner rule is
        # exercised against a genuinely root-owned root in `tests/test_root.py`.
        managed.PROJECT_OWNER_UID = os.getuid()
        with mock.patch.object(managed, "command", host):
            return managed.prepare_dns(root=self.root, state=state, policy=policy), host

    def dropin(self):
        return self.root / DROPIN


class TestDotPolicy(DotHost, unittest.TestCase):
    def test_the_default_is_best_effort_and_can_be_overridden(self):
        managed = load_managed()
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(managed.dot_policy(), 'best-effort')
        with mock.patch.dict(os.environ, {'GOWAVE_DOT_POLICY': ' required '}, clear=True):
            self.assertEqual(managed.dot_policy(), 'required')
        with mock.patch.dict(os.environ, {'GOWAVE_DOT_POLICY': 'required'}, clear=True):
            # An explicit argument wins over the environment.
            self.assertEqual(managed.dot_policy('off'), 'off')

    def test_an_unknown_policy_names_the_value_and_the_choices(self):
        managed = load_managed()
        with self.assertRaisesRegex(ValueError, 'Unsupported DNS-over-TLS policy: sometimes'):
            managed.dot_policy('sometimes')
        with self.assertRaisesRegex(ValueError, 'off, best-effort, required'):
            managed.dot_policy('sometimes')

    def test_only_written_policies_have_a_document(self):
        managed = load_managed()
        self.assertIn('DNSOverTLS=opportunistic', managed.dot_content('best-effort'))
        self.assertIn('DNSOverTLS=yes', managed.dot_content('required'))
        with self.assertRaisesRegex(ValueError, 'Unsupported DNS-over-TLS policy: off'):
            managed.dot_content('off')

    def test_best_effort_is_written_and_read_back_as_opportunistic(self):
        result, host = self.prepare(FakeHost(), policy='best-effort')
        self.assertEqual(result['status'], 'configured', result)
        self.assertEqual(result['policy'], 'best-effort')
        self.assertEqual(result['recovery'], 'not-needed')
        self.assertIn('DNSOverTLS=opportunistic', self.dropin().read_text(encoding='utf-8'))
        self.assertTrue(self.resolv.is_symlink())
        self.assertEqual(os.readlink(self.resolv), '/run/systemd/resolve/stub-resolv.conf')
        self.assertIn(('busctl', 'get-property', 'org.freedesktop.resolve1',
                       '/org/freedesktop/resolve1', 'org.freedesktop.resolve1.Manager', 'DNSOverTLS'),
                      host.calls)
        queries = [args[-1] for args in host.calls if args[0] == 'resolvectl' and args[1] == 'query']
        self.assertEqual(queries, ['cloudflare.com', 'debian.org'])

    def test_required_is_verified_against_the_strict_mode(self):
        result, _ = self.prepare(FakeHost(mode='s "yes"'), policy='required')
        self.assertEqual(result['status'], 'configured', result)
        self.assertIn('DNSOverTLS=yes', self.dropin().read_text(encoding='utf-8'))

    def test_a_mode_that_did_not_take_effect_is_rolled_back_and_reported(self):
        result, _ = self.prepare(FakeHost(mode='s "opportunistic"'), policy='required')
        self.assertEqual(result['status'], 'failed_rolled_back', result)
        self.assertEqual(result['recovery'], 'verified')
        self.assertEqual(result['policy'], 'required')
        self.assertIn('DNSOverTLS is not required', result['warnings'][0])
        self.assertFalse(self.dropin().exists())
        self.assertFalse(self.resolv.is_symlink())
        self.assertEqual(self.resolv.read_text(encoding='utf-8'), 'nameserver 192.0.2.53\n')

    def test_an_unverified_restoration_is_not_called_recovered(self):
        result, _ = self.prepare(FakeHost(mode='s "opportunistic"', fail_getent_after=1), policy='required')
        self.assertEqual(result['status'], 'failed_unverified', result)
        self.assertEqual(result['recovery'], 'failed')

    def test_off_writes_no_document_and_leaves_a_neighbour_alone(self):
        neighbour = self.root / "etc/systemd/resolved.conf.d/50-operator.conf"
        neighbour.parent.mkdir(parents=True)
        neighbour.write_text('[Resolve]\nCache=no\n', encoding='utf-8')

        result, host = self.prepare(FakeHost(), policy='off')
        self.assertEqual(result['status'], 'configured', result)
        self.assertEqual(result['dot'], 'off')
        self.assertEqual(result['recovery'], 'not-needed')
        self.assertEqual(result['warnings'], [])
        self.assertFalse(self.dropin().exists())
        self.assertEqual(neighbour.read_text(encoding='utf-8'), '[Resolve]\nCache=no\n')
        self.assertTrue(self.resolv.is_symlink())
        # `off` proves resolution, not a DNSOverTLS mode it does not set.
        self.assertNotIn('busctl', host.names())

    def test_off_removes_the_previous_managed_document(self):
        self.prepare(FakeHost(), policy='best-effort')
        self.assertTrue(self.dropin().is_file())

        result, host = self.prepare(FakeHost(), policy='off')
        self.assertEqual(result['status'], 'configured', result)
        self.assertEqual(result['dot'], 'off')
        self.assertFalse(self.dropin().exists())
        self.assertTrue(self.resolv.is_symlink())
        self.assertNotIn('busctl', host.names())

    def test_a_rerun_over_the_existing_document_and_package_succeeds(self):
        first, _ = self.prepare(FakeHost(), policy='best-effort')
        self.assertEqual(first['status'], 'configured', first)
        second, host = self.prepare(FakeHost(), policy='best-effort')
        self.assertEqual(second['status'], 'configured', second)
        self.assertIn(('apt-get', '-o', 'DPkg::Lock::Timeout=300', '-o', 'Dpkg::Options::=--force-confdef',
                       '-o', 'Dpkg::Options::=--force-confold', '--no-remove',
                       '--no-install-recommends', '-y', 'install', 'systemd-resolved'), host.calls)

    def test_a_platform_owned_resolver_is_left_in_place(self):
        # A container runtime bind-mounts /etc/resolv.conf, so unlinking it is
        # EBUSY and the platform owns the path. The DoT policy lives in the
        # resolved drop-in, not in a second claim on that file: the install must
        # succeed, keep the platform's file untouched, and say so.
        managed = load_managed()
        managed.PROJECT_OWNER_UID = os.getuid()
        host = FakeHost()
        original = self.resolv.read_text(encoding='utf-8')
        with mock.patch.object(managed, "command", host), \
                mock.patch.object(managed, "platform_owns_resolv", lambda root=Path('/'): True):
            result = managed.prepare_dns(root=self.root, policy='best-effort')
        self.assertEqual(result['status'], 'configured', result['warnings'])
        self.assertFalse(self.resolv.is_symlink())
        self.assertEqual(self.resolv.read_text(encoding='utf-8'), original)
        self.assertTrue(any('owned by the platform' in item for item in result['warnings']))
        self.assertTrue(self.dropin().is_file())

    def test_a_document_owned_by_someone_else_is_refused(self):
        managed = load_managed()
        managed.PROJECT_OWNER_UID = os.getuid() + 1
        self.dropin().parent.mkdir(parents=True)
        self.dropin().write_text(managed.dot_content('best-effort'), encoding='utf-8')
        host = FakeHost()
        with mock.patch.object(managed, "command", host):
            with self.assertRaisesRegex(ValueError, 'Unsafe owner/permissions'):
                managed.prepare_dns(root=self.root, policy='best-effort')
        self.assertNotIn('apt-get', host.names())

    def test_an_unowned_drop_in_is_refused_before_a_package_is_touched(self):
        self.dropin().parent.mkdir(parents=True)
        self.dropin().write_text('[Resolve]\nDNSOverTLS=yes\n', encoding='utf-8')
        host = FakeHost()
        with self.assertRaisesRegex(ValueError, 'Unowned project configuration path'):
            self.prepare(host, policy='best-effort')
        self.assertNotIn('apt-get', host.names())
        self.assertEqual(self.dropin().read_text(encoding='utf-8'), '[Resolve]\nDNSOverTLS=yes\n')

    def test_the_command_line_reads_the_policy_from_the_environment(self):
        result = subprocess.run(
            ['python3', str(MANAGED_PY), '--prepare-dns'],
            capture_output=True, text=True,
            env={**os.environ, 'GOWAVE_DOT_POLICY': 'sometimes'},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn('Unsupported DNS-over-TLS policy: sometimes', result.stdout)


def security_report(result):
    """A report built from one helper result; the other controls are verified.

    The three fixed controls keep the readiness verdict attributable to DoT
    alone, so a `failed` result cannot come from an unrelated control.
    """
    controls = {
        name: {'policy': 'required', 'status': 'verified', 'reason_code': 'CONTROL_VERIFIED',
               'recovery': 'not-needed', 'evidence_codes': ['CONTROL_EVIDENCE']}
        for name in ('firewall', 'ssh_protection', 'security_updates')
    }
    controls['dot'] = reports.dot_control(result)
    return {'schema_version': 1, 'host_id': 'fixture-host', 'role': 'aio',
            'installer_revision': 'test', 'observed_at': datetime.now(timezone.utc).isoformat(),
            'controls': controls}


class TestDotFailureModes(DotHost, unittest.TestCase):
    """Task 3.4: what an unusable encrypted path does to each policy.

    The encrypted path is blocked at the query stage, after the document is
    written — the shape a censored or firewalled network produces. `best-effort`
    may continue only because the original resolver comes back and is proven to
    resolve again; `required` stops even then, because the policy it was asked
    to deliver is exactly the one that is missing. An unproven restoration stops
    every policy, and neither outcome may be reported as success.
    """

    def test_best_effort_fails_the_control_but_keeps_the_host_usable(self):
        result, host = self.prepare(FakeHost(tls_blocked=True), policy='best-effort')
        self.assertEqual(result['status'], 'failed_rolled_back', result)
        self.assertEqual(result['recovery'], 'verified')
        self.assertEqual(result['policy'], 'best-effort')
        self.assertIn('encrypted path blocked', result['warnings'][0])
        self.assertFalse(self.dropin().exists())
        self.assertEqual(self.resolv.read_text(encoding='utf-8'), 'nameserver 192.0.2.53\n')
        # The verification really ran an uncached query before giving up.
        self.assertIn(('resolvectl', 'query', '--cache=no', 'cloudflare.com'), host.calls)
        control = reports.dot_control(result)
        self.assertEqual((control['status'], control['recovery'], control['policy']),
                         ('failed', 'verified', 'best-effort'))
        # A failed control with a proven rollback is a warning, not a failure.
        self.assertEqual(reports.readiness(security_report(result)), 'ready-with-warnings')

    def test_required_reports_the_same_rollback_but_blocks_readiness(self):
        result, _ = self.prepare(FakeHost(tls_blocked=True), policy='required')
        self.assertEqual(result['status'], 'failed_rolled_back', result)
        self.assertEqual(result['recovery'], 'verified')
        # The helper's facts are identical to the best-effort run; only the
        # requested policy differs, and that is what makes the verdict a failure.
        self.assertEqual(reports.dot_control(result)['status'], 'failed')
        self.assertEqual(reports.readiness(security_report(result)), 'failed')

    def test_an_unproven_restoration_fails_every_policy(self):
        for policy in ('best-effort', 'required'):
            with self.subTest(policy=policy):
                result, _ = self.prepare(FakeHost(tls_blocked=True, fail_getent_after=1), policy=policy)
                self.assertEqual(result['status'], 'failed_unverified', result)
                self.assertEqual(result['recovery'], 'failed')
                control = reports.dot_control(result)
                self.assertEqual((control['status'], control['recovery']), ('failed', 'failed'))
                self.assertEqual(reports.readiness(security_report(result)), 'failed')

    def test_a_control_result_is_never_rewritten_as_verified(self):
        configured, _ = self.prepare(FakeHost(), policy='best-effort')
        self.assertEqual((configured['status'], configured['recovery']), ('configured', 'not-needed'))
        self.assertEqual(reports.readiness(security_report(configured)), 'ready')
        failed, _ = self.prepare(FakeHost(tls_blocked=True), policy='best-effort')
        self.assertEqual((failed['status'], failed['recovery']), ('failed_rolled_back', 'verified'))
        self.assertEqual(reports.dot_control(failed)['status'], 'failed')
        # A hand-built conflation is refused: a control that needed recovery
        # cannot be `verified`, and a failed one that claims no recovery is a
        # failure rather than a warning.
        verified = security_report(configured)
        verified['controls']['dot']['recovery'] = 'verified'
        with self.assertRaisesRegex(StateError, 'verified control cannot require recovery'):
            reports.validate(verified)
        failed_without_recovery = security_report(failed)
        failed_without_recovery['controls']['dot']['recovery'] = 'not-needed'
        self.assertEqual(reports.readiness(failed_without_recovery), 'failed')

    def test_a_disabled_policy_is_skipped_and_never_counted_as_verified(self):
        result, _ = self.prepare(FakeHost(), policy='off')
        self.assertEqual(result['status'], 'configured', result)
        control = reports.dot_control(result)
        self.assertEqual((control['status'], control['policy'], control['recovery']),
                         ('skipped', 'off', 'not-needed'))
        self.assertEqual(reports.readiness(security_report(result)), 'ready')
        report = security_report(result)
        report['controls']['dot']['status'] = 'verified'
        with self.assertRaisesRegex(StateError, 'disabled control must be skipped'):
            reports.validate(report)

    def test_an_unknown_helper_status_is_refused_instead_of_guessed(self):
        with self.assertRaisesRegex(StateError, 'unknown DNS-over-TLS helper status: failed'):
            reports.dot_control({'status': 'failed', 'policy': 'required'})
        with self.assertRaisesRegex(StateError, 'invalid DNS-over-TLS policy'):
            reports.dot_control({'status': 'configured', 'policy': 'sometimes'})


STUB = '''import json, os, sys
with open(os.environ["STUB_MARKER"], "a", encoding="utf-8") as stream:
    stream.write(os.environ.get("GOWAVE_DOT_POLICY", "<unset>") + "\\n")
print(json.dumps({"status": os.environ["STUB_STATUS"]}))
sys.exit(int(os.environ["STUB_RC"]))
'''


class TestDotPolicyWrapper(unittest.TestCase):
    """`configure_dot` turns the helper's report into continue-or-stop."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.stub = self.root / "managed_stub.py"
        self.stub.write_text(STUB, encoding="utf-8")
        self.marker = self.root / "calls.txt"

    def configure(self, status='configured', rc='0', policy=None):
        environment = {**os.environ, "STUB_STATUS": status, "STUB_RC": rc,
                       "STUB_MARKER": str(self.marker)}
        environment.pop("GOWAVE_DOT_POLICY", None)
        if policy is not None:
            environment["GOWAVE_DOT_POLICY"] = policy
        script = f'source "{SECURITY_SH}"\nMANAGED_SECURITY_PY="{self.stub}"\nconfigure_dot\n'
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env=environment)

    def policies_requested(self):
        return self.marker.read_text(encoding="utf-8").split() if self.marker.exists() else []

    def test_a_configured_policy_passes_and_the_requested_value_reaches_the_helper(self):
        result = self.configure(policy='off')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.policies_requested(), ['off'])
        self.assertIn('"status": "configured"', result.stdout)

    def test_best_effort_continues_after_a_verified_rollback_with_a_warning(self):
        result = self.configure(status='failed_rolled_back', rc='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('continues without it', result.stderr)
        self.assertIn('"status": "failed_rolled_back"', result.stdout)

    def test_best_effort_stops_when_the_rollback_is_unproven(self):
        result = self.configure(status='failed_unverified', rc='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('rollback was not verified', result.stderr)

    def test_required_stops_even_after_a_verified_rollback(self):
        result = self.configure(status='failed_rolled_back', rc='1', policy='required')
        self.assertEqual(result.returncode, 1)
        self.assertIn('rollback was not verified', result.stderr)

    def test_an_unknown_policy_is_refused_before_the_helper_runs(self):
        result = self.configure(policy='strict')
        self.assertEqual(result.returncode, 1)
        self.assertIn('unsupported DNS-over-TLS policy', result.stderr)
        self.assertEqual(self.policies_requested(), [])

    def test_the_recovery_outcome_is_kept_for_the_host_report(self):
        def outcome(status, rc, policy=None):
            environment = {**os.environ, "STUB_STATUS": status, "STUB_RC": rc,
                           "STUB_MARKER": str(self.marker)}
            environment.pop("GOWAVE_DOT_POLICY", None)
            if policy is not None:
                environment["GOWAVE_DOT_POLICY"] = policy
            script = (f'source "{SECURITY_SH}"\nMANAGED_SECURITY_PY="{self.stub}"\n'
                      'if configure_dot; then printf "rc=0 recovery=%s\\n" "$_DOT_RECOVERY"; '
                      'else printf "rc=$? recovery=%s\\n" "$_DOT_RECOVERY"; fi\n')
            return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                  env=environment).stdout.strip().splitlines()[-1]

        self.assertEqual(outcome('configured', '0'), 'rc=0 recovery=not-needed')
        self.assertEqual(outcome('configured', '0', 'off'), 'rc=0 recovery=not-needed')
        # The tolerated best-effort failure is a failed control whose recovery
        # was proven, which is what keeps the final report a warning.
        self.assertEqual(outcome('failed_rolled_back', '1'), 'rc=0 recovery=verified')
        self.assertEqual(outcome('failed_unverified', '1'), 'rc=1 recovery=unknown')
        self.assertEqual(outcome('failed_rolled_back', '1', 'required'), 'rc=1 recovery=unknown')


class TestDotPolicyDocumentation(unittest.TestCase):
    """The page an operator reads and the helper that applies the policy agree."""

    HEADING = "## DNS-over-TLS policy / Политика DNS-over-TLS"

    def section(self):
        page = (REPO_ROOT / "docs" / "SETUP_WIZARD.md").read_text(encoding="utf-8")
        self.assertIn(self.HEADING, page)
        start = page.index(self.HEADING) + len(self.HEADING)
        end = page.index("\n## ", start)
        return page[start:end]

    def test_every_policy_value_is_documented_with_the_same_names(self):
        managed = load_managed()
        section = self.section()
        self.assertIn("`GOWAVE_DOT_POLICY`", section)
        self.assertIn("The default is `best-effort`", section)
        for policy in managed.DOT_POLICIES:
            self.assertIn(f"`{policy}`", section)

    def test_the_documented_documents_are_the_ones_the_helper_writes(self):
        managed = load_managed()
        section = self.section()
        self.assertIn(managed.FILES[4], section)
        for policy in managed.DOT_MODES:
            mode = managed.DOT_MODES[policy]
            self.assertIn(f"DNSOverTLS={mode}", managed.dot_content(policy))
            self.assertIn(f"`DNSOverTLS={mode}`", section)
        off_row = next(line for line in section.splitlines() if line.startswith("| `off`"))
        self.assertIn("no document", off_row)

    def test_the_page_states_the_continue_and_stop_rule_in_both_languages(self):
        section = self.section()
        self.assertIn("Continuation is allowed only when the rollback is verified", section)
        self.assertIn("Непроверенное восстановление останавливает", section)
        self.assertIn("`resolvectl status`", section)
        self.assertIn("DNSSEC", section)

    def test_both_installers_pass_the_policy_to_the_shared_helper(self):
        master = (REPO_ROOT / "modules" / "security.sh").read_text(encoding="utf-8")
        worker = (REPO_ROOT / "gowave-node-auto.sh").read_text(encoding="utf-8")
        self.assertIn('local policy="${GOWAVE_DOT_POLICY:-best-effort}"', master)
        self.assertIn('local policy="${GOWAVE_DOT_POLICY:-best-effort}"', worker)
        self.assertIn("--prepare-dns", master)
        self.assertIn("--prepare-dns", worker)


if __name__ == "__main__":
    unittest.main()
