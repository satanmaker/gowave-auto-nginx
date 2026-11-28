#!/usr/bin/env python3
"""The firewall transaction: baseline, apply, verification and recovery.

Every case runs a disposable host: a temporary root holding the UFW files, and
fake `ufw`, `iptables-save`, `iptables-restore`, `ip6tables-save` and
`ip6tables-restore` binaries on PATH that keep a real ruleset. A case can
therefore fail one specific mutation and read what the host actually holds
afterwards, instead of trusting the exit status of the script.
"""
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
FIREWALL_IMAGE_PY = REPO_ROOT / "assets" / "security" / "firewall_image.py"
FIREWALL_SH = REPO_ROOT / "modules" / "firewall.sh"
SECURITY_SH = REPO_ROOT / "modules" / "security.sh"
OS_SH = REPO_ROOT / "modules" / "os.sh"
NODE_AUTO = REPO_ROOT / "gowave-node-auto.sh"

POLICY_MAP = r'''policy_word() {
    case "${1%% *}" in
        DROP|REJECT) echo deny ;;
        ACCEPT) echo allow ;;
        *) echo "${1%% *}" ;;
    esac
}
policy_target() {
    case "${1%% *}" in
        deny|reject) echo DROP ;;
        allow) echo ACCEPT ;;
        *) echo "${1%% *}" ;;
    esac
}
'''

FAKE_UFW = r'''#!/usr/bin/env bash
set -u
__POLICY_MAP__
state="${FAKE_UFW_STATE:?}"
root="${FAKE_UFW_ROOT:?}"
declaration=no
if [[ -f "$root/etc/default/ufw" ]]; then
    declaration=$(sed -n 's/^IPV6=//p' "$root/etc/default/ufw" | tail -1)
    declaration="${declaration:-no}"
fi
printf '%s|%s\n' "$*" "$declaration" >> "$state/calls.log"
if [[ -n "${FAKE_UFW_FAIL:-}" && "$*" == *"${FAKE_UFW_FAIL}"* ]]; then
    printf 'simulated ufw failure: %s\n' "$*" >&2
    exit 1
fi
insert() {
    printf '%s\n' "$1" >> "$state/body$2"
}
case "${1:-}" in
    status)
        if [[ "$(cat "$state/active" 2>/dev/null || echo 0)" == "1" ]]; then
            printf 'Status: active\n'
            printf 'Logging: on (low)\n'
            printf 'Default: %s (incoming), %s (outgoing), disabled (routed)\n' \
                "$(cat "$state/incoming")" "$(cat "$state/outgoing")"
            printf 'New profiles: skip\n'
        else
            printf 'Status: inactive\n'
        fi
        ;;
    default)
        case "${3:-}" in
            incoming) printf '%s\n' "$2" > "$state/incoming" ;;
            outgoing) printf '%s\n' "$2" > "$state/outgoing" ;;
        esac
        ;;
    --force)
        if [[ "${2:-}" == "enable" ]]; then
            printf '1\n' > "$state/active"
            printf 'Firewall is active and enabled on system startup\n'
        else
            printf '0\n' > "$state/active"
            printf 'Firewall stopped and disabled on system startup\n'
        fi
        ;;
    allow|deny)
        target=ACCEPT
        [[ "$1" == "deny" ]] && target=DROP
        shift
        source=""
        port=""
        comment=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --dport|--dports) port="${2:-}"; shift 2 ;;
                -s|from) source="${2:-}"; shift 2 ;;
                port) port="${2:-}"; shift 2 ;;
                comment) comment="${2:-}"; shift 2 ;;
                to|any|proto|-p) shift 2 ;;
                *tcp) port="${1%%/*}"; shift ;;
                *) shift ;;
            esac
        done
        rule="-A ufw-user-input"
        if [[ -n "$source" ]]; then
            case "$source" in
                *:*) rule+=" -s $source/128" ;;
                *) rule+=" -s $source/32" ;;
            esac
        fi
        if [[ -n "$port" ]]; then
            rule+=" -p tcp -m tcp --dport $port"
        else
            rule+=" -p tcp -m tcp"
        fi
        # UFW writes the comment the operator gave it into the rule itself, so
        # the ruleset a later run reads carries `-m comment --comment "..."`.
        if [[ -n "$comment" ]]; then
            rule+=" -m comment --comment \"$comment\""
        fi
        rule+=" -j $target"
        insert "$rule" 4
        if [[ "$declaration" == "yes" ]]; then
            insert "${rule/ufw-user-input/ufw6-user-input}" 6
        fi
        ;;
esac
exit 0
'''

FAKE_SAVE = r'''#!/usr/bin/env bash
set -u
__POLICY_MAP__
state="${FAKE_UFW_STATE:?}"
family=4
[[ "${0##*/}" == ip6tables-save ]] && family=6
if [[ -n "${FAKE_SAVE_FAIL:-}" && "$family" == "${FAKE_SAVE_FAIL}" ]]; then
    printf 'simulated %s failure\n' "${0##*/}" >&2
    exit 1
fi
printf '*filter\n'
printf ':INPUT %s [0:0]\n' "$(policy_target "$(cat "$state/incoming" 2>/dev/null || echo deny)")"
printf ':OUTPUT %s [0:0]\n' "$(policy_target "$(cat "$state/outgoing" 2>/dev/null || echo allow)")"
printf ':%s - [0:0]\n' "$([[ "$family" == 6 ]] && echo ufw6-user-input || echo ufw-user-input)"
[[ -f "$state/body$family" ]] && cat "$state/body$family"
printf 'COMMIT\n'
'''

FAKE_RESTORE = r'''#!/usr/bin/env bash
set -u
__POLICY_MAP__
state="${FAKE_UFW_STATE:?}"
family=4
[[ "${0##*/}" == ip6tables-restore ]] && family=6
[[ -n "${FAKE_RESTORE_SKIP:-}" && "$family" == "${FAKE_RESTORE_SKIP}" ]] && exit 0
: > "$state/body$family"
while IFS= read -r line; do
    case "$line" in
        ':INPUT '*) policy_word "${line#:INPUT }" | cut -d' ' -f1 > "$state/incoming" ;;
        ':OUTPUT '*) policy_word "${line#:OUTPUT }" | cut -d' ' -f1 > "$state/outgoing" ;;
        '-A ufw-user-input '*|'-A ufw6-user-input '*) printf '%s\n' "$line" >> "$state/body$family" ;;
    esac
done
exit 0
'''


def fake(body):
    return body.replace('__POLICY_MAP__', POLICY_MAP)


class Host:
    """A disposable host whose firewall commands are simulated."""

    def __init__(self, ipv6=False, active=False, incoming='deny', outgoing='allow'):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.state = self.root / 'state'
        self.state.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name, body in (('ufw', FAKE_UFW), ('iptables-save', FAKE_SAVE),
                           ('iptables-restore', FAKE_RESTORE), ('ip6tables-save', FAKE_SAVE),
                           ('ip6tables-restore', FAKE_RESTORE)):
            path = self.bin / name
            path.write_text(fake(body))
            path.chmod(0o755)
        (self.state / 'active').write_text('1\n' if active else '0\n')
        (self.state / 'incoming').write_text(incoming + '\n')
        (self.state / 'outgoing').write_text(outgoing + '\n')
        (self.state / 'calls.log').write_text('')
        self.recovery = self.root / 'recovery'
        self.recovery.mkdir()
        self.ufw_default = self.root / 'etc' / 'default' / 'ufw'
        self.ufw_default.parent.mkdir(parents=True)
        self.ufw_default.write_text(
            'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n'
            'IPV6=%s\n' % ('yes' if ipv6 else 'no')
        )
        self.ufw_dir = self.root / 'etc' / 'ufw'
        self.ufw_dir.mkdir()
        (self.ufw_dir / 'user.rules').write_text(self.run_save(4))
        (self.ufw_dir / 'user6.rules').write_text(self.run_save(6))
        self.if_inet6 = self.root / 'proc' / 'net' / 'if_inet6'
        self.if_inet6.parent.mkdir(parents=True)
        self.if_inet6.write_text('00000000000000000000000000000001 01 80 10 80       lo\n'
                                 if ipv6 else '')
        self.helper = self.root / 'managed.py'
        # The SSH discovery shells out to sshd; the policy itself is what these
        # cases exercise, so the ports are pinned in the copied helper.
        self.helper.write_text(MANAGED_PY.read_text().replace(
            "if __name__ == '__main__':",
            "inspect_ssh_ports = lambda: [22]\nif __name__ == '__main__':",
        ))

    def close(self):
        self._temp.cleanup()

    def run_save(self, family):
        name = 'iptables-save' if family == 4 else 'ip6tables-save'
        result = subprocess.run([str(self.bin / name)], capture_output=True, text=True,
                                env={**os.environ, 'FAKE_UFW_STATE': str(self.state)},
                                check=True)
        return result.stdout

    def env(self, **extra):
        return {**os.environ,
                'PATH': f'{self.bin}:{os.environ["PATH"]}',
                'FAKE_UFW_STATE': str(self.state),
                'FAKE_UFW_ROOT': str(self.root),
                'RECOVERY_DIR': str(self.recovery),
                **extra}

    def configure(self, action='configure_ufw false "" 3002', **extra):
        script = (f'source "{OS_SH}"\n'
                  f'source "{FIREWALL_SH}"\n'
                  f'source "{SECURITY_SH}"\n'
                  f'MANAGED_SECURITY_PY="{self.helper}"\n'
                  f'{action} "{self.if_inet6}" "{self.ufw_default}" "{self.root}"')
        return subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                              env=self.env(**extra), timeout=180)

    def calls(self):
        """The ufw arguments each call received, without the IPV6= witness."""
        return [line.rsplit('|', 1)[0] for line in self.raw_calls()]

    def raw_calls(self):
        return (self.state / 'calls.log').read_text().splitlines()

    def body(self, family=4):
        path = self.state / f'body{family}'
        return path.read_text() if path.exists() else ''

    def add_existing_rule(self, line, family=4):
        with open(self.state / f'body{family}', 'a') as handle:
            handle.write(line + '\n')
        name = 'user.rules' if family == 4 else 'user6.rules'
        (self.ufw_dir / name).write_text(self.run_save(family))


class FirewallImageTests(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.addCleanup(self.host.close)

    def image(self, action):
        return subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(self.host.root),
             str(self.host.recovery / 'image'), action],
            capture_output=True, text=True, env=self.host.env(), timeout=120)

    def test_capture_records_a_baseline_that_restores_both_families(self):
        host = Host(active=True)
        self.addCleanup(host.close)
        host.add_existing_rule('-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT')
        captured = subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(host.root), str(host.recovery / 'image'), 'capture'],
            capture_output=True, text=True, env=host.env(), timeout=120)
        self.assertEqual(captured.returncode, 0, captured.stderr)
        manifest = json.loads((host.recovery / 'image' / 'manifest.json').read_text())
        self.assertIs(manifest['created_by_tx'], True)
        self.assertIs(manifest['enabled'], True)
        self.assertEqual(manifest['defaults']['incoming'], 'deny')
        self.assertIn('/etc/ufw/user.rules', manifest['files'])
        self.assertIn('ip6tables', manifest)

        # The install then changes the host: a new rule, a new declaration.
        host.add_existing_rule('-A ufw-user-input -p tcp -m tcp --dport 443 -j ACCEPT')
        host.ufw_default.write_text('IPV6=yes\n')

        restored = subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(host.root), str(host.recovery / 'image'), 'restore'],
            capture_output=True, text=True, env=host.env(), timeout=120)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertEqual(host.ufw_default.read_text(),
                         'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nIPV6=no\n')
        self.assertNotIn('--dport 443', host.body(4))
        self.assertIn('--dport 8080', host.body(4))
        self.assertEqual((host.state / 'active').read_text().strip(), '1')

    def test_capture_refuses_when_the_baseline_cannot_be_read(self):
        refused = subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(self.host.root),
             str(self.host.recovery / 'image'), 'capture'],
            capture_output=True, text=True, env=self.host.env(FAKE_UFW_FAIL='status'), timeout=120)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('refusing to change a firewall this install cannot restore', refused.stderr)
        self.assertFalse((self.host.recovery / 'image').exists())

    def test_capture_refuses_when_a_ruleset_cannot_be_dumped(self):
        refused = subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(self.host.root),
             str(self.host.recovery / 'image'), 'capture'],
            capture_output=True, text=True, env=self.host.env(FAKE_SAVE_FAIL='6'), timeout=120)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('refusing to change a firewall this install cannot restore', refused.stderr)
        self.assertFalse((self.host.recovery / 'image').exists())

    def test_capture_refuses_a_second_image_over_the_first(self):
        self.assertEqual(self.image('capture').returncode, 0)
        again = self.image('capture')
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('already exists', again.stderr)

    def test_restore_refuses_missing_manifest_and_symlink(self):
        missing = self.image('restore')
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('No firewall before-image', missing.stderr)
        (self.host.recovery / 'image').mkdir()
        (self.host.recovery / 'image' / 'manifest.json').symlink_to('/dev/null')
        linked = self.image('restore')
        self.assertNotEqual(linked.returncode, 0)
        self.assertIn('symlink', linked.stderr)

    def test_restore_reads_the_ipv6_ruleset_back(self):
        host = Host(ipv6=True)
        self.addCleanup(host.close)
        host.add_existing_rule('-A ufw6-user-input -p tcp -m tcp --dport 8443 -j ACCEPT', family=6)
        captured = subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(host.root), str(host.recovery / 'image'), 'capture'],
            capture_output=True, text=True, env=host.env(), timeout=120)
        self.assertEqual(captured.returncode, 0, captured.stderr)
        # A restore that leaves the v6 table unapplied must be refused: the v4
        # comparison alone cannot see a family that is not filtering what the
        # image recorded.
        (host.state / 'body6').write_text('')
        restored = subprocess.run(
            ['python3', str(FIREWALL_IMAGE_PY), str(host.root), str(host.recovery / 'image'), 'restore'],
            capture_output=True, text=True, env=host.env(FAKE_RESTORE_SKIP='6'), timeout=120)
        self.assertNotEqual(restored.returncode, 0)
        self.assertIn('IPv6 ruleset does not match the before-image', restored.stderr)


class FirewallTransactionTests(unittest.TestCase):
    def setUp(self):
        self.host = Host()
        self.addCleanup(self.host.close)

    def test_the_applied_policy_is_verified_from_the_running_ruleset(self):
        result = self.host.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('UFW configuration complete.', result.stdout)
        self.assertIn('UFW: IPv6 disabled in kernel; setting IPV6=no', result.stdout)
        calls = self.host.calls()
        mutations = [call for call in calls if call.startswith(('default ', 'allow ', 'deny '))]
        self.assertTrue(mutations[0].startswith('default deny incoming'), mutations[:3])
        self.assertTrue(any(call.startswith('allow 22/tcp') for call in calls))
        self.assertTrue(any(call.startswith('allow 80/tcp') for call in calls))
        self.assertTrue(any(call.startswith('allow 443/tcp') for call in calls))
        self.assertTrue(any(call.startswith('deny 3002/tcp') for call in calls))
        for port in (3000, 3001, 7443, 8443, 8444, 9443, 9444, 10001, 10002, 10003):
            self.assertTrue(any(call.startswith(f'deny {port}/tcp') for call in calls), port)
        live = self.host.body(4)
        self.assertIn('--dport 22', live)
        self.assertIn('-j ACCEPT', live)
        self.assertIn('--dport 3002', live)
        self.assertIn('-j DROP', live)
        # The comment UFW writes into the rule must not stop the read-back from
        # recognising it: this is the form the host holds on a second run.
        self.assertIn('--comment "GoWave Auto NGINX"', live)
        self.assertEqual((self.host.state / 'incoming').read_text().strip(), 'deny')
        self.assertEqual((self.host.state / 'outgoing').read_text().strip(), 'allow')
        self.assertEqual((self.host.state / 'active').read_text().strip(), '1')

    def test_the_family_declaration_precedes_the_rules_it_filters(self):
        host = Host(ipv6=True)
        self.addCleanup(host.close)
        host.ufw_default.write_text('IPV6=no\n')
        result = host.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('UFW: IPv6 active in kernel; setting IPV6=yes', result.stdout)
        rules = [call for call in host.raw_calls() if call.startswith(('allow ', 'deny '))]
        self.assertTrue(rules)
        self.assertTrue(all(call.endswith('|yes') for call in rules),
                        'a rule written before the declaration leaves the v6 table behind')
        self.assertIn('--dport 3002', host.body(6))
        self.assertIn('-j DROP', host.body(6))

    def test_a_failing_rule_restores_the_baseline_and_reports_it(self):
        self.host.add_existing_rule('-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT')
        before = (self.host.ufw_dir / 'user.rules').read_text()
        before_default = self.host.ufw_default.read_text()
        result = self.host.configure(FAKE_UFW_FAIL='allow 443/tcp')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('UFW configuration complete.', result.stdout)
        self.assertIn('Restoring the firewall baseline captured before this transaction', result.stderr)
        self.assertIn('Firewall baseline restored and read back as captured.', result.stderr)
        self.assertEqual((self.host.ufw_dir / 'user.rules').read_text(), before)
        self.assertEqual(self.host.ufw_default.read_text(), before_default)
        self.assertIn('--dport 8080', self.host.body(4))
        self.assertNotIn('--dport 3002', self.host.body(4))

    def test_a_failing_activation_restores_the_baseline(self):
        result = self.host.configure(FAKE_UFW_FAIL='--force enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ufw --force enable failed', result.stderr)
        self.assertIn('Firewall baseline restored and read back as captured.', result.stderr)
        self.assertEqual((self.host.state / 'active').read_text().strip(), '0')

    def test_recovery_runs_once_and_reports_a_failed_restoration_separately(self):
        host = Host(active=True)
        self.addCleanup(host.close)
        result = host.configure(FAKE_UFW_FAIL='--force enable')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.count('Restoring the firewall baseline captured before this transaction'), 1)
        self.assertIn('CRITICAL: firewall restoration failed after:', result.stderr)
        self.assertNotIn('Firewall baseline restored and read back as captured.', result.stderr)

    def test_conflicting_existing_policy_refuses_before_any_mutation(self):
        self.host.add_existing_rule('-A ufw-user-input -p tcp -m tcp --dport 3002 -j ACCEPT')
        before = (self.host.ufw_dir / 'user.rules').read_text()
        result = self.host.configure()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('conflicts with existing firewall policy', result.stderr)
        self.assertIn('3002', result.stderr)
        self.assertFalse([call for call in self.host.calls()
                          if call.startswith(('allow ', 'deny ', 'default '))],
                         'a refused preflight must not reach a mutation')
        self.assertEqual((self.host.ufw_dir / 'user.rules').read_text(), before)
        self.assertFalse((self.host.recovery / 'firewall-before-image').exists())

    def test_unrelated_administrator_allows_are_preserved_and_reported(self):
        self.host.add_existing_rule('-A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT')
        result = self.host.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Firewall preflight preserved 1 unrelated administrator allow rule(s).', result.stderr)
        self.assertIn('--dport 8080', self.host.body(4))

    def test_a_panel_only_host_carries_no_node_exception(self):
        result = self.host.configure('configure_ufw false "" ""')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse([call for call in self.host.calls() if '3002' in call])
        self.assertTrue(any(call.startswith('allow 443/tcp') for call in self.host.calls()))

    def test_a_worker_allows_its_master_source_before_the_deny(self):
        result = self.host.configure('configure_ufw true "192.0.2.10" 3002')
        self.assertEqual(result.returncode, 0, result.stderr)
        rules = [call for call in self.host.calls() if call.startswith(('allow ', 'deny '))]
        allowed = [index for index, call in enumerate(rules) if 'from 192.0.2.10' in call]
        denied = [index for index, call in enumerate(rules) if call.startswith('deny 3002/tcp')]
        self.assertTrue(allowed)
        self.assertTrue(denied)
        self.assertLess(allowed[0], denied[0], 'the source exception must precede the deny')
        self.assertIn('-s 192.0.2.10/32', self.host.body(4))

    def test_the_transaction_is_committed_after_a_verified_install(self):
        script = (f'source "{OS_SH}"\n'
                  f'source "{FIREWALL_SH}"\n'
                  f'source "{SECURITY_SH}"\n'
                  f'MANAGED_SECURITY_PY="{self.host.helper}"\n'
                  f'firewall_prepare_install all-in-one 3002 "{self.host.if_inet6}" "{self.host.root}" && '
                  f'firewall_begin_transaction "{self.host.root}" && '
                  f'firewall_commit_transaction && echo COMMITTED')
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True,
                                env=self.host.env(), timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('COMMITTED', result.stdout)
        self.assertFalse(list(self.host.recovery.glob('firewall_*/firewall-before-image')))


class FirewallEffectiveTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('managed_effective', str(MANAGED_PY))
        self.managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.managed)
        self.policy = self.managed.firewall_policy('aio', [22])

    def ruleset(self, rules, input_policy='DROP', output_policy='ACCEPT', family=4):
        chain = 'ufw6-user-input' if family == 6 else 'ufw-user-input'
        return (f'*filter\n:INPUT {input_policy} [0:0]\n:OUTPUT {output_policy} [0:0]\n'
                f':{chain} - [0:0]\n' + '\n'.join(rules) + '\nCOMMIT\n')

    def complete(self):
        rules = ['-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT',
                 '-A ufw-user-input -p tcp -m tcp --dport 80 -j ACCEPT',
                 '-A ufw-user-input -p tcp -m tcp --dport 443 -j ACCEPT']
        rules += [f'-A ufw-user-input -p tcp -m tcp --dport {port} -j DROP'
                  for port in self.policy['internal_ports'] + [self.policy['node_port']]]
        return self.ruleset(rules)

    def status(self, incoming='deny', outgoing='allow'):
        return (f'Status: active\nDefault: {incoming} (incoming), {outgoing} (outgoing), '
                'disabled (routed)\n')

    def test_the_complete_policy_reads_back(self):
        result = self.managed.firewall_effective(
            self.policy, {4: self.complete()}, self.status(), 'IPV6=no\n')
        self.assertEqual(result['defaults']['incoming'], 'deny')
        self.assertEqual(result['defaults']['outgoing'], 'allow')

    def test_a_missing_allow_or_deny_is_named(self):
        without_443 = self.complete().replace('--dport 443 -j ACCEPT', '--dport 444 -j ACCEPT')
        with self.assertRaisesRegex(ValueError, 'allow 443'):
            self.managed.firewall_effective(self.policy, {4: without_443}, self.status(), 'IPV6=no\n')
        without_deny = self.complete().replace('--dport 3002 -j DROP', '--dport 3003 -j DROP')
        with self.assertRaisesRegex(ValueError, 'deny 3002'):
            self.managed.firewall_effective(self.policy, {4: without_deny}, self.status(), 'IPV6=no\n')

    def test_a_permissive_default_or_inactive_firewall_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'did not enter the active state'):
            self.managed.firewall_effective(self.policy, {4: self.complete()},
                                            'Status: inactive\n', 'IPV6=no\n')
        with self.assertRaisesRegex(ValueError, 'deny incoming and allow outgoing'):
            self.managed.firewall_effective(self.policy, {4: self.complete()},
                                            self.status(incoming='allow'), 'IPV6=no\n')
        with self.assertRaisesRegex(ValueError, 'default policy'):
            self.managed.firewall_effective(
                self.policy, {4: self.ruleset([], input_policy='ACCEPT')}, self.status(), 'IPV6=no\n')

    def test_the_comment_ufw_writes_does_not_hide_a_rule(self):
        # UFW stores the comment inside the rule, so every rule this installer
        # writes comes back carrying `-m comment --comment "..."`. Both readers
        # must still recognise it, or the read-back fails on the first run and
        # the preflight refuses the installer's own rules on the second.
        commented = self.complete().replace(
            ' -j ', ' -m comment --comment "GoWave Auto NGINX" -j ')
        result = self.managed.firewall_effective(
            self.policy, {4: commented}, self.status(), 'IPV6=no\n')
        self.assertEqual(result['status'], 'success')
        preserved = self.managed.firewall_conflicts(self.policy, {
            4: '-A ufw-user-input -p tcp -m tcp --dport 8080 -m comment --comment "admin" -j ACCEPT'})
        self.assertEqual(preserved['conflicts'], [])
        self.assertEqual(len(preserved['preserved_exceptions']), 1)
        conflict = self.managed.firewall_conflicts(self.policy, {
            4: '-A ufw-user-input -p tcp -m tcp --dport 3002 -m comment --comment "mine" -j ACCEPT'})
        self.assertEqual(conflict['conflicts'][0]['ports'], [3002])

    def test_the_declaration_must_follow_the_listener_decision(self):
        with self.assertRaisesRegex(ValueError, 'IPv6 declaration'):
            self.managed.firewall_effective(self.policy, {4: self.complete()}, self.status(), 'IPV6=yes\n')

    def test_a_dual_stack_host_verifies_the_second_family(self):
        dual = self.managed.firewall_policy('aio', [22], ipv6=True)
        with self.assertRaisesRegex(ValueError, 'IPv6 ruleset was not read'):
            self.managed.firewall_effective(dual, {4: self.complete()}, self.status(), 'IPV6=yes\n')
        only_ssh = ['-A ufw6-user-input -p tcp -m tcp --dport 22 -j ACCEPT']
        with self.assertRaisesRegex(ValueError, 'allow 443'):
            self.managed.firewall_effective(
                dual, {4: self.complete(), 6: self.ruleset(only_ssh, family=6)}, self.status(), 'IPV6=yes\n')

    def test_a_dual_stack_host_reads_its_ipv6_chain_back(self):
        # ufw names the IPv6 chain `ufw6-user-input`. Reading it with the IPv4
        # name made every IPv6 rule look absent in the live acceptance run, so a
        # complete second family must verify here — a defect this test fails on
        # when the parser is fixed at the IPv4 chain name.
        dual = self.managed.firewall_policy('aio', [22], ipv6=True)
        v6_rules = [rule.replace('ufw-user-input', 'ufw6-user-input')
                    for rule in self.complete().splitlines()[4:-1]]
        result = self.managed.firewall_effective(
            dual, {4: self.complete(), 6: self.ruleset(v6_rules, family=6)}, self.status(), 'IPV6=yes\n')
        self.assertEqual(result['status'], 'success')

    def test_a_worker_source_exception_is_required_and_accepted(self):
        worker = self.managed.firewall_policy('worker', [22], 3002, ['192.0.2.10'])
        extra = '-A ufw-user-input -s 192.0.2.10/32 -p tcp -m tcp --dport 3002 -j ACCEPT'
        base = self.complete()
        body = base.splitlines()[4:-1] + [extra]
        result = self.managed.firewall_effective(worker, {4: self.ruleset(body)},
                                                 self.status(), 'IPV6=no\n')
        self.assertEqual(result['status'], 'success')
        without = [line for line in body if '192.0.2.10' not in line]
        with self.assertRaisesRegex(ValueError, 'allow 192.0.2.10'):
            self.managed.firewall_effective(worker, {4: self.ruleset(without)}, self.status(), 'IPV6=no\n')


class StreamedWorkerParityTests(unittest.TestCase):
    def test_the_streamed_copy_captures_the_same_baseline(self):
        source = NODE_AUTO.read_text()
        marker = "python3 - \"$root\" \"$image\" \"$action\" <<'FIREWALL_IMAGE_PY'"
        start = source.index(marker)
        start = source.index('\n', start) + 1
        end = source.index('\nFIREWALL_IMAGE_PY', start)
        streamed = source[start:end]
        compile(streamed, 'FIREWALL_IMAGE_PY', 'exec')
        self.assertEqual(source.count('<<\'FIREWALL_IMAGE_PY\''), 3,
                         'the payload carries the image code twice and the rollback script once')
        self.assertEqual(source.count('The restored IPv6 ruleset does not match the before-image.'), 3)

        local = Host()
        remote = Host()
        self.addCleanup(local.close)
        self.addCleanup(remote.close)
        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / 'streamed.py'
            helper.write_text(streamed + '\n')
            for script, host in ((FIREWALL_IMAGE_PY, local), (helper, remote)):
                result = subprocess.run(
                    ['python3', str(script), str(host.root), str(host.recovery / 'image'), 'capture'],
                    capture_output=True, text=True, env=host.env(), timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
        left = json.loads((local.recovery / 'image' / 'manifest.json').read_text())
        right = json.loads((remote.recovery / 'image' / 'manifest.json').read_text())
        self.assertEqual(left, right)


if __name__ == '__main__':
    unittest.main()
