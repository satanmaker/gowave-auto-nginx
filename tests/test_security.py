#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANAGED_PY = REPO_ROOT / "assets" / "security" / "managed.py"
SECURITY_SH = REPO_ROOT / "modules" / "security.sh"


class TestSecurityModule(unittest.TestCase):
    def test_ssh_ports_parsing(self):
        # Import managed.py directly
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        # Standard sshd -T
        effective = "port 22\naddressfamily any\n"
        self.assertEqual(managed.ssh_ports(effective), [22])

        # Multiple ports
        effective_multi = "port 22\nport 2222\n"
        self.assertEqual(managed.ssh_ports(effective_multi), [22, 2222])

        # Socket activation listen
        socket_listen = "[::]:2200 (Stream) 0.0.0.0:2200 (Stream)"
        self.assertEqual(managed.ssh_ports(effective, socket_listen), [2200])

        # Invalid port
        with self.assertRaises(ValueError):
            managed.ssh_ports("port 70000\n")

    def test_firewall_policy_role_matrix(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('managed_policy', str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)
        for ipv6 in (False, True):
            for role in ('panel-only', 'aio', 'worker'):
                for node_port in (3002, 3333):
                    with self.subTest(ipv6=ipv6, role=role, node_port=node_port):
                        sources = ['192.0.2.10'] if role == 'worker' else []
                        if role == 'worker' and ipv6:
                            sources.append('2001:db8::10')
                        policy = managed.firewall_policy(role, [2222, 2200], node_port, sources, ipv6)
                        commands = policy['commands']
                        self.assertEqual(commands[:2], [['default', 'deny', 'incoming'], ['default', 'allow', 'outgoing']])
                        for port in (2200, 2222, 80, 443):
                            self.assertIn(['allow', f'{port}/tcp'], commands)
                        for port in (3000, 3001, 7443, 8443, 8444, 9443, 9444, 10001, 10002, 10003):
                            self.assertIn(['deny', f'{port}/tcp'], commands)
                        if role == 'panel-only':
                            self.assertIsNone(policy['node_port'])
                            self.assertNotIn(['deny', f'{node_port}/tcp'], commands)
                        else:
                            self.assertIn(['deny', f'{node_port}/tcp'], commands)
                        for source in sources:
                            allow = ['allow', 'proto', 'tcp', 'from', source, 'to', 'any', 'port', str(node_port)]
                            self.assertIn(allow, commands)
                            self.assertLess(commands.index(allow), commands.index(['deny', f'{node_port}/tcp']))

    def test_master_and_streamed_worker_policy_use_same_ssh_discovery(self):
        import base64
        helper = MANAGED_PY.read_text().replace(
            "if __name__ == '__main__':",
            "inspect_ssh_ports = lambda: ssh_ports('port 22\\n', '[::]:2200 (Stream) 0.0.0.0:2222 (Stream)')\nif __name__ == '__main__':",
        )
        worker_source = (REPO_ROOT / 'gowave-node-auto.sh').read_text()
        start = worker_source.index('worker_firewall_policy_json() {')
        end = worker_source.index('\nconfigure_firewall() {', start)
        with tempfile.TemporaryDirectory() as temporary:
            helper_path = Path(temporary) / 'managed.py'
            helper_path.write_text(helper)
            master = subprocess.run(
                ['bash', '-c', f'source "{SECURITY_SH}"; MANAGED_SECURITY_PY="{helper_path}"; firewall_policy_json worker 3333 192.0.2.10 "" false'],
                capture_output=True, text=True, timeout=10,
            )
            worker = subprocess.run(
                ['bash', '-c', 'set -Eeuo pipefail\nkernel_has_ipv6() { return 1; }\n' + worker_source[start:end] + '\nworker_firewall_policy_json'],
                env={**os.environ, 'NODE_PORT': '3333', 'PANEL_IP': '192.0.2.10',
                     'SECURITY_HELPER_B64': base64.b64encode(helper.encode()).decode()},
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(master.returncode, 0, master.stderr)
            self.assertEqual(worker.returncode, 0, worker.stderr)
            self.assertEqual(json.loads(master.stdout), json.loads(worker.stdout))
            self.assertEqual(json.loads(worker.stdout)['policy']['ssh_ports'], [2200, 2222])

    def test_firewall_policy_refuses_invalid_sources_and_port_collisions(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('managed_invalid_policy', str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)
        cases = (
            ('worker', [22], 3002, [], False),
            ('worker', [22], 3002, ['0.0.0.0'], False),
            ('worker', [22], 3002, ['2001:db8::1'], False),
            ('aio', [22], 443, [], False),
            ('aio', [3002], 3002, [], False),
            ('aio', [7443], 3002, [], False),
            ('aio', [True], 3002, [], False),
        )
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                managed.firewall_policy(*args)

    def test_firewall_preflight_classifies_existing_rules_without_mutation(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('managed_conflicts', str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)
        policy = managed.firewall_policy('worker', [22], 3333, ['192.0.2.10'], True)
        for expression in ('', '--dport 3333', '--dport 3000:4000', '-m multiport --dports 22,3333'):
            with self.subTest(expression=expression):
                rule = f'-A ufw-user-input -p tcp {expression} -j ACCEPT'
                result = managed.firewall_conflicts(policy, {4: rule})
                self.assertEqual(len(result['conflicts']), 1)
                self.assertIn(3333, result['conflicts'][0]['ports'])
        rules = '\n'.join((
            '-A ufw-user-input -p tcp --dport 22 -j ACCEPT',
            '-A ufw-user-input -p tcp --dport 8080 -j ACCEPT',
            '-A ufw-user-input -p tcp -m tcp -s 192.0.2.10/32 --dport 3333 -j ACCEPT',
            '-A ufw-user-input -i lo -j ACCEPT',
        ))
        result = managed.firewall_conflicts(policy, {4: rules})
        self.assertEqual(result['conflicts'], [])
        # The 22 allow is the policy's own rule, so only the 8080 grant is an
        # administrator exception the operator has to be told about.
        self.assertEqual(len(result['preserved_exceptions']), 1)
        self.assertEqual(managed.firewall_conflicts(policy, {6: '-A ufw-user-input -p tcp --dport 3333 -j ACCEPT'})['conflicts'][0]['family'], 6)
        with self.assertRaises(ValueError):
            managed.firewall_conflicts(policy, {4: rules}, ['firewalld.service'])
        with self.assertRaises(ValueError):
            managed.firewall_conflicts(policy, {4: '-A ufw-user-input -p tcp -m mystery -j ACCEPT'})

    def test_firewall_inspection_reads_files_and_never_calls_mutators(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location('managed_inspection', str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)
        policy = managed.firewall_policy('aio', [22])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'etc' / 'ufw'
            directory.mkdir(parents=True)
            rules = directory / 'user.rules'
            rules.write_text('-A ufw-user-input -p tcp --dport 8080 -j ACCEPT\n')
            before = rules.read_bytes()
            with mock.patch.object(managed, 'command', return_value='inactive') as command:
                result = managed.inspect_firewall_conflicts(policy, root)
                self.assertEqual(result['conflicts'], [])
                self.assertEqual(len(result['preserved_exceptions']), 1)
                self.assertEqual(rules.read_bytes(), before)
                for args in command.call_args_list:
                    self.assertEqual(args.args[:2], ('systemctl', 'is-active'))
                rules.write_text('-A ufw-user-input -p tcp --dport 3002 -j ACCEPT\n')
                with self.assertRaisesRegex(ValueError, 'conflicts'):
                    managed.inspect_firewall_conflicts(policy, root)
                rules.unlink()
                rules.symlink_to('/dev/null')
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    managed.inspect_firewall_conflicts(policy, root)
                rules.unlink()
                with self.assertRaisesRegex(ValueError, 'Cannot inspect'):
                    managed.inspect_firewall_conflicts(policy, root)
                rules.write_text('')
                command.return_value = 'active'
                with self.assertRaisesRegex(ValueError, 'Competing'):
                    managed.inspect_firewall_conflicts(policy, root)

    def test_password_warning(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        self.assertTrue(managed.password_warning("passwordauthentication yes\n"))
        self.assertFalse(managed.password_warning("passwordauthentication no\nkbdinteractiveauthentication no\n"))

    def test_apt_config_automatic_reboot_false(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        ubuntu_apt = managed.apt_config("ubuntu")
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', ubuntu_apt)
        self.assertIn('archive=${distro_codename}-security', ubuntu_apt)

        debian_apt = managed.apt_config("debian")
        self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', debian_apt)
        self.assertIn('origin=Debian,label=Debian-Security', debian_apt)

    def test_preflight_supported_os(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "etc").mkdir()
            os_release = root / "etc" / "os-release"

            # Debian 12
            os_release.write_text('ID=debian\nVERSION_ID="12"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "debian")

            # Debian 13
            os_release.write_text('ID=debian\nVERSION_ID="13"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "debian")

            # Ubuntu 24.04
            os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "ubuntu")

            # Ubuntu 26.04
            os_release.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
            self.assertEqual(managed.preflight(root=root, files=(), services=()), "ubuntu")

            # Unsupported
            os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
            with self.assertRaises(ValueError):
                managed.preflight(root=root, files=(), services=())

    def test_dns_drop_in_directory_stays_readable_under_strict_umask(self):
        """systemd-resolved runs as systemd-resolve and cannot read a 0700 drop-in dir."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("managed", str(MANAGED_PY))
        managed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(managed)

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "etc").mkdir()
            txn = managed.Transaction(root=root, services=(), files=())
            previous_umask = os.umask(0o077)
            try:
                txn.write("/etc/systemd/resolved.conf.d/90-gowave-auto-nginx.conf", managed.DOT)
            finally:
                os.umask(previous_umask)
                txn.temp.cleanup()

            drop_in_dir = root / "etc" / "systemd" / "resolved.conf.d"
            self.assertEqual(drop_in_dir.stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                (drop_in_dir / "90-gowave-auto-nginx.conf").stat().st_mode & 0o777, 0o644
            )

    def test_bbr_and_mtu_configuration(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            sysctl_file = tmp / "99-gowave.conf"
            bbr_service = tmp / "bbr-load.service"
            state_file = tmp / "state.json"
            original_state = {
                "schemaVersion": 2,
                "nodes": [{"name": "worker-1", "uuid": "node-1"}],
                "squadUuid": "squad-1",
            }
            state_file.write_text(json.dumps(original_state))

            cmd = f'source "{SECURITY_SH}" && configure_bbr_and_mtu "{state_file}" "{sysctl_file}" "{bbr_service}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # Check MTU probing directive
            sysctl_content = sysctl_file.read_text()
            self.assertIn("net.ipv4.tcp_mtu_probing = 1", sysctl_content)

            # Check systemd unit ordering Before=systemd-sysctl.service
            service_content = bbr_service.read_text()
            self.assertIn("Before=systemd-sysctl.service", service_content)
            self.assertIn("ConditionVirtualization=!container", service_content)

            # Check state.json records congestionControl and has mode 0600
            if state_file.exists():
                data = json.loads(state_file.read_text())
                self.assertIn(data.get("congestionControl"), ("bbr", "cubic"))
                self.assertEqual(data["nodes"], original_state["nodes"])
                self.assertEqual(data["squadUuid"], original_state["squadUuid"])
                self.assertEqual(oct(state_file.stat().st_mode & 0o777), "0o600")

    def test_bbr_state_update_refuses_corrupt_existing_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            state_file = tmp / "state.json"
            sysctl_file = tmp / "99-gowave.conf"
            bbr_service = tmp / "bbr-load.service"
            corrupt = "{broken state"
            state_file.write_text(corrupt)

            cmd = f'source "{SECURITY_SH}" && configure_bbr_and_mtu "{state_file}" "{sysctl_file}" "{bbr_service}"'
            result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state_file.read_text(), corrupt)

    def test_log_rotation_and_journal_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            logrotate_file = tmp / "gowave-nginx"
            journal_file = tmp / "99-gowave.conf"

            cmd = f'source "{SECURITY_SH}" && configure_log_rotation "{logrotate_file}" "{journal_file}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            # Check logrotate content
            logrotate_content = logrotate_file.read_text()
            self.assertIn("daily", logrotate_content)
            self.assertIn("rotate 7", logrotate_content)
            self.assertIn("compress", logrotate_content)

            # Check journal cap SystemMaxUse=100M
            journal_content = journal_file.read_text()
            self.assertIn("SystemMaxUse=100M", journal_content)

    # `configure_ufw` itself is exercised by tests/test_firewall.py against a
    # disposable host, including the declaration-before-rules ordering and the
    # rollback of every failed mutation.


if __name__ == "__main__":
    unittest.main()
