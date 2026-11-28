#!/usr/bin/env python3
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "modules" / "os.sh"
OPERATOR_PATH = Path(__file__).resolve().parent.parent / "gowave-auto.sh"


class TestOSDetection(unittest.TestCase):
    def run_bash_fn(self, fn_name, *args, env=None):
        cmd = f'source "{MODULE_PATH}" && {fn_name} ' + " ".join(f'"{a}"' for a in args)
        return subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True,
            text=True,
            env=env or os.environ.copy(),
        )

    def test_check_os_supported_distributions(self):
        supported = [
            ("ubuntu", "24.04"),
            ("ubuntu", "26.04"),
            ("debian", "12"),
            ("debian", "13"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            os_release = Path(tmpdir) / "os-release"
            for distro, ver in supported:
                for quote in ("", '"', "'"):
                    with self.subTest(distro=distro, version=ver, quote=quote):
                        os_release.write_text(f"ID={quote}{distro}{quote}\nVERSION_ID={quote}{ver}{quote}\n")
                        res = self.run_bash_fn("check_os", str(os_release))
                        self.assertEqual(res.returncode, 0, f"Expected 0 for {distro} {ver}, got: {res.stderr}")

    def test_check_os_unsupported_distributions(self):
        unsupported = [
            ("ubuntu", "22.04"),
            ("ubuntu", "20.04"),
            ("debian", "11"),
            ("debian", "10"),
            ("centos", "7"),
            ("fedora", "39"),
            ("arch", "rolling"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            os_release = Path(tmpdir) / "os-release"
            for distro, ver in unsupported:
                with self.subTest(distro=distro, version=ver):
                    os_release.write_text(f'ID="{distro}"\nVERSION_ID="{ver}"\n')
                    res = self.run_bash_fn("check_os", str(os_release))
                    self.assertNotEqual(res.returncode, 0, f"Expected non-zero for {distro} {ver}")
                    self.assertIn("Unsupported OS", res.stderr)

    def test_check_os_missing_file_and_injection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / "pwned"
            os_release = Path(tmpdir) / "os-release"
            os_release.write_text(f'ID=$(touch "{marker}")\nVERSION_ID="12"\n')

            res = self.run_bash_fn("check_os", str(os_release))
            self.assertNotEqual(res.returncode, 0)
            self.assertFalse(marker.exists(), "Command injection vulnerability detected in check_os!")

            # Missing file
            missing = Path(tmpdir) / "nonexistent"
            res = self.run_bash_fn("check_os", str(missing))
            self.assertNotEqual(res.returncode, 0)

    def test_nginx_http2_syntax_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir) / "fake-nginx"

            # Test < 1.25.1 (e.g. 1.24.0, 1.22.1)
            for legacy_ver in ("1.24.0", "1.22.1", "1.20.0"):
                fake_bin.write_text(f'#!/bin/sh\necho "nginx version: nginx/{legacy_ver}" >&2\n')
                fake_bin.chmod(0o755)
                res = self.run_bash_fn("render_nginx_listen_ssl_http2", "127.0.0.1:7443", "proxy_protocol", str(fake_bin))
                self.assertEqual(res.returncode, 0)
                self.assertIn("listen 127.0.0.1:7443 ssl http2 proxy_protocol;", res.stdout)
                self.assertNotIn("http2 on;", res.stdout)

            # Test >= 1.25.1 (e.g. 1.25.1, 1.26.3, 1.27.0)
            for modern_ver in ("1.25.1", "1.26.3", "1.27.0"):
                fake_bin.write_text(f'#!/bin/sh\necho "nginx version: nginx/{modern_ver}" >&2\n')
                fake_bin.chmod(0o755)
                res = self.run_bash_fn("render_nginx_listen_ssl_http2", "127.0.0.1:7443", "proxy_protocol", str(fake_bin))
                self.assertEqual(res.returncode, 0)
                self.assertIn("listen 127.0.0.1:7443 ssl proxy_protocol;", res.stdout)
                self.assertIn("http2 on;", res.stdout)

    def test_check_kernel_ipv6(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            inet6_file = Path(tmpdir) / "if_inet6"

            # Present and non-empty
            inet6_file.write_text("00000000000000000000000000000001 01 80 10 80 lo\n")
            res = self.run_bash_fn("check_kernel_ipv6", str(inet6_file))
            self.assertEqual(res.returncode, 0)

            # Empty file
            inet6_file.write_text("")
            res = self.run_bash_fn("check_kernel_ipv6", str(inet6_file))
            self.assertNotEqual(res.returncode, 0)

            # Whitespace only, which no address table ever contains
            inet6_file.write_text("\n   \n")
            res = self.run_bash_fn("check_kernel_ipv6", str(inet6_file))
            self.assertNotEqual(res.returncode, 0)

            # Missing file
            res = self.run_bash_fn("check_kernel_ipv6", str(Path(tmpdir) / "no_file"))
            self.assertNotEqual(res.returncode, 0)

    def test_the_address_table_is_read_rather_than_measured(self):
        # /proc/net/if_inet6 reports st_size 0 however many addresses it prints,
        # so a helper that trusted ``[[ -s ]]`` reported "IPv6 disabled" on every
        # dual-stack host. /proc/version is the same shape: zero-sized, non-empty.
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir)
            sysctl = fake_bin / "sysctl"
            sysctl.write_text("#!/usr/bin/env bash\necho 0\n")
            sysctl.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            res = self.run_bash_fn("check_kernel_ipv6", "/proc/version", env=env)
            self.assertEqual(res.returncode, 0, res.stderr)

    def test_configure_debian_security_apt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            apt_dir = Path(tmpdir) / "apt.conf.d"
            os_release = Path(tmpdir) / "os-release"

            # Debian 12
            os_release.write_text('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
            res = self.run_bash_fn("configure_debian_security_apt", str(apt_dir), str(os_release))
            self.assertEqual(res.returncode, 0)
            conf = (apt_dir / "zz-gowave-auto-nginx").read_text()
            self.assertIn("origin=Debian,label=Debian-Security,codename=bookworm-security", conf)
            self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', conf)

            # Ubuntu 24.04
            os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            res = self.run_bash_fn("configure_debian_security_apt", str(apt_dir), str(os_release))
            self.assertEqual(res.returncode, 0)
            conf = (apt_dir / "zz-gowave-auto-nginx").read_text()
            self.assertIn('Unattended-Upgrade::Automatic-Reboot "false";', conf)

    def test_install_validates_inputs_before_touching_the_host(self):
        """The input contract is pure shell, so it precedes bootstrap and every mutation."""
        script = OPERATOR_PATH.read_text(encoding="utf-8")
        start = script.index("cmd_install() {")
        # The whole function, not a fixed character window: the window ended
        # before the cover probe once the install-mode branches grew, and a
        # guard that can no longer see the line it names is not a guard.
        body = script[start:script.index("\n}\n", start)]
        contract = body.index("preflight_require_inputs install")
        bootstrap = body.index("bootstrap_early_tools || return 1")
        cover = body.index("cover_server_ip=$(resolve_panel_ipv4)")
        self.assertLess(contract, bootstrap)
        self.assertLess(contract, body.index("check_os"))
        self.assertLess(contract, body.index("systemctl stop nginx"))
        self.assertLess(contract, body.index("run_preflight_panel"))
        # The call, not the word: the comment above the contract names the step
        # it is compared against, and a bare substring search reads that mention
        # as the call it is meant to precede.
        self.assertLess(contract, body.index("\n    install_prerequisites\n"))
        self.assertLess(bootstrap, cover)

    def test_bootstrap_packages_are_part_of_the_prerequisite_inventory(self):
        required = set(self.run_bash_fn("get_required_packages").stdout.split())
        bootstrap = set(self.run_bash_fn("get_bootstrap_packages").stdout.split())
        self.assertTrue(bootstrap)
        self.assertLessEqual(bootstrap, required)
        self.assertIn("python3", bootstrap)
        self.assertIn("iproute2", bootstrap)

    def test_nginx_pin_refusal_paths_do_not_install_packages(self):
        root = MODULE_PATH.parent
        script = r'''
source "$1/tempdir.sh"
source "$1/nginx_package.sh"
export TMPDIR="$2"
mode="$3"
dpkg() {
    if [[ "$1" == --print-architecture ]]; then
        printf 'amd64\n'
        return 0
    fi
    [[ "$mode" == downgrade ]]
}
dpkg-query() {
    [[ "$mode" == downgrade ]] || return 1
    printf '1.31.10-1~trixie\n'
}
curl() { :; }
gpg() { if [[ "$*" == *--export* ]]; then printf 'key\n'; fi; }
apt-cache() { printf 'nginx | 1.30.7-1~trixie | https://nginx.org/packages/debian trixie/nginx amd64 Packages\n'; }
apt-get() {
    printf '%s\n' "$*" >> "$TMPDIR/apt.log"
    [[ "$*" == *' update '* && "$mode" != auth ]]
}
install_pinned_nginx debian trixie
'''
        for mode, diagnostic in (
            ("downgrade", "Refusing to downgrade"),
            ("auth", "Could not authenticate"),
            ("missing", "no distribution fallback is approved"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(["bash", "-c", script, "test", str(root), directory, mode],
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
                log = Path(directory) / "apt.log"
                if mode == "downgrade":
                    self.assertFalse(log.exists())
                else:
                    calls = log.read_text().splitlines()
                    self.assertEqual(len(calls), 1)
                    self.assertIn(" update ", calls[0])
                    self.assertIn("Dir::Etc::sourceparts=-", calls[0])
                self.assertEqual(list(Path(directory).iterdir()), [log] if log.exists() else [])

    def test_the_vendor_fetch_carries_a_retry_budget(self):
        """One dropped connection to the vendor must not abort a re-apply.

        The signed vendor repository is the only source the pin accepts, so a
        single failed connection used to fail the whole Worker run and roll a
        serving host back. The budget is asserted on the commands the module
        actually runs: the refresh, the download and the install share one
        options array, so the retry reaches all three.
        """
        script = r'''
source "$1/tempdir.sh"
source "$1/nginx_package.sh"
export TMPDIR="$2"
dpkg() { printf 'amd64\n'; }
dpkg-query() { return 1; }
curl() {
    printf '%s\n' "$*" >> "$TMPDIR/curl.log"
    local out='' prev=''
    for arg in "$@"; do
        [[ "$prev" == -o ]] && out="$arg"
        prev="$arg"
    done
    [[ -n "$out" ]] && printf 'KEY\n' > "$out"
    return 0
}
gpg() { if [[ "$*" == *--export* ]]; then printf 'key\n'; fi; }
apt-cache() { return 1; }
apt-get() { printf '%s\n' "$*" >> "$TMPDIR/apt.log"; return 1; }
install_pinned_nginx debian trixie
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", "-c", script, "test", str(MODULE_PATH.parent), directory],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0, "an unreachable vendor was reported as installed")
            self.assertIn("Could not authenticate", result.stderr)
            curl_call = (Path(directory) / "curl.log").read_text()
            self.assertIn("--retry 3", curl_call)
            self.assertIn("--retry-connrefused", curl_call)
            apt_call = (Path(directory) / "apt.log").read_text()
            self.assertIn("Acquire::Retries=5", apt_call)

    def test_nginx_pin_checks_package_identity_before_install_and_stream_afterwards(self):
        script = r'''
source "$1/tempdir.sh"
source "$1/nginx_package.sh"
export TMPDIR="$2"
mode="$3"
version=1.30.8-1~trixie
dpkg() { printf 'amd64\n'; }
dpkg-query() {
    [[ -f "$TMPDIR/installed" ]] || return 1
    printf 'install ok installed %s\n' "$version"
}
curl() { :; }
gpg() { if [[ "$*" == *--export* ]]; then printf 'key\n'; fi; }
apt-cache() { printf 'nginx | %s | https://nginx.org/packages/debian trixie/nginx amd64 Packages\n' "$version"; }
apt-get() {
    case " $* " in
        *' update '*) ;;
        *' download nginx:amd64=1.30.8-1~trixie '*) touch nginx_test.deb ;;
        *' --no-install-recommends '*' install '*) touch "$TMPDIR/installed" ;;
        *) return 1 ;;
    esac
}
dpkg-deb() {
    case "$1:${3:-}" in
        -f:Package) printf 'nginx\n' ;;
        -f:Version) if [[ "$mode" == wrong-version ]]; then printf '1.30.7\n'; else printf '%s\n' "$version"; fi ;;
        -f:Architecture) printf 'amd64\n' ;;
        --fsys-tarfile:) printf 'authenticated binary\n' ;;
        *) return 1 ;;
    esac
}
tar() { command dd status=none; }
cmp() { [[ "$(command dd status=none)" == 'authenticated binary' && "$mode" != binary-mismatch ]]; }
{
    printf '#!/bin/sh\nprintf "configure arguments: --with-stream"\n'
    if [[ "$mode" != no-stream ]]; then
        printf 'printf " --with-stream_ssl_preread_module"\n'
    fi
    printf 'printf "\\n"\n'
} > "$TMPDIR/fake-nginx"
chmod +x "$TMPDIR/fake-nginx"
export NGINX_BINARY="$TMPDIR/fake-nginx"
install_pinned_nginx debian trixie
'''
        for mode, diagnostic in (
            ("verified", "Verified official NGINX"),
            ("wrong-version", "does not match the approved identity"),
            ("binary-mismatch", "does not match the authenticated package"),
            ("no-stream", "lacks the required static Stream SNI support"),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(["bash", "-c", script, "test", str(MODULE_PATH.parent), directory, mode],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, int(mode != "verified"), result.stderr)
                self.assertIn(diagnostic, result.stdout if mode == "verified" else result.stderr)
                self.assertEqual((Path(directory) / "installed").exists(), mode != "wrong-version")

    def test_install_prerequisites_always_enforces_the_nginx_pin(self):
        script = f'''
source "{MODULE_PATH}"
detect_os() {{ OS_ID=debian; OS_CODENAME=trixie; }}
check_prerequisites() {{ return 0; }}
ensure_systemd_resolved() {{ :; }}
install_pinned_nginx() {{ printf '%s:%s\\n' "$1" "$2"; return "${{PIN_RC:-0}}"; }}
install_prerequisites
'''
        satisfied = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        self.assertEqual(satisfied.returncode, 0, satisfied.stderr)
        self.assertIn("debian:trixie", satisfied.stdout)
        refused = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10,
                                 env={**os.environ, "PIN_RC": "1"})
        self.assertNotEqual(refused.returncode, 0)

    def test_required_packages_inventory(self):
        res = self.run_bash_fn("get_required_packages")
        self.assertEqual(res.returncode, 0)
        pkgs = set(res.stdout.strip().splitlines())
        expected = {
            "certbot",
            "python3",
            "python3-systemd",
            "sqlite3",
            "gnupg",
            "curl",
            "tar",
            "gzip",
            "openssl",
            "ufw",
            "fail2ban",
            "systemd-resolved",
            "iproute2",
            "ca-certificates",
            "openssh-client",
        }
        self.assertEqual(pkgs, expected)


if __name__ == "__main__":
    unittest.main()
