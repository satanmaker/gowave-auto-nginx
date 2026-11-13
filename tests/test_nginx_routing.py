#!/usr/bin/env python3
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NGINX_SH = REPO_ROOT / "modules" / "nginx.sh"


class TestNginxRouting(unittest.TestCase):
    def test_ensure_nginx_stream_block(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            conf = tmp / "nginx.conf"
            conf.write_text("user www-data;\nevents { worker_connections 1024; }\nhttp { server {} }\n")

            cmd = f'source "{NGINX_SH}" && ensure_nginx_stream_block "{conf}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            content = conf.read_text()
            self.assertIn("stream {", content)
            self.assertIn("include /etc/nginx/stream-enabled/*.conf;", content)
            self.assertIn("# Managed by GoWave Auto NGINX: Stream SNI Multiplexer", content)

            # Running a second time should not duplicate
            res2 = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res2.returncode, 0, res2.stderr)
            self.assertEqual(conf.read_text().count("stream {"), 1)

    def test_generate_stream_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-stream.conf"
            inet6 = tmp / "if_inet6"

            # Case 1: IPv6 disabled
            cmd1 = f'source "{NGINX_SH}" && generate_stream_config "panel.example.com" "reality.example.com" "{out}" "{inet6}"'
            res1 = subprocess.run(["bash", "-c", cmd1], capture_output=True, text=True)
            self.assertEqual(res1.returncode, 0, res1.stderr)
            c1 = out.read_text()
            self.assertIn("listen 443 so_keepalive=on;", c1)
            self.assertNotIn("listen [::]:443", c1)
            self.assertIn("panel.example.com 127.0.0.1:7443;", c1)
            self.assertIn("reality.example.com 127.0.0.1:8443;", c1)
            self.assertIn("default 127.0.0.1:8443;", c1)
            self.assertIn("ssl_preread on;", c1)
            self.assertIn("proxy_protocol on;", c1)

            # Case 2: IPv6 enabled
            inet6.write_text("00000000000000000000000000000001 01 80 10 80 lo\n")
            res2 = subprocess.run(["bash", "-c", cmd1], capture_output=True, text=True)
            self.assertEqual(res2.returncode, 0, res2.stderr)
            c2 = out.read_text()
            self.assertIn("listen [::]:443 so_keepalive=on;", c2)

            # Case 3: Vision domain routing to 8444
            cmd3 = f'source "{NGINX_SH}" && generate_stream_config "panel.example.com" "reality.example.com" "{out}" "{inet6}" "vision.example.com"'
            res3 = subprocess.run(["bash", "-c", cmd3], capture_output=True, text=True)
            self.assertEqual(res3.returncode, 0, res3.stderr)
            c3 = out.read_text()
            self.assertIn("vision.example.com 127.0.0.1:8444;", c3)

    def test_generate_panel_https_vhost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-panel.conf"

            cmd = f'source "{NGINX_SH}" && generate_panel_https_vhost "panel.example.com" "{out}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            c = out.read_text()
            self.assertIn("server_name panel.example.com;", c)
            self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", c)
            self.assertIn("set_real_ip_from 127.0.0.1;", c)
            self.assertIn("real_ip_header proxy_protocol;", c)
            self.assertIn("location ^~ /api/sub/ {", c)
            self.assertIn("proxy_set_header User-Agent $http_user_agent;", c)
            self.assertIn("location ^~ /api/ {", c)
            self.assertIn("location / {", c)
            self.assertIn("location ^~ /xhttp-down/ {", c)
            self.assertIn("proxy_pass http://127.0.0.1:10001;", c)
            self.assertIn("location = /ws {", c)
            self.assertIn("proxy_pass http://127.0.0.1:10002;", c)
            self.assertIn("location /trojan-grpc {", c)
            self.assertIn("grpc_pass grpc://127.0.0.1:10003;", c)

    def test_generate_decoy_vhost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-decoy.conf"
            cover_dir = tmp / "cover-reality"

            cmd = f'source "{NGINX_SH}" && generate_decoy_vhost "reality.example.com" "{out}" nginx "{cover_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            c = out.read_text()
            self.assertIn("server_name reality.example.com;", c)
            self.assertIn("ssl_protocols TLSv1.3;", c)
            self.assertIn("access_log /var/log/nginx/gowave-decoy-access.log combined;", c)
            self.assertIn(f"root {cover_dir};", c)

            # Verify static assets copied
            self.assertTrue((cover_dir / "index.html").exists())
            self.assertTrue((cover_dir / "robots.txt").exists())
            self.assertTrue((cover_dir / "404.html").exists())

    def test_derive_cover_domain(self):
        cases = (
            ("panel.example.com", "example.com"),
            ("reality.example.com", "example.com"),
            ("panel.sub.example.org", "example.org"),
            ("example.com", ""),
            ("", ""),
        )
        for domain, expected in cases:
            with self.subTest(domain=domain):
                res = subprocess.run(
                    ["bash", "-c", f'source "{NGINX_SH}" && derive_cover_domain "{domain}"'],
                    capture_output=True, text=True,
                )
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(res.stdout.strip(), expected)

    def test_cover_domains_resolve_here_requires_both_records(self):
        cases = (
            ("", "203.0.113.10"),           # no cover domain at all
            ("example.com", ""),            # public IPv4 unknown
        )
        for domain, server_ip in cases:
            with self.subTest(domain=domain, server_ip=server_ip):
                res = subprocess.run(
                    ["bash", "-c",
                     f'source "{NGINX_SH}" && cover_domains_resolve_here "{domain}" "{server_ip}"'],
                    capture_output=True, text=True,
                )
                self.assertNotEqual(res.returncode, 0, "cover site must stay disabled")

    def test_render_cover_site_substitutes_every_placeholder(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cover_dir = Path(tmpdir) / "cover-reality"
            cmd = f'source "{NGINX_SH}" && render_cover_site "{cover_dir}" "reality.example.com"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            index = (cover_dir / "index.html").read_text()
            self.assertNotIn("{{", index)
            self.assertIn("Example", index)  # brand derives from the site label
            self.assertIn("/static/art/hero-1.svg", index)
            self.assertNotIn('src="/static/hero.svg"', index)
            self.assertNotIn('href="/favicon.ico"', index)

            css = (cover_dir / "static" / "site.css").read_text()
            self.assertIn("--accent:#0f6b5c", css)
            self.assertIn("--accent2:#14876f", css)

            for page in cover_dir.rglob("*"):
                if page.suffix in {".html", ".css", ".svg"}:
                    self.assertNotIn("{{", page.read_text(), f"unrendered placeholder in {page}")

    def test_cover_domain_reaches_the_decoy_and_redirects_http(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            inet6 = tmp / "if_inet6"
            stream = tmp / "stream.conf"
            http = tmp / "http.conf"
            decoy = tmp / "decoy.conf"
            cover_dir = tmp / "cover-reality"

            cmd = (
                f'source "{NGINX_SH}" && '
                f'generate_stream_config "panel.example.com" "reality.example.com" "{stream}" "{inet6}" "" "example.com" && '
                f'generate_production_http_vhost "panel.example.com" "reality.example.com" "{http}" "{inet6}" "" "example.com" && '
                f'generate_decoy_vhost "reality.example.com" "{decoy}" nginx "{cover_dir}" "example.com"'
            )
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            # The apex terminates on the decoy listener, not on the Xray fallback.
            stream_conf = stream.read_text()
            self.assertIn("example.com 127.0.0.1:9443;", stream_conf)
            self.assertIn("www.example.com 127.0.0.1:9443;", stream_conf)

            http_conf = http.read_text()
            self.assertIn("server_name panel.example.com reality.example.com example.com www.example.com;", http_conf)
            self.assertIn("www\\.example\\.com", http_conf)
            self.assertIn("return 301 https://$host$request_uri;", http_conf)

            decoy_conf = decoy.read_text()
            self.assertIn("server_name reality.example.com example.com www.example.com;", decoy_conf)
            self.assertIn("error_page 404 /404.html;", decoy_conf)
            self.assertTrue((cover_dir / "index.html").exists())
            self.assertNotIn("{{", (cover_dir / "index.html").read_text())

    def test_generate_bootstrap_acme_vhost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "00-bootstrap-acme.conf"
            inet6 = tmp / "if_inet6"

            # Case 1: Without vision domain
            cmd1 = f'source "{NGINX_SH}" && generate_bootstrap_acme_vhost "panel.example.com" "reality.example.com" "{out}" "{inet6}"'
            res1 = subprocess.run(["bash", "-c", cmd1], capture_output=True, text=True)
            self.assertEqual(res1.returncode, 0, res1.stderr)
            c1 = out.read_text()
            self.assertIn("server_name panel.example.com reality.example.com;", c1)
            self.assertNotIn("vision.example.com", c1)

            # Case 2: With vision domain
            cmd2 = f'source "{NGINX_SH}" && generate_bootstrap_acme_vhost "panel.example.com" "reality.example.com" "{out}" "{inet6}" "vision.example.com"'
            res2 = subprocess.run(["bash", "-c", cmd2], capture_output=True, text=True)
            self.assertEqual(res2.returncode, 0, res2.stderr)
            c2 = out.read_text()
            self.assertIn("server_name panel.example.com reality.example.com vision.example.com;", c2)

    def test_generate_production_http_vhost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-http.conf"
            inet6 = tmp / "if_inet6"

            # Case 1: Without vision domain
            cmd1 = f'source "{NGINX_SH}" && generate_production_http_vhost "panel.example.com" "reality.example.com" "{out}" "{inet6}"'
            res1 = subprocess.run(["bash", "-c", cmd1], capture_output=True, text=True)
            self.assertEqual(res1.returncode, 0, res1.stderr)
            c1 = out.read_text()
            self.assertIn("server_name panel.example.com reality.example.com;", c1)
            self.assertIn("if ($host ~* ^(panel.example.com|reality.example.com)$)", c1)
            self.assertNotIn("vision.example.com", c1)

            # Case 2: With vision domain
            cmd2 = f'source "{NGINX_SH}" && generate_production_http_vhost "panel.example.com" "reality.example.com" "{out}" "{inet6}" "vision.example.com"'
            res2 = subprocess.run(["bash", "-c", cmd2], capture_output=True, text=True)
            self.assertEqual(res2.returncode, 0, res2.stderr)
            c2 = out.read_text()
            self.assertIn("server_name panel.example.com reality.example.com vision.example.com;", c2)
            self.assertIn("if ($host ~* ^(panel.example.com|reality.example.com|vision.example.com)$)", c2)

    def test_generate_vision_fallback_vhost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-vision-fallback.conf"
            cover_dir = tmp / "cover-reality"

            cmd = f'source "{NGINX_SH}" && generate_vision_fallback_vhost "vision.example.com" "{out}" "{cover_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            c = out.read_text()
            self.assertIn("server_name vision.example.com;", c)
            self.assertIn("listen 127.0.0.1:9444 proxy_protocol;", c)
            self.assertIn(f"root {cover_dir};", c)
            self.assertTrue((cover_dir / "index.html").exists())
            self.assertTrue((cover_dir / "robots.txt").exists())
            self.assertTrue((cover_dir / "404.html").exists())

    def test_validate_acme_server(self):
        # Empty/unset is allowed (production default)
        cmd_empty = f'source "{NGINX_SH}" && validate_acme_server ""'
        self.assertEqual(subprocess.run(["bash", "-c", cmd_empty], capture_output=True).returncode, 0)

        # Official Staging URL allowed
        cmd_staging = f'source "{NGINX_SH}" && validate_acme_server "https://acme-staging-v02.api.letsencrypt.org/directory"'
        self.assertEqual(subprocess.run(["bash", "-c", cmd_staging], capture_output=True).returncode, 0)

        # Official Production URL allowed
        cmd_prod = f'source "{NGINX_SH}" && validate_acme_server "https://acme-v02.api.letsencrypt.org/directory"'
        self.assertEqual(subprocess.run(["bash", "-c", cmd_prod], capture_output=True).returncode, 0)

        # Arbitrary / untrusted URL rejected
        cmd_bad = f'source "{NGINX_SH}" && validate_acme_server "https://attacker.example.com/directory"'
        res_bad = subprocess.run(["bash", "-c", cmd_bad], capture_output=True, text=True)
        self.assertNotEqual(res_bad.returncode, 0)
        self.assertIn("Invalid GOWAVE_ACME_SERVER", res_bad.stderr)

    def test_validate_acme_test_mode_is_fail_closed(self):
        fixture = "https://pebble.testbed.internal:14000/dir"
        with tempfile.TemporaryDirectory() as tmpdir:
            ca_file = Path(tmpdir) / "pebble-ca.pem"
            ca_file.write_text("test-ca-material\n")
            digest = hashlib.sha256(ca_file.read_bytes()).hexdigest()

            # The fixture endpoint is rejected unless the explicit opt-in is set.
            res_no_mode = subprocess.run(
                ["bash", "-c", f'source "{NGINX_SH}" && validate_acme_server "{fixture}"'],
                capture_output=True, text=True,
            )
            self.assertNotEqual(res_no_mode.returncode, 0)
            self.assertIn("GOWAVE_ACME_TEST_MODE=1", res_no_mode.stderr)

            # Test mode without a pinned CA fails closed.
            env = {"GOWAVE_ACME_TEST_MODE": "1"}
            res_no_ca = subprocess.run(
                ["bash", "-c", f'source "{NGINX_SH}" && validate_acme_server "{fixture}"'],
                capture_output=True, text=True, env={**os.environ, **env},
            )
            self.assertNotEqual(res_no_ca.returncode, 0)
            self.assertIn("GOWAVE_ACME_TEST_CA_FILE", res_no_ca.stderr)

            # A wrong CA digest is rejected.
            env = {
                "GOWAVE_ACME_TEST_MODE": "1",
                "GOWAVE_ACME_TEST_CA_FILE": str(ca_file),
                "GOWAVE_ACME_TEST_CA_SHA256": "0" * 64,
            }
            res_bad_digest = subprocess.run(
                ["bash", "-c", f'source "{NGINX_SH}" && validate_acme_server "{fixture}"'],
                capture_output=True, text=True, env={**os.environ, **env},
            )
            self.assertNotEqual(res_bad_digest.returncode, 0)
            self.assertIn("digest mismatch", res_bad_digest.stderr)

            # The exact fixture endpoint with the pinned CA is accepted.
            env["GOWAVE_ACME_TEST_CA_SHA256"] = digest
            res_ok = subprocess.run(
                ["bash", "-c", f'source "{NGINX_SH}" && validate_acme_server "{fixture}"'],
                capture_output=True, text=True, env={**os.environ, **env},
            )
            self.assertEqual(res_ok.returncode, 0, res_ok.stderr)

            # Arbitrary URLs remain rejected even with test mode enabled.
            res_arbitrary = subprocess.run(
                ["bash", "-c", f'source "{NGINX_SH}" && validate_acme_server "https://attacker.example.com/dir"'],
                capture_output=True, text=True, env={**os.environ, **env},
            )
            self.assertNotEqual(res_arbitrary.returncode, 0)
            self.assertIn("pinned fixture endpoint", res_arbitrary.stderr)

    def test_check_acme_lineage_fixture_requires_pinned_ca(self):
        fixture = "https://pebble.testbed.internal:14000/dir"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ca_key = tmp / "ca.key"
            ca_cert = tmp / "ca.pem"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(ca_key), "-out", str(ca_cert),
                 "-days", "2", "-subj", "/CN=GoWave Podman Pebble CA"],
                check=True, stderr=subprocess.DEVNULL,
            )
            digest = hashlib.sha256(ca_cert.read_bytes()).hexdigest()
            live_dir = tmp / "live"
            live_dir.mkdir()
            renewal_conf = tmp / "panel.example.com.conf"
            renewal_conf.write_text(f"[renewalparams]\nserver = {fixture}\n")

            # A fixture lineage is rejected outside test mode.
            cmd_lineage = (
                f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" '
                f'"{fixture}" "{renewal_conf}" "{live_dir}"'
            )
            res_no_mode = subprocess.run(["bash", "-c", cmd_lineage], capture_output=True, text=True)
            self.assertNotEqual(res_no_mode.returncode, 0)
            self.assertIn("GOWAVE_ACME_TEST_MODE=1", res_no_mode.stderr)

            env = {
                "GOWAVE_ACME_TEST_MODE": "1",
                "GOWAVE_ACME_TEST_CA_FILE": str(ca_cert),
                "GOWAVE_ACME_TEST_CA_SHA256": digest,
            }

            # A certificate that does not chain to the pinned CA is rejected.
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(live_dir / "privkey.pem"),
                 "-out", str(live_dir / "fullchain.pem"),
                 "-days", "2", "-subj", "/CN=panel.example.com"],
                check=True, stderr=subprocess.DEVNULL,
            )
            res_untrusted = subprocess.run(
                ["bash", "-c", cmd_lineage], capture_output=True, text=True,
                env={**os.environ, **env},
            )
            self.assertNotEqual(res_untrusted.returncode, 0)
            self.assertIn("does not chain to the pinned local ACME test CA", res_untrusted.stderr)

            # A certificate issued by the pinned fixture CA is reusable.
            leaf_key = tmp / "leaf.key"
            leaf_csr = tmp / "leaf.csr"
            leaf_cert = tmp / "leaf.pem"
            subprocess.run(
                ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(leaf_key), "-out", str(leaf_csr),
                 "-subj", "/CN=panel.example.com"],
                check=True, stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["openssl", "x509", "-req", "-in", str(leaf_csr), "-CA", str(ca_cert),
                 "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(leaf_cert),
                 "-days", "2", "-sha256"],
                check=True, stderr=subprocess.DEVNULL,
            )
            (live_dir / "fullchain.pem").write_bytes(leaf_cert.read_bytes())
            (live_dir / "privkey.pem").write_bytes(leaf_key.read_bytes())
            res_trusted = subprocess.run(
                ["bash", "-c", cmd_lineage], capture_output=True, text=True,
                env={**os.environ, **env},
            )
            self.assertEqual(res_trusted.returncode, 0, res_trusted.stderr)

    def test_run_certbot_scopes_test_ca_trust(self):
        fixture = "https://pebble.testbed.internal:14000/dir"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ca_file = tmp / "pebble-ca.pem"
            ca_file.write_text("test-ca-material\n")
            digest = hashlib.sha256(ca_file.read_bytes()).hexdigest()
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            fake_certbot = bin_dir / "certbot"
            fake_certbot.write_text(
                "#!/usr/bin/env bash\n"
                "printf 'REQUESTS_CA_BUNDLE=%s\\nSSL_CERT_FILE=%s\\n' "
                "\"${REQUESTS_CA_BUNDLE:-}\" \"${SSL_CERT_FILE:-}\"\n"
            )
            fake_certbot.chmod(0o755)

            env = os.environ.copy()
            env.update({
                "PATH": f"{bin_dir}:{env['PATH']}",
                "GOWAVE_ACME_TEST_MODE": "1",
                "GOWAVE_ACME_SERVER": fixture,
                "GOWAVE_ACME_TEST_CA_FILE": str(ca_file),
                "GOWAVE_ACME_TEST_CA_SHA256": digest,
            })
            res = subprocess.run(
                ["bash", "-c", f'source "{NGINX_SH}" && run_certbot certonly'],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn(f"REQUESTS_CA_BUNDLE={ca_file}", res.stdout)
            self.assertIn(f"SSL_CERT_FILE={ca_file}", res.stdout)

    def test_check_acme_lineage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            renewal_conf = tmp / "panel.example.com.conf"
            live_dir = tmp / "live"
            live_dir.mkdir()
            cert_file = live_dir / "fullchain.pem"

            # Case 1: Fresh domain, no files exist -> passes
            cmd_fresh = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            self.assertEqual(subprocess.run(["bash", "-c", cmd_fresh], capture_output=True).returncode, 0)

            # Case 2: Renewal conf has matching production server -> passes
            renewal_conf.write_text("[renewalparams]\nserver = https://acme-v02.api.letsencrypt.org/directory\n")
            cmd_match = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            self.assertEqual(subprocess.run(["bash", "-c", cmd_match], capture_output=True).returncode, 0)

            # Case 3: Renewal conf was staging, requested production -> rejected
            renewal_conf.write_text("[renewalparams]\nserver = https://acme-staging-v02.api.letsencrypt.org/directory\n")
            cmd_mismatch = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            res_mismatch = subprocess.run(["bash", "-c", cmd_mismatch], capture_output=True, text=True)
            self.assertNotEqual(res_mismatch.returncode, 0)
            self.assertIn("ACME directory mismatch", res_mismatch.stderr)

            # Case 4: Renewal conf missing server parameter -> fails closed
            renewal_conf.write_text("[renewalparams]\nauthenticator = webroot\n")
            cmd_noserver = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            res_noserver = subprocess.run(["bash", "-c", cmd_noserver], capture_output=True, text=True)
            self.assertNotEqual(res_noserver.returncode, 0)
            self.assertIn("no readable 'server' field", res_noserver.stderr)

            # Case 5: Renewal conf has unrecognized server URL -> fails closed
            renewal_conf.write_text("[renewalparams]\nserver = https://unrecognized.acme.org/dir\n")
            cmd_unrec = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            res_unrec = subprocess.run(["bash", "-c", cmd_unrec], capture_output=True, text=True)
            self.assertNotEqual(res_unrec.returncode, 0)
            self.assertIn("unrecognized ACME directory", res_unrec.stderr)

            # Case 6: Certificate with (STAGING) in issuer rejected when production requested
            renewal_conf.unlink()
            key_file = live_dir / "privkey.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "1", "-subj", "/CN=(STAGING) Pretend Root"
            ], check=True, stderr=subprocess.DEVNULL)
            cmd_staging_cert = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            res_stg_cert = subprocess.run(["bash", "-c", cmd_staging_cert], capture_output=True, text=True)
            self.assertNotEqual(res_stg_cert.returncode, 0)
            self.assertIn("issued by staging", res_stg_cert.stderr)

            # Case 7: Certificate with production issuer rejected when staging requested
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "1", "-subj", "/CN=ISRG Root X1"
            ], check=True, stderr=subprocess.DEVNULL)
            cmd_prod_cert = f'source "{NGINX_SH}" && check_acme_lineage "panel.example.com" "https://acme-staging-v02.api.letsencrypt.org/directory" "{renewal_conf}" "{live_dir}"'
            res_prod_cert = subprocess.run(["bash", "-c", cmd_prod_cert], capture_output=True, text=True)
            self.assertNotEqual(res_prod_cert.returncode, 0)
            self.assertIn("issued by production", res_prod_cert.stderr)

    def test_verify_acme_certificate_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            live_dir = tmp / "live" / "vision.example.com"
            live_dir.mkdir(parents=True)
            cert_file = live_dir / "fullchain.pem"
            key_file = live_dir / "privkey.pem"

            # 1. Missing files fails closed
            cmd_missing = f'source "{NGINX_SH}" && verify_acme_certificate "vision.example.com" "{live_dir}"'
            self.assertNotEqual(subprocess.run(["bash", "-c", cmd_missing], capture_output=True).returncode, 0)

            # 2. Hostname mismatch fails closed
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "30", "-subj", "/CN=wrong.example.com",
                "-addext", "subjectAltName=DNS:wrong.example.com"
            ], check=True, stderr=subprocess.DEVNULL)
            # Assert the fixture itself rejects the requested hostname. This
            # prevents host OpenSSL configuration from silently adding a
            # matching SAN and turning the negative case into a false positive.
            fixture_check = subprocess.run([
                "openssl", "x509", "-checkhost", "vision.example.com",
                "-noout", "-in", str(cert_file)
            ], capture_output=True, text=True)
            self.assertIn(
                "Hostname vision.example.com does NOT match certificate",
                fixture_check.stdout,
            )
            cmd_wrong_host = f'source "{NGINX_SH}" && verify_acme_certificate "vision.example.com" "{live_dir}"'
            res_wrong_host = subprocess.run(["bash", "-c", cmd_wrong_host], capture_output=True, text=True)
            self.assertNotEqual(res_wrong_host.returncode, 0)
            self.assertIn("Certificate SAN/CN does not cover", res_wrong_host.stderr)

            # 3. Key mismatch fails closed
            alt_key = tmp / "alt.key"
            subprocess.run(["openssl", "genrsa", "-out", str(alt_key), "2048"], check=True, stderr=subprocess.DEVNULL)
            # Recreate certificate for vision.example.com with key_file
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "30", "-subj", "/CN=vision.example.com",
                "-addext", "subjectAltName=DNS:vision.example.com"
            ], check=True, stderr=subprocess.DEVNULL)
            # Overwrite privkey with alt_key
            key_file.write_bytes(alt_key.read_bytes())
            cmd_bad_key = f'source "{NGINX_SH}" && verify_acme_certificate "vision.example.com" "{live_dir}"'
            res_bad_key = subprocess.run(["bash", "-c", cmd_bad_key], capture_output=True, text=True)
            self.assertNotEqual(res_bad_key.returncode, 0)
            self.assertIn("do not cryptographically match", res_bad_key.stderr)

            # 4. Valid certificate and key passes
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "30", "-subj", "/CN=vision.example.com",
                "-addext", "subjectAltName=DNS:vision.example.com"
            ], check=True, stderr=subprocess.DEVNULL)
            cmd_valid = f'source "{NGINX_SH}" && verify_acme_certificate "vision.example.com" "{live_dir}"'
            self.assertEqual(subprocess.run(["bash", "-c", cmd_valid], capture_output=True).returncode, 0)

    def test_acme_lineage_snapshot_and_rollback_preexisting(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            rec_dir = tmp / "recovery"
            le_dir = tmp / "letsencrypt"
            domain = "panel.example.com"

            renewal_dir = le_dir / "renewal"
            archive_dir = le_dir / "archive" / domain
            live_dir = le_dir / "live" / domain
            renewal_dir.mkdir(parents=True)
            archive_dir.mkdir(parents=True)
            live_dir.mkdir(parents=True)

            renewal_conf = renewal_dir / f"{domain}.conf"
            renewal_conf.write_text("[renewalparams]\nserver = https://acme-v02.api.letsencrypt.org/directory\n")

            cert_file = archive_dir / "fullchain1.pem"
            key_file = archive_dir / "privkey1.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "30", "-subj", f"/CN={domain}"
            ], check=True, stderr=subprocess.DEVNULL)
            key_file.chmod(0o600)

            (live_dir / "fullchain.pem").symlink_to(f"../../archive/{domain}/fullchain1.pem")
            (live_dir / "privkey.pem").symlink_to(f"../../archive/{domain}/privkey1.pem")

            # Snapshot pre-existing lineage
            tx_id = "tx_preflight_1"
            cmd_snap = f'source "{NGINX_SH}" && snapshot_acme_lineage "{tx_id}" "{domain}" "{rec_dir}" "{le_dir}"'
            res_snap = subprocess.run(["bash", "-c", cmd_snap], capture_output=True, text=True)
            self.assertEqual(res_snap.returncode, 0, res_snap.stderr)

            snap_dir = rec_dir / tx_id / "acme" / domain
            self.assertTrue(snap_dir.is_dir())
            manifest = snap_dir / "lineage-manifest.json"
            self.assertTrue(manifest.is_file())
            self.assertIn('"existed_before": true', manifest.read_text())

            # Verify privkey copy in snapshot is 0600
            snap_privkey = snap_dir / "archive" / "privkey1.pem"
            self.assertTrue(snap_privkey.is_file())
            self.assertEqual(snap_privkey.stat().st_mode & 0o777, 0o600)

            # Mutate live/archive lineage (simulate certbot replacing certificate with different key)
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key_file), "-out", str(cert_file),
                "-days", "1", "-subj", "/CN=mutated.example.com"
            ], check=True, stderr=subprocess.DEVNULL)
            renewal_conf.write_text("[renewalparams]\nmutated = true\n")

            # Rollback to pre-existing lineage
            cmd_rollback = f'source "{NGINX_SH}" && restore_acme_lineage "{tx_id}" "{domain}" "{rec_dir}" "{le_dir}"'
            res_rollback = subprocess.run(["bash", "-c", cmd_rollback], capture_output=True, text=True)
            self.assertEqual(res_rollback.returncode, 0, res_rollback.stderr)

            # Assert original certificate restored
            restored_fc = live_dir / "fullchain.pem"
            res_check = subprocess.run(["openssl", "x509", "-in", str(restored_fc), "-noout", "-subject"], capture_output=True, text=True)
            self.assertIn(domain, res_check.stdout)

            # Cleanup snapshot
            cmd_clean = f'source "{NGINX_SH}" && cleanup_acme_snapshot "{tx_id}" "{domain}" "{rec_dir}"'
            self.assertEqual(subprocess.run(["bash", "-c", cmd_clean], capture_output=True).returncode, 0)
            self.assertFalse(snap_dir.exists())

    def test_acme_lineage_snapshot_and_rollback_new_domain(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            rec_dir = tmp / "recovery"
            le_dir = tmp / "letsencrypt"
            domain = "brand-new.example.com"

            tx_id = "tx_preflight_2"
            cmd_snap = f'source "{NGINX_SH}" && snapshot_acme_lineage "{tx_id}" "{domain}" "{rec_dir}" "{le_dir}"'
            res_snap = subprocess.run(["bash", "-c", cmd_snap], capture_output=True, text=True)
            self.assertEqual(res_snap.returncode, 0, res_snap.stderr)

            snap_dir = rec_dir / tx_id / "acme" / domain
            manifest = snap_dir / "lineage-manifest.json"
            self.assertTrue(manifest.is_file())
            self.assertIn('"existed_before": false', manifest.read_text())

            # Simulate certbot creating lineage during transaction
            renewal_dir = le_dir / "renewal"
            archive_dir = le_dir / "archive" / domain
            live_dir = le_dir / "live" / domain
            renewal_dir.mkdir(parents=True, exist_ok=True)
            archive_dir.mkdir(parents=True, exist_ok=True)
            live_dir.mkdir(parents=True, exist_ok=True)
            (renewal_dir / f"{domain}.conf").write_text("dummy")
            (live_dir / "fullchain.pem").write_text("dummy")

            # Rollback must delete transaction-created lineage
            cmd_rollback = f'source "{NGINX_SH}" && restore_acme_lineage "{tx_id}" "{domain}" "{rec_dir}" "{le_dir}"'
            res_rollback = subprocess.run(["bash", "-c", cmd_rollback], capture_output=True, text=True)
            self.assertEqual(res_rollback.returncode, 0, res_rollback.stderr)

            self.assertFalse((renewal_dir / f"{domain}.conf").exists())
            self.assertFalse(live_dir.exists())
            self.assertFalse(archive_dir.exists())

    def test_deploy_hook_ownership_preflight_unowned_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hook_file = tmp / "gowave-nginx.sh"
            hook_file.write_text("#!/bin/sh\necho foreign\n")
            rec_dir = tmp / "recovery"

            cmd = f'source "{NGINX_SH}" && verify_deploy_hook_preflight "{hook_file}" "tx1" "{rec_dir}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("Pre-existing unowned Certbot deploy hook found", res.stderr)

    def test_deploy_hook_ownership_repeated_install_accepts_its_own_hook(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hook_file = tmp / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
            rec_dir = tmp / "recovery"

            first = f'source "{NGINX_SH}" && install_managed_deploy_hook "install_1" "{hook_file}" "{rec_dir}"'
            res_first = subprocess.run(["bash", "-c", first], capture_output=True, text=True)
            self.assertEqual(res_first.returncode, 0, res_first.stderr)
            # Commit keeps the manifest: it is the only host-local proof that the
            # hook at this path was written by this product.
            self.assertTrue((rec_dir / "install_1" / "deploy-hook-manifest.json").is_file())

            # Every repeat install runs under a new transaction id, so its own
            # manifest does not exist yet; the hook a prior transaction recorded is
            # reused instead of being refused.
            for tx_id in ("install_2", "install_3"):
                repeat = f'source "{NGINX_SH}" && install_managed_deploy_hook "{tx_id}" "{hook_file}" "{rec_dir}"'
                res_repeat = subprocess.run(["bash", "-c", repeat], capture_output=True, text=True)
                self.assertEqual(res_repeat.returncode, 0, res_repeat.stderr)

            # A hook someone else rewrote is not the file any transaction recorded.
            hook_file.write_text("#!/bin/sh\necho hijacked\n")
            fourth = f'source "{NGINX_SH}" && verify_deploy_hook_preflight "{hook_file}" "install_4" "{rec_dir}"'
            res_fourth = subprocess.run(["bash", "-c", fourth], capture_output=True, text=True)
            self.assertNotEqual(res_fourth.returncode, 0)
            self.assertIn("Pre-existing unowned Certbot deploy hook found", res_fourth.stderr)

    def test_deploy_hook_ownership_create_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hook_file = tmp / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
            rec_dir = tmp / "recovery"
            tx_id = "tx_hook_1"

            # 1. Install managed deploy hook
            cmd_install = f'source "{NGINX_SH}" && install_managed_deploy_hook "{tx_id}" "{hook_file}" "{rec_dir}"'
            res_install = subprocess.run(["bash", "-c", cmd_install], capture_output=True, text=True)
            self.assertEqual(res_install.returncode, 0, res_install.stderr)
            self.assertTrue(hook_file.is_file())
            manifest = rec_dir / tx_id / "deploy-hook-manifest.json"
            self.assertTrue(manifest.is_file())

            # 2. Rollback
            cmd_rollback = f'source "{NGINX_SH}" && rollback_managed_deploy_hook "{tx_id}" "{hook_file}" "{rec_dir}"'
            res_rollback = subprocess.run(["bash", "-c", cmd_rollback], capture_output=True, text=True)
            self.assertEqual(res_rollback.returncode, 0, res_rollback.stderr)
            self.assertFalse(hook_file.exists())

    def test_deploy_hook_ownership_rollback_preserves_modified_replacement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hook_file = tmp / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
            rec_dir = tmp / "recovery"
            tx_id = "tx_hook_2"

            # Install managed hook
            cmd_install = f'source "{NGINX_SH}" && install_managed_deploy_hook "{tx_id}" "{hook_file}" "{rec_dir}"'
            res_install = subprocess.run(["bash", "-c", cmd_install], capture_output=True, text=True)
            self.assertEqual(res_install.returncode, 0)

            # Mutate hook content
            hook_file.write_text("#!/bin/sh\necho modified\n")

            # Rollback must preserve modified file and return nonzero
            cmd_rollback = f'source "{NGINX_SH}" && rollback_managed_deploy_hook "{tx_id}" "{hook_file}" "{rec_dir}"'
            res_rollback = subprocess.run(["bash", "-c", cmd_rollback], capture_output=True, text=True)
            self.assertNotEqual(res_rollback.returncode, 0)
            self.assertIn("digest mismatch", res_rollback.stderr)
            self.assertTrue(hook_file.is_file())


if __name__ == "__main__":
    unittest.main()
