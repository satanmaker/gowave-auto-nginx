#!/usr/bin/env python3
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tools.podman_e2e import panel_surface  # noqa: E402

NGINX_SH = REPO_ROOT / "modules" / "nginx.sh"
PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"


def issue_lineage(letsencrypt_root, name, sans, server=PRODUCTION_DIRECTORY, expired=False, archived=False):
    """Place a lineage where certbot would: live/<name>/ and renewal/<name>.conf.

    An expired certificate cannot be made with `openssl req -days` (the option
    takes no negative value) and `-not_after` is too new for the OpenSSL 3.0 the
    supported distributions ship, so the expired case goes through a throwaway CA
    whose `-startdate`/`-enddate` accept any window.

    ``archived`` reproduces certbot's real layout: the files live in
    ``archive/<name>/`` and ``live/<name>/`` holds relative symlinks into it.
    The snapshot helper refuses a lineage whose archive directory is absent, and
    this is the shape a host that certbot has issued to actually has.
    """
    root = Path(letsencrypt_root)
    live_dir = root / "live" / name
    renewal_dir = root / "renewal"
    live_dir.mkdir(parents=True, exist_ok=True)
    renewal_dir.mkdir(parents=True, exist_ok=True)
    (renewal_dir / f"{name}.conf").write_text(
        f"[renewalparams]\nserver = {server}\nauthenticator = webroot\n", encoding="utf-8"
    )
    cert = live_dir / "fullchain.pem"
    key = live_dir / "privkey.pem"
    subject_alt_names = ",".join(f"DNS:{san}" for san in sans)
    if expired:
        work = root / f".ca-{name}"
        work.mkdir(parents=True, exist_ok=True)
        (work / "serial").write_text("01\n", encoding="utf-8")
        (work / "index.txt").write_text("", encoding="utf-8")
        (work / "newcerts").mkdir(exist_ok=True)
        (work / "ca.cnf").write_text(
            "[ ca ]\n"
            "default_ca = CA_default\n"
            "[ CA_default ]\n"
            "dir = .\n"
            "database = ./index.txt\n"
            "serial = ./serial\n"
            "new_certs_dir = ./newcerts\n"
            "default_md = sha256\n"
            "policy = policy_any\n"
            "copy_extensions = copy\n"
            "[ policy_any ]\n"
            "commonName = supplied\n"
            "[ v3 ]\n"
            f"subjectAltName = {subject_alt_names}\n"
            "basicConstraints = critical,CA:FALSE\n",
            encoding="utf-8",
        )
        subprocess.run([
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", "req.csr", "-subj", f"/CN={sans[0]}",
        ], check=True, cwd=work, stderr=subprocess.DEVNULL)
        subprocess.run([
            "openssl", "ca", "-batch", "-config", "ca.cnf", "-selfsign",
            "-keyfile", str(key), "-in", "req.csr", "-out", str(cert),
            "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
            "-extensions", "v3", "-notext",
        ], check=True, cwd=work, stderr=subprocess.DEVNULL)
    else:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "30",
            "-subj", f"/CN={sans[0]}",
            "-addext", f"subjectAltName={subject_alt_names}",
        ], check=True, stderr=subprocess.DEVNULL)

    if archived:
        store = root / "archive" / name
        store.mkdir(parents=True, exist_ok=True)
        for path in (cert, key):
            target = store / path.name
            shutil.move(str(path), str(target))
            path.symlink_to(Path("..") / ".." / "archive" / name / path.name)
    return live_dir


def select_lineage(name, letsencrypt_root, server=PRODUCTION_DIRECTORY):
    cmd = (
        f'source "{NGINX_SH}" && select_acme_lineage '
        f'"{name}" "{server}" "{letsencrypt_root}"'
    )
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)


def render_panel_vhost(directory, panel_domain="panel.example.com"):
    out = Path(directory) / "gowave-panel.conf"
    cmd = f'source "{NGINX_SH}" && generate_panel_https_vhost "{panel_domain}" "{out}"'
    res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    if res.returncode != 0:
        raise AssertionError(res.stderr)
    return out.read_text()


def nginx_block(text, header):
    """Return the body of the first block whose opening line contains ``header``."""
    start = text.index(header)
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(f"unterminated block: {header}")


def map_entries(text, header):
    """Parse a map body into ``(mode, pattern, value)`` with ``mode`` in default|exact|regex."""
    body = nginx_block(text, header)
    body = body[body.index("{") + 1:body.rindex("}")]
    entries = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.rpartition(" ")
        key = key.strip()
        value = value.rstrip(";").strip()
        if key == "default":
            entries.append(("default", None, value))
        elif key.startswith('"~'):
            entries.append(("regex", key.strip('"')[1:], value))
        elif key.startswith("~*"):
            entries.append(("regex_i", key[2:], value))
        elif key.startswith("~"):
            entries.append(("regex", key[1:], value))
        else:
            entries.append(("exact", key, value))
    return entries


def map_lookup(entries, subject):
    fallback = ""
    for mode, pattern, value in entries:
        if mode == "default":
            fallback = value
        elif mode == "exact" and subject == pattern:
            return value
        elif mode == "regex" and re.search(pattern, subject):
            return value
        elif mode == "regex_i" and re.search(pattern, subject, re.IGNORECASE):
            return value
    return fallback


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
            # The panel vhost must not announce its build, must not copy a
            # client-supplied forwarding header, and must declare its maps above
            # the server block it serves.
            self.assertIn("server_tokens off;", c)
            self.assertLess(c.index("map $http_user_agent $gowave_sub_ua_class {"),
                            c.index("server {"), "the User-Agent map must precede the server block")
            self.assertLess(c.index("map $request_uri $gowave_sub_path_bad {"),
                            c.index("server {"), "the path map must precede the server block")
            self.assertNotIn("proxy_add_x_forwarded_for", c)
            self.assertEqual(c.count("proxy_set_header X-Forwarded-For $remote_addr;"), 5)

    def test_panel_vhost_hands_the_panel_only_the_peer_address(self):
        """Every header the Panel prefers over the socket is answered by the edge.

        The Panel reads ten address headers before it falls back to the
        connection, and a vhost that rewrote only the two conventional ones left
        eight by which a client could choose the address the Panel records for
        rate limits, login attempts and notifications. The guard is written
        against that list rather than a literal so a header the Panel starts
        honouring cannot be added there and left forwarded here.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            c = render_panel_vhost(tmpdir)
            cleared = tuple(panel_surface.PANEL_CLEARED_CLIENT_IP_HEADERS)
            self.assertIn("X-Remnawave-Real-IP", cleared)
            self.assertNotIn("X-Forwarded-For", cleared)
            self.assertNotIn("X-Real-IP", cleared)
            locations = (
                "location ^~ /api/sub/",
                "location ^~ /api/",
                "location / {",
                "location ^~ /xhttp-down/",
                "location = /ws {",
            )
            for header in locations:
                block = nginx_block(c, header)
                for name in panel_surface.PANEL_CLIENT_IP_HEADERS:
                    expected = (
                        "$remote_addr"
                        if name in panel_surface.PANEL_FORWARDED_CLIENT_IP_HEADERS
                        else '""'
                    )
                    self.assertIn(
                        f"proxy_set_header {name} {expected};", block,
                        f"{header} does not hand the Panel {name!r} as {expected}",
                    )
                # Nothing the Panel trusts may arrive from the client itself.
                self.assertNotRegex(
                    block,
                    r"proxy_set_header\s+(?:"
                    + "|".join(re.escape(name) for name in panel_surface.PANEL_CLIENT_IP_HEADERS)
                    + r")\s+\$http_",
                )

    def test_panel_vhost_subscription_headers_are_status_independent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c = render_panel_vhost(tmpdir)
            block = nginx_block(c, "location ^~ /api/sub/")
            self.assertIn('add_header Cache-Control "no-store, private" always;', block)
            self.assertIn(
                'add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet" always;', block)
            # `always` is the whole point: without it a 502 from the Panel reaches
            # the client with no cache directive.
            for line in block.splitlines():
                if "add_header" in line:
                    self.assertIn("always", line, f"header without `always`: {line.strip()}")

    def test_panel_vhost_subscription_access_log_is_off(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c = render_panel_vhost(tmpdir)
            self.assertIn("access_log off;", nginx_block(c, "location ^~ /api/sub/"))
            # The transports keep the suppression they already had.
            self.assertIn("access_log off;", nginx_block(c, "location ^~ /xhttp-down/"))
            self.assertIn("access_log off;", nginx_block(c, "location = /ws {"))

    def test_panel_vhost_user_agent_classification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c = render_panel_vhost(tmpdir)
            header = "map $http_user_agent $gowave_sub_ua_class"
            entries = map_entries(c, header)
            self.assertEqual(entries[0], ("default", None, "client"))
            self.assertNotIn('""', nginx_block(c, header),
                             "an empty header key would answer an absent User-Agent itself")
            previews = (
                "TelegramBot (like TwitterBot)",
                "WhatsApp/2.23.20.0",
                "facebookexternalhit/1.1",
                "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
                "Discordbot/2.0",
                "Twitterbot/1.0",
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (compatible; bingbot/2.0)",
                "Mozilla/5.0 (compatible; YandexBot/3.0)",
                "Mozilla/5.0 (compatible; YandexImages/3.0)",
                "Mozilla/5.0 (compatible; Applebot/0.1)",
                "Mozilla/5.0 (compatible; AhrefsBot/7.0)",
                "Mozilla/5.0 (compatible; SemrushBot/7~bl)",
            )
            for ua in previews:
                with self.subTest(user_agent=ua):
                    self.assertEqual(map_lookup(entries, ua), "preview")
            clients = (
                "",
                "curl/8.5.0",
                "clash-verge/v2.0.0",
                "ClashforWindows/0.20.39",
                "mihomo/1.18.0",
                "v2rayN/6.31",
                "sing-box 1.10.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0",
                "GoWave/1.0",
            )
            for ua in clients:
                with self.subTest(user_agent=ua):
                    self.assertEqual(map_lookup(entries, ua), "client")
            # The `204` is answered by the same location, so `add_header` applies.
            self.assertIn("if ($gowave_sub_ua_class = preview) {", c)
            self.assertIn("return 204;", nginx_block(c, "location ^~ /api/sub/"))

    def test_panel_vhost_path_guard_is_keyed_on_the_raw_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c = render_panel_vhost(tmpdir)
            header = "map $request_uri $gowave_sub_path_bad"
            self.assertIn(header, c)
            self.assertNotIn("map $uri $gowave_sub_path_bad", c)
            # The counted pattern keeps its quotes: braces are block delimiters
            # to the config parser, and an unquoted one fails `nginx -t`.
            self.assertIn('"~^/api/sub/[A-Za-z0-9_-]+/[a-z0-9-]{17,}"', c)
            entries = map_entries(c, header)
            self.assertEqual([value for mode, _, value in entries if mode == "default"], ["0"])
            good = (
                "/api/sub/",
                "/api/sub/abcd1234",
                # The identifier is a shortUuid the Panel issues from base64url,
                # so an upper-case letter or an underscore is part of a real link.
                "/api/sub/k_2yr52aHyK4j4jg",
                "/api/sub/k_2yr52aHyK4j4jg/v2ray-json",
                "/api/sub/k_2yr52aHyK4j4jg/mihomo",
                "/api/sub/k_2yr52aHyK4j4jg/clash",
                "/api/sub/k_2yr52aHyK4j4jg/clash?token=abc",
                "/api/sub/abcd1234/clash",
                "/api/sub/abcd1234/mihomo",
                "/api/sub/abcd1234/singbox",
                "/api/sub/abcd1234/json",
                "/api/sub/abcd1234/v2ray-json",
                "/api/sub/abcd1234/stash",
                "/api/sub/abcd1234/info",
                "/api/sub/abcd1234/clash?token=abc",
                "/api/sub/abcd1234/0123456789abcdef",
            )
            for target in good:
                with self.subTest(target=target):
                    self.assertEqual(map_lookup(entries, target), "0", target)
            bad = (
                "/api/sub/x/../y",
                "/api/sub/x/../../../etc/passwd",
                "/api/sub/k_2yr52aHyK4j4jg/../../x",
                "/api/sub/abcd1234/x%2Fy",
                "/api/sub/abcd1234/CLASH",
                "/api/sub/abcd1234/cl ash",
                "/api/sub/abcd1234/a;b",
                "/api/sub/abcd1234/0123456789abcdefg",
                "/api/sub/k_2yr52aHyK4j4jg/0123456789abcdefg",
            )
            for target in bad:
                with self.subTest(target=target):
                    self.assertEqual(map_lookup(entries, target), "1", target)
            # Server level is the only place that sees a target which normalises
            # out of the prefix.
            server = nginx_block(c, "server {")
            self.assertLess(server.index("if ($gowave_sub_path_bad)"),
                            server.index("location "),
                            "the guard must run in the rewrite phase, before location selection")

    def test_panel_vhost_scanner_set_is_anchored_and_cannot_shadow_product_routes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            c = render_panel_vhost(tmpdir)
            block = nginx_block(c, "location ~* ^/(?:")
            self.assertIn("return 444;", block)
            pattern = re.search(r"location ~\* (\^/.*?) \{", block).group(1)
            closed = (
                "/.env",
                "/.git/config",
                "/.git/",
                "/.DS_Store",
                "/wp-login.php",
                "/wp-admin/",
                "/wp-admin",
                "/phpmyadmin/",
                "/server-status",
                "/actuator/health",
                "/actuator",
            )
            for path in closed:
                with self.subTest(path=path):
                    self.assertRegex(path, re.compile(pattern, re.IGNORECASE))
            served = (
                "/",
                "/login",
                "/dashboard",
                "/api/",
                "/api/sub/abcd1234/clash",
                "/api/nodes",
                "/api/auth/login",
                "/xhttp-down/abcd",
                "/ws",
                "/trojan-grpc",
                "/.well-known/acme-challenge/token",
                "/.well-known/security.txt",
                "/assets/app.9f8e7d.js",
                "/.gitlab-ci.yml",
                "/phpmyadminish",
                "/server-statusx",
            )
            for path in served:
                with self.subTest(path=path):
                    self.assertNotRegex(path, re.compile(pattern, re.IGNORECASE))
            # A regex location wins over the plain prefix `location /`, but never
            # over `^~ /api/` or `^~ /xhttp-down/`.
            self.assertLess(c.index("location ~* ^/(?:"), c.index("    location / {"))

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
            # The decoy is a static site, not an nginx: a response that names the
            # build and the distribution is a fingerprint the site does not need.
            self.assertIn("server_tokens off;", c)

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

    def test_cover_domain_for_names_every_refusal(self):
        """The decoy decision returns the apex or says why it cannot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()
            getent = fake_bin / "getent"
            getent.write_text(
                "#!/usr/bin/env bash\n"
                'name="${2}"\n'
                'if [[ -n "${FAKE_UNRESOLVED:-}" && "$name" == "$FAKE_UNRESOLVED" ]]; then\n'
                "    exit 2\n"
                "fi\n"
                'printf \'%s\\n\' "${FAKE_RESOLVED:-203.0.113.10} STREAM ${name}"\n'
            )
            getent.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

            def run(domain, server_ip="", resolved="203.0.113.10", unresolved=""):
                environment["FAKE_RESOLVED"] = resolved
                environment["FAKE_UNRESOLVED"] = unresolved
                return subprocess.run(
                    ["bash", "-c",
                     f'source "{NGINX_SH}" && cover_domain_for "{domain}" "{server_ip}"'],
                    capture_output=True, text=True, env=environment,
                )

            # A registrable apex that both names resolve to.
            res = run("panel.example.com", "203.0.113.10")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "example.com")
            self.assertEqual(res.stderr, "")

            # The last two labels win, however deep the deployment domain is.
            res = run("a.panel.sub.example.org", "203.0.113.10")
            self.assertEqual(res.stdout.strip(), "example.org")

            # No subdomain: nothing to derive, and the refusal names the cause.
            res = run("example.com", "203.0.113.10")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertIn("example.com has no subdomain", res.stderr)

            # A single label is refused the same way instead of silently.
            res = run("localhost", "")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertIn("localhost has no subdomain", res.stderr)

            # An apex that does not resolve is a different, named refusal.
            res = run("panel.example.com", "203.0.113.10", resolved="198.51.100.7")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertIn("do not resolve to 203.0.113.10", res.stderr)

            # Half of the pair is named on its own, so the operator knows which
            # record to fix rather than re-checking both.
            res = run("panel.example.com", "203.0.113.10",
                      unresolved="www.example.com")
            self.assertEqual(res.stdout, "")
            self.assertIn("Camouflage apex disabled — www.example.com does not resolve "
                          "to 203.0.113.10", res.stderr)

            res = run("panel.example.com", "203.0.113.10", unresolved="example.com")
            self.assertEqual(res.stdout, "")
            self.assertIn("Camouflage apex disabled — example.com does not resolve "
                          "to 203.0.113.10", res.stderr)
            self.assertNotIn("www.example.com", res.stderr)

            # No domain at all is not an error and not a refusal to explain.
            res = run("", "")
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertEqual(res.stderr, "")

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

    def test_select_acme_lineage_adopts_a_suffixed_covering_lineage(self):
        """A lineage named after a suffix serves the name it covers.

        Re-issuing under the requested name is what leaves a host with two
        lineages for one name, and the vhost pointing at whichever the derivation
        happened to spell.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            le_dir = Path(tmpdir) / "letsencrypt"
            live_dir = issue_lineage(le_dir, "panel.example.com-0001", ["panel.example.com"])

            res = select_lineage("panel.example.com", le_dir)

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), str(live_dir))
            self.assertIn("Adopting the ACME lineage panel.example.com-0001", res.stderr)

    def test_select_acme_lineage_does_not_mix_acme_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            le_dir = Path(tmpdir) / "letsencrypt"
            issue_lineage(le_dir, "panel.example.com-0001", ["panel.example.com"], server=STAGING_DIRECTORY)

            res = select_lineage("panel.example.com", le_dir, server=PRODUCTION_DIRECTORY)

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "", "a staging lineage must not serve a production run")
            self.assertIn("was not issued by", res.stderr)

    def test_select_acme_lineage_prefers_the_exact_name_and_repeats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            le_dir = Path(tmpdir) / "letsencrypt"
            exact = issue_lineage(le_dir, "panel.example.com", ["panel.example.com"])
            suffixed = issue_lineage(le_dir, "panel.example.com-0001", ["panel.example.com"])

            first = select_lineage("panel.example.com", le_dir)
            second = select_lineage("panel.example.com", le_dir)
            self.assertEqual(first.stdout.strip(), str(exact))
            self.assertEqual(second.stdout.strip(), first.stdout.strip(), "the same tree must answer the same")

            shutil.rmtree(exact.parent / "panel.example.com")
            (le_dir / "renewal" / "panel.example.com.conf").unlink()
            after = select_lineage("panel.example.com", le_dir)
            self.assertEqual(after.stdout.strip(), str(suffixed))

    def test_select_acme_lineage_ignores_a_name_the_certificate_does_not_cover(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            le_dir = Path(tmpdir) / "letsencrypt"
            # `evilpanel.example.com` ends with the requested name but is a
            # different name: coverage is decided per label, not by suffix.
            issue_lineage(le_dir, "other.example.com-0001", ["evilpanel.example.com"])

            res = select_lineage("panel.example.com", le_dir)

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "")

    def test_select_acme_lineage_never_selects_an_expired_lineage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            le_dir = Path(tmpdir) / "letsencrypt"
            issue_lineage(le_dir, "panel.example.com", ["panel.example.com"], expired=True)

            only_expired = select_lineage("panel.example.com", le_dir)
            self.assertEqual(only_expired.returncode, 0, only_expired.stderr)
            self.assertEqual(only_expired.stdout.strip(), "", "an expired certificate is not coverage")
            self.assertIn("has expired", only_expired.stderr)

            valid = issue_lineage(le_dir, "panel.example.com-0001", ["panel.example.com"])
            beside_valid = select_lineage("panel.example.com", le_dir)
            self.assertEqual(beside_valid.stdout.strip(), str(valid))
            self.assertIn("has expired", beside_valid.stderr)

    def test_select_acme_lineage_skips_a_symlinked_live_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            le_dir = Path(tmpdir) / "letsencrypt"
            real = issue_lineage(Path(tmpdir) / "elsewhere", "panel.example.com-0001", ["panel.example.com"])
            (le_dir / "live").mkdir(parents=True)
            (le_dir / "renewal").mkdir(parents=True)
            (le_dir / "live" / "panel.example.com-0001").symlink_to(real, target_is_directory=True)
            shutil.copy(
                real.parents[1] / "renewal" / "panel.example.com-0001.conf",
                le_dir / "renewal" / "panel.example.com-0001.conf",
            )

            res = select_lineage("panel.example.com", le_dir)

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(res.stdout.strip(), "", "a symlinked live entry is not a lineage this host owns")

    def test_record_certificate_lineages_keeps_the_rest_of_the_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state.json"
            state.write_text('{"installationMode": "all-in-one", "nodes": []}', encoding="utf-8")

            cmd = (
                f'source "{NGINX_SH}" && record_certificate_lineages "{state}" '
                '"/etc/letsencrypt/live/panel.example.com-0001" '
                '"/etc/letsencrypt/live/reality.example.com"'
            )
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            data = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(data["installationMode"], "all-in-one")
            self.assertEqual(data["nodes"], [])
            self.assertEqual(data["certificateLineages"], {
                "panel": "/etc/letsencrypt/live/panel.example.com-0001",
                "reality": "/etc/letsencrypt/live/reality.example.com",
            })
            self.assertEqual(oct(state.stat().st_mode & 0o777), "0o600")

    def test_an_adopted_lineage_survives_a_failed_transaction(self):
        """The snapshot is what marks an adoption pre-existing, so rollback restores it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            rec_dir = tmp / "recovery"
            le_dir = tmp / "letsencrypt"
            lineage = "panel.example.com-0001"
            live_dir = issue_lineage(le_dir, lineage, ["panel.example.com"], archived=True)
            original = (live_dir / "fullchain.pem").read_bytes()

            snap = f'source "{NGINX_SH}" && snapshot_acme_lineage "tx_adopt" "{lineage}" "{rec_dir}" "{le_dir}"'
            self.assertEqual(subprocess.run(["bash", "-c", snap], capture_output=True, text=True).returncode, 0)
            manifest = json.loads((rec_dir / "tx_adopt" / "acme" / lineage / "lineage-manifest.json").read_text())
            self.assertTrue(manifest["existed_before"])

            # certbot rewrites the adopted lineage and then the run fails.
            (live_dir / "fullchain.pem").write_bytes(b"renewed by certbot\n")

            restore = f'source "{NGINX_SH}" && restore_acme_lineage "tx_adopt" "{lineage}" "{rec_dir}" "{le_dir}"'
            res = subprocess.run(["bash", "-c", restore], capture_output=True, text=True)

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Restoring pre-existing ACME lineage", res.stderr)
            self.assertNotIn("Removing transaction-created", res.stderr)
            self.assertEqual((live_dir / "fullchain.pem").read_bytes(), original)

            # A rollback that only knows the requested name has no manifest for the
            # adopted lineage, so it fails closed instead of deleting it.
            blind = f'source "{NGINX_SH}" && restore_acme_lineage "tx_adopt" "panel.example.com" "{rec_dir}" "{le_dir}"'
            res_blind = subprocess.run(["bash", "-c", blind], capture_output=True, text=True)
            self.assertNotEqual(res_blind.returncode, 0)
            self.assertTrue((live_dir / "fullchain.pem").is_file())

    def test_the_installer_issues_and_renders_the_adopted_lineage(self):
        """Source contract: selection precedes issuance, and every step uses the pick.

        The unit tests above prove the selection function; this one proves the
        installer actually feeds its answer to certbot, to the snapshot, to the
        verifiers and to both vhost generators, instead of re-deriving the path.
        """
        installer = (REPO_ROOT / "gowave-auto.sh").read_text(encoding="utf-8")
        selected = installer.index("panel_live=$(select_acme_lineage")
        self.assertLess(selected, installer.index('snapshot_acme_lineage "$acme_tx_id" "$panel_lineage"'))
        self.assertLess(selected, installer.index('--cert-name "$panel_lineage"'))
        for expected in (
            'snapshot_acme_lineage "$acme_tx_id" "$reality_lineage"',
            'restore_acme_lineage "$acme_tx_id" "$panel_lineage"',
            'restore_acme_lineage "$acme_tx_id" "$reality_lineage"',
            '--cert-name "$reality_lineage"',
            '--cert-name "$vision_lineage"',
            'verify_acme_certificate "$panel_domain" "$panel_live"',
            'generate_panel_https_vhost "$panel_domain" "/etc/nginx/conf.d/gowave-panel.conf" nginx "$panel_live"',
            '"$cover_domain" "$reality_live"',
            'GOWAVE_VISION_CERT_DIR="${vision_live}"',
        ):
            self.assertIn(expected, installer)

        nginx_source = NGINX_SH.read_text(encoding="utf-8")
        self.assertNotIn("ssl_certificate /etc/letsencrypt/live/$", nginx_source)

    def test_panel_vhost_serves_from_the_given_lineage_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "gowave-panel.conf"
            lineage = "/etc/letsencrypt/live/panel.example.com-0001"
            cmd = (
                f'source "{NGINX_SH}" && generate_panel_https_vhost '
                f'"panel.example.com" "{out}" nginx "{lineage}"'
            )
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            text = out.read_text(encoding="utf-8")
            self.assertIn(f"ssl_certificate {lineage}/fullchain.pem;", text)
            self.assertIn(f"ssl_certificate_key {lineage}/privkey.pem;", text)
            self.assertNotIn("/etc/letsencrypt/live/panel.example.com/", text)

    def test_decoy_vhost_serves_from_the_given_lineage_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-decoy.conf"
            cover = tmp / "cover"
            cover.mkdir()
            lineage = "/etc/letsencrypt/live/reality.example.com-0002"
            cmd = (
                f'source "{NGINX_SH}" && generate_decoy_vhost '
                f'"reality.example.com" "{out}" nginx "{cover}" "" "{lineage}"'
            )
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            text = out.read_text(encoding="utf-8")
            self.assertIn(f"ssl_certificate {lineage}/fullchain.pem;", text)
            self.assertIn(f"ssl_certificate_key {lineage}/privkey.pem;", text)
            self.assertNotIn("/etc/letsencrypt/live/reality.example.com/", text)

    def test_the_vision_vhost_renders_no_certificate_of_its_own(self):
        """Vision's TLS is Xray's: the vhost behind it is plain HTTP on 127.0.0.1:9444."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-vision-fallback.conf"
            cover = tmp / "cover"
            cover.mkdir()
            cmd = f'source "{NGINX_SH}" && generate_vision_fallback_vhost "vision.example.com" "{out}" "{cover}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn("ssl_certificate", out.read_text(encoding="utf-8"))

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
            # Commit keeps the transaction manifest, and the ownership record next
            # to the snapshots proves the hook at this path is this product's file.
            self.assertTrue((rec_dir / "install_1" / "deploy-hook-manifest.json").is_file())
            self.assertTrue((rec_dir / "deploy-hook-ownership.json").is_file())

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

    def test_deploy_hook_ownership_survives_the_transaction_snapshot(self):
        """Pruning the snapshot must not turn this product's own hook into a foreign file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hook_file = tmp / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
            rec_dir = tmp / "recovery"

            install = f'source "{NGINX_SH}" && install_managed_deploy_hook "install_1" "{hook_file}" "{rec_dir}"'
            res_install = subprocess.run(["bash", "-c", install], capture_output=True, text=True)
            self.assertEqual(res_install.returncode, 0, res_install.stderr)
            record = rec_dir / "deploy-hook-ownership.json"
            self.assertTrue(record.is_file())
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)

            shutil.rmtree(rec_dir / "install_1")
            repeat = f'source "{NGINX_SH}" && install_managed_deploy_hook "install_2" "{hook_file}" "{rec_dir}"'
            res_repeat = subprocess.run(["bash", "-c", repeat], capture_output=True, text=True)
            self.assertEqual(res_repeat.returncode, 0, res_repeat.stderr)

            # The retained record names the exact file it wrote, so an operator edit
            # voids ownership instead of silently licensing the overwrite.
            hook_file.write_text("#!/bin/sh\necho hijacked\n")
            preflight = f'source "{NGINX_SH}" && verify_deploy_hook_preflight "{hook_file}" "install_3" "{rec_dir}"'
            res_preflight = subprocess.run(["bash", "-c", preflight], capture_output=True, text=True)
            self.assertNotEqual(res_preflight.returncode, 0)
            self.assertIn("Pre-existing unowned Certbot deploy hook found", res_preflight.stderr)

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
            # Ownership is cleared with the hook, so nothing claims the path next time.
            self.assertFalse((rec_dir / "deploy-hook-ownership.json").exists())

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

    def test_deploy_hook_rollback_accepts_a_prior_transactions_hook(self):
        """A failed repeat install owes nothing: the hook is the one it already had."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hook_file = tmp / "renewal-hooks" / "deploy" / "gowave-nginx.sh"
            rec_dir = tmp / "recovery"

            first = f'source "{NGINX_SH}" && install_managed_deploy_hook "install_1" "{hook_file}" "{rec_dir}"'
            res_first = subprocess.run(["bash", "-c", first], capture_output=True, text=True)
            self.assertEqual(res_first.returncode, 0, res_first.stderr)
            installed = hook_file.read_bytes()

            # The repeat install fails before it touches the hook, so its own
            # transaction never wrote a manifest. Refusing here would report an
            # incomplete rollback for a failure that left no side effect behind.
            cmd_rollback = f'source "{NGINX_SH}" && rollback_managed_deploy_hook "install_2" "{hook_file}" "{rec_dir}"'
            res_rollback = subprocess.run(["bash", "-c", cmd_rollback], capture_output=True, text=True)
            self.assertEqual(res_rollback.returncode, 0, res_rollback.stderr)
            self.assertEqual(hook_file.read_bytes(), installed)
            self.assertTrue((rec_dir / "deploy-hook-ownership.json").is_file())

            # The recognition is by recorded digest, not by path: a hook nobody
            # recorded stays a refusal under the same transaction id.
            foreign = tmp / "unmanaged" / "gowave-nginx.sh"
            foreign.parent.mkdir(parents=True)
            foreign.write_text("#!/bin/sh\necho foreign\n")
            cmd_foreign = f'source "{NGINX_SH}" && rollback_managed_deploy_hook "install_2" "{foreign}" "{rec_dir}"'
            res_foreign = subprocess.run(["bash", "-c", cmd_foreign], capture_output=True, text=True)
            self.assertNotEqual(res_foreign.returncode, 0)
            self.assertIn("exists without an ownership manifest", res_foreign.stderr)


if __name__ == "__main__":
    unittest.main()
