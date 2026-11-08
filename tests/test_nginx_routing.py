#!/usr/bin/env python3
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

    def test_generate_panel_https_vhost(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            out = tmp / "gowave-panel.conf"

            cmd = f'source "{NGINX_SH}" && generate_panel_https_vhost "panel.example.com" "{out}"'
            res = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)

            c = out.read_text()
            self.assertIn("server_name panel.example.com;", c)
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


if __name__ == "__main__":
    unittest.main()
