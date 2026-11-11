#!/usr/bin/env python3
"""Regression tests for malformed subscription response structures."""
from __future__ import annotations

import ssl
import unittest
from unittest.mock import MagicMock, patch
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from live_vps.subscriptions import (
    fetch_and_validate_mihomo_subscription,
    fetch_and_validate_xray_subscription,
)


class TestSubscriptionResponseShapes(unittest.TestCase):
    def _urlopen_response(self, body: str, headers: dict | None = None):
        response = MagicMock()
        response.status = 200
        response.headers = headers if headers is not None else {"Cache-Control": "no-store"}
        response.read.return_value = body.encode("utf-8")
        context = MagicMock()
        context.__enter__.return_value = response
        return context

    def _assert_xray_rejected(self, body: str, expected_error: str):
        with patch(
            "live_vps.subscriptions.urllib.request.urlopen",
            return_value=self._urlopen_response(body),
        ):
            ok, result = fetch_and_validate_xray_subscription(
                "panel.example.test", "opaque", ssl.create_default_context()
            )
        self.assertFalse(ok)
        self.assertIn(expected_error, result["error"])

    def _assert_mihomo_rejected(self, body: str, expected_error: str):
        with patch(
            "live_vps.subscriptions.urllib.request.urlopen",
            return_value=self._urlopen_response(body, headers={}),
        ):
            ok, result = fetch_and_validate_mihomo_subscription(
                "panel.example.test", "opaque", ssl.create_default_context()
            )
        self.assertFalse(ok)
        self.assertIn(expected_error, result["error"])

    def test_xray_rejects_non_object_json_root(self):
        for body in ("[]", "null", "42", '"subscription"'):
            with self.subTest(body=body):
                self._assert_xray_rejected(body, "root must be an object")

    def test_xray_rejects_non_list_outbounds(self):
        for outbounds in ('{}', '"invalid"', "42", "null"):
            with self.subTest(outbounds=outbounds):
                self._assert_xray_rejected(
                    '{"outbounds":' + outbounds + '}',
                    "outbounds must be a list",
                )

    def test_xray_rejects_non_object_outbound_and_malformed_tls_settings(self):
        self._assert_xray_rejected(
            '{"outbounds":[null]}', "outbound at index 0 must be an object"
        )
        malformed_stream = [{"protocol": "vless", "streamSettings": []}] + [
            {"protocol": "vless"} for _ in range(7)
        ]
        self._assert_xray_rejected(
            '{"outbounds":' + __import__("json").dumps(malformed_stream) + '}',
            "streamSettings must be an object",
        )
        malformed_tls = [
            {"protocol": "vless", "streamSettings": {"tlsSettings": [1]}}
        ] + [{"protocol": "vless"} for _ in range(7)]
        self._assert_xray_rejected(
            '{"outbounds":' + __import__("json").dumps(malformed_tls) + '}',
            "TLS settings must be an object",
        )
        self._assert_xray_rejected(
            '{"outbounds":[{"protocol":42}]}', "invalid protocol"
        )

    def test_mihomo_rejects_non_mapping_yaml_root(self):
        for body in ("[]", "null", "42", '"subscription"'):
            with self.subTest(body=body):
                self._assert_mihomo_rejected(body, "root must be a mapping")

    def test_mihomo_rejects_invalid_proxy_collection_and_entries(self):
        for proxies in ("{}", "42", "null", '"invalid"'):
            with self.subTest(proxies=proxies):
                self._assert_mihomo_rejected(
                    "proxies: " + proxies, "proxies must be a list"
                )
        malformed_proxies = (
            "proxies:\n  - null\n"
            + "".join(
                f"  - name: proxy-{i}\n"
                "    type: vless\n"
                "    client-fingerprint: firefox\n"
                for i in range(7)
            )
        )
        self._assert_mihomo_rejected(
            malformed_proxies, "proxy at index 0 must be a mapping"
        )

    def test_mihomo_rejects_non_string_rules(self):
        body = (
            "proxies:\n"
            + "".join(
                f"  - name: proxy-{i}\n"
                "    type: vless\n"
                "    client-fingerprint: firefox\n"
                for i in range(8)
            )
            + "rules:\n  - {unexpected: mapping}\n"
        )
        self._assert_mihomo_rejected(body, "rules must be a list of strings")

    def test_mihomo_rejects_invalid_vision_count_consistently(self):
        with patch(
            "live_vps.subscriptions.urllib.request.urlopen",
            return_value=self._urlopen_response("proxies: []", headers={}),
        ):
            ok, result = fetch_and_validate_mihomo_subscription(
                "panel.example.test", "opaque", ssl.create_default_context(),
                vision_count=True,
            )
        self.assertFalse(ok)
        self.assertIn("vision_count must be an integer", result["error"])


if __name__ == "__main__":
    unittest.main()
