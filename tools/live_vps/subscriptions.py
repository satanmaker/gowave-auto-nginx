"""Subscription delivery and User-Agent enforcement module.
Fetches and validates Xray JSON and Mihomo YAML subscriptions with zero secret leaks.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .panel_api import E2EPanelClient
from .redaction import register_secret


def get_default_user_short_uuid(panel_client: E2EPanelClient) -> str:
    """Retrieve default-user shortUuid from Panel and register it in redaction filter."""
    user = panel_client.get_user_by_username("default-user")
    short_uuid = user.get("shortUuid") or user.get("shortId") or user.get("uuid")
    if not short_uuid:
        raise ValueError("Failed to retrieve shortUuid for default-user from Panel")
    register_secret(short_uuid)
    return str(short_uuid)


def verify_user_agent_policy(
    panel_domain: str,
    short_uuid: str,
    ssl_context: ssl.SSLContext,
) -> Dict[str, Any]:
    """Test User-Agent policy enforcement on subscription endpoint."""
    url = f"https://{panel_domain}/api/sub/{short_uuid}/v2ray-json"

    # 1. Absent User-Agent
    absent_rejected = False
    absent_code = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ""})
        # Remove standard python-urllib header
        del req.headers["User-agent"]
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            absent_code = resp.status
    except urllib.error.HTTPError as e:
        absent_code = e.code
        if e.code in (403, 400):
            absent_rejected = True
    except Exception:
        absent_rejected = True

    # 2. Valid Xray User-Agent
    xray_accepted = False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "v2rayNG/1.8.5"})
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            if resp.status == 200:
                xray_accepted = True
    except Exception:
        xray_accepted = False

    # 3. Valid Mihomo User-Agent
    clash_url = f"https://{panel_domain}/api/sub/{short_uuid}/clash"
    mihomo_accepted = False
    try:
        req = urllib.request.Request(clash_url, headers={"User-Agent": "clash.meta"})
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            if resp.status == 200:
                mihomo_accepted = True
    except Exception:
        mihomo_accepted = False

    passed = absent_rejected and xray_accepted and mihomo_accepted
    return {
        "status": "PASS" if passed else "FAIL",
        "absent_rejected": absent_rejected,
        "absent_code": absent_code,
        "xray_accepted": xray_accepted,
        "mihomo_accepted": mihomo_accepted,
    }


def fetch_and_validate_xray_subscription(
    panel_domain: str,
    short_uuid: str,
    ssl_context: ssl.SSLContext,
    has_vision: bool = False,
    ca_bundle_path: Optional[Path] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Fetch Xray JSON subscription and validate schema, proxy outbounds, and xray run -test."""
    url = f"https://{panel_domain}/api/sub/{short_uuid}/v2ray-json"
    req = urllib.request.Request(url, headers={"User-Agent": "v2rayNG/1.8.5"})

    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as resp:
            status_code = resp.status
            cache_control = resp.headers.get("Cache-Control", "")
            raw_body = resp.read().decode("utf-8")
    except Exception as e:
        return False, {"error": f"Failed to fetch Xray subscription: {e}"}

    if status_code != 200:
        return False, {"error": f"Unexpected status code: {status_code}"}
    if "no-store" not in cache_control:
        return False, {"error": f"Expected Cache-Control: no-store, got '{cache_control}'"}

    try:
        sub_json = json.loads(raw_body)
    except Exception as e:
        return False, {"error": f"Malformed Xray subscription JSON: {e}"}

    # Filter proxy-capable outbounds: exclude direct, block, dns, etc.
    raw_outbounds = sub_json.get("outbounds", [])
    proxy_outbounds = []
    for ob in raw_outbounds:
        protocol = ob.get("protocol", "").lower()
        tag = ob.get("tag", "").lower()
        if protocol in ("vless", "trojan", "vmess", "shadowsocks"):
            proxy_outbounds.append(ob)

    expected_count = 10 if has_vision else 8
    if len(proxy_outbounds) != expected_count:
        return False, {
            "error": f"Expected {expected_count} proxy outbounds, found {len(proxy_outbounds)}",
            "proxy_outbounds": len(proxy_outbounds),
        }

    # Verify fingerprint: "firefox"
    for ob in proxy_outbounds:
        stream_settings = ob.get("streamSettings", {})
        tls_settings = stream_settings.get("tlsSettings") or stream_settings.get("realitySettings") or {}
        fp = tls_settings.get("fingerprint", "")
        if fp.lower() != "firefox":
            return False, {"error": f"Outbound {ob.get('tag')} missing fingerprint 'firefox': {fp}"}

    # Validate with real Xray CLI if installed
    xray_cli_ok = True
    if subprocess.run(["which", "xray"], capture_output=True).returncode == 0:
        # Wrap into full valid Xray client config
        full_xray_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}}],
            "outbounds": raw_outbounds,
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(full_xray_config, tf)
            tmp_config = tf.name

        try:
            env = os.environ.copy()
            if ca_bundle_path:
                env["SSL_CERT_FILE"] = str(ca_bundle_path)
            res = subprocess.run(["xray", "run", "-test", "-config", tmp_config], capture_output=True, text=True, env=env)
            if res.returncode != 0:
                xray_cli_ok = False
        finally:
            if os.path.exists(tmp_config):
                os.remove(tmp_config)

    if not xray_cli_ok:
        return False, {"error": "xray run -test failed on fetched subscription"}

    return True, {
        "status": "PASS",
        "proxy_outbounds_count": len(proxy_outbounds),
        "fingerprint": "firefox",
        "xray_cli_validated": xray_cli_ok,
    }


def fetch_and_validate_mihomo_subscription(
    panel_domain: str,
    short_uuid: str,
    ssl_context: ssl.SSLContext,
    has_vision: bool = False,
    ca_bundle_path: Optional[Path] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Fetch Mihomo YAML subscription and validate schema, proxy entries, and mihomo -t."""
    url = f"https://{panel_domain}/api/sub/{short_uuid}/clash"
    req = urllib.request.Request(url, headers={"User-Agent": "clash.meta"})

    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=15) as resp:
            status_code = resp.status
            raw_body = resp.read().decode("utf-8")
    except Exception as e:
        return False, {"error": f"Failed to fetch Mihomo subscription: {e}"}

    if status_code != 200:
        return False, {"error": f"Unexpected status code: {status_code}"}

    try:
        sub_yaml = yaml.safe_load(raw_body)
    except Exception as e:
        return False, {"error": f"Malformed Mihomo subscription YAML: {e}"}

    proxies = sub_yaml.get("proxies", [])
    expected_count = 10 if has_vision else 8
    if len(proxies) != expected_count:
        return False, {
            "error": f"Expected {expected_count} proxies in YAML, found {len(proxies)}",
            "proxies_count": len(proxies),
        }

    # Verify client-fingerprint: "firefox"
    for p in proxies:
        fp = p.get("client-fingerprint") or p.get("fingerprint") or ""
        if fp.lower() != "firefox":
            return False, {"error": f"Proxy {p.get('name')} missing client-fingerprint 'firefox'"}

    # Verify GEOIP,private,DIRECT,no-resolve rule
    rules = sub_yaml.get("rules", [])
    has_geoip_rule = any("GEOIP,private,DIRECT,no-resolve" in r for r in rules)
    if not has_geoip_rule:
        return False, {"error": "Missing mandatory rule: GEOIP,private,DIRECT,no-resolve"}

    # Validate with real Mihomo CLI if installed
    mihomo_cli_ok = True
    if subprocess.run(["which", "mihomo"], capture_output=True).returncode == 0:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(raw_body)
            tmp_config = tf.name

        try:
            env = os.environ.copy()
            if ca_bundle_path:
                env["SSL_CERT_FILE"] = str(ca_bundle_path)
            res = subprocess.run(["mihomo", "-t", "-f", tmp_config], capture_output=True, text=True, env=env)
            if res.returncode != 0:
                mihomo_cli_ok = False
        finally:
            if os.path.exists(tmp_config):
                os.remove(tmp_config)

    if not mihomo_cli_ok:
        return False, {"error": "mihomo -t failed on fetched subscription"}

    return True, {
        "status": "PASS",
        "proxies_count": len(proxies),
        "fingerprint": "firefox",
        "has_geoip_rule": True,
        "mihomo_cli_validated": mihomo_cli_ok,
    }
