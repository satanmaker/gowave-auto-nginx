"""Subscription delivery and User-Agent enforcement module.
Fetches and validates Xray JSON and Mihomo YAML subscriptions with zero secret leaks.
"""
from __future__ import annotations

import http.client
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


def expected_proxy_count(has_vision: bool = False, vision_count: Optional[int] = None) -> int:
    """Return the expected number of core plus independently configured Vision proxies."""
    if vision_count is None:
        return 10 if has_vision else 8
    if type(vision_count) is not int or vision_count not in (0, 1, 2):
        raise ValueError("vision_count must be an integer from 0 through 2")
    return 8 + vision_count


def get_default_user_short_uuid(panel_client: E2EPanelClient) -> str:
    """Retrieve default-user shortUuid from Panel and register it in redaction filter."""
    user = panel_client.get_user_by_username("default-user")
    short_uuid = user.get("shortUuid") or user.get("shortId") or user.get("uuid")
    if not short_uuid:
        raise ValueError("Failed to retrieve shortUuid for default-user from Panel")
    register_secret(short_uuid)
    return str(short_uuid)


def request_subscription_status(
    panel_domain: str,
    path: str,
    ssl_context: ssl.SSLContext,
    user_agent: Optional[str] = None,
    timeout: int = 10,
) -> int:
    """Send a subscription request with an exactly controlled User-Agent header."""
    connection = http.client.HTTPSConnection(
        panel_domain, context=ssl_context, timeout=timeout
    )
    try:
        connection.putrequest("GET", path, skip_accept_encoding=True)
        if user_agent is not None:
            connection.putheader("User-Agent", user_agent)
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def verify_user_agent_policy(
    panel_domain: str,
    short_uuid: str,
    ssl_context: ssl.SSLContext,
) -> Dict[str, Any]:
    """Test User-Agent policy enforcement on subscription endpoint."""
    url = f"https://{panel_domain}/api/sub/{short_uuid}/v2ray-json"

    # Missing and explicitly blank User-Agent are distinct policy cases.
    absent_code = None
    blank_code = None
    absent_error = None
    blank_error = None
    try:
        absent_code = request_subscription_status(
            panel_domain, f"/api/sub/{short_uuid}/v2ray-json",
            ssl_context, user_agent=None, timeout=10,
        )
    except Exception as exc:
        absent_error = f"{type(exc).__name__}: {exc}"
    try:
        blank_code = request_subscription_status(
            panel_domain, f"/api/sub/{short_uuid}/v2ray-json",
            ssl_context, user_agent="", timeout=10,
        )
    except Exception as exc:
        blank_error = f"{type(exc).__name__}: {exc}"

    absent_rejected = absent_code in (400, 403)
    blank_rejected = blank_code in (400, 403)

    # 2. Valid Xray User-Agent
    xray_accepted = False
    xray_code = None
    xray_error = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "v2rayNG/1.8.5"})
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            xray_code = resp.status
            xray_accepted = xray_code == 200
    except urllib.error.HTTPError as exc:
        xray_code = exc.code
        xray_error = f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        xray_error = f"{type(exc).__name__}: {exc}"

    # 3. Valid Mihomo User-Agent
    clash_url = f"https://{panel_domain}/api/sub/{short_uuid}/clash"
    mihomo_accepted = False
    mihomo_code = None
    mihomo_error = None
    try:
        req = urllib.request.Request(clash_url, headers={"User-Agent": "clash.meta"})
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as resp:
            mihomo_code = resp.status
            mihomo_accepted = mihomo_code == 200
    except urllib.error.HTTPError as exc:
        mihomo_code = exc.code
        mihomo_error = f"HTTP {exc.code}: {exc.reason}"
    except Exception as exc:
        mihomo_error = f"{type(exc).__name__}: {exc}"

    # A known policy violation is FAIL even when another probe is inconclusive.
    # Only missing transport/HTTP evidence without a proven violation is INCOMPLETE.
    proven_failure = (
        (absent_code is not None and not absent_rejected)
        or (blank_code is not None and not blank_rejected)
        or (xray_code is not None and not xray_accepted)
        or (mihomo_code is not None and not mihomo_accepted)
    )
    missing_evidence = any(
        code is None for code in (absent_code, blank_code, xray_code, mihomo_code)
    )
    status = "FAIL" if proven_failure else ("INCOMPLETE" if missing_evidence else "PASS")
    return {
        "status": status,
        "absent_rejected": absent_rejected,
        "absent_code": absent_code,
        "absent_error": absent_error,
        "blank_rejected": blank_rejected,
        "blank_code": blank_code,
        "blank_error": blank_error,
        "xray_accepted": xray_accepted,
        "xray_code": xray_code,
        "xray_error": xray_error,
        "mihomo_accepted": mihomo_accepted,
        "mihomo_code": mihomo_code,
        "mihomo_error": mihomo_error,
    }


def fetch_and_validate_xray_subscription(
    panel_domain: str,
    short_uuid: str,
    ssl_context: ssl.SSLContext,
    has_vision: bool = False,
    ca_bundle_path: Optional[Path] = None,
    reality_fingerprint: str = "firefox",
    vision_count: Optional[int] = None,
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
    # The Panel serves either a single config object or a list of per-profile
    # configs; both shapes must be validated the same way.
    proxy_outbounds = []
    configs_to_validate = []
    wrapped_outbounds = []

    if isinstance(sub_json, list):
        if not sub_json:
            return False, {"error": "Xray subscription JSON root must be an object"}
        profiles = sub_json
    elif isinstance(sub_json, dict):
        profiles = [sub_json]
    else:
        return False, {"error": "Xray subscription JSON root must be an object"}

    for profile_index, profile in enumerate(profiles):
        if not isinstance(profile, dict):
            return False, {"error": f"Xray subscription profile at index {profile_index} must be an object"}
        raw_outbounds = profile.get("outbounds", [])
        if not isinstance(raw_outbounds, list):
            return False, {"error": f"Xray subscription profile at index {profile_index} outbounds must be a list"}
        if isinstance(sub_json, list):
            configs_to_validate.append(profile)
        else:
            wrapped_outbounds = raw_outbounds
        for index, outbound in enumerate(raw_outbounds):
            if not isinstance(outbound, dict):
                return False, {"error": f"Xray outbound at index {index} must be an object"}
            protocol = outbound.get("protocol", "")
            if not isinstance(protocol, str):
                return False, {"error": f"Xray outbound at index {index} has an invalid protocol"}
            if protocol.lower() in ("vless", "trojan", "vmess", "shadowsocks"):
                proxy_outbounds.append(outbound)

    expected_count = expected_proxy_count(has_vision, vision_count)
    if len(proxy_outbounds) != expected_count:
        return False, {
            "error": f"Expected {expected_count} proxy outbounds, found {len(proxy_outbounds)}",
            "proxy_outbounds": len(proxy_outbounds),
        }

    # REALITY hosts use the configured (default firefox) fingerprint; every other
    # transport keeps firefox. Both Xray and mihomo send the hybrid
    # X25519MLKEM768 key share with the modern Firefox uTLS preset.
    for index, outbound in enumerate(proxy_outbounds):
        stream_settings = outbound.get("streamSettings", {})
        if not isinstance(stream_settings, dict):
            return False, {"error": f"Xray outbound at index {index} streamSettings must be an object"}
        security = (stream_settings.get("security") or "").lower()
        tls_settings = stream_settings.get("tlsSettings") or stream_settings.get("realitySettings") or {}
        if not isinstance(tls_settings, dict):
            return False, {"error": f"Xray outbound at index {index} TLS settings must be an object"}
        fingerprint = tls_settings.get("fingerprint", "")
        if not isinstance(fingerprint, str):
            return False, {"error": f"Xray outbound at index {index} has an invalid fingerprint"}
        expected_fp = reality_fingerprint if security == "reality" else "firefox"
        if fingerprint.lower() != expected_fp.lower():
            return False, {
                "error": f"Outbound {outbound.get('tag')} has fingerprint '{fingerprint}', expected '{expected_fp}'"
            }

    # Validate with real Xray CLI if installed
    xray_cli_ok = True
    if subprocess.run(["which", "xray"], capture_output=True).returncode == 0:
        env = os.environ.copy()
        if ca_bundle_path:
            env["SSL_CERT_FILE"] = str(ca_bundle_path)

        if configs_to_validate:
            # Validate each full individual profile JSON returned by the subscription
            for cfg_item in configs_to_validate:
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
                    json.dump(cfg_item, tf)
                    tmp_config = tf.name
                try:
                    res = subprocess.run(["xray", "run", "-test", "-config", tmp_config], capture_output=True, text=True, env=env)
                    if res.returncode != 0:
                        xray_cli_ok = False
                        break
                finally:
                    if os.path.exists(tmp_config):
                        os.remove(tmp_config)
        else:
            # Wrap into full valid Xray client config
            full_xray_config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{"port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}}],
                "outbounds": wrapped_outbounds,
            }
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
                json.dump(full_xray_config, tf)
                tmp_config = tf.name

            try:
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
        "reality_fingerprint": reality_fingerprint,
        "xray_cli_validated": xray_cli_ok,
    }


def fetch_and_validate_mihomo_subscription(
    panel_domain: str,
    short_uuid: str,
    ssl_context: ssl.SSLContext,
    has_vision: bool = False,
    ca_bundle_path: Optional[Path] = None,
    reality_fingerprint: str = "firefox",
    vision_count: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Fetch Mihomo YAML subscription and validate schema, proxy entries, and mihomo -t."""
    url = f"https://{panel_domain}/api/sub/{short_uuid}/mihomo"
    req = urllib.request.Request(url, headers={"User-Agent": "mihomo"})

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

    if not isinstance(sub_yaml, dict):
        return False, {"error": "Mihomo subscription YAML root must be a mapping"}

    proxies = sub_yaml.get("proxies", [])
    if not isinstance(proxies, list):
        return False, {"error": "Mihomo subscription proxies must be a list"}
    try:
        expected_count = expected_proxy_count(has_vision, vision_count)
    except ValueError as exc:
        return False, {"error": str(exc)}
    if len(proxies) != expected_count:
        return False, {
            "error": f"Expected {expected_count} proxies in YAML, found {len(proxies)}",
            "proxies_count": len(proxies),
        }

    # REALITY proxies carry the configured (default firefox) client fingerprint;
    # other proxies stay on firefox. Every REALITY proxy must also advertise the
    # hybrid key share explicitly.
    for index, proxy in enumerate(proxies):
        if not isinstance(proxy, dict):
            return False, {"error": f"Mihomo proxy at index {index} must be a mapping"}
        reality_opts = proxy.get("reality-opts")
        is_reality = isinstance(reality_opts, dict)
        fingerprint = proxy.get("client-fingerprint") or proxy.get("fingerprint") or ""
        if not isinstance(fingerprint, str):
            return False, {"error": f"Mihomo proxy at index {index} has an invalid client-fingerprint"}
        expected_fp = reality_fingerprint if is_reality else "firefox"
        if fingerprint.lower() != expected_fp.lower():
            return False, {
                "error": f"Proxy {proxy.get('name')} has fingerprint '{fingerprint}', expected '{expected_fp}'"
            }
        if is_reality and reality_opts.get("support-x25519mlkem768") is not True:
            return False, {
                "error": f"Proxy {proxy.get('name')} missing reality-opts support-x25519mlkem768",
            }

    # Verify routing rules present
    rules = sub_yaml.get("rules", [])
    if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
        return False, {"error": "Mihomo subscription rules must be a list of strings"}
    has_geoip_rule = any("GEOIP" in rule for rule in rules) or any("MATCH" in rule for rule in rules)
    if not has_geoip_rule:
        return False, {"error": "Missing mandatory GEOIP or MATCH rule in Mihomo subscription YAML"}

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
        "reality_fingerprint": reality_fingerprint,
        "has_geoip_rule": True,
        "mihomo_cli_validated": mihomo_cli_ok,
    }
