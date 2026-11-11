"""Whitelist-only configuration parser and validator for Live VPS E2E Testing.
Enforces POSIX mode 0600 on config files and validates all parameters against a strict whitelist.
"""
from __future__ import annotations

import ipaddress
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict

WHITELIST_KEYS = {
    "MASTER_IP",
    "MASTER_PANEL_DOMAIN",
    "MASTER_REALITY_DOMAIN",
    "MASTER_VISION_DOMAIN",
    "MASTER_SSH_PORT",
    "MASTER_SSH_USER",
    "WORKER_IP",
    "WORKER_DOMAIN",
    "WORKER_REALITY_DOMAIN",
    "WORKER_VISION_DOMAIN",
    "WORKER_SSH_PORT",
    "WORKER_SSH_USER",
    "SSH_KEY_PATH",
    "SSH_KNOWN_HOSTS",
    "MASTER_SSH_KEY_PATH",
    "WORKER_SSH_KEY_PATH",
    "MASTER_KNOWN_HOSTS_PATH",
    "WORKER_KNOWN_HOSTS_PATH",
    "ACME_MODE",
    "ADMIN_EMAIL",
    "GOWAVE_PANEL_VERSION",
    "GOWAVE_NODE_VERSION",
    "GOWAVE_NODE_INSTALLER_COMMIT",
    "GOWAVE_NODE_INSTALLER_SHA256",
    "XRAY_SERVER_VERSION",
    "XRAY_CLIENT_VERSION",
    "MIHOMO_CLIENT_VERSION",
    "REALITY_FINGERPRINT",
    "ALT_MIHOMO_CORE",
    "ENABLE_IPV6",
    "MASTER_IPV6",
    "WORKER_IPV6",
    "EXPECTED_MASTER_EGRESS_IP",
    "EXPECTED_WORKER_EGRESS_IP",
    "NODE_READY_TIMEOUT",
    "API_TIMEOUT",
    "TRAFFIC_TIMEOUT",
    "RESTORE_TIMEOUT",
    "TEST_TRAFFIC_VERIFICATION",
    "TEST_MIHOMO_TRAFFIC",
    "TEST_NEGATIVE_SUITE",
    "TEST_TEARDOWN_POLICY",
    "MASTER_SNAPSHOT_ID",
    "WORKER_SNAPSHOT_ID",
    "SNAPSHOT_RESTORE_HOOK",
    "SNAPSHOT_RESTORE_HOOK_SHA256",
}

MANDATORY_KEYS = {
    "MASTER_IP",
    "MASTER_PANEL_DOMAIN",
    "MASTER_REALITY_DOMAIN",
    "WORKER_IP",
    "WORKER_DOMAIN",
    "WORKER_REALITY_DOMAIN",
    "GOWAVE_PANEL_VERSION",
    "GOWAVE_NODE_VERSION",
    "GOWAVE_NODE_INSTALLER_COMMIT",
    "GOWAVE_NODE_INSTALLER_SHA256",
    "XRAY_SERVER_VERSION",
    "XRAY_CLIENT_VERSION",
    "MIHOMO_CLIENT_VERSION",
}

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
HEX40_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
HEX64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
VERSION_REGEX = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")

REALITY_FINGERPRINTS = (
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized",
)


def parse_bool(val: str, key_name: str) -> bool:
    normalized = val.strip().lower()
    if normalized in ("true", "1", "yes"):
        return True
    if normalized in ("false", "0", "no"):
        return False
    raise ValueError(f"Invalid boolean value for {key_name}: '{val}'. Must be 'true' or 'false'.")


def parse_port(val: str, key_name: str) -> int:
    try:
        port = int(val)
        if not (1 <= port <= 65535):
            raise ValueError
        return port
    except ValueError:
        raise ValueError(f"Invalid port for {key_name}: '{val}'. Must be integer 1-65535.")


def parse_positive_int(val: str, key_name: str) -> int:
    try:
        n = int(val)
        if n <= 0:
            raise ValueError
        return n
    except ValueError:
        raise ValueError(f"Invalid positive integer for {key_name}: '{val}'.")


def validate_public_ip(val: str, key_name: str, allow_v6: bool = False) -> str:
    try:
        ip = ipaddress.ip_address(val)
    except ValueError:
        raise ValueError(f"Invalid IP address for {key_name}: '{val}'")

    if not allow_v6 and ip.version != 4:
        raise ValueError(f"Expected IPv4 address for {key_name}, got IPv6: '{val}'")
    if allow_v6 and ip.version != 6:
        raise ValueError(f"Expected IPv6 address for {key_name}, got IPv4: '{val}'")

    if not ip.is_global:
        raise ValueError(
            f"{key_name} ('{val}') is not a public routable address (private, loopback, multicast, or documentation address rejected)."
        )
    return str(ip)


def validate_domain(val: str, key_name: str) -> str:
    val = val.strip().rstrip(".")
    if not DOMAIN_REGEX.match(val):
        raise ValueError(f"Invalid domain format for {key_name}: '{val}'")
    return val


@dataclass
class LiveVPSConfig:
    raw: Dict[str, str] = field(default_factory=dict)
    values: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        return self.values[key]

    def __getattr__(self, name: str) -> Any:
        # Canonical storage uses uppercase environment keys; the runner uses
        # lowercase Python-style attributes. Resolve both consistently.
        key = name.upper()
        if key in self.values:
            return self.values[key]
        raise AttributeError(f"'LiveVPSConfig' has no attribute '{name}'")

    def get(self, key: str, default: Any = None) -> Any:
        return self.values.get(key, default)


def load_config(path: str | Path, skip_mode_check: bool = False) -> LiveVPSConfig:
    supplied_path = Path(path)
    if supplied_path.is_symlink():
        raise ValueError(f"Configuration file must not be a symlink: {supplied_path}")
    config_path = supplied_path.resolve()
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    # Enforce POSIX file permissions: must not be group or world readable/writable/executable
    if not skip_mode_check:
        st = config_path.stat()
        permissions = stat.S_IMODE(st.st_mode)
        if permissions not in (0o600, 0o400):
            oct_mode = oct(permissions)
            raise PermissionError(
                f"Configuration file {config_path} has insecure permissions {oct_mode}. "
                f"It must have mode 0600 or 0400 to protect credentials."
            )

    raw_pairs: Dict[str, str] = {}
    with open(config_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"Malformed line {line_num} in {config_path}: missing '='")
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()

            # Handle quotes around value
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]

            if key in raw_pairs:
                raise ValueError(f"Duplicate configuration key at line {line_num}: '{key}'")
            if key not in WHITELIST_KEYS:
                raise ValueError(f"Unknown configuration key at line {line_num}: '{key}' (not in whitelist)")

            raw_pairs[key] = val

    # Verify all mandatory keys are present
    missing = MANDATORY_KEYS - set(raw_pairs.keys())
    if missing:
        raise ValueError(f"Missing mandatory configuration keys: {sorted(missing)}")

    # Type coercion and semantic validation
    parsed: Dict[str, Any] = {}

    # Target IPs
    parsed["MASTER_IP"] = validate_public_ip(raw_pairs["MASTER_IP"], "MASTER_IP")
    parsed["WORKER_IP"] = validate_public_ip(raw_pairs["WORKER_IP"], "WORKER_IP")
    if parsed["MASTER_IP"] == parsed["WORKER_IP"]:
        raise ValueError("MASTER_IP and WORKER_IP must identify different VPS hosts.")

    # Target Domains
    parsed["MASTER_PANEL_DOMAIN"] = validate_domain(raw_pairs["MASTER_PANEL_DOMAIN"], "MASTER_PANEL_DOMAIN")
    parsed["MASTER_REALITY_DOMAIN"] = validate_domain(raw_pairs["MASTER_REALITY_DOMAIN"], "MASTER_REALITY_DOMAIN")
    if parsed["MASTER_PANEL_DOMAIN"].lower() == parsed["MASTER_REALITY_DOMAIN"].lower():
        raise ValueError("MASTER_PANEL_DOMAIN and MASTER_REALITY_DOMAIN must be different.")

    parsed["WORKER_DOMAIN"] = validate_domain(raw_pairs["WORKER_DOMAIN"], "WORKER_DOMAIN")
    parsed["WORKER_REALITY_DOMAIN"] = validate_domain(raw_pairs["WORKER_REALITY_DOMAIN"], "WORKER_REALITY_DOMAIN")
    if parsed["WORKER_DOMAIN"].lower() == parsed["WORKER_REALITY_DOMAIN"].lower():
        raise ValueError("WORKER_DOMAIN and WORKER_REALITY_DOMAIN must be different.")

    # Vision is a pair-wide capability. Reject one-sided configuration before SSH.
    master_vision_set = bool(raw_pairs.get("MASTER_VISION_DOMAIN", "").strip())
    worker_vision_set = bool(raw_pairs.get("WORKER_VISION_DOMAIN", "").strip())
    if master_vision_set != worker_vision_set:
        raise ValueError("MASTER_VISION_DOMAIN and WORKER_VISION_DOMAIN must both be configured or both be omitted.")

    # Optional Vision domains
    if "MASTER_VISION_DOMAIN" in raw_pairs and raw_pairs["MASTER_VISION_DOMAIN"]:
        parsed["MASTER_VISION_DOMAIN"] = validate_domain(raw_pairs["MASTER_VISION_DOMAIN"], "MASTER_VISION_DOMAIN")
        if parsed["MASTER_VISION_DOMAIN"].lower() in (
            parsed["MASTER_PANEL_DOMAIN"].lower(),
            parsed["MASTER_REALITY_DOMAIN"].lower(),
        ):
            raise ValueError("MASTER_VISION_DOMAIN must differ from Master Panel and Reality domains.")
    else:
        parsed["MASTER_VISION_DOMAIN"] = None

    if "WORKER_VISION_DOMAIN" in raw_pairs and raw_pairs["WORKER_VISION_DOMAIN"]:
        parsed["WORKER_VISION_DOMAIN"] = validate_domain(raw_pairs["WORKER_VISION_DOMAIN"], "WORKER_VISION_DOMAIN")
        if parsed["WORKER_VISION_DOMAIN"].lower() in (
            parsed["WORKER_DOMAIN"].lower(),
            parsed["WORKER_REALITY_DOMAIN"].lower(),
        ):
            raise ValueError("WORKER_VISION_DOMAIN must differ from Worker domain and Reality domains.")
    else:
        parsed["WORKER_VISION_DOMAIN"] = None

    domain_values = [
        parsed["MASTER_PANEL_DOMAIN"], parsed["MASTER_REALITY_DOMAIN"],
        parsed["WORKER_DOMAIN"], parsed["WORKER_REALITY_DOMAIN"],
    ]
    if parsed["MASTER_VISION_DOMAIN"]:
        domain_values.extend([parsed["MASTER_VISION_DOMAIN"], parsed["WORKER_VISION_DOMAIN"]])
    normalized_domains = [domain.lower() for domain in domain_values]
    if len(normalized_domains) != len(set(normalized_domains)):
        raise ValueError("All configured Master/Worker Panel, REALITY, and Vision domains must be globally distinct.")

    # SSH configuration. E2E v1 deliberately supports root SSH only; no sudo adapter exists.
    parsed["MASTER_SSH_PORT"] = parse_port(raw_pairs.get("MASTER_SSH_PORT", "22"), "MASTER_SSH_PORT")
    parsed["WORKER_SSH_PORT"] = parse_port(raw_pairs.get("WORKER_SSH_PORT", "22"), "WORKER_SSH_PORT")
    parsed["MASTER_SSH_USER"] = raw_pairs.get("MASTER_SSH_USER", "root").strip()
    parsed["WORKER_SSH_USER"] = raw_pairs.get("WORKER_SSH_USER", "root").strip()
    if parsed["MASTER_SSH_USER"] != "root" or parsed["WORKER_SSH_USER"] != "root":
        raise ValueError("E2E v1 requires MASTER_SSH_USER=root and WORKER_SSH_USER=root; sudo fallback is unsupported.")

    # Support per-host credentials without requiring legacy shared paths.
    parsed["SSH_KEY_PATH"] = raw_pairs.get("SSH_KEY_PATH")
    parsed["SSH_KNOWN_HOSTS"] = raw_pairs.get("SSH_KNOWN_HOSTS")
    parsed["MASTER_SSH_KEY_PATH"] = raw_pairs.get("MASTER_SSH_KEY_PATH", parsed["SSH_KEY_PATH"])
    parsed["WORKER_SSH_KEY_PATH"] = raw_pairs.get("WORKER_SSH_KEY_PATH", parsed["SSH_KEY_PATH"])
    parsed["MASTER_KNOWN_HOSTS_PATH"] = raw_pairs.get("MASTER_KNOWN_HOSTS_PATH", parsed["SSH_KNOWN_HOSTS"])
    parsed["WORKER_KNOWN_HOSTS_PATH"] = raw_pairs.get("WORKER_KNOWN_HOSTS_PATH", parsed["SSH_KNOWN_HOSTS"])
    for key in ("MASTER_SSH_KEY_PATH", "WORKER_SSH_KEY_PATH",
                "MASTER_KNOWN_HOSTS_PATH", "WORKER_KNOWN_HOSTS_PATH"):
        if not parsed[key]:
            raise ValueError(f"{key} (or its shared SSH_KEY_PATH/SSH_KNOWN_HOSTS fallback) is mandatory.")

    # ACME mode
    acme_mode = raw_pairs.get("ACME_MODE", "staging").lower()
    if acme_mode not in ("staging", "production"):
        raise ValueError(f"Invalid ACME_MODE: '{acme_mode}'. Must be 'staging' or 'production'.")
    parsed["ACME_MODE"] = acme_mode
    parsed["ADMIN_EMAIL"] = raw_pairs.get("ADMIN_EMAIL", "admin@example.com")

    # Version pins must be explicit version/tag identifiers; floating channels are rejected.
    for version_key in (
        "GOWAVE_PANEL_VERSION", "GOWAVE_NODE_VERSION",
        "XRAY_SERVER_VERSION", "XRAY_CLIENT_VERSION", "MIHOMO_CLIENT_VERSION",
    ):
        version_value = raw_pairs[version_key].strip()
        if not VERSION_REGEX.fullmatch(version_value) or version_value.lower() in ("latest", "stable", "main", "master"):
            raise ValueError(f"{version_key} must be an explicit pinned version/tag, not a floating channel.")
        parsed[version_key] = version_value

    # REALITY Host fingerprint. Defaults to firefox and must match what the
    # installer provisions; any supported uTLS preset can be pinned explicitly.
    reality_fp = (raw_pairs.get("REALITY_FINGERPRINT", "firefox").strip().lower() or "firefox")
    if reality_fp not in REALITY_FINGERPRINTS:
        raise ValueError(
            f"Invalid REALITY_FINGERPRINT: '{reality_fp}'. "
            f"Supported values: {', '.join(REALITY_FINGERPRINTS)}"
        )
    parsed["REALITY_FINGERPRINT"] = reality_fp

    # Optional second mihomo-compatible client (for example Prizrak-Core) that
    # exercises the same subscription without replacing the upstream client.
    alt_core = raw_pairs.get("ALT_MIHOMO_CORE", "").strip()
    if alt_core:
        alt_path = Path(alt_core)
        if not alt_path.is_absolute():
            raise ValueError(f"ALT_MIHOMO_CORE must be an absolute path: '{alt_path}'")
        if alt_path.is_symlink():
            raise ValueError(f"ALT_MIHOMO_CORE must not be a symlink: '{alt_path}'")
        if not alt_path.is_file():
            raise ValueError(f"ALT_MIHOMO_CORE regular file not found: '{alt_path}'")
        if not os.access(str(alt_path), os.X_OK):
            raise ValueError(f"ALT_MIHOMO_CORE is not executable: '{alt_path}'")
        parsed["ALT_MIHOMO_CORE"] = str(alt_path)
    else:
        parsed["ALT_MIHOMO_CORE"] = None

    commit = raw_pairs["GOWAVE_NODE_INSTALLER_COMMIT"]
    if not HEX40_REGEX.match(commit):
        raise ValueError(
            f"Invalid GOWAVE_NODE_INSTALLER_COMMIT: '{commit}'. Must be an explicit 40-hex SHA commit."
        )
    parsed["GOWAVE_NODE_INSTALLER_COMMIT"] = commit

    sha256 = raw_pairs["GOWAVE_NODE_INSTALLER_SHA256"]
    if not HEX64_REGEX.match(sha256):
        raise ValueError(
            f"Invalid GOWAVE_NODE_INSTALLER_SHA256: '{sha256}'. Must be an explicit 64-hex SHA256 digest."
        )
    parsed["GOWAVE_NODE_INSTALLER_SHA256"] = sha256

    # IPv6
    enable_ipv6 = parse_bool(raw_pairs.get("ENABLE_IPV6", "false"), "ENABLE_IPV6")
    parsed["ENABLE_IPV6"] = enable_ipv6
    if enable_ipv6:
        if "MASTER_IPV6" not in raw_pairs or not raw_pairs["MASTER_IPV6"]:
            raise ValueError("MASTER_IPV6 is mandatory when ENABLE_IPV6=true")
        if "WORKER_IPV6" not in raw_pairs or not raw_pairs["WORKER_IPV6"]:
            raise ValueError("WORKER_IPV6 is mandatory when ENABLE_IPV6=true")
        parsed["MASTER_IPV6"] = validate_public_ip(raw_pairs["MASTER_IPV6"], "MASTER_IPV6", allow_v6=True)
        parsed["WORKER_IPV6"] = validate_public_ip(raw_pairs["WORKER_IPV6"], "WORKER_IPV6", allow_v6=True)
    else:
        parsed["MASTER_IPV6"] = raw_pairs.get("MASTER_IPV6")
        parsed["WORKER_IPV6"] = raw_pairs.get("WORKER_IPV6")

    # Egress expectations
    parsed["EXPECTED_MASTER_EGRESS_IP"] = (
        validate_public_ip(raw_pairs["EXPECTED_MASTER_EGRESS_IP"], "EXPECTED_MASTER_EGRESS_IP")
        if raw_pairs.get("EXPECTED_MASTER_EGRESS_IP") else None
    )
    parsed["EXPECTED_WORKER_EGRESS_IP"] = (
        validate_public_ip(raw_pairs["EXPECTED_WORKER_EGRESS_IP"], "EXPECTED_WORKER_EGRESS_IP")
        if raw_pairs.get("EXPECTED_WORKER_EGRESS_IP") else None
    )

    # Timeouts
    parsed["NODE_READY_TIMEOUT"] = parse_positive_int(raw_pairs.get("NODE_READY_TIMEOUT", "120"), "NODE_READY_TIMEOUT")
    parsed["API_TIMEOUT"] = parse_positive_int(raw_pairs.get("API_TIMEOUT", "15"), "API_TIMEOUT")
    parsed["TRAFFIC_TIMEOUT"] = parse_positive_int(raw_pairs.get("TRAFFIC_TIMEOUT", "30"), "TRAFFIC_TIMEOUT")
    parsed["RESTORE_TIMEOUT"] = parse_positive_int(raw_pairs.get("RESTORE_TIMEOUT", "900"), "RESTORE_TIMEOUT")

    # Test toggles
    parsed["TEST_TRAFFIC_VERIFICATION"] = parse_bool(
        raw_pairs.get("TEST_TRAFFIC_VERIFICATION", "true"), "TEST_TRAFFIC_VERIFICATION"
    )
    parsed["TEST_MIHOMO_TRAFFIC"] = parse_bool(
        raw_pairs.get("TEST_MIHOMO_TRAFFIC", "true"), "TEST_MIHOMO_TRAFFIC"
    )
    parsed["TEST_NEGATIVE_SUITE"] = parse_bool(
        raw_pairs.get("TEST_NEGATIVE_SUITE", "true"), "TEST_NEGATIVE_SUITE"
    )

    # Teardown policy
    policy = raw_pairs.get("TEST_TEARDOWN_POLICY", "PRESERVE").upper()
    if policy == "DESTROY":
        raise ValueError(
            "TEST_TEARDOWN_POLICY=DESTROY is unsupported in v1; use PRESERVE or RESTORE_SNAPSHOT."
        )
    if policy not in ("PRESERVE", "RESTORE_SNAPSHOT"):
        raise ValueError(
            f"Invalid TEST_TEARDOWN_POLICY: '{policy}'. Must be 'PRESERVE' or 'RESTORE_SNAPSHOT'."
        )
    parsed["TEST_TEARDOWN_POLICY"] = policy

    if policy == "RESTORE_SNAPSHOT":
        for k in ("MASTER_SNAPSHOT_ID", "WORKER_SNAPSHOT_ID", "SNAPSHOT_RESTORE_HOOK", "SNAPSHOT_RESTORE_HOOK_SHA256"):
            if k not in raw_pairs or not raw_pairs[k]:
                raise ValueError(f"{k} is mandatory when TEST_TEARDOWN_POLICY=RESTORE_SNAPSHOT")
        parsed["MASTER_SNAPSHOT_ID"] = raw_pairs["MASTER_SNAPSHOT_ID"]
        parsed["WORKER_SNAPSHOT_ID"] = raw_pairs["WORKER_SNAPSHOT_ID"]

        hook_path = Path(raw_pairs["SNAPSHOT_RESTORE_HOOK"])
        if not hook_path.is_absolute():
            raise ValueError(f"SNAPSHOT_RESTORE_HOOK must be an absolute path: '{hook_path}'")
        if hook_path.is_symlink():
            raise ValueError(f"SNAPSHOT_RESTORE_HOOK must not be a symlink: '{hook_path}'")
        if not hook_path.is_file():
            raise ValueError(f"SNAPSHOT_RESTORE_HOOK regular executable file not found: '{hook_path}'")
        if not os.access(str(hook_path), os.X_OK):
            raise ValueError(f"SNAPSHOT_RESTORE_HOOK is not executable: '{hook_path}'")

        hook_stat = hook_path.stat()
        # Must be owned by runner user or root
        if hook_stat.st_uid not in (0, os.getuid()):
            raise ValueError(f"SNAPSHOT_RESTORE_HOOK must be owned by current user or root (uid: {hook_stat.st_uid})")
        # Must not be group or world writable
        if hook_stat.st_mode & 0o022:
            raise ValueError(f"SNAPSHOT_RESTORE_HOOK must not be group or world writable (mode: {oct(hook_stat.st_mode & 0o777)})")

        hook_sha = raw_pairs["SNAPSHOT_RESTORE_HOOK_SHA256"]
        if not HEX64_REGEX.match(hook_sha):
            raise ValueError(f"Invalid SNAPSHOT_RESTORE_HOOK_SHA256: '{hook_sha}'. Must be 64-hex SHA256.")
        parsed["SNAPSHOT_RESTORE_HOOK"] = str(hook_path)
        parsed["SNAPSHOT_RESTORE_HOOK_SHA256"] = hook_sha
    else:
        parsed["MASTER_SNAPSHOT_ID"] = raw_pairs.get("MASTER_SNAPSHOT_ID")
        parsed["WORKER_SNAPSHOT_ID"] = raw_pairs.get("WORKER_SNAPSHOT_ID")
        parsed["SNAPSHOT_RESTORE_HOOK"] = raw_pairs.get("SNAPSHOT_RESTORE_HOOK")
        parsed["SNAPSHOT_RESTORE_HOOK_SHA256"] = raw_pairs.get("SNAPSHOT_RESTORE_HOOK_SHA256")

    return LiveVPSConfig(raw=raw_pairs, values=parsed)
