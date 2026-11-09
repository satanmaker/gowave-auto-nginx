"""DNS verification module for Live VPS E2E testing.
Verifies A and AAAA records across multiple independent resolvers.
"""
from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8"]


@dataclass
class DNSCheckResult:
    domain: str
    expected_ip: str
    record_type: str
    ok: bool
    resolved_ips: List[str] = field(default_factory=list)
    resolver_results: Dict[str, List[str]] = field(default_factory=dict)
    error: Optional[str] = None


def resolve_dig(domain: str, record_type: str = "A", resolver: Optional[str] = None) -> List[str]:
    """Resolve a DNS record using dig."""
    cmd = ["dig", "+short", "+time=5", "+tries=2"]
    if resolver:
        cmd.append(f"@{resolver}")
    cmd.extend([domain, record_type])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode != 0:
            return []
        lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        # Filter out trailing dots or CNAME targets if only IPs are expected
        ips = [l for l in lines if not l.endswith(".")]
        return ips
    except Exception:
        return []


def verify_domain_dns(
    domain: str,
    expected_ip: str,
    record_type: str = "A",
    resolvers: Optional[List[str]] = None,
) -> DNSCheckResult:
    """Verify that domain resolves to expected_ip across at least two independent resolvers."""
    res_list = resolvers or DEFAULT_RESOLVERS
    if len(set(res_list)) < 2:
        raise ValueError("At least two distinct independent resolvers are required for DNS preflight verification.")

    resolver_results: Dict[str, List[str]] = {}
    all_resolved = set()

    for r in res_list:
        ips = resolve_dig(domain, record_type=record_type, resolver=r)
        resolver_results[r] = ips
        all_resolved.update(ips)

    if not all_resolved:
        return DNSCheckResult(
            domain=domain,
            expected_ip=expected_ip,
            record_type=record_type,
            ok=False,
            resolved_ips=[],
            resolver_results=resolver_results,
            error=f"Domain {domain} did not resolve on any tested resolvers: {res_list}",
        )

    # A domain routed directly to one VPS must resolve to exactly that address
    # on every resolver. An expected address mixed with unexpected records is
    # still a DNS configuration error (especially for dual-stack leakage).
    mismatched = []
    for r, ips in resolver_results.items():
        if not ips:
            mismatched.append(f"{r} returned no records")
        elif set(ips) != {expected_ip}:
            mismatched.append(f"{r} returned {ips} (expected exactly [{expected_ip}])")

    if mismatched:
        return DNSCheckResult(
            domain=domain,
            expected_ip=expected_ip,
            record_type=record_type,
            ok=False,
            resolved_ips=sorted(all_resolved),
            resolver_results=resolver_results,
            error=f"DNS mismatch for {domain} ({record_type}): " + "; ".join(mismatched),
        )

    return DNSCheckResult(
        domain=domain,
        expected_ip=expected_ip,
        record_type=record_type,
        ok=True,
        resolved_ips=sorted(all_resolved),
        resolver_results=resolver_results,
    )



def verify_domain_no_aaaa(
    domain: str,
    resolvers: Optional[List[str]] = None,
) -> DNSCheckResult:
    """Require authoritative NOERROR/NODATA-style responses with no AAAA data."""
    res_list = resolvers or DEFAULT_RESOLVERS
    if len(set(res_list)) < 2:
        raise ValueError("At least two distinct independent resolvers are required for DNS preflight verification.")

    resolver_results: Dict[str, List[str]] = {}
    errors = []
    for resolver in res_list:
        cmd = ["dig", "+time=5", "+tries=2", "+noall", "+answer", "+comments"]
        cmd.append(f"@{resolver}")
        cmd.extend([domain, "AAAA"])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        except Exception as exc:
            errors.append(f"{resolver}: {type(exc).__name__}")
            resolver_results[resolver] = []
            continue

        if proc.returncode != 0:
            errors.append(f"{resolver}: dig exited {proc.returncode}")
            resolver_results[resolver] = []
            continue
        status_match = re.search(r"status:\s*([A-Z]+)", proc.stdout)
        if not status_match or status_match.group(1) != "NOERROR":
            errors.append(f"{resolver}: DNS response status was {status_match.group(1) if status_match else 'unavailable'}")
            resolver_results[resolver] = []
            continue

        addresses = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[-2].upper() == "AAAA":
                addresses.append(parts[-1])
        resolver_results[resolver] = addresses

    all_resolved = sorted({address for values in resolver_results.values() for address in values})
    ok = not errors and all(not values for values in resolver_results.values())
    error = None
    if errors:
        error = "Could not obtain conclusive AAAA DNS responses: " + "; ".join(errors)
    elif all_resolved:
        error = f"Unexpected AAAA records published for {domain}: {all_resolved}"

    return DNSCheckResult(
        domain=domain,
        expected_ip="NONE",
        record_type="AAAA",
        ok=ok,
        resolved_ips=all_resolved,
        resolver_results=resolver_results,
        error=error,
    )


def verify_all_domains(
    config: Any,
    resolvers: Optional[List[str]] = None,
) -> Dict[str, DNSCheckResult]:
    """Verify exact A/AAAA DNS targets (or the absence of AAAA) for both VPS."""
    results: Dict[str, DNSCheckResult] = {}
    domain_targets = {
        "MASTER_PANEL_DOMAIN": (config.MASTER_PANEL_DOMAIN, config.MASTER_IP, config.MASTER_IPV6),
        "MASTER_REALITY_DOMAIN": (config.MASTER_REALITY_DOMAIN, config.MASTER_IP, config.MASTER_IPV6),
        "WORKER_DOMAIN": (config.WORKER_DOMAIN, config.WORKER_IP, config.WORKER_IPV6),
        "WORKER_REALITY_DOMAIN": (config.WORKER_REALITY_DOMAIN, config.WORKER_IP, config.WORKER_IPV6),
    }
    if config.MASTER_VISION_DOMAIN:
        domain_targets["MASTER_VISION_DOMAIN"] = (
            config.MASTER_VISION_DOMAIN, config.MASTER_IP, config.MASTER_IPV6
        )
    if config.WORKER_VISION_DOMAIN:
        domain_targets["WORKER_VISION_DOMAIN"] = (
            config.WORKER_VISION_DOMAIN, config.WORKER_IP, config.WORKER_IPV6
        )

    for key, (domain, ipv4, ipv6) in domain_targets.items():
        results[key] = verify_domain_dns(domain, ipv4, "A", resolvers)
        if getattr(config, "ENABLE_IPV6", False):
            if not ipv6:
                results[f"{key}_AAAA"] = DNSCheckResult(
                    domain=domain, expected_ip="UNCONFIGURED", record_type="AAAA",
                    ok=False, error="ENABLE_IPV6=true but the target IPv6 address is missing",
                )
            else:
                results[f"{key}_AAAA"] = verify_domain_dns(domain, ipv6, "AAAA", resolvers)
        else:
            results[f"{key}_AAAA_ABSENT"] = verify_domain_no_aaaa(domain, resolvers)

    return results
