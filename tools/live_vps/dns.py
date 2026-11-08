"""DNS verification module for Live VPS E2E testing.
Verifies A and AAAA records across multiple independent resolvers.
"""
from __future__ import annotations

import subprocess
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
    if len(res_list) < 2:
        raise ValueError("At least two independent resolvers are required for DNS preflight verification.")

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

    # Check if expected IP is among the resolved IPs on every resolver that returned results
    mismatched = []
    for r, ips in resolver_results.items():
        if not ips:
            mismatched.append(f"{r} returned no records")
        elif expected_ip not in ips:
            mismatched.append(f"{r} returned {ips} (expected {expected_ip})")

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


def verify_all_domains(
    config: Any,
    resolvers: Optional[List[str]] = None,
) -> Dict[str, DNSCheckResult]:
    """Verify all required domains in config for Master and Worker."""
    results: Dict[str, DNSCheckResult] = {}

    # Master domains -> MASTER_IP
    results["MASTER_PANEL_DOMAIN"] = verify_domain_dns(
        config.MASTER_PANEL_DOMAIN, config.MASTER_IP, "A", resolvers
    )
    results["MASTER_REALITY_DOMAIN"] = verify_domain_dns(
        config.MASTER_REALITY_DOMAIN, config.MASTER_IP, "A", resolvers
    )
    if config.MASTER_VISION_DOMAIN:
        results["MASTER_VISION_DOMAIN"] = verify_domain_dns(
            config.MASTER_VISION_DOMAIN, config.MASTER_IP, "A", resolvers
        )

    # Worker domains -> WORKER_IP
    results["WORKER_DOMAIN"] = verify_domain_dns(
        config.WORKER_DOMAIN, config.WORKER_IP, "A", resolvers
    )
    results["WORKER_REALITY_DOMAIN"] = verify_domain_dns(
        config.WORKER_REALITY_DOMAIN, config.WORKER_IP, "A", resolvers
    )
    if config.WORKER_VISION_DOMAIN:
        results["WORKER_VISION_DOMAIN"] = verify_domain_dns(
            config.WORKER_VISION_DOMAIN, config.WORKER_IP, "A", resolvers
        )

    # IPv6 verification if ENABLE_IPV6=true
    if getattr(config, "ENABLE_IPV6", False):
        if config.MASTER_IPV6:
            results["MASTER_PANEL_DOMAIN_AAAA"] = verify_domain_dns(
                config.MASTER_PANEL_DOMAIN, config.MASTER_IPV6, "AAAA", resolvers
            )
            results["MASTER_REALITY_DOMAIN_AAAA"] = verify_domain_dns(
                config.MASTER_REALITY_DOMAIN, config.MASTER_IPV6, "AAAA", resolvers
            )
            if config.MASTER_VISION_DOMAIN:
                results["MASTER_VISION_DOMAIN_AAAA"] = verify_domain_dns(
                    config.MASTER_VISION_DOMAIN, config.MASTER_IPV6, "AAAA", resolvers
                )
        if config.WORKER_IPV6:
            results["WORKER_DOMAIN_AAAA"] = verify_domain_dns(
                config.WORKER_DOMAIN, config.WORKER_IPV6, "AAAA", resolvers
            )
            results["WORKER_REALITY_DOMAIN_AAAA"] = verify_domain_dns(
                config.WORKER_REALITY_DOMAIN, config.WORKER_IPV6, "AAAA", resolvers
            )
            if config.WORKER_VISION_DOMAIN:
                results["WORKER_VISION_DOMAIN_AAAA"] = verify_domain_dns(
                    config.WORKER_VISION_DOMAIN, config.WORKER_IPV6, "AAAA", resolvers
                )

    return results
