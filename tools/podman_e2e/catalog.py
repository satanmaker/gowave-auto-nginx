"""Shared acceptance case catalog for the Podman and Live VPS suites.

The catalog is the single definition of every acceptance case: ID, owning
requirement, source scenario, assertion text, environment classification, gate
tier, and (once implemented) the suite driver. The Podman runner and the live
runner read the same file; a case is never defined twice.

Run this module as a script to regenerate the catalog from the live spec:

    python3 -m tools.podman_e2e.catalog generate
    python3 -m tools.podman_e2e.catalog check

``tests/cases/behaviors.yaml`` is the behaviour inventory beside the catalog:
every case belongs to exactly one behaviour, and each behaviour names the cases
that establish it, the cases that exercise its error paths, the topologies it
is proven in and the gate that blocks on it. ``check`` audits that inventory
and refuses a rendered report that is not the text the inventory renders to:

    python3 -m tools.podman_e2e.catalog behaviors --write
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml

from . import matrix as matrix_data

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LIVE_SPEC = REPO_ROOT / "openspec" / "specs" / "live-vps-e2e" / "spec.md"
CATALOG_PATH = REPO_ROOT / "tests" / "cases" / "catalog.yaml"
PARITY_PATH = REPO_ROOT / "tests" / "cases" / "PARITY.md"
BEHAVIORS_PATH = REPO_ROOT / "tests" / "cases" / "behaviors.yaml"
BEHAVIOR_REPORT_PATH = REPO_ROOT / "docs" / "PODMAN_E2E_BEHAVIORS.md"
MATRIX_PATH = REPO_ROOT / "tests" / "cases" / "matrix.yaml"

# The nine areas the delta spec's coverage requirement names, in its own order.
# The inventory declares them and every one of them has to carry a behaviour:
# an area the requirement names but no entry covers is a failure, not a gap.
BEHAVIOR_SCHEMA = "gowave-podman-behaviors/v1"
BEHAVIOR_AREAS: Tuple[str, ...] = (
    "installation",
    "provisioning",
    "subscription-representations",
    "data-plane",
    "decoy",
    "tls-dns-acme",
    "network-policy",
    "lifecycle",
    "failure-injection",
)

PODMAN_CASES: Sequence[str] = ("aio", "multi-node")
ALL_CASES: Sequence[str] = ("podman", "live")

# The modules that build the Podman case list, keyed by the topology their
# `Case(...)` calls declare. Implementation facts are read from this code and
# written into the catalog, never the other way round: an entry cannot claim a
# driver no function implements, and a function cannot run a case the catalog
# does not declare implemented.
DRIVER_MODULES: Dict[str, Path] = {
    "aio": REPO_ROOT / "tools" / "podman_e2e" / "aio.py",
    "multi-node": REPO_ROOT / "tools" / "podman_e2e" / "multi_node.py",
}

# Two drivers mint one `Case` per matrix tuple instead of writing each out, so
# their ids are computed rather than spelled. The exception is a closed list —
# the ids themselves are the ones `data_plane_cases()` puts in the catalog and
# `tests/test_podman_matrix.py` checks against the matrix — and a new builder
# appearing in the code is refused rather than silently escaping the catalog.
# Keyed by module file stem, because that is what the source names.
MATRIX_DRIVEN_BUILDERS: Set[Tuple[str, str]] = {
    ("aio", "_data_plane_case"),
    ("multi_node", "data_plane_case"),
}

DRIVER_STATUSES: Sequence[str] = ("implemented", "planned", "not-applicable")


class CatalogError(RuntimeError):
    """The catalog and the code that implements it disagree."""


REQUIREMENT_PREFIX = {
    "Disposable Environment Gate": "ENV",
    "Complete Mutation-Target Baseline and Resource Ownership": "OWN",
    "Preflight SSH Trust and DNS Verification": "PRE",
    "Target Address, Domain, and SSH Identity Safety": "ADDR",
    "Independent Optional Vision Domains": "VIS",
    "Pinned Version Fidelity": "VER",
    "All-in-One Master VPS Installation Verification": "AIO",
    "Distributed Worker VPS Deployment Verification": "WRK",
    "Public mTLS Control Plane Verification (Master → Worker)": "MTLS",
    "TLS-aware Bounded Panel API Client": "APIC",
    "Panel API Cluster Structure Audit": "CLUS",
    "Real Subscription Delivery and User-Agent Policy": "SUB",
    "UFW Firewall Isolation Verification": "FW",
    "NGINX SNI Routing and REALITY Decoy Verification": "NGX",
    "Data Plane E2E Traffic Through All VPN Endpoints": "DP",
    "Negative Scenario and Fault Injection Tests": "NEG",
    "Global Certbot Deploy Hook Ownership": "HOOK",
    "Signal-Safe and Verifiable Transaction Compensation": "TXN",
    "Teardown Policy Enforcement": "TD",
    "Pair-Wide Run Locking": "LOCK",
    "Shared Mutation Lock Across All Management Entry Points": "MLOCK",
    "Durable Run State for Partial CLI Modes": "STATE",
    "Redacted Diagnostic Artifact Collection": "RED",
    "Result Status Semantics": "RES",
    "Local Operator Credential Bootstrap and Cleanup": "BOOT",
    "Per-Case Data-Plane Packet Evidence": "PKT",
    "Local interactive operator entrypoint": "OP",
    "Out-of-band SSH host identity verification": "SSHID",
    "Temporary SSH access with remote expiry": "TSSH",
    "Immediate credential revocation gates overall status": "REV",
    "Local-only live VPS credential handling": "LOCAL",
}

MULTI_NODE_ONLY = {
    "Distributed Worker VPS Deployment Verification",
    "Public mTLS Control Plane Verification (Master → Worker)",
    "Panel API Cluster Structure Audit",
    "UFW Firewall Isolation Verification",
    "Pair-Wide Run Locking",
    "Shared Mutation Lock Across All Management Entry Points",
    "Local-only live VPS credential handling",
}

PARTIAL_SCENARIOS = {
    ("Preflight SSH Trust and DNS Verification", "Private or reserved IP rejected"):
        "Container proves the private/reserved rule against Podman addresses with an explicitly scoped, fail-closed exemption; the live run is authoritative for real public addresses.",
    ("UFW Firewall Isolation Verification", "Master local and external access are distinguished"):
        "Container proves isolation between distinct source addresses; provider-level external reachability is live-only.",
    ("Data Plane E2E Traffic Through All VPN Endpoints", "Staging and public CA chains are both trusted without bypass"):
        "Container proves explicit verify anchors and no global trust change; public Let's Encrypt issuance is live-only.",
    ("Data Plane E2E Traffic Through All VPN Endpoints", "Xray TLS outbounds carry explicit Staging trust anchors"):
        "Container proves the injected verify anchor is required; real Staging material is live-only.",
    ("Data Plane E2E Traffic Through All VPN Endpoints", "Staging CA material is pinned and reproducible"):
        "Container proves fixture CA pinning by digest; real Staging CA distribution is live-only.",
    ("Teardown Policy Enforcement", "Snapshot restore reacquires the remote lock pair before baseline verification"):
        "Container proves lock ordering and hook protocol; provider snapshots are live-only.",
    ("Local Operator Credential Bootstrap and Cleanup", "Host identity is verified before password authentication"):
        "Container proves host identity precedes the password; the live controller's public-target path is live-only.",
    ("Local Operator Credential Bootstrap and Cleanup", "Temporary access is bounded and revoked"):
        "Container proves bounded key lifetime and revocation; live account behaviour is live-only.",
}

LIVE_ONLY_SCENARIOS = {
    ("Teardown Policy Enforcement", "Single-host snapshot reboot does not self-deadlock lock reacquisition"):
        "Requires a provider snapshot and a real reboot; a container cannot reproduce the host lifecycle.",
    ("Local-only live VPS credential handling", "Local operator starts a live run"):
        "Starts the interactive operator against real disposable VPS instances; live infrastructure only.",
}

PODMAN_FIRST_CASES: List[Dict[str, Any]] = [
    {
        "id": "AIO-INSTALL",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "The real operator runs its documented All-in-One install on a clean supported systemd host that offers only what a VPS offers, exits successfully, and needs no test-side product provisioning.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "MN-INSTALL",
        "requirement": "Distributed Worker VPS Deployment Verification",
        "assertion": "The real operator runs its documented All-in-One install on a clean Master host while a second clean supported systemd host sits beside it untouched, and the Worker stays unprovisioned until the operator registers it.",
        "topology": ["multi-node"],
        "promotion_target": "Distributed Worker VPS Deployment Verification",
    },
    {
        "id": "AIO-PACKAGES",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "Every prerequisite the operator documents as its own responsibility is installed by that operator on a clean host, checked against a harness-owned package list rather than the product's own claim.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-AUTH",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "The documented admin login returns a bearer token that the real Panel API accepts while the same call is refused anonymously, and the authenticated read surface reports one local node, one config profile, the default squad, and one host per inbound that all describe the same four-inbound set for a Vision-less All-in-One install.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-CLIENT",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "A client is created through POST /api/users into the default squad, read back by username and by id with the same shortUuid, and deleted with DELETE /api/users/{id} returning 204 after which the username is no longer served.",
        "topology": ["aio"],
        "promotion_target": "Real Subscription Delivery and User-Agent Policy",
    },
    {
        "id": "SUB-SERVED",
        "requirement": "Panel subscription representations",
        "assertion": "Every representation the Panel serves — the base64 share-link list, the Xray JSON profile list, the Mihomo and Clash YAML, and the sing-box JSON — is fetched with the User-Agent of the client that consumes it, and the pinned Xray and Mihomo binaries load what was served without the Panel-issued outbound being replaced.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Real Subscription Delivery and User-Agent Policy",
    },
    {
        "id": "SUB-B64",
        "requirement": "Panel subscription representations",
        "assertion": "The base64 share-link list at /api/sub/<shortUuid> contains one link per proxy entry with the expected protocol, host, SNI and firefox fingerprint, and an Xray-family client imports it while the raw JSON body imports nothing.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Real Subscription Delivery and User-Agent Policy",
    },
    {
        "id": "SUB-UA-ABSENT",
        "requirement": "Real Panel subscription lifecycle",
        "assertion": "A subscription request that carries no User-Agent header at all is rejected with 403 for every representation, as a result separate from the blank-header case.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Real Subscription Delivery and User-Agent Policy",
    },
    {
        "id": "SUB-UA-BLANK",
        "requirement": "Real Panel subscription lifecycle",
        "assertion": "An explicitly blank User-Agent header is rejected with 403 as a result separate from the absent-header case.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Real Subscription Delivery and User-Agent Policy",
    },
    {
        "id": "SUB-JSON-SHAPES",
        "requirement": "Panel subscription representations",
        "assertion": "/v2ray-json is validated in both served shapes: a list entry as a complete config, and only a bare outbound object wrapped with the minimal runtime wrapper.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Real Subscription Delivery and User-Agent Policy",
    },
    {
        "id": "AIO-REVOKE",
        "requirement": "Real client data-plane verification",
        "assertion": "A subscription is served, updated through PATCH and captured once one real transfer proves the Panel's asynchronous user push reached the node, the documented revoke action rotates the credentials and the subscription path with the old path returning 404, and freshly started engines replaying the pre-revocation payload deliver nothing while the controlled endpoint records none of their request ids.",
        "topology": ["aio"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    },
    {
        "id": "AIO-RESTART",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "Restarting the product's own systemd units leaves every declared unit active, the Panel answering the documented authenticated call again inside one bounded deadline, every served outbound carrying a payload to the endpoint before the matrix runs, and both pinned clients transferring a unique payload through every core transport with the installed host as the source.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-IDEMPOTENT",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "The real operator install is executed a second time against the installed target and leaves the Panel inventory — nodes, config profiles, squads, hosts and API tokens — and the host inventory — systemd unit files and digested NGINX configuration — unchanged, the credentials file root-owned 0600 and still authenticating, the already served subscription carrying the same credentials, and both pinned clients still transferring payloads.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-NEG-DEST",
        "requirement": "Real client data-plane verification",
        "assertion": "One served outbound carries a payload to the permitted public endpoint first, then a payload addressed to the endpoint's private face — which the product's own routing sends to its block outbound — is refused, and the endpoint's record read directly does not contain the prohibited request id.",
        "topology": ["aio"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    },
    {
        "id": "AIO-NEG-PORT",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "On the installed host the product's port preflight reports a declared port held by a process outside the managed units as a conflict, does not report 443 held by the product's own NGINX as one, and stops reporting the borrowed port once the foreign listener exits.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-NEG-ACME",
        "requirement": "Fail-closed local ACME test mode",
        "assertion": "The local ACME fixture endpoint is refused without GOWAVE_ACME_TEST_MODE=1, an arbitrary directory URL is refused inside test mode, a CA whose digest does not match the pinned one is refused, and the production ACME directory is still accepted.",
        "topology": ["aio"],
        "promotion_target": "Independent All-in-One Acceptance Topology",
    },
    {
        "id": "AIO-NEG-DEP",
        "requirement": "Security and network isolation verification",
        "assertion": "With the product's NGINX unit stopped, the public HTTPS surface stops answering from the independent Control Machine while the Panel's loopback API still authenticates, and after the unit is started the same public call succeeds again inside one bounded deadline.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-CHANNEL-NOOP",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "The channel command invoked for the channel the host is already on reports that nothing changed, exits successfully, and takes no snapshot, rewrites no environment file or journal, and leaves the Panel process in place, so a repeated lifecycle call is a no-op rather than a restart.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-CHANNEL-ROLLBACK",
        "requirement": "Signal-Safe and Verifiable Transaction Compensation",
        "assertion": "A channel switch whose restarted Panel cannot start is undone from the snapshot taken before it: the binary, database, frontend, environment, state.json, NGINX tree and ACME lineage come back identical to the pre-switch state after each was overwritten, the journal ends ROLLED_BACK rather than staying at APPLYING, and the restored installation answers its authenticated API and carries a payload through every served outbound of both pinned clients.",
        "topology": ["aio"],
        "promotion_target": "Signal-Safe and Verifiable Transaction Compensation",
    },
    {
        "id": "AIO-INTERRUPT",
        "requirement": "Failure injection and recovery",
        "assertion": "An operator killed with SIGKILL while its channel switch is in the product's APPLYING state leaves a documented recoverable state: the journal still validates and names that in-progress transaction with the snapshot it took, the mutation lock is free, the switch never printed its success line, and the supported `recover --boot-files` entrypoint rolls that very snapshot back to the pre-switch channel, the journal ends ROLLED_BACK, and the Panel comes back active serving the same clients and a payload through both pinned engines.",
        "topology": ["aio"],
        "promotion_target": "Signal-Safe and Verifiable Transaction Compensation",
    },
    {
        "id": "AIO-CHANNEL-DEV",
        "requirement": "All-in-One Master VPS Installation Verification",
        "assertion": "The documented stable-to-dev transition is a snapshot, an environment rewrite and a restart: the journal ends COMMITTED with the target channel recorded, exactly one snapshot holds the pre-switch tree, the Panel answers its health route and serves every representation, both pinned clients transfer a payload through every served outbound, and the guarded dev-to-stable direction is still refused without --force and changes nothing.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-FAULT-DISK",
        "requirement": "Failure injection and recovery",
        "assertion": "A backup store that cannot hold the archive fails loudly and publishes nothing: no archive-shaped or partial file appears in the store, the Panel, its database, the frontend, state.json, the NGINX and ACME trees and the health route are unchanged by the failed write, and after the fault is removed the same operator command publishes a mode-0600 archive that the product's own preflight validator accepts.",
        "topology": ["aio"],
        "promotion_target": "Backup and Restore Format v1",
    },
    {
        "id": "AIO-FAULT-PANEL",
        "requirement": "Failure injection and recovery",
        "assertion": "With gowave.service stopped, NGINX keeps answering on 443 for the Panel's own name and its routes return the gateway error rather than a Panel or subscription response, the data plane the node already configured still carries a payload through every served outbound, no operator-owned file or database row moves while the unit is down, and starting it again restores the health route and serves the same client inventory and byte-identical representations.",
        "topology": ["aio"],
        "promotion_target": "All-in-One Master VPS Installation Verification",
    },
    {
        "id": "AIO-FAULT-XRAY",
        "requirement": "Failure injection and recovery",
        "assertion": "Killing the core the node runs with SIGKILL is answered by gowave-node itself: a replacement core appears inside gowave-node.service's own cgroup within the deadline, the node's MainPID, ActiveEnterTimestamp and restart counter are unchanged, no unit of its own supervises a core, the operator-owned tree is untouched, and every served outbound carries a payload again afterwards.",
        "topology": ["aio"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    },
    {
        "id": "AIO-FAULT-LATENCY",
        "requirement": "Failure injection and recovery",
        "assertion": "Adding a netem delay to every interface of the installed host degrades but does not break it: the Control Machine's own request time rises by at least the injected delay while the Panel still answers 200 and every served outbound still carries a payload, removing the delay returns the request time to its baseline, and the operator-owned files, database integrity and units are unchanged throughout.",
        "topology": ["aio"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    },
    {
        "id": "NGX-05",
        "requirement": "NGINX SNI Routing and REALITY Decoy Verification",
        "assertion": "On every role the product installs, the generated NGINX tree passes `nginx -t`, its dump carries that role's own server name and its ssl_preread SNI routing, the product's managed ACME deploy hook does not reload NGINX when an invalid snippet makes `nginx -t` fail — leaving the master, its workers and the 443 listener untouched — and the same hook does reload it, without replacing the master, once the snippet is removed.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "TLS-01",
        "requirement": "NGINX SNI Routing and REALITY Decoy Verification",
        "assertion": "On every role the product exposes over HTTPS, an independent client that trusts only the fixture CA completes a TLSv1.3 handshake whose certificate names exactly that role's domain, is inside its validity window with renewal headroom, and chains to the issuing CA; the same client still negotiates TLSv1.2, is refused when it pins TLSv1.1, and fails chain verification when the CA is withheld — while the role's generated vhost states its protocol list itself instead of inheriting the distribution default.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "DECOY-01",
        "requirement": "NGINX SNI Routing and REALITY Decoy Verification",
        "assertion": "From an independent Control Machine, the camouflage listener answers the cover apex, its www, the REALITY name without REALITY authentication, and an SNI the stream map does not list with the same rendered cover site, and refuses every path the panel vhost serves — /api/, /api/sub/, /api/nodes, /api/auth/login, /xhttp-down/, /ws, /trojan-grpc and the scanned /metrics and /server-status — with that site's own 404 document rather than any management response, while the Panel's management surface still authenticates over loopback and refuses an anonymous /api/nodes call on its own name.",
        "topology": ["aio"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "ACME-01",
        "requirement": "Real ACME issuance and renewal through the pinned directory",
        "assertion": "On the installed host the certificate serving the Panel domain was issued during this run by the pinned ACME directory, Certbot's own renewal record names the webroot method and that webroot, a token written into the webroot is fetched through the product's port 80 vhost from an independent client, and a forced renewal performs an HTTP-01 challenge and yields a new serial whose leaf the independent client receives after the product's deploy hook reloads NGINX without replacing the master.",
        "topology": ["aio"],
        "promotion_target": "Global Certbot Deploy Hook Ownership",
    },
    {
        "id": "ACME-02",
        "requirement": "Real ACME issuance and renewal through the pinned directory",
        "assertion": "With the port 80 challenge webroot closed to the validator, and again with the pinned directory unreachable from the host, a forced renewal exits non-zero, quotes its own cause, leaves the installed serial, notBefore and archive count unchanged, and keeps serving the working leaf to an independent client; once each outage is removed the same forced renewal issues a new serial whose leaf the client then receives.",
        "topology": ["aio"],
        "promotion_target": "Global Certbot Deploy Hook Ownership",
    },
    {
        "id": "DNS-01",
        "requirement": "Preflight SSH Trust and DNS Verification",
        "assertion": "From the installed host's own resolution path and from an independent Control Machine, a name that publishes only an A record is answered with exactly that address and never with an AAAA, and a name that publishes only an AAAA is answered with exactly that address and never with an A, with the fixture publishing the TTL the zone declares; the fixture's own query log names each vantage's source address asking that question, an unknown name inside the zone is refused with NXDOMAIN and resolves to nothing, a record changed under a short TTL is answered with the new address within that record's lifetime instead of being served from a stale cache, and a wrong or about-to-expire answer is served exactly as published rather than repaired — after which the installed zone is restored and serves the installed names again.",
        "topology": ["aio"],
        "promotion_target": "Preflight SSH Trust and DNS Verification",
    },
    {
        "id": "NGX-COVER-DERIVE",
        "requirement": "Camouflage decoy and certificate lineage",
        "assertion": "The cover apex is the last two labels of panel_domain and a domain with fewer than three labels produces no cover lineage and is handled explicitly.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "NGX-COVER-SITE",
        "requirement": "Camouflage decoy and certificate lineage",
        "assertion": "The rendered cover site is a complete branded site: every template document is present, the brand is derived from the apex's second-to-last label and appears in the front page's title, header and footer, no document keeps a template placeholder, no document names the panel, its API routes or the loopback decoy listeners, and an independent client fetching every page and every asset the pages reference from the apex receives byte-identical copies of the files the host rendered with the MIME type NGINX assigns each asset kind.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "NGX-DECOY-ROUTE",
        "requirement": "Camouflage decoy and certificate lineage",
        "assertion": "On both roles the running stream map sends the cover apex and www.<apex> to the loopback listener 127.0.0.1:9443 — and no other name to it — while every VPN and panel name keeps its own local port and an unmatched SNI falls back to the node's own REALITY listener; the camouflage socket is bound to 127.0.0.1 only and refuses a real TCP connection from both client networks that reach 443 on the same host, and an independent client fetching the apex, its www and the REALITY name without REALITY authentication receives the rendered cover page over the installed lineage whose SAN list names both cover names.",
        "topology": ["multi-node"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "NGX-COVER-UNRESOLVED",
        "requirement": "Camouflage decoy and certificate lineage",
        "assertion": "When the apex or www.<apex> does not resolve to the host IPv4, the operator refuses before issuing the lineage and leaves no partial decoy or stale sites-enabled entry.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "NGINX SNI Routing and REALITY Decoy Verification",
    },
    {
        "id": "NGX-WORKER-ACME80",
        "requirement": "Camouflage decoy and certificate lineage",
        "assertion": "A Worker install or reconfiguration keeps its port 80 ACME vhost reachable so renewal retains a working HTTP-01 path.",
        "topology": ["multi-node"],
        "promotion_target": "Distributed Worker VPS Deployment Verification",
    },
    {
        "id": "TLS-VERIFY-ANCHORS",
        "requirement": "Private test CA trust for both client engines",
        "assertion": "Every Xray TLS outbound carries the fixture CA through tlsSettings.certificates with usage verify, and removing the anchor turns the case into a chain-verification failure.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    },
    {
        "id": "MN-BACKUP",
        "requirement": "Backup and Restore Format v1",
        "assertion": "Both archive types are produced through the operator's own interface — --type panel on Master and --type node on Worker — as mode-0600 Format v1 archives whose actual contents match their documented allowlists: the Panel archive carries the database, environment, NGINX vhosts, the complete certificate lineage and run state with every declared checksum present and no binary, while the Worker archive carries exactly its environment file, and the product's own validator accepts both.",
        "topology": ["multi-node"],
        "promotion_target": "Signal-Safe and Verifiable Transaction Compensation",
    },
    {
        "id": "MN-BACKUP-VOL",
        "requirement": "Backup and Restore Format v1",
        "assertion": "Both unencrypted archives are written into a /var/backups/gowave that is a run-owned Podman volume of its own — a filesystem distinct from the container's root, owned by root at mode 0700 with exactly one mount entry and carrying the run's cleanup label — each role's archive lands on that volume at mode 0600, and the run's artifact tree holds no gzip stream, no file named or suffixed as an archive, and no line carrying a private key or secret-bearing variable, so the volume's removal by label during cleanup leaves nothing behind.",
        "topology": ["multi-node"],
        "promotion_target": "Signal-Safe and Verifiable Transaction Compensation",
    },
    {
        "id": "MN-BACKUP-BAD",
        "requirement": "Backup and Restore Format v1",
        "assertion": "An archive the product did not write, or wrote incompletely, is refused by the product's own restore on the role it names — truncated, garbage, checksum-mismatched, missing a member its manifest declares, missing the member its type requires, and of the wrong type are each rejected with their own message and no traceback, while the untouched archives of both roles still pass the 15-point preflight; every refusal leaves Master's unit state, NGINX, environment and database bytes and snapshot count, and the Worker's environment digest and unit, exactly as they were, so a partially applied restore can never be mistaken for a refused one.",
        "topology": ["multi-node"],
        "promotion_target": "Signal-Safe and Verifiable Transaction Compensation",
    },
    {
        "id": "MN-RESTORE",
        "requirement": "Backup and Restore Format v1",
        "assertion": "A Panel archive and a Worker archive, both written by the product on the roles this run provisioned, are restored by the product's own restore command on those roles: a client created through the Panel API and then deleted comes back with its identity, the inventory and the exact bytes of every representation it was served, the Worker's environment file returns to the bytes the archive captured (the injected marker gone) with its unit active, and both nodes reconnect and carry data-plane payload through every served outbound afterwards.",
        "topology": ["multi-node"],
        "promotion_target": "Signal-Safe and Verifiable Transaction Compensation",
    },
    {
        "id": "PODNET-MASTER-ADDR",
        "requirement": "Podman-only Master address selection for Worker provisioning",
        "assertion": "The real node add path uses the validated private Master address on the run-scoped network, Worker observes that source, and the override is rejected without the explicit opt-in or when the address is not assigned to Master.",
        "topology": ["multi-node"],
        "promotion_target": "Distributed Worker VPS Deployment Verification",
    },
    {
        "id": "WRK-06",
        "requirement": "Distributed Worker VPS Deployment Verification",
        "assertion": "The config the Worker node actually loaded is the one the Panel assigned to it: every declared inbound matches on tag, protocol, port, transport, and security layer, the applied config declares outbounds, and the runtime directory, applied config, and settings file are private.",
        "topology": ["multi-node"],
        "promotion_target": "Distributed Worker VPS Deployment Verification",
    },
    {
        "id": "ACME-REJECT-ARB",
        "requirement": "Fail-closed local ACME test mode",
        "assertion": "Arbitrary ACME directory URLs are rejected by Master and Worker both outside and inside the test-only opt-in; only the pinned fixture endpoint and the Let's Encrypt allowlist are accepted.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Global Certbot Deploy Hook Ownership",
    },
    {
        "id": "GATE-BUDGET",
        "requirement": "Pre-push and pull-request acceptance gate",
        "assertion": "A run that exhausts the declared runtime budget before every case executed reports INCOMPLETE naming the unexecuted cases and cannot be converted into PASS.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Result Status Semantics",
    },
    {
        "id": "GATE-COVERAGE",
        "requirement": "Coverage completeness and error paths",
        "assertion": "An unmapped behavior, a behavior covered only on its happy path, or a case mapped to no behavior fails the coverage audit with the item named.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Result Status Semantics",
    },
    {
        "id": "GATE-PREPUSH",
        "requirement": "Pre-push and pull-request acceptance gate",
        "assertion": "The documented pre-push entrypoint runs both topologies with pinned fixtures and no live credentials and blocks a regressed change with its case IDs.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Result Status Semantics",
    },
    {
        "id": "GATE-DIVERGENCE",
        "requirement": "Live scenario parity",
        "assertion": "A live scenario without a catalog entry, a live-parity case executed by only one suite, or a topology count departing from 8/10 and 16/18/20 fails the divergence guard.",
        "topology": ["aio", "multi-node"],
        "promotion_target": "Result Status Semantics",
    },
    {
        "id": "MN-REVOKE",
        "requirement": "Real client data-plane verification",
        "assertion": "A cluster client's subscription is served and captured once both nodes' tuples have carried a payload from their own egress addresses, the documented revoke action rotates the credentials and the subscription path with the old path returning 404, and freshly started engines replaying the pre-revocation payload deliver nothing through either node while the controlled endpoint records none of their request ids.",
        "topology": ["multi-node"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    },
    {
        "id": "MN-OUTAGE",
        "requirement": "Failure injection and recovery",
        "assertion": "A subscription captured while the cluster is healthy carries a payload through the Worker, `systemctl stop gowave-node.service` on the Worker is observed by the Panel as that node offline while the Master stays connected and still delivers, the same captured payload is refused through the Worker, and after the unit is started again the node reconnects with its control plane established and the same subscription transfers through the Worker once more.",
        "topology": ["multi-node"],
        "promotion_target": "Negative Scenario and Fault Injection Tests",
    },
    {
        "id": "MN-RESTART",
        "requirement": "Failure injection and recovery",
        "assertion": "`systemctl restart gowave-node.service` on the Worker starts a new node process, leaves the unit active, and leaves the Panel's registry record unchanged in uuid, endpoint, assigned inbounds and recorded version with the node connected again, and the subscription captured before the restart transfers through the Worker without a client re-import or a resync.",
        "topology": ["multi-node"],
        "promotion_target": "Negative Scenario and Fault Injection Tests",
    },
    {
        "id": "MN-SSHKEY",
        "requirement": "Preflight SSH Trust and DNS Verification",
        "assertion": "Through the controller's own remote-finalize SSH operation, a known_hosts entry holding a key that is not the Worker's is refused by OpenSSH host-key verification before the remote command runs, and after the Worker rotates its host key the stale pin is refused the same way while re-pinning the new key lets the same command run and take its observable effect.",
        "topology": ["multi-node"],
        "promotion_target": "Preflight SSH Trust and DNS Verification",
    },
    {
        "id": "MN-SSH-DOWN",
        "requirement": "Failure injection and recovery",
        "assertion": "With `ssh.service` stopped on the Worker, the controller's remote-finalize operation is refused by the transport before the remote command runs, naming the connection failure rather than host-key verification, while the Worker's node unit stays active and the same captured subscription still carries a payload from the Worker's own data address; starting the daemon again lets the very operation that was refused run and remove the planted snapshot.",
        "topology": ["multi-node"],
        "promotion_target": "Negative Scenario and Fault Injection Tests",
    },
    {
        "id": "MN-VISION",
        "requirement": "Independent Optional Vision Domains",
        "assertion": "In each of the four per-node Vision combinations, every node is checked against its own Vision domain alone: a configured node declares exactly one Vision inbound and one disabled-free Panel host bound to it under its own name, holds a certificate covering that name that renews from this run's ACME directory, routes the name to its Vision inbound and runs that inbound in its applied config; an unconfigured node has none of those under its own name, so swapping the two nodes' Vision configuration fails.",
        "topology": ["multi-node"],
        "promotion_target": "Independent Optional Vision Domains",
    },
]

SCENARIO_RE = re.compile(r"^#### Scenario:\s*(.+?)\s*$")
REQUIREMENT_RE = re.compile(r"^### Requirement:\s*(.+?)\s*$")


def data_plane_cases() -> List[Dict[str, Any]]:
    """One Podman-first catalog entry per matrix tuple, generated from the matrix.

    The All-in-One matrix cases are not hand-written: the case id, the transport
    and the client come from the matrix, so a tuple the suite runs and a tuple the
    catalog advertises cannot drift apart. The optional Vision tuples are listed
    even though a Vision-less run does not execute them — a catalog is the set of
    cases a topology may run, and the run's own count case decides which of them
    the selected configuration owed.
    """
    data = matrix_data.load()
    entries: List[Dict[str, Any]] = []
    for inbound, client in matrix_data.tuples(data, vision=True):
        entries.append({
            "id": matrix_data.case_id(data, matrix_data.AIO, str(inbound["id"]), client),
            "requirement": "Real client data-plane verification",
            "assertion": (
                f"The {client} client consumes the Panel-issued {inbound['id']} outbound — "
                f"{inbound['protocol']} over {inbound['transport']} with the {inbound['security']} "
                "security layer — sends a unique payload through it, and the controlled endpoint "
                "echoes the request id and body digest while recording the installed host, not the "
                f"client, as the source, under the {inbound['id']} inbound's own SNI."
            ),
            "topology": ["aio"],
            "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
        })
    entries.append({
        "id": "AIO-MATRIX",
        "requirement": "Real client data-plane verification",
        "assertion": (
            "The executed positive data-plane cases are exactly the matrix tuples for the selected "
            "Vision configuration — 8 without the optional inbound and 10 with it — and a count that "
            "disagrees with the matrix, a declared case the matrix does not enumerate, or a tuple that "
            "produced no result fails the run instead of being counted as green."
        ),
        "topology": ["aio"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    })
    nodes = (data.get("topologies") or {}).get(matrix_data.MULTI_NODE, {}).get("nodes") or []
    for node in nodes:
        for inbound, client in matrix_data.tuples(data, vision=True):
            entries.append({
                "id": matrix_data.case_id(
                    data, matrix_data.MULTI_NODE, str(inbound["id"]), client, node=str(node),
                ),
                "requirement": "Real client data-plane verification",
                "assertion": (
                    f"The {client} client consumes the Panel-issued {inbound['id']} outbound of the "
                    f"{node} node — {inbound['protocol']} over {inbound['transport']} with the "
                    f"{inbound['security']} security layer — sends a unique payload through it, and the "
                    "controlled endpoint echoes the request id and body digest while recording that "
                    "node's own egress address, not the client's, under the SNI that node publishes for "
                    "the inbound. Both nodes serve the same transport/security pairs, so the case names "
                    "the node: a transfer that dialled the other node's name would prove the other node."
                ),
                "topology": ["multi-node"],
                "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
            })
    entries.append({
        "id": "MN-MATRIX",
        "requirement": "Real client data-plane verification",
        "assertion": (
            "The executed positive data-plane cases are exactly the matrix tuples of both nodes — "
            "each node contributing one case per inbound it was configured with times every client, "
            "so 16 without the optional inbound, 18 with Vision on one node and 20 with it on both — "
            "and a count that disagrees with the matrix, a node that never ran one of the clients, a "
            "declared case the matrix does not enumerate, or a tuple that produced no result fails "
            "the run instead of being counted as green."
        ),
        "topology": ["multi-node"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    })
    entries.append({
        "id": "MN-EGRESS",
        "requirement": "Non-bypassable node egress attribution",
        "assertion": (
            "The Master and the Worker own distinct egress identities, every matrix payload is "
            "recorded by the external endpoint under the identity of the node its case names, and "
            "a payload sent straight at the endpoint from the Control Machine or the pinned-engine "
            "client is refused with the denial recorded under that client's own source, so a "
            "client cannot manufacture the source evidence the data-plane cases rest on."
        ),
        "topology": ["multi-node"],
        "promotion_target": "Data Plane E2E Traffic Through All VPN Endpoints",
    })
    return entries


@dataclass
class LiveScenario:
    requirement: str
    title: str
    body: str

    @property
    def assertion(self) -> str:
        return normalize_assertion(self.body)

    @property
    def assertion_sha256(self) -> str:
        return hashlib.sha256(self.assertion.encode("utf-8")).hexdigest()


def normalize_assertion(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            if lines and lines[-1] != "":
                lines.append("")
            continue
        line = re.sub(r"^[-*]\s+", "", line)
        lines.append(line)
    return "\n".join(lines).strip()


def parse_live_spec(path: Path = LIVE_SPEC) -> List[LiveScenario]:
    scenarios: List[LiveScenario] = []
    requirement: Optional[str] = None
    title: Optional[str] = None
    body: List[str] = []

    def flush() -> None:
        nonlocal title, body
        if requirement and title:
            scenarios.append(LiveScenario(requirement, title, "\n".join(body).strip()))
        title = None
        body = []

    for line in path.read_text(encoding="utf-8").splitlines():
        req_match = REQUIREMENT_RE.match(line)
        if req_match:
            flush()
            requirement = req_match.group(1)
            continue
        scen_match = SCENARIO_RE.match(line)
        if scen_match:
            flush()
            title = scen_match.group(1)
            continue
        if line.startswith("#"):
            flush()
            continue
        if title is not None:
            body.append(line)
    flush()
    return scenarios


def classify(requirement: str, title: str) -> Tuple[str, Optional[str]]:
    key = (requirement, title)
    if key in LIVE_ONLY_SCENARIOS:
        return "live-only", LIVE_ONLY_SCENARIOS[key]
    if key in PARTIAL_SCENARIOS:
        return "partial", PARTIAL_SCENARIOS[key]
    return "container", None


_CONSTANT_CACHE: Dict[str, Dict[str, str]] = {}


def _module_constants(module: str) -> Dict[str, str]:
    """The string constants of a sibling module, read once per process."""
    if module not in _CONSTANT_CACHE:
        path = REPO_ROOT / "tools" / "podman_e2e" / f"{module}.py"
        if not path.is_file():
            _CONSTANT_CACHE[module] = {}
        else:
            _CONSTANT_CACHE[module] = _string_constants(ast.parse(path.read_text(encoding="utf-8")))
    return _CONSTANT_CACHE[module]


def _string_constants(tree: ast.Module) -> Dict[str, str]:
    """Module-level string constants, which is how a case id is spelled.

    Three spellings are read, because the suite uses all of them:
    `NAME = "..."`, the annotated `NAME: str = "..."`, and an alias such as
    `NGINX_CONFIG_CASE_ID = aio.NGX_CONFIG_CASE_ID` or `NAME = OTHER_NAME`.
    A missed spelling would be refused as a builder rather than resolved, which
    is safe but would hide the real case behind a wrong error.
    """
    aliases = _imported_modules(tree)
    pending: Dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            pending[node.target.id] = node.value
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    pending[target.id] = node.value

    def resolve(node: ast.AST, seen: Set[str]) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in constants:
                return constants[node.id]
            if node.id in pending and node.id not in seen:
                return resolve(pending[node.id], seen | {node.id})
            return None
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = aliases.get(node.value.id)
            if owner is None:
                return None
            return _module_constants(owner).get(node.attr)
        return None

    constants: Dict[str, str] = {}
    for _ in range(4):
        before = len(constants)
        for name, value in pending.items():
            if name in constants:
                continue
            resolved = resolve(value, {name})
            if resolved is not None:
                constants[name] = resolved
        if len(constants) == before:
            break
    return constants


def _imported_modules(tree: ast.Module) -> Dict[str, str]:
    """Local alias -> module name, for `budget.case_budget`-style callables.

    Both spellings this package uses are read: `from . import budget` and
    `from tools.podman_e2e import budget, aio`. Anything else — a stdlib alias,
    say — is not a module of this suite and is resolved as a local object.
    """
    alias: Dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        inside_package = node.module == "tools.podman_e2e" or (
            node.level == 1 and node.module is None
        )
        if not inside_package:
            continue
        for name in node.names:
            alias[name.asname or name.name] = name.name
    return alias


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted_name(node.value)
        return f"{head}.{node.attr}" if head else node.attr
    return ""


def _case_callable(run_argument: ast.AST) -> str:
    """The callable a `Case(...)` wraps, as the source spells it."""
    body: ast.AST = run_argument
    if isinstance(run_argument, ast.Lambda):
        body = run_argument.body
    if isinstance(body, ast.Call):
        body = body.func
    return _dotted_name(body)


def _case_nodes(tree: ast.Module) -> List[ast.Call]:
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "Case" and len(node.args) >= 3
    ]


def _dict_literal_keys(node: ast.Dict) -> Set[str]:
    return {key.value for key in node.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)}


def evidence_keys(function: ast.FunctionDef) -> List[str]:
    """The evidence keys a driver's own source records.

    Three shapes count, because they are the three the runner turns into a
    ``CaseResult.evidence`` entry: ``evidence["key"] = ...``, a dict literal
    assigned to ``evidence``, and a dict literal the driver returns. A key the
    driver stopped recording disappears from here, which is what lets the
    catalog statement be checked rather than believed.
    """
    keys: Set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) \
                and node.value.id == "evidence":
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                keys.add(node.slice.value)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            if any(isinstance(target, ast.Name) and target.id == "evidence" for target in node.targets):
                keys |= _dict_literal_keys(node.value)
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            keys |= _dict_literal_keys(node.value)
    return sorted(keys)


def _resolve_callable(
    topology: str, dotted: str, module_tree: ast.Module, aliases: Dict[str, str],
) -> Optional[Tuple[str, str]]:
    """Resolve a `Case` callable to (file stem, name) or None when it is not ours.

    A bare name and a `product.method` belong to the topology's own module; a
    `budget.case_budget` names another module of this package.
    """
    head, _, tail = dotted.partition(".")
    if tail and head in aliases:
        target = REPO_ROOT / "tools" / "podman_e2e" / f"{aliases[head]}.py"
        if not target.is_file():
            return None
        target_tree = ast.parse(target.read_text(encoding="utf-8"))
        names = {node.name for node in target_tree.body if isinstance(node, ast.FunctionDef)}
        return (aliases[head], tail) if tail in names else None
    if tail:
        classes = [node for node in module_tree.body if isinstance(node, ast.ClassDef)]
        for cls in classes:
            if any(isinstance(item, ast.FunctionDef) and item.name == tail for item in cls.body):
                return (DRIVER_MODULES[topology].stem, f"{cls.name}.{tail}")
        return None
    names = {node.name for node in module_tree.body if isinstance(node, ast.FunctionDef)}
    return (DRIVER_MODULES[topology].stem, head) if head in names else None


def _function_node(module_tree: ast.Module, name: str) -> Optional[ast.FunctionDef]:
    """The driver node for a resolved callable (`Class.method` resolves to the method)."""
    if "." in name:
        _, _, method = name.partition(".")
        for cls in module_tree.body:
            if isinstance(cls, ast.ClassDef):
                for item in cls.body:
                    if isinstance(item, ast.FunctionDef) and item.name == method:
                        return item
        return None
    for node in module_tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def matrix_driven_ids(topology: str) -> Set[str]:
    """The case ids the matrix-driven builders mint, taken from the catalog's own rows."""
    return {
        entry["id"] for entry in data_plane_cases()
        if entry["topology"] == [topology] and "-DP-" in entry["id"]
    }


def run_starts(path: Path = REPO_ROOT / "tools" / "podman_e2e" / "topology.py") -> List[Dict[str, Any]]:
    """The start sequence a run performs, read from the topology's own `create()`.

    A per-case fixture list cannot be derived from a driver's source: a case
    consumes a fixture through an endpoint or a container, not a declared
    dependency, so `AIO-NEG-DEST` reads the echo endpoint through
    `endpoint_records` without naming any echo attribute. Nor can the fixtures
    be told apart from the rest of the contour by a syntactic marker, which is
    why this records the whole sequence with the markers it does have instead of
    a guessed classification: the client container is started with
    `image_alias=FIXTURE_IMAGE`, so that marker does not separate the
    `dns`/`echo` fixtures from it, and `target`, `untrusted_client` and `worker`
    carry no marker at all. What the source does prove is which steps
    `create()` performs, and that is what is recorded.
    """
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    aliases = _imported_modules(tree)
    acme_modules = {alias for alias, module in aliases.items() if module == "acme_fixture"}
    steps: Dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("_start_"):
            steps[node.name[len("_start_"):]] = node

    created: Set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name == "create"):
            continue
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                name = _dotted_name(call.func)
                if name.startswith("self._start_"):
                    created.add(name[len("self._start_"):])

    starts: List[Dict[str, Any]] = []
    for step in sorted(created):
        body = steps.get(step)
        if body is None:
            raise CatalogError(f"topology starts {step!r}, which has no _start_{step} body to read")
        starts.append({
            "step": step,
            "started_by": _display(path),
            "scope": "run",
            "fixture_image": any(
                keyword.arg == "image_alias"
                and isinstance(keyword.value, ast.Name) and keyword.value.id == "FIXTURE_IMAGE"
                for call in ast.walk(body) if isinstance(call, ast.Call)
                for keyword in call.keywords
            ),
            "acme_module": any(
                isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                and node.value.id in acme_modules
                for node in ast.walk(body)
            ),
        })
    return starts


def _run_start_errors(catalog: Dict[str, Any]) -> List[str]:
    """The catalog's start inventory is the topology's own `create()` sequence."""
    errors: List[str] = []
    recorded = catalog.get("run_starts")
    if not isinstance(recorded, list) or not recorded:
        errors.append("the catalog records no run_starts inventory, so a run's start sequence is unstated")
        return errors
    derived = {entry["step"]: entry for entry in run_starts()}
    stated: Dict[str, Dict[str, Any]] = {}
    for entry in recorded:
        step = entry.get("step")
        if step in stated:
            errors.append(f"start step {step!r} is recorded twice")
        stated[step] = entry
        if step not in derived:
            errors.append(f"start step {step!r} is recorded, but no topology `create()` performs it")
            continue
        for field_name in ("started_by", "scope", "fixture_image", "acme_module"):
            if entry.get(field_name) != derived[step][field_name]:
                errors.append(
                    f"start step {step!r}: {field_name} is {entry.get(field_name)!r}, "
                    f"the topology says {derived[step][field_name]!r}"
                )
    for step in sorted(set(derived) - set(stated)):
        errors.append(f"start step {step!r} is performed by the topology and not recorded")
    for case in catalog.get("cases", []):
        if "fixtures" in case:
            errors.append(
                f"{case.get('id')}: a per-case fixtures list cannot be derived from the driver, "
                "so it is refused rather than guessed; the run-level sequence is `run_starts`"
            )
    return errors


def driver_registry() -> Dict[str, Dict[str, Dict[str, Any]]]:
    """case id -> topology -> {driver, evidence}, read from the code that runs it.

    Raises ``CatalogError`` when a `Case` names a callable this package does not
    define, or when a builder mints ids outside the closed matrix-driven list:
    both are cases the catalog could not check, so they are refused here rather
    than recorded as if they had been.
    """
    registry: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for topology, path in DRIVER_MODULES.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = _string_constants(tree)
        aliases = _imported_modules(tree)

        def record(case_id: str, dotted: str) -> None:
            resolved = _resolve_callable(topology, dotted, tree, aliases)
            if resolved is None:
                raise CatalogError(
                    f"{topology}: Case({case_id!r}) names {dotted!r}, which this package does not define"
                )
            module, name = resolved
            function = _function_node(tree, name) if module == path.stem else _function_node(
                ast.parse((REPO_ROOT / "tools" / "podman_e2e" / f"{module}.py").read_text(encoding="utf-8")),
                name,
            )
            if function is None:
                raise CatalogError(f"{topology}: {module}:{name} has no function body to read")
            registry.setdefault(case_id, {})[topology] = {
                "driver": f"{module}:{name}",
                "evidence": evidence_keys(function),
            }

        for node in _case_nodes(tree):
            first = node.args[0]
            dotted = _case_callable(node.args[2])
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                record(first.value, dotted)
            elif isinstance(first, ast.Name) and first.id in constants:
                record(constants[first.id], dotted)
            elif isinstance(first, ast.Attribute) and isinstance(first.value, ast.Name):
                owner = _imported_modules(tree).get(first.value.id)
                sibling = REPO_ROOT / "tools" / "podman_e2e" / f"{owner}.py"
                if owner is None or not sibling.is_file():
                    raise CatalogError(f"{topology}: Case id {ast.unparse(first)} has no resolvable constant")
                sibling_constants = _string_constants(ast.parse(sibling.read_text(encoding="utf-8")))
                if first.attr not in sibling_constants:
                    raise CatalogError(f"{topology}: Case id {ast.unparse(first)} is not a literal constant")
                record(sibling_constants[first.attr], dotted)
            else:
                builder = dotted or ast.unparse(first)
                if (path.stem, builder) not in MATRIX_DRIVEN_BUILDERS:
                    raise CatalogError(
                        f"{topology}: Case({ast.unparse(first)!r}) mints ids this catalog cannot check; "
                        f"add {builder!r} to MATRIX_DRIVEN_BUILDERS with the ids it produces"
                    )

        for builder in sorted(name for module, name in MATRIX_DRIVEN_BUILDERS if module == path.stem):
            function = _function_node(tree, builder)
            if function is None:
                raise CatalogError(f"{topology}: the declared matrix-driven builder {builder!r} is gone")
            for case_id in sorted(matrix_driven_ids(topology)):
                registry.setdefault(case_id, {})[topology] = {
                    "driver": f"{path.stem}:{builder}",
                    "evidence": evidence_keys(function),
                }
    return registry


# Some live-parity scenarios are witnessed by a container case that carries a
# different id: DP-01 quantifies over every active endpoint and client, and the
# case that quantifies over exactly those tuples is AIO-MATRIX / MN-MATRIX. Which
# container case witnesses a given live sentence is a judgement the source cannot
# make for us, so it is declared here — and pinned from both sides: the named case
# must be one the code builds for that topology, and the evidence written into the
# catalog entry is read out of that case rather than typed by hand.
LIVE_PARITY_OBSERVERS: Dict[str, Dict[str, str]] = {
    "DP-01": {"aio": "AIO-MATRIX", "multi-node": "MN-MATRIX"},
}


def apply_implementations(cases: List[Dict[str, Any]], registry: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
    """Write the code's own implementation facts into the catalog entries."""
    known = {case["id"] for case in cases}
    unknown = sorted(set(registry) - known)
    if unknown:
        raise CatalogError(
            "the code runs cases the catalog does not define: " + ", ".join(unknown)
        )
    undeclared = sorted(set(LIVE_PARITY_OBSERVERS) - known)
    if undeclared:
        raise CatalogError(
            "an observer is mapped to a live scenario the catalog does not define: "
            + ", ".join(undeclared)
        )
    for case in cases:
        drivers = {
            topology: {**facts, "evidence": list(facts.get("evidence") or [])}
            for topology, facts in sorted(registry.get(case["id"], {}).items())
        }
        for topology, observer in sorted(LIVE_PARITY_OBSERVERS.get(case["id"], {}).items()):
            if topology in drivers:
                raise CatalogError(
                    f"{case['id']}: it runs as a case and is also mapped to the observer "
                    f"{observer!r} in {topology}, so one of the two is stale"
                )
            facts = registry.get(observer, {}).get(topology)
            if facts is None:
                raise CatalogError(
                    f"{case['id']}: the declared {topology} observer {observer!r} is not a Case "
                    "the code builds for that topology"
                )
            # A fresh list per entry: two entries sharing one list would be dumped
            # as a YAML anchor and alias, which reads as a link nobody declared.
            drivers[topology] = {
                **facts,
                "evidence": list(facts.get("evidence") or []),
                "case": observer,
            }
        case["drivers"] = drivers
        if drivers:
            case["driver_status"] = "implemented"
        elif case.get("driver_status") == "implemented":
            case["driver_status"] = "planned"


def build_catalog(spec_path: Path = LIVE_SPEC) -> Dict[str, Any]:
    scenarios = parse_live_spec(spec_path)
    counters: Dict[str, int] = {}
    cases: List[Dict[str, Any]] = []
    for scenario in scenarios:
        prefix = REQUIREMENT_PREFIX.get(scenario.requirement)
        if not prefix:
            raise ValueError(f"No stable ID prefix for requirement: {scenario.requirement!r}")
        counters[prefix] = counters.get(prefix, 0) + 1
        case_id = f"{prefix}-{counters[prefix]:02d}"
        environment, note = classify(scenario.requirement, scenario.title)
        if environment == "live-only":
            runs_in = ["live"]
            state = "live-only"
        elif environment == "partial":
            runs_in = ["podman", "live"]
            state = "live-parity"
        else:
            runs_in = ["podman", "live"]
            state = "live-parity"
        topologies = ["multi-node"] if scenario.requirement in MULTI_NODE_ONLY else ["aio", "multi-node"]
        case: Dict[str, Any] = {
            "id": case_id,
            "requirement": scenario.requirement,
            "live_scenario": scenario.title,
            "assertion": scenario.assertion,
            "assertion_sha256": scenario.assertion_sha256,
            "runs_in": runs_in,
            "state": state,
            "environment": environment,
            "topology": topologies,
            "gate": "pre-push",
            "driver_status": "planned" if "podman" in runs_in else "not-applicable",
            "drivers": {},
        }
        if note:
            key = "partial_split" if environment == "partial" else "live_only_reason"
            case[key] = note
        case["promotion_target"] = None
        cases.append(case)

    extras = PODMAN_FIRST_CASES + data_plane_cases()
    for extra in extras:
        cases.append({
            "id": extra["id"],
            "requirement": extra["requirement"],
            "live_scenario": None,
            "assertion": extra["assertion"],
            "assertion_sha256": hashlib.sha256(extra["assertion"].encode("utf-8")).hexdigest(),
            "runs_in": ["podman"],
            "state": "incubating",
            "environment": "container",
            "topology": extra["topology"],
            "gate": "pre-push",
            "driver_status": "planned",
            "drivers": {},
            "promotion_target": extra["promotion_target"],
        })

    apply_implementations(cases, driver_registry())

    counts = {
        "live_total": len(scenarios),
        "container": sum(1 for c in cases if c["live_scenario"] and c["environment"] == "container"),
        "partial": sum(1 for c in cases if c["environment"] == "partial"),
        "live_only": sum(1 for c in cases if c["environment"] == "live-only"),
        "podman_first": len(extras),
        "total": len(cases),
    }
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    return {
        "version": 1,
        "schema": "gowave-case-catalog/v1",
        "live_spec": str(spec_path.relative_to(REPO_ROOT)),
        "live_spec_sha256": spec_sha,
        "counts": counts,
        "run_starts": run_starts(),
        "expected_positive_case_counts": {
            "aio": {"vision_disabled": 8, "vision_enabled": 10},
            "multi-node": {
                "vision_neither": 16,
                "vision_one_node": 18,
                "vision_both": 20,
            },
        },
        "cases": cases,
    }


def load_catalog(path: Path = CATALOG_PATH) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def write_catalog(catalog: Dict[str, Any], path: Path = CATALOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )


def validate_catalog(catalog: Dict[str, Any], spec_path: Path = LIVE_SPEC) -> List[str]:
    errors: List[str] = []
    scenarios = parse_live_spec(spec_path)
    by_live: Dict[Tuple[str, str], Dict[str, Any]] = {}
    ids: Dict[str, Dict[str, Any]] = {}
    for case in catalog.get("cases", []):
        case_id = case.get("id")
        if not case_id:
            errors.append("Catalog case without an id")
            continue
        if case_id in ids:
            errors.append(f"Duplicate case id: {case_id}")
        ids[case_id] = case
        if case.get("live_scenario"):
            key = (case.get("requirement", ""), case["live_scenario"])
            if key in by_live:
                errors.append(f"Duplicate live scenario mapping: {key[0]} / {key[1]}")
            by_live[key] = case

    for scenario in scenarios:
        key = (scenario.requirement, scenario.title)
        case = by_live.get(key)
        if case is None:
            errors.append(f"Live scenario has no catalog entry: {scenario.requirement} / {scenario.title}")
            continue
        if case.get("assertion_sha256") != scenario.assertion_sha256:
            errors.append(f"Assertion drift for {case.get('id')}: catalog text differs from the live spec")
        if case.get("environment") == "live-only" and case.get("runs_in") != ["live"]:
            errors.append(f"{case.get('id')}: live-only case must only run in the live suite")
        if case.get("environment") == "partial" and not case.get("partial_split"):
            errors.append(f"{case.get('id')}: partial case must state its split")
        if case.get("environment") == "live-only" and not case.get("live_only_reason"):
            errors.append(f"{case.get('id')}: live-only case must state its reason")

    for key, case in by_live.items():
        if key not in {(s.requirement, s.title) for s in scenarios}:
            errors.append(f"Catalog entry has no live scenario: {case.get('id')} / {key[1]}")

    counts = catalog.get("counts", {})
    expected = {
        "live_total": 125,
        "container": 115,
        "partial": 8,
        "live_only": 2,
    }
    for field_name, expected_value in expected.items():
        if counts.get(field_name) != expected_value:
            errors.append(
                f"Parity count drift: {field_name}={counts.get(field_name)} expected {expected_value}"
            )

    for case in catalog.get("cases", []):
        if not case.get("live_scenario") and case.get("runs_in") != ["podman"]:
            errors.append(f"{case.get('id')}: Podman-first case must run only in Podman")
        if not case.get("live_scenario") and not case.get("promotion_target"):
            errors.append(f"{case.get('id')}: Podman-first case requires a promotion target")
    errors.extend(_implementation_errors(catalog))
    errors.extend(_run_start_errors(catalog))
    return errors


def _implementation_errors(catalog: Dict[str, Any]) -> List[str]:
    """The code and the catalog must name each other's cases, both ways."""
    errors: List[str] = []
    registry = driver_registry()
    cases = catalog.get("cases", [])
    by_id = {case.get("id"): case for case in cases}
    for case in cases:
        case_id = case.get("id")
        status = case.get("driver_status")
        drivers = case.get("drivers") or {}
        if status not in DRIVER_STATUSES:
            errors.append(f"{case_id}: driver_status {status!r} is not one of {list(DRIVER_STATUSES)}")
        if status == "implemented" and not drivers:
            errors.append(f"{case_id}: implemented, but names no driver")
        if status != "implemented" and drivers:
            errors.append(f"{case_id}: driver_status {status!r}, but names drivers")
        for topology, facts in sorted(drivers.items()):
            observed = facts.get("case") or case_id
            expected = (registry.get(observed) or {}).get(topology)
            if expected is None:
                errors.append(
                    f"{case_id}: the {topology} driver {facts.get('driver')!r} is not a Case the code builds"
                )
                continue
            if facts.get("case") != LIVE_PARITY_OBSERVERS.get(case_id, {}).get(topology):
                errors.append(
                    f"{case_id} / {topology}: the observer is {facts.get('case')!r}, "
                    f"the declaration says {LIVE_PARITY_OBSERVERS.get(case_id, {}).get(topology)!r}"
                )
            if topology not in case.get("topology", []):
                errors.append(f"{case_id}: driven in {topology}, which its topology list does not name")
            if facts.get("driver") != expected["driver"]:
                errors.append(
                    f"{case_id} / {topology}: driver {facts.get('driver')!r} is not the one the code wraps, "
                    f"{expected['driver']!r}"
                )
            if list(facts.get("evidence") or []) != expected["evidence"]:
                errors.append(
                    f"{case_id} / {topology}: the evidence keys differ from what the driver records: "
                    f"{facts.get('evidence')} != {expected['evidence']}"
                )
    for case_id, topologies in sorted(registry.items()):
        entry = by_id.get(case_id)
        if entry is None:
            errors.append(f"the code runs {case_id}, which the catalog does not define")
            continue
        if entry.get("driver_status") != "implemented":
            errors.append(f"{case_id}: the code runs it, the catalog says {entry.get('driver_status')!r}")
        for topology in sorted(topologies):
            if topology not in (entry.get("drivers") or {}):
                errors.append(f"{case_id}: the code drives it in {topology}, the catalog does not name it")
    return errors


def require_executable(cases: Iterable[Tuple[str, str]]) -> None:
    """Refuse a run whose case list is not what the catalog declares.

    The runner builds its cases in Python and the catalog states which of them
    exist; without this check a case could run under an id no audit knows. It is
    called before the install, so a disagreement costs no product time.
    """
    catalog = load_catalog()
    by_id = {case.get("id"): case for case in catalog.get("cases", [])}
    problems: List[str] = []
    for case_id, topology in cases:
        entry = by_id.get(case_id)
        if entry is None:
            problems.append(f"{case_id}: no catalog entry")
        elif entry.get("driver_status") != "implemented":
            problems.append(f"{case_id}: the catalog says {entry.get('driver_status')!r}")
        elif topology not in (entry.get("drivers") or {}):
            problems.append(f"{case_id}: the catalog names no {topology} driver")
    if problems:
        raise CatalogError(
            "the case list does not match tests/cases/catalog.yaml: " + "; ".join(problems)
        )


def executable_gaps(catalog: Dict[str, Any], suite: str = "podman") -> List[str]:
    """Return cases that claim to run in a suite but have no implemented driver."""
    gaps = []
    for case in catalog.get("cases", []):
        if suite in case.get("runs_in", []) and not case.get("drivers"):
            gaps.append(f"{case['id']} ({case.get('environment')})")
    return gaps


def _display(path: Path) -> str:
    """A path as the repository names it, or as it stands when it is outside."""
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def load_behaviors(path: Path = BEHAVIORS_PATH) -> Dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def coverage_audit(
    catalog: Dict[str, Any],
    behaviors_path: Path = BEHAVIORS_PATH,
    matrix_path: Path = MATRIX_PATH,
) -> List[str]:
    """Judge the behaviour inventory against the catalog it claims to cover.

    The inventory is a partition, not a summary: every catalog case is named by
    exactly one behaviour, and every behaviour states where its cases run and
    which tier blocks on them. A behaviour with no case is an empty promise; a
    behaviour whose only cases establish its happy path has no measured failure
    behaviour; a case no behaviour names is a guarantee nobody wrote down.
    """
    behaviors_path = Path(behaviors_path)
    if not behaviors_path.exists():
        return [f"Behavior inventory is missing: {_display(behaviors_path)}"]
    try:
        inventory = load_behaviors(behaviors_path)
    except yaml.YAMLError as exc:
        return [f"Behavior inventory is not valid YAML: {_display(behaviors_path)}: {exc}"]
    if not isinstance(inventory, dict):
        return [f"Behavior inventory must be a mapping: {_display(behaviors_path)}"]

    errors: List[str] = []
    topology_manifest = (yaml.safe_load(Path(matrix_path).read_text(encoding="utf-8")) or {}).get(
        "topologies"
    ) or {}
    gated_by = {
        str(name): {str(tier) for tier in (entry or {}).get("gate") or []}
        for name, entry in topology_manifest.items()
    }

    schema = inventory.get("schema")
    if schema != BEHAVIOR_SCHEMA:
        errors.append(
            f"Behavior inventory schema is {schema!r}, expected {BEHAVIOR_SCHEMA!r}"
        )
    declared_areas = inventory.get("areas")
    if not isinstance(declared_areas, list):
        errors.append("Behavior inventory declares no areas")
        declared_areas = []
    for area in declared_areas:
        if area not in BEHAVIOR_AREAS:
            errors.append(f"Behavior inventory declares unknown area {area!r}")
    for area in BEHAVIOR_AREAS:
        if area not in declared_areas:
            errors.append(f"Behavior inventory does not declare area {area}")

    cases = inventory.get("behaviors")
    if not isinstance(cases, list) or not cases:
        return errors + ["Behavior inventory names no behavior"]

    by_id: Dict[str, Dict[str, Any]] = {
        str(case.get("id")): case for case in catalog.get("cases", []) if case.get("id")
    }
    owners: Dict[str, List[str]] = {}
    covered_areas: Set[str] = set()
    seen_names: Set[str] = set()

    def reachable(case_ids: Iterable[str]) -> Set[str]:
        found: Set[str] = set()
        for case_id in case_ids:
            found |= set((by_id.get(case_id) or {}).get("topology") or [])
        return found

    for index, behavior in enumerate(cases):
        if not isinstance(behavior, dict):
            errors.append(f"Behavior #{index + 1} is not a mapping")
            continue
        name = behavior.get("name")
        if not isinstance(name, str) or not name.strip():
            name = f"<unnamed #{index + 1}>"
        elif name in seen_names:
            errors.append(f"Duplicate behavior name: {name}")
        seen_names.add(name)

        area = behavior.get("area")
        if area not in BEHAVIOR_AREAS:
            errors.append(f"Behavior {name} declares unknown area {area!r}")
        else:
            covered_areas.add(area)

        gate = behavior.get("gate")
        if not isinstance(gate, str) or not gate.strip():
            errors.append(f"Behavior {name} declares no gate")
            gate = None

        declared = behavior.get("topology")
        if not isinstance(declared, list) or not declared:
            errors.append(f"Behavior {name} declares no topology")
            declared = []
        elif len({str(item) for item in declared}) != len(declared):
            errors.append(f"Behavior {name} declares a topology more than once")
        declared_topologies = {str(item) for item in declared}
        for topology in sorted(declared_topologies):
            if topology not in gated_by:
                errors.append(
                    f"Behavior {name} declares unknown topology {topology}"
                )

        happy = behavior.get("cases")
        failure = behavior.get("error_paths")
        if not isinstance(happy, list):
            errors.append(f"Behavior {name} names no cases")
            happy = []
        if not isinstance(failure, list):
            errors.append(f"Behavior {name} names no error paths")
            failure = []
        if not happy:
            errors.append(f"Behavior has no case: {name}")
        if not failure:
            errors.append(f"Behavior has no error-path case: {name}")

        named_here: Set[str] = set()
        establishing: List[str] = []
        for case_id in list(happy) + list(failure):
            if not isinstance(case_id, str):
                errors.append(f"Behavior {name} names a case that is not an id: {case_id!r}")
                continue
            if case_id in named_here:
                errors.append(f"Behavior {name} names case {case_id} more than once")
                continue
            named_here.add(case_id)
            case = by_id.get(case_id)
            if case is None:
                errors.append(f"Behavior {name} references unknown case {case_id}")
                continue
            owners.setdefault(case_id, []).append(name)
            if gate and case.get("gate") != gate:
                errors.append(
                    f"Behavior {name} declares gate {gate} but case {case_id} "
                    f"is gated {case.get('gate')}"
                )
        establishing = [item for item in happy if isinstance(item, str) and item in by_id]

        reached = reachable(named_here)
        for topology in sorted(declared_topologies - reached):
            errors.append(
                f"Behavior {name} declares topology {topology} that none of its cases runs in"
            )
        for topology in sorted(reachable(establishing) - declared_topologies):
            errors.append(
                f"Behavior {name} does not declare topology {topology} where its cases are established"
            )
        if gate:
            for topology in sorted(declared_topologies & set(gated_by)):
                if gate not in gated_by[topology]:
                    errors.append(
                        f"Behavior {name} declares gate {gate} for {topology}, which "
                        f"{_display(matrix_path)} does not gate that way"
                    )

    for case_id in sorted(by_id):
        claimants = owners.get(case_id) or []
        if not claimants:
            errors.append(f"Case is mapped to no behavior: {case_id}")
        elif len(claimants) > 1:
            errors.append(
                f"Case is mapped by more than one behavior: {case_id} "
                f"({', '.join(sorted(claimants))})"
            )

    for area in BEHAVIOR_AREAS:
        if area not in covered_areas:
            errors.append(f"Area has no behavior: {area}")
    return errors


def render_behaviors(catalog: Dict[str, Any], inventory: Dict[str, Any]) -> str:
    """The inventory for a reader who will not open the YAML."""
    behaviors = [entry for entry in inventory.get("behaviors") or [] if isinstance(entry, dict)]
    named = {
        case_id
        for entry in behaviors
        for case_id in (entry.get("cases") or []) + (entry.get("error_paths") or [])
    }
    lines = [
        "<!-- Generated by `python3 -m tools.podman_e2e.catalog behaviors --write`. -->",
        "",
        "# Podman acceptance behaviour inventory",
        "",
        "Rendered from `tests/cases/behaviors.yaml`; do not edit by hand. Every row",
        "names the cases that establish the behaviour and the cases that exercise",
        "its error paths, the topologies it is proven in and the gate tier that",
        "blocks on it. The topology column lists every topology the row's cases",
        "apply to, so which case runs where is `tests/cases/catalog.yaml`'s own",
        "per-case `topology`, not this column.",
        "`python3 -m tools.podman_e2e.catalog check` fails on a",
        "behaviour with no case, a behaviour covered only on its happy path, an",
        "area the delta spec names but no entry covers, and a case no behaviour",
        "names (an orphan) or two behaviours claim.",
        "",
        f"Behaviours: {len(behaviors)} across {len(BEHAVIOR_AREAS)} areas, naming "
        f"{len(named)} of {len(catalog.get('cases') or [])} catalog cases.",
        "",
        "| Area | Behaviours | Cases | Error-path cases |",
        "|---|---:|---:|---:|",
    ]
    for area in BEHAVIOR_AREAS:
        entries = [entry for entry in behaviors if entry.get("area") == area]
        happy = sum(len(entry.get("cases") or []) for entry in entries)
        failure = sum(len(entry.get("error_paths") or []) for entry in entries)
        lines.append(f"| {area} | {len(entries)} | {happy} | {failure} |")
    for area in BEHAVIOR_AREAS:
        entries = [entry for entry in behaviors if entry.get("area") == area]
        if not entries:
            continue
        lines.extend(
            [
                "",
                f"## {area}",
                "",
                "| Behaviour | Topologies | Gate | Cases | Error paths |",
                "|---|---|---|---|---|",
            ]
        )
        for entry in entries:
            topologies = ", ".join(str(item) for item in entry.get("topology") or [])
            cases = ", ".join(f"`{case_id}`" for case_id in entry.get("cases") or [])
            failure = ", ".join(f"`{case_id}`" for case_id in entry.get("error_paths") or [])
            lines.append(
                f"| {entry.get('name')} | {topologies} | {entry.get('gate')} "
                f"| {cases} | {failure} |"
            )
    lines.append("")
    return "\n".join(lines)


def report_problems(
    catalog: Dict[str, Any],
    behaviors_path: Path = BEHAVIORS_PATH,
    report_path: Optional[Path] = None,
) -> List[str]:
    """The rendered inventory must be the text the YAML renders to."""
    behaviors_path = Path(behaviors_path)
    path = Path(BEHAVIOR_REPORT_PATH if report_path is None else report_path)
    if not behaviors_path.exists():
        return []
    try:
        inventory = load_behaviors(behaviors_path)
    except yaml.YAMLError:
        return []
    if not isinstance(inventory, dict):
        return []
    expected = render_behaviors(catalog, inventory)
    if not path.exists():
        return [
            f"{_display(path)} is missing: run "
            f"`python3 -m tools.podman_e2e.catalog behaviors --write`"
        ]
    if path.read_text(encoding="utf-8") != expected:
        return [
            f"{_display(path)} is not what the behaviour inventory renders to: run "
            f"`python3 -m tools.podman_e2e.catalog behaviors --write` and commit the result"
        ]
    return []


def executed_ids_from_results(paths: Iterable[Path]) -> set:
    executed = set()
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for case in data.get("cases", []):
            if case.get("status") not in ("SKIP", None):
                executed.add(case.get("id"))
    return executed


def divergence_guard(
    catalog_path: Path = CATALOG_PATH,
    spec_path: Path = LIVE_SPEC,
    podman_results: Sequence[Path] = (),
    live_results: Sequence[Path] = (),
) -> List[str]:
    catalog = load_catalog(catalog_path)
    errors = validate_catalog(catalog, spec_path)
    if errors:
        return errors

    matrix = yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))
    expected = catalog.get("expected_positive_case_counts", {})
    matrix_expected = matrix.get("topologies", {})
    for topology, values in expected.items():
        matrix_counts = matrix_expected.get(topology, {}).get("positive_case_counts", {})
        if set(values.values()) != set(matrix_counts.values()):
            errors.append(
                f"Positive case counts diverge between catalog and matrix for {topology}: "
                f"{sorted(values.values())} vs {sorted(matrix_counts.values())}"
            )

    by_id = {case["id"]: case for case in catalog.get("cases", [])}
    podman_executed = executed_ids_from_results(podman_results)
    live_executed = executed_ids_from_results(live_results)
    for case_id in podman_executed:
        case = by_id.get(case_id)
        if case is None:
            errors.append(f"Podman run executed an unknown case: {case_id}")
        elif "podman" not in case.get("runs_in", []):
            errors.append(f"Podman ran a live-only case: {case_id}")
    for case_id in live_executed:
        case = by_id.get(case_id)
        if case is None:
            errors.append(f"Live run executed an unknown case: {case_id}")
        elif case.get("state") == "live-parity" and case_id not in podman_executed:
            errors.append(f"live-parity case was not executed by the Podman suite: {case_id}")
    return errors


def render_parity(catalog: Dict[str, Any]) -> str:
    groups: Dict[str, Dict[str, int]] = {}
    for case in catalog["cases"]:
        if not case.get("live_scenario"):
            continue
        group = groups.setdefault(case["requirement"], {"container": 0, "partial": 0, "live-only": 0})
        group[case["environment"]] += 1
    lines = [
        "# Podman / Live parity inventory",
        "",
        "Generated from `tests/cases/catalog.yaml`; do not edit by hand.",
        "",
        f"Live scenarios: {catalog['counts']['live_total']} — "
        f"container {catalog['counts']['container']}, "
        f"partial {catalog['counts']['partial']}, "
        f"live-only {catalog['counts']['live_only']}.",
        "",
        "| Live requirement group | Scenarios | Container | Partial | Live-only |",
        "|---|---:|---:|---:|---:|",
    ]
    for requirement in REQUIREMENT_PREFIX:
        if requirement not in groups:
            continue
        counts = groups[requirement]
        total = sum(counts.values())
        lines.append(
            f"| {requirement} | {total} | {counts['container']} | {counts['partial']} | {counts['live-only']} |"
        )
    lines.extend(["", "## Partial splits", ""])
    for case in catalog["cases"]:
        if case.get("environment") == "partial":
            lines.append(f"- **{case['id']}** — {case.get('partial_split')}")
    lines.extend(["", "## Live-only exclusions", ""])
    for case in catalog["cases"]:
        if case.get("environment") == "live-only":
            lines.append(f"- **{case['id']}** — {case.get('live_only_reason')}")
    lines.extend(["", "## Podman-first cases awaiting live promotion", ""])
    for case in catalog["cases"]:
        if case.get("state") == "incubating":
            lines.append(f"- **{case['id']}** — promotion target: {case.get('promotion_target')}")
    lines.append("")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("generate", help="Regenerate catalog.yaml and PARITY.md from the live spec")
    sub.add_parser("check", help="Validate catalog parity, counts, coverage, and the rendered inventory")
    sub.add_parser("gaps", help="List cases without an implemented driver")
    behaviors = sub.add_parser("behaviors", help="Render the checked-in behaviour inventory")
    behaviors.add_argument(
        "--write", action="store_true",
        help=f"write {_display(BEHAVIOR_REPORT_PATH)} instead of printing it",
    )
    args = parser.parse_args(argv)

    if args.command == "generate":
        catalog = build_catalog()
        write_catalog(catalog)
        PARITY_PATH.write_text(render_parity(catalog), encoding="utf-8")
        print(f"Wrote {CATALOG_PATH.relative_to(REPO_ROOT)} and {PARITY_PATH.relative_to(REPO_ROOT)}")
        return 0

    if args.command == "check":
        catalog = load_catalog()
        errors = validate_catalog(catalog)
        errors.extend(coverage_audit(catalog))
        errors.extend(report_problems(catalog))
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        print("CATALOG: PASS")
        return 0

    if args.command == "behaviors":
        catalog = load_catalog()
        inventory = load_behaviors()
        if not args.write:
            print(render_behaviors(catalog, inventory), end="")
            return 0
        BEHAVIOR_REPORT_PATH.write_text(render_behaviors(catalog, inventory), encoding="utf-8")
        print(f"Wrote {_display(BEHAVIOR_REPORT_PATH)}")
        return 0

    if args.command == "gaps":
        catalog = load_catalog()
        gaps = executable_gaps(catalog)
        for gap in gaps:
            print(gap)
        return 0 if not gaps else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
