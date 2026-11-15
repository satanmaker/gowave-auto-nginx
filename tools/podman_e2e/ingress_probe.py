#!/usr/bin/env python3
"""Report what the host a proxy request must reach can see of that request.

Three scopes, each answering one question the product's own records cannot:

``packets``
    Count inbound TCP segments addressed to one port and report the addresses
    that sent them. The filter names the destination port and nothing else — not
    a source address, because a carrier NAT or a split tunnel can make the
    address a client believes it has wrong, and not an interface, because a
    client may reach the host over any of them. Attribution therefore happens
    after the fact, from the addresses the kernel actually delivered.

``hold``
    Open one TCP connection to each host of the case, say nothing on it, and
    report the local port of each. It connects to the same name the proxy
    request dials, over the same network, so the address a host sees here is the
    address that host has to see on the request.

``peer``
    Report the source address this host's own kernel has for one of those
    connections, named only by its two ports. The caller never tells the host
    which address to expect, which is what keeps this a report rather than an
    echo of the runner's own constant.

Nothing here writes a file, and no scope keeps a packet's payload: ``packets``
prints counts per source address plus the kernel's own drop count, ``peer``
prints one address, ``hold`` prints ports. A summary the running process prints
cannot leave a PCAP behind, and an account kept per source address cannot be
replaced by an interface counter.

Errors are named rather than described, because the caller has to tell evidence
that is *unavailable* from evidence that says the request reached the wrong host:
the first is INCOMPLETE and the second is a FAIL, and neither may be inferred
from the other.

    python3 tools/podman_e2e/ingress_probe.py --scope packets --port 443
    python3 tools/podman_e2e/ingress_probe.py --scope hold --peer local=panel.example:22
    python3 tools/podman_e2e/ingress_probe.py --scope peer --port 22 --remote-port 45123
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import select
import socket
import struct
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ``SOCK_RAW`` on ``AF_PACKET`` needs ``CAP_NET_RAW``; a container without it
# reports that instead of an empty capture, because an empty capture on both
# hosts is indistinguishable from a request that never arrived.
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
IPPROTO_TCP = 6
# ``SOL_PACKET`` and ``PACKET_STATISTICS`` are Linux-only constants Python does
# not export; the numbers are from linux/if_packet.h and stable.
SOL_PACKET = 263
PACKET_STATISTICS = 6

# The window bounds a capture whose caller has died. A summary that ends because
# the window ran out is reported as such: it may have missed the request.
DEFAULT_WINDOW_SECONDS = 45
POLL_SECONDS = 0.02

EXIT_NO_CAPABILITY = 11
EXIT_BAD_ARGUMENT = 12
EXIT_NO_CONNECTION = 13
EXIT_NO_SUMMARY = 14


class ProbeError(Exception):
    """A named failure the caller turns into a verdict, never into a crash."""

    def __init__(self, code: str, detail: str, status: int) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status


def _print(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def _open_packet_sockets() -> Dict[str, socket.socket]:
    """One packet socket per IP family, bound to nothing so every interface counts."""
    sockets: Dict[str, socket.socket] = {}
    try:
        for family, ethertype in (("ipv4", ETH_P_IP), ("ipv6", ETH_P_IPV6)):
            try:
                handle = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))
            except OSError:
                # A host without IPv6 still gives the IPv4 half; only the total
                # absence of a packet socket is a missing capability.
                if family == "ipv6":
                    continue
                raise
            handle.setblocking(False)
            sockets[family] = handle
    except PermissionError as exc:
        raise ProbeError(
            "no_cap_net_raw",
            f"this host cannot open a packet socket, so inbound packets are unobservable: {exc}",
            EXIT_NO_CAPABILITY,
        ) from exc
    except OSError as exc:
        raise ProbeError(
            "no_capture_socket",
            f"this host cannot open a packet socket: {exc}",
            EXIT_NO_CAPABILITY,
        ) from exc
    if not sockets:
        raise ProbeError(
            "no_capture_socket", "this host opened no packet socket at all", EXIT_NO_CAPABILITY,
        )
    return sockets


def _ip_header(frame: bytes, family: str) -> bytes:
    """The IP header of one frame, which may arrive with or without a link header.

    A packet socket on an Ethernet device hands over the link header and one on
    the loopback device does not, and both carry product traffic: the node dials
    its own edge over loopback while a client reaches it over the network. The
    version nibble is what tells the two apart, so neither shape is assumed.
    """
    if not frame:
        return b""
    if frame[0] >> 4 == (4 if family == "ipv4" else 6):
        return frame
    if len(frame) < 14:
        return b""
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    if ethertype == (ETH_P_IP if family == "ipv4" else ETH_P_IPV6):
        return frame[14:]
    # One 802.1Q tag: a product host may sit behind a VLAN sub-interface.
    if ethertype == 0x8100 and len(frame) >= 18:
        return frame[18:]
    return b""


def _segment_source(frame: bytes, family: str, port: int) -> Optional[str]:
    """The source address of one inbound TCP segment to ``port``, if it is one."""
    payload = _ip_header(frame, family)
    if family == "ipv4":
        if len(payload) < 20:
            return None
        header = (payload[0] & 0x0F) * 4
        if payload[9] != IPPROTO_TCP or len(payload) < header + 4:
            return None
        destination = struct.unpack_from("!H", payload, header + 2)[0]
        if destination != port:
            return None
        return str(ipaddress.IPv4Address(payload[12:16]))
    if len(payload) < 40:
        return None
    if payload[6] != IPPROTO_TCP or len(payload) < 44:
        return None
    destination = struct.unpack_from("!H", payload, 42)[0]
    if destination != port:
        return None
    return str(ipaddress.IPv6Address(payload[8:24]))


def _next_frame(handle: socket.socket) -> bytes:
    """One queued frame, or empty once the capture socket has nothing left.

    The socket is non-blocking, so an empty queue arrives as ``BlockingIOError``
    rather than as a wait, and it is the read that ends the drain. A truncated
    frame is still a segment the host received, but its header is what the count
    needs and the parser skips what it cannot read, so an unreadable frame ends
    the drain too instead of being counted twice.
    """
    try:
        return handle.recv(65535)
    except OSError:
        return b""


def _drain(handle: socket.socket, family: str, port: int, counts: Dict[str, int]) -> None:
    frame = _next_frame(handle)
    while frame:
        source = _segment_source(frame, family, port)
        if source:
            counts[source] = counts.get(source, 0) + 1
        frame = _next_frame(handle)


def _stopped(deadline: float) -> Tuple[bool, bool]:
    """Whether to stop, and whether the harness asked rather than the window ending."""
    if time.monotonic() >= deadline:
        return True, False
    try:
        ready, _, _ = select.select([sys.stdin], [], [], POLL_SECONDS)
    except (OSError, ValueError):
        return False, False
    if not ready:
        return False, False
    line = sys.stdin.readline()
    if not line or line.strip() in ("", "stop"):
        return True, True
    return False, False


def capture_packets(port: int, window: int) -> int:
    if not 1 <= port <= 65535:
        raise ProbeError(
            "no_endpoint_port",
            f"the request's destination port is {port!r}, so no filter can name it",
            EXIT_BAD_ARGUMENT,
        )
    sockets = _open_packet_sockets()
    started = time.monotonic()
    _print({
        "ready": True,
        "scope": "packets",
        "port": port,
        "families": sorted(sockets),
        "window_seconds": window,
    })
    counts: Dict[str, int] = {}
    deadline = started + window
    stopped_by_harness = False
    try:
        stop, by_harness = _stopped(deadline)
        while not stop:
            for family, handle in sockets.items():
                _drain(handle, family, port, counts)
            stop, by_harness = _stopped(deadline)
        # The decision to stop was taken after this pass, so one more drain picks
        # up what landed while it was being made.
        for family, handle in sockets.items():
            _drain(handle, family, port, counts)
        stopped_by_harness = by_harness
    finally:
        drops = 0
        for handle in sockets.values():
            try:
                statistics = handle.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
                _packets_seen, socket_drops = struct.unpack("=II", statistics)
                drops += socket_drops
            except OSError:
                pass
            handle.close()
    _print({
        "captured": sum(counts.values()),
        "sources": dict(sorted(counts.items(), key=lambda item: (-item[1], item[0]))),
        "port": port,
        "seconds": round(time.monotonic() - started, 3),
        "stopped_by": "harness" if stopped_by_harness else "window",
        "drops": drops,
    })
    return 0


def _decode_v4(value: str) -> str:
    return str(ipaddress.IPv4Address(bytes.fromhex(value)[::-1]))


def _decode_v6(value: str) -> str:
    raw = bytes.fromhex(value)
    return str(ipaddress.IPv6Address(b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))))


def _connection_peers(local_port: int, remote_port: int) -> List[Tuple[str, str]]:
    """Every established connection this host holds with that port pair."""
    found: List[Tuple[str, str]] = []
    for family, path in (("ipv4", "/proc/net/tcp"), ("ipv6", "/proc/net/tcp6")):
        try:
            with open(path, encoding="ascii", errors="replace") as handle:
                next(handle, None)
                rows = handle.readlines()
        except OSError:
            continue
        for line in rows:
            fields = line.split()
            if len(fields) < 4 or fields[3] != "01":
                continue
            local_address, _, local_port_hex = fields[1].rpartition(":")
            peer_address, _, peer_port_hex = fields[2].rpartition(":")
            try:
                local_number = int(local_port_hex, 16)
                number = int(peer_port_hex, 16)
            except ValueError:
                continue
            if local_number != local_port or number != remote_port:
                continue
            try:
                address = _decode_v4(peer_address) if family == "ipv4" else _decode_v6(peer_address)
            except ValueError:
                continue
            found.append((family, address))
    return found


def report_peer(local_port: int, remote_port: int) -> int:
    """Report the source address this host's kernel has for one connection."""
    if not 1 <= local_port <= 65535 or not 0 <= remote_port <= 65535:
        raise ProbeError(
            "no_identity_port",
            f"the connection to look up is {local_port!r}/{remote_port!r}, which is not a port pair",
            EXIT_BAD_ARGUMENT,
        )
    found = _connection_peers(local_port, remote_port)
    if not found:
        raise ProbeError(
            "no_identity_connection",
            f"this host holds no established connection on local port {local_port} from remote "
            f"port {remote_port}, so it cannot say who the client is",
            EXIT_NO_CONNECTION,
        )
    families = {family for family, _address in found}
    addresses = sorted({address for _family, address in found})
    if len(addresses) != 1 or len(families) != 1:
        raise ProbeError(
            "identity_ambiguous",
            f"this host attributes the connection to {addresses} over {sorted(families)}, so the "
            "client's address is not one fact",
            EXIT_NO_CONNECTION,
        )
    _print({
        "peer": addresses[0],
        "family": families.pop(),
        "local_port": local_port,
        "remote_port": remote_port,
        "state": "ESTABLISHED",
    })
    return 0


def hold(peers: Sequence[Tuple[str, str, int]], timeout: int) -> int:
    """Open one connection per host, say nothing, and wait to be released."""
    if not peers:
        raise ProbeError("no_identity_peer", "no host was named to hold a connection to", EXIT_BAD_ARGUMENT)
    held: Dict[str, socket.socket] = {}
    try:
        for role, host, port in peers:
            try:
                handle = socket.create_connection((host, port), timeout=timeout)
            except OSError as exc:
                raise ProbeError(
                    "no_identity_connection",
                    f"the client could not open a connection to the {role} host {host}:{port}: {exc}",
                    EXIT_NO_CONNECTION,
                ) from exc
            handle.settimeout(None)
            held[role] = handle
            _print({"held": role, "local_port": handle.getsockname()[1]})
        # The harness releases the connections by closing stdin, so a holder
        # outlives a crashed caller only until its own timeout runs out.
        for line in sys.stdin:
            if line.strip() in ("", "stop"):
                break
    finally:
        for handle in held.values():
            try:
                handle.close()
            except OSError:
                pass
    _print({"released": len(held)})
    return 0


def _peer_arguments(values: Iterable[str]) -> List[Tuple[str, str, int]]:
    parsed: List[Tuple[str, str, int]] = []
    for value in values:
        role, _, rest = value.partition("=")
        host, _, port = rest.rpartition(":")
        if not role or not host or not port.isdigit():
            raise ProbeError(
                "no_identity_peer", f"{value!r} is not a role=host:port peer", EXIT_BAD_ARGUMENT,
            )
        parsed.append((role, host, int(port)))
    return parsed


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Report packet and connection evidence on one host")
    parser.add_argument("--scope", required=True, choices=("packets", "hold", "peer"))
    parser.add_argument("--port", type=int, default=0,
                        help="The port the filter names: the proxy's destination port for "
                             "the packets scope, this host's listening port for the peer scope")
    parser.add_argument("--remote-port", type=int, default=0,
                        help="The client's local port, for the peer scope")
    parser.add_argument("--peer", action="append", default=[],
                        metavar="ROLE=HOST:PORT",
                        help="One host to hold a connection to, for the hold scope")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SECONDS,
                        help="How long a capture may run before it stops on its own")
    parser.add_argument("--timeout", type=int, default=10,
                        help="How long one connection may take to establish")
    args = parser.parse_args(argv)

    try:
        if args.scope == "packets":
            return capture_packets(args.port, max(1, args.window))
        if args.scope == "peer":
            return report_peer(args.port, args.remote_port)
        return hold(_peer_arguments(args.peer), max(1, args.timeout))
    except ProbeError as error:
        _print({"error": error.code, "detail": error.detail})
        return error.status


if __name__ == "__main__":
    sys.exit(main())
