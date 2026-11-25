"""Printers that announce themselves:
one mDNS question for ``_moonraker._tcp.local``, where a printer's
``[zeroconf]`` is on, and the answers for a couple of seconds. Whatever comes
back is only a place to look (``scan.probe`` decides what it is), and comes
from anyone on the network, so the parser trusts nothing in it.

Standard library only. Python 3.9.
"""

from __future__ import annotations

import select
import socket
import struct
import time

GROUP, PORT = "224.0.0.251", 5353
SERVICE = "_moonraker._tcp.local"
SECONDS = 2.0
MOST_ANSWERS = 256
MOST_POINTERS = 16
PTR, A, SRV = 12, 1, 33


def question(name: str = SERVICE) -> bytes:
    """A one-shot query (RFC 6762 §6.7): answered to this socket."""
    out = struct.pack("!6H", 0, 0, 1, 0, 0, 0)
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00" + struct.pack("!2H", PTR, 1)


def _name(data: bytes, at: int) -> tuple[str, int]:
    """A name and where the record goes on; ValueError on anything odd."""
    labels, end, jumps = [], None, 0
    while True:
        if at >= len(data):
            raise ValueError("short")
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if at + 1 >= len(data) or jumps >= MOST_POINTERS:
                raise ValueError("pointer")
            target = ((n & 0x3F) << 8) | data[at + 1]
            if target >= at:  # only ever backwards, so it can't loop
                raise ValueError("pointer")
            end = at + 2 if end is None else end
            at, jumps = target, jumps + 1
            continue
        if n & 0xC0 or at + 1 + n > len(data):
            raise ValueError("label")
        labels.append(data[at + 1 : at + 1 + n].decode("ascii", "replace"))
        at += 1 + n
        if sum(len(x) + 1 for x in labels) > 255:
            raise ValueError("long")
    return ".".join(labels).lower(), (at if end is None else end)


def parse(data: bytes) -> tuple[list[str], dict[str, tuple[str, int]], dict[str, str]]:
    """(instances, instance → (target, port), target → IPv4) from one packet.
    Nothing usable (or something broken): empty."""
    instances: list[str] = []
    services: dict[str, tuple[str, int]] = {}
    addresses: dict[str, str] = {}
    try:
        if len(data) < 12:
            return instances, services, addresses
        _, flags, qd, an, ns, ar = struct.unpack("!6H", data[:12])
        if not flags & 0x8000:  # (a question, not an answer)
            return instances, services, addresses
        at = 12
        for _ in range(qd):
            _, at = _name(data, at)
            at += 4
        for _ in range(min(an + ns + ar, MOST_ANSWERS)):
            name, at = _name(data, at)
            if at + 10 > len(data):
                break
            kind, _, _, size = struct.unpack("!HHIH", data[at : at + 10])
            at += 10
            if at + size > len(data):
                break
            if kind == PTR and name == SERVICE:
                instances.append(_name(data, at)[0])
            elif kind == SRV and size >= 7:
                port = struct.unpack("!H", data[at + 4 : at + 6])[0]
                services[name] = (_name(data, at + 6)[0], port)
            elif kind == A and size == 4:
                addresses[name] = socket.inet_ntoa(data[at : at + 4])
            at += size
    except (ValueError, struct.error, OSError, IndexError):
        pass
    return instances, services, addresses


def look(seconds: float = SECONDS, sock=None) -> list[tuple[str, int]]:
    """(address, port) of what answered, each once. Nothing if multicast isn't
    possible here (a Docker-only network, say)."""
    own = sock is None
    try:
        s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return []
    instances: set[str] = set()
    services: dict[str, tuple[str, int]] = {}
    addresses: dict[str, str] = {}
    sources: dict[str, str] = {}
    packets = 0
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.sendto(question(), (GROUP, PORT))
        until = time.monotonic() + seconds
        while packets < MOST_ANSWERS:
            left = until - time.monotonic()
            if left <= 0 or not select.select([s], [], [], left)[0]:
                break
            data, source = s.recvfrom(9000)
            packets += 1
            i, sv, ad = parse(data)
            instances.update(i)
            for name, found in sv.items():
                services[name] = found
                sources.setdefault(name, source[0])
            addresses.update(ad)
    except OSError:
        pass
    finally:
        if own:
            s.close()
    out: list[tuple[str, int]] = []
    for name in sorted(instances)[:64]:
        target, port = services.get(name, ("", 0))
        where = addresses.get(target) or sources.get(name)
        if where and port and (where, port) not in out:
            out.append((where, port))
    return out
