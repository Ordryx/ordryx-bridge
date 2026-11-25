"""Looking for printers: only when
Ordryx asks or a printer has gone missing. This computer first (Moonraker on
7125 and the next few ports, as KIAUH gives each extra Klipper; and 80,
Mainsail's), then, if the bridge reaches its network and may look, what
announces itself (mdns.py), then its own /24 on 7125 and 80. Whatever connects
is asked ``/server/info`` and kept only if it answers as Moonraker (a refusal
for a key is kept as "needs a key"). Only printers go up; everything else is
a count.

Standard library only. Python 3.9.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import urllib.parse
import urllib.request

from . import calls, mdns
from .calls import LOCAL_PORTS, LOOK, NETWORK_PORTS, _base, _Failed, fetch

CONNECT_SECONDS = 0.5
AT_ONCE = 32
MOST_FOUND = 64


def _get(url: str, timeout: float = 2.0) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        status, _, raw = fetch(req, timeout, 1024 * 1024)
    except _Failed:
        return 0, None
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return status, None
    return status, data if isinstance(data, dict) else None


def _open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_SECONDS):
            return True
    except OSError:
        return False


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def probe(host: str, port: int, known: calls.Known | None = None) -> dict | None:
    """A printer at host:port, or None if what's there isn't Moonraker."""
    base = _base(host, port)
    status, info = _get(base + "/server/info")
    # Moonraker's own refusal (JSON, as calls.is_refusal), never just any: a
    # router's or a NAS's sign-in page refuses every path too.
    if status in (401, 403) and info is not None:
        return {
            "address": base,
            "hostname": "",
            "klipper": "",
            "cameras": 0,
            "needs_key": True,
            "id": f"{host}:{port}",
        }
    result = _dict(info).get("result")
    if status != 200 or not isinstance(result, dict) or "klippy_state" not in result:
        return None
    if known is not None:
        known.remember(host, port)
    out = {
        "address": base,
        "hostname": "",
        "klipper": str(result.get("klippy_state") or "")[:24],
        "cameras": 0,
        "needs_key": False,
        "id": f"{host}:{port}",
    }
    _, pinfo = _get(base + "/printer/info")
    pr = _dict(pinfo).get("result")
    if isinstance(pr, dict) and isinstance(pr.get("hostname"), str):
        out["hostname"] = pr["hostname"][:64]
    _, cams = _get(base + "/server/webcams/list")
    cl = _dict(_dict(cams).get("result")).get("webcams")
    if isinstance(cl, list):
        out["cameras"] = sum(1 for w in cl if isinstance(w, dict) and w.get("enabled", True))
    out["id"] = stable_id(base) or out["id"]
    return out


SERIAL = re.compile(r"[0-9a-f]{8,32}\Z")
MAC = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
UNIT = re.compile(r"[A-Za-z0-9_.@-]{1,40}\Z")
NOT_ITS_OWN = ("lo", "docker", "veth", "br-", "virbr", "tailscale", "wg", "tun", "tap")


def machine_id(info) -> str:
    """A printer's own id from Moonraker's ``system_info``: its computer (the
    CPU's serial number, else its lowest factory-set network card address) and Moonraker's
    unit name there, which alone is "moonraker" on nearly every printer and only
    tells KIAUH's instances on one computer apart. "" when the computer gives
    neither: nothing to know it by. The same in the bridge (scan.py) and the
    shop (client.py); a test holds them together."""
    info = info if isinstance(info, dict) else {}
    cpu = info.get("cpu_info")
    serial = cpu.get("serial_number") if isinstance(cpu, dict) else None
    serial = serial.strip().lower() if isinstance(serial, str) else ""
    machine = serial if SERIAL.match(serial) and serial.strip("0") else ""
    if not machine:
        cards = info.get("network")
        macs = []
        for name, card in (cards if isinstance(cards, dict) else {}).items():
            mac = card.get("mac_address") if isinstance(card, dict) else None
            mac = mac.strip().lower() if isinstance(mac, str) else ""
            own = isinstance(name, str) and not name.startswith(NOT_ITS_OWN)
            # (one a program made up, as Docker's 02:42:…, is the same on any computer)
            if own and MAC.match(mac) and mac.strip("0:") and not int(mac[:2], 16) & 2:
                macs.append(mac)
        machine = min(macs) if macs else ""
    if not machine:
        return ""
    ids = info.get("instance_ids")
    unit = ids.get("moonraker") if isinstance(ids, dict) else None
    unit = unit if isinstance(unit, str) and UNIT.match(unit) else "moonraker"
    return f"{machine}/{unit}"


def stable_id(base: str) -> str:
    """The printer's own id, whatever its address ("": it gives none)."""
    _, sysinfo = _get(base + "/machine/system_info")
    return machine_id(_dict(_dict(sysinfo).get("result")).get("system_info"))


def look(
    reach: str,
    lan_address: str | None,
    known: calls.Known | None = None,
    announced=mdns.look,
) -> dict:
    """What this bridge can find now, for its reach."""
    targets = [("127.0.0.1", p) for p in LOCAL_PORTS]
    if reach == LOOK:
        targets += [t for t in announced() if calls.may_reach(t[0], reach)]
        if lan_address:
            net = ipaddress.ip_network(f"{lan_address}/24", strict=False)
            targets += [
                (str(h), p) for h in net.hosts() if str(h) != lan_address for p in NETWORK_PORTS
            ]
            targets += [(lan_address, p) for p in NETWORK_PORTS]
    targets = list(dict.fromkeys(targets))
    with concurrent.futures.ThreadPoolExecutor(AT_ONCE) as pool:
        opened = list(pool.map(lambda t: _open(*t), targets))
        open_ = [t for t, ok in zip(targets, opened) if ok]
        found = list(pool.map(lambda t: probe(t[0], t[1], known), open_))
    printers, seen, other = [], set(), 0

    # (one that needs a key gives no id: Mainsail's port is the same printer as
    # any other found on its computer)
    def here(host):  # (this computer's own address is this computer)
        return "127.0.0.1" if host == lan_address else host

    hosts = [urllib.parse.urlsplit(f["address"]) for f in found if f is not None]
    elsewhere = {here(u.hostname) for u in hosts if (u.port or 80) != 80}
    for f in found:
        if f is None:
            other += 1
            continue
        at = urllib.parse.urlsplit(f["address"])
        if f["needs_key"] and (at.port or 80) == 80 and here(at.hostname) in elsewhere:
            continue
        # One printer answers at several addresses of one computer (Mainsail's
        # port and Moonraker's; this computer's LAN address and loopback): once,
        # the first. The same id on another computer is never taken for it.
        host = here(at.hostname)
        same = (host, f["id"].split(":")[-1] if f["needs_key"] else f["id"])
        if same not in seen and len(printers) < MOST_FOUND:
            seen.add(same)
            printers.append(f)
    return {"found": printers, "other": other}
