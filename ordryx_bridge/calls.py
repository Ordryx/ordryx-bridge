"""What the bridge will do for Ordryx, checked here whatever Ordryx asks: a
fixed list of Moonraker calls, to printers it may reach, and camera pictures.
Never a general tunnel.

- **An address must have answered as Moonraker** (``Known``): before anything
  is asked of it the bridge asks ``/server/info`` itself and remembers the
  answer briefly, so even a stolen owner session reaches printers, never the
  router or the NAS.
- **A camera** is any other GET, only on a host with such a Moonraker, never
  one of Moonraker's own paths, and only a picture or stream comes back. The
  API key goes only to the port that proved it's Moonraker.

Standard library only. Python 3.9.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

THIS_COMPUTER, TYPED, LOOK = "this-computer", "typed", "look"
REACHES = (THIS_COMPUTER, TYPED, LOOK)

# Base64 makes this a third bigger, and the whole message has to fit in the
# largest WebSocket message the shop's server takes (8 MiB).
MAX_ANSWER = 5 * 1024 * 1024
PRIVATE_NETWORKS = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
PICTURES = ("image/jpeg", "image/png", "image/webp")
PROVEN_SECONDS = 120.0  # how long a Moonraker's answer is believed
LOCAL_PORTS = (7125, 7126, 7127, 7128, 7129, 7130, 80)
NETWORK_PORTS = (7125, 80)

# (method, path) → the query keys it may carry (None: Klipper's object names)
ALLOWED: dict[tuple[str, str], frozenset[str] | None] = {
    ("GET", "/printer/objects/query"): None,
    ("GET", "/printer/objects/list"): frozenset(),
    ("GET", "/printer/info"): frozenset(),
    ("GET", "/server/info"): frozenset(),
    ("GET", "/machine/system_info"): frozenset(),
    ("GET", "/server/history/list"): frozenset({"limit", "since", "order", "start", "before"}),
    ("GET", "/server/files/metadata"): frozenset({"filename"}),
    ("GET", "/server/webcams/list"): frozenset(),
    ("GET", "/server/spoolman/spool_id"): frozenset(),
    ("POST", "/server/spoolman/spool_id"): frozenset(),
    ("POST", "/printer/print/pause"): frozenset(),
    ("POST", "/printer/print/resume"): frozenset(),
    ("POST", "/printer/print/cancel"): frozenset(),
}
OBJECT_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_ .-]{0,99}\Z")
# Moonraker's and its neighbours' own paths: never "a camera", whatever answers
NOT_CAMERAS = ("/access", "/api", "/machine", "/printer", "/server", "/websocket")


PICTURES_AT_ONCE = 4
_pictures = threading.BoundedSemaphore(PICTURES_AT_ONCE)


class Refused(Exception):
    """Not something the bridge does: said back to Ordryx as the call's error."""


class _Failed(Exception):
    """The printer couldn't be asked: its word for the shop."""


def tighter(a: str | None, b: str | None) -> str:
    got = [r for r in (a, b) if r in REACHES]
    return min(got, key=REACHES.index) if got else THIS_COMPUTER


def may_reach(host: str, reach: str) -> bool:
    """Loopback on this computer; else RFC 1918 addresses on its network.
    Never link-local, public, "this host" (0.0.0.0) or a name (it could point
    anywhere)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback:
        return (ip.version == 4 and str(ip) == host) or host == "::1"
    if reach == THIS_COMPUTER or ip.version != 4 or str(ip) != host:
        return False
    return any(ip in n for n in PRIVATE_NETWORKS)


def _camera_path(path: str) -> bool:
    if not path.startswith("/") or "%" in path or ".." in path or "//" in path:
        return False
    if "." in path.split("/"):  # (/./printer/… is /printer/… to whatever answers)
        return False
    low = path.lower()
    return not any(low == p or low.startswith(p + "/") for p in NOT_CAMERAS)


def check(method: str, url: str, reach: str) -> urllib.parse.SplitResult:
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F or c == "\\" for c in url):
        raise Refused("not allowed: that address")
    # Older Pythons read http://[192.168.1.5].example.com as that address, and
    # then connect to the name: square brackets only as loopback's own.
    if ("[" in url or "]" in url) and not url.startswith(("http://[::1]:", "http://[::1]/")):
        raise Refused("not allowed: that address")
    if url.count("[") > 1 or url.count("]") > 1:
        raise Refused("not allowed: that address")
    try:
        u = urllib.parse.urlsplit(url)
        u.port  # noqa: B018 (raises on one that isn't a port)
    except ValueError:
        raise Refused("not allowed: that address") from None
    if u.port == 0:
        raise Refused("not allowed: that address")
    # ("@" and not its parts: an empty user name reads as none, and urllib's host
    # would then be the literal "@192.168.1.5", another name than the one checked)
    if u.scheme != "http" or "@" in u.netloc or u.fragment:
        raise Refused("not allowed: only plain http to a printer")
    if not may_reach(u.hostname or "", reach):
        raise Refused("not allowed: that address isn't one this bridge reaches")
    if (method, u.path) in ALLOWED:
        keys = ALLOWED[(method, u.path)]
        asked = {k for k, _ in urllib.parse.parse_qsl(u.query, keep_blank_values=True)}
        if keys is None:
            if not all(OBJECT_NAME.match(k) for k in asked):
                raise Refused("not allowed: that query")
        elif not asked <= keys:
            raise Refused("not allowed: that query")
        return u
    if method == "GET" and _camera_path(u.path):  # a camera's picture: checked by its answer
        return u
    raise Refused("not allowed: that call")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


# No redirects, and never the computer's proxy settings: a printer's address is
# asked directly or not at all.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects)


def _read(r, timeout: float, limit: int) -> bytes:
    """The answer, within ``timeout`` in all: a socket's timeout is per read, so a
    stream or something dripping a byte at a time would otherwise never end."""
    until = time.monotonic() + timeout
    got, size = [], 0
    while True:
        if time.monotonic() > until:
            raise _Failed("timeout")
        chunk = r.read1(65536) if hasattr(r, "read1") else r.read(65536)
        if not chunk:
            return b"".join(got)
        size += len(chunk)
        if size > limit:
            raise _Failed("too big")
        got.append(chunk)


# What an answer says of the printer's own clock, passed on to the shop (which
# sets its prints' times by it, and by nothing a proxy or a cache answered).
CLOCK_HEADERS = ("Date", "Via", "Age")


def fetch(
    req: urllib.request.Request,
    timeout: float,
    limit: int = MAX_ANSWER,
    heads: dict | None = None,
):
    """(status, content type, body), or ``_Failed`` with the shop's word.
    ``heads``: filled with the answer's ``CLOCK_HEADERS``."""
    try:
        try:
            r = _opener.open(req, timeout=timeout)
            status = r.status
        except urllib.error.HTTPError as e:
            r, status = e, e.code
        try:
            kind = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if heads is not None:
                for name in CLOCK_HEADERS:
                    said = r.headers.get(name)
                    if isinstance(said, str) and len(said) < 100:
                        heads[name] = said
            raw = _read(r, timeout, limit)
        finally:
            r.close()
    except (TimeoutError, socket.timeout):
        raise _Failed("timeout") from None
    except ConnectionRefusedError:
        raise _Failed("refused") from None
    except urllib.error.URLError as e:
        if isinstance(e.reason, (TimeoutError, socket.timeout)):
            raise _Failed("timeout") from None
        if isinstance(e.reason, ConnectionRefusedError):
            raise _Failed("refused") from None
        raise _Failed("unreachable") from None
    except (OSError, ValueError, http.client.HTTPException):
        raise _Failed("unreachable") from None
    return status, kind, raw


def _base(host: str, port: int) -> str:
    host = f"[{host}]" if ":" in host else host
    return f"http://{host}" + ("" if port == 80 else f":{port}")


class Known:
    """Which addresses answered as Moonraker lately (memory only). The key the
    shop last sent for one that did, for asking it again on a camera's behalf;
    a call that comes without a key forgets it (the shop cleared it)."""

    def __init__(self, clock=time.monotonic) -> None:
        self.clock = clock
        self.lock = threading.Lock()
        self.proven: dict[tuple[str, int], float] = {}
        self.keys: dict[tuple[str, int], str] = {}

    def _fresh(self, at: tuple[str, int]) -> bool:
        with self.lock:
            when = self.proven.get(at)
            return when is not None and self.clock() - when < PROVEN_SECONDS

    def ask(self, host: str, port: int, key: str | None, timeout: float = 4.0) -> str:
        """For a call from the shop, with its key or none: "yes" (it's Moonraker),
        "key" (it refused: it may be, with the right key) or "no"; ``_Failed``
        if nothing answered."""
        at = (host, port)
        with self.lock:
            if not key:
                self.keys.pop(at, None)
        said = "yes" if self._fresh(at) else self._prove(at, key, timeout)
        if said == "yes" and key:
            with self.lock:
                self.keys[at] = key
        return said

    def _prove(self, at: tuple[str, int], key: str | None, timeout: float) -> str:
        def ask(with_key: str | None):
            headers = {"Accept": "application/json", "User-Agent": "Ordryx-Bridge"}
            if with_key:
                headers["X-Api-Key"] = with_key
            req = urllib.request.Request(_base(*at) + "/server/info", headers=headers)
            status, _, raw = fetch(req, timeout, 1024 * 1024)
            return status, raw

        # First with no key: the shop's key goes only to what refuses as
        # Moonraker does, never to whatever else is at an address someone typed.
        status, raw = ask(None)
        refuses = status in (401, 403) and is_refusal(raw)
        if refuses and key:
            status, raw = ask(key)
            refuses = status in (401, 403) and is_refusal(raw)
        if status == 200 and is_moonraker(raw):
            self.remember(*at)
            return "yes"
        with self.lock:
            self.proven.pop(at, None)
            self.keys.pop(at, None)
        return "key" if refuses else "no"

    def remember(self, host: str, port: int) -> None:
        with self.lock:
            self.proven[(host, port)] = self.clock()

    def camera_host(self, host: str) -> bool:
        """Is there a Moonraker on this host? Asked of its ports this bridge has
        proved (each with its own key, if the shop gave one), then the usual
        ones with no key at all: a camera's call never offers a key anywhere."""
        with self.lock:
            mine = [p for h, p in self.proven if h == host]
            keys = {p: k for (h, p), k in self.keys.items() if h == host}
        usual = LOCAL_PORTS if ipaddress.ip_address(host).is_loopback else NETWORK_PORTS
        for port in dict.fromkeys(mine + list(usual)):
            if self._fresh((host, port)):
                return True
            try:
                if self._prove((host, port), keys.get(port), 2.0) == "yes":
                    return True
            except _Failed:
                continue
        return False

    def is_proven(self, host: str, port: int) -> bool:
        return self._fresh((host, port))


def is_moonraker(raw: bytes) -> bool:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return False
    result = data.get("result") if isinstance(data, dict) else None
    return isinstance(result, dict) and "klippy_state" in result


def is_refusal(raw: bytes) -> bool:
    """Moonraker's way of refusing (for a key): JSON, as all it answers is. A
    router's or a NAS's sign-in page refuses every path too, with a page."""
    try:
        return isinstance(json.loads(raw), dict)
    except (ValueError, RecursionError):
        return False


def _body_ok(path: str, body: bytes | None) -> bool:
    """A POST's body: the spool's number for setting the spool, else nothing."""
    if path != "/server/spoolman/spool_id":
        return not body or body.strip() == b"{}"
    try:
        data = json.loads(body or b"")
    except (ValueError, RecursionError):
        return False
    if not isinstance(data, dict) or set(data) != {"spool_id"}:
        return False
    sid = data["spool_id"]
    return sid is None or (isinstance(sid, int) and not isinstance(sid, bool))


def call(msg: dict, reach: str, known: Known) -> dict:
    """One of Ordryx's calls, answered for the connection: status, the
    content type, the body (base64); or an ``error`` word."""
    method, url = msg.get("method"), msg.get("url")
    if method not in ("GET", "POST") or not isinstance(url, str) or len(url) > 2000:
        return {"error": "not allowed: that call"}
    try:
        u = check(method, url, reach)
    except Refused as e:
        return {"error": str(e)}
    host, port = u.hostname or "", 80 if u.port is None else u.port
    listed = (method, u.path) in ALLOWED
    sent = msg.get("headers") if isinstance(msg.get("headers"), dict) else {}
    key = sent.get("X-Api-Key")
    key = key if isinstance(key, str) and key and len(key) < 300 else None
    body = None
    if method == "POST":
        try:
            body = base64.b64decode(msg.get("body") or "", validate=True) or None
        except (ValueError, TypeError):
            return {"error": "not allowed: that body"}
        if body is not None and (len(body) > 4096 or not _body_ok(u.path, body)):
            return {"error": "not allowed: that body"}
    timeout = msg.get("timeout")
    ok_timeout = isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
    timeout = float(timeout) if ok_timeout and 0 < timeout <= 30 else 8.0
    began = time.monotonic()
    try:
        if listed:
            said = known.ask(host, port, key, min(timeout, 4.0))
            if said == "key":
                # (it refused the key, or needs one: said without asking it more)
                return {"status": 401, "headers": {}, "body": ""}
            if said == "no":
                return {"error": "not allowed: that isn't a printer"}
        elif not known.camera_host(host):
            return {"error": "not allowed: no printer on that computer"}
    except _Failed as e:
        return {"error": str(e)}
    headers = {"Accept": "application/json", "User-Agent": "Ordryx-Bridge"}
    if key and known.is_proven(host, port):
        headers["X-Api-Key"] = key
    if body:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(u.geturl(), data=body, headers=headers, method=method)
    left = max(1.0, timeout - (time.monotonic() - began))  # (asking what's there took some)
    heads: dict = {}
    try:
        if listed:
            status, kind, raw = fetch(req, left, heads=heads)
        elif _pictures.acquire(timeout=left):
            # (pictures are the big answers: a few at a time, in a small computer's memory)
            try:
                status, kind, raw = fetch(req, left)
            finally:
                _pictures.release()
        else:
            return {"error": "timeout"}
    except _Failed as e:
        return {"error": str(e)}
    if not listed and kind not in PICTURES:
        return {"error": "not allowed: only a camera's picture"}
    return {
        "status": status,
        "headers": {**heads, **({"Content-Type": kind} if kind else {})},
        "body": base64.b64encode(raw).decode(),
    }
