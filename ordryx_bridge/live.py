"""Live video on the shop's network: the
bridge serves its printers' camera streams over HTTPS, at its own name
(``k7f2q9ab.local.ordryx.com``, pointing at this computer's private address)
with a real certificate, so a page of the shop's Ordryx shows them with no
warning and no mixed content.

- **Its key stays here** (``https/key.pem``, 0600): the shop gets a CSR,
  asks the Ordryx account for the certificate over its Link, and hands it
  back. Made with the ``openssl`` command (every Klipper Pi has it).
- **Tickets, not sign-ins**: a page can't send the shop's cookie here, so the
  shop hands whoever may see the camera a ticket: the camera's address, an
  expiry a minute or two away and a nonce, signed with a secret the shop
  gives this bridge over its connection (kept in memory only). Each is good
  once. The address is still checked against the bridge's own limits, and
  what comes back must be a picture or a video stream.
- A stream lasts ``STREAM_SECONDS`` at most, ``VIEWERS`` at once per camera, and
  ``CONNECTIONS`` at once in all: anyone on the network can knock.
- ``/health`` answers anyone: the page asks it to learn whether it's on the
  shop's network (if not, snapshots through the shop, as before). Only the
  shop's own pages are told they may read answers across origins.

Standard library, and ``cryptography`` to read a certificate (as keys.py).
Python 3.9.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import logging
import os
import re
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509

from . import calls

log = logging.getLogger("ordryx_bridge")

PORT = 7443
STREAM_SECONDS = 600
VIEWERS = 3
LONGEST_TICKET = 180  # seconds: a ticket further out than this is refused
STREAMS = ("multipart/x-mixed-replace",)
CONNECTIONS = 32
REACH_EVERY = 5.0  # seconds: how often a stream looks at what the bridge may reach now
NAME = re.compile(r"[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){1,8}\Z")


class Live:
    """The certificate, the tickets and the listener."""

    def __init__(
        self, folder: Path, port: int, reach, known: calls.Known, origin: str = ""
    ) -> None:
        self.dir = folder / "https"
        self.port = port
        self.reach = reach  # () -> the bridge's reach now
        self.known = known  # what's answered as Moonraker (calls.Known)
        self.origin = origin  # the shop's pages, the only ones told they may read answers
        self.slots = threading.BoundedSemaphore(CONNECTIONS)
        self.name: str | None = None
        self.ref: str | None = None
        self.secret: bytes | None = None
        self.used: dict[str, float] = {}  # nonce -> its expiry
        self.watching: dict[str, int] = {}  # camera address -> viewers now
        self.lock = threading.Lock()
        self.server: ThreadingHTTPServer | None = None
        self.context: ssl.SSLContext | None = None

    # ── the certificate ─────────────────────────────────────────────────────

    @property
    def key(self) -> Path:
        return self.dir / "key.pem"

    @property
    def cert(self) -> Path:
        return self.dir / "cert.pem"

    def configure(self, name: str, ref: str, secret: str) -> bool:
        """The shop's word for its name and tickets; a name that couldn't be
        one is refused (it goes into a certificate request)."""
        if not NAME.match(name):
            return False
        self.name, self.ref = name, ref
        self.secret = secret.encode()
        return True

    def fresh(self) -> bool:
        """A certificate for its name with more than a third of its life left."""
        facts = _facts(self.cert)
        if facts is None or self.name not in facts["names"]:
            return False
        start, end = facts["not_before"], facts["not_after"]
        return end - time.time() > (end - start) / 3

    def csr(self) -> str:
        """A certificate request for its name, made with its own key (made once)."""
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self.key.exists():
            _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.key))
            os.chmod(self.key, 0o600)
        return _openssl(
            "req", "-new", "-key", str(self.key), "-subj", f"/CN={self.name}",
            "-addext", f"subjectAltName=DNS:{self.name}", "-sha256",
        )  # fmt: skip

    def take(self, pem: str) -> bool:
        """The shop's answer: kept and served if it's for this key and name."""
        if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem or len(pem) > 32768:
            return False
        if not self.key.exists() or not self.name:
            return False
        tmp = self.dir / "cert.pem.new"
        try:
            tmp.write_text(pem)
            ctx = _context(tmp, self.key)
        except (ssl.SSLError, OSError, ValueError) as e:
            log.warning("the certificate the shop sent doesn't fit this bridge's key: %s", e)
            tmp.unlink(missing_ok=True)
            return False
        facts = _facts(tmp)
        if facts is None or self.name not in facts["names"]:
            tmp.unlink(missing_ok=True)
            return False
        tmp.replace(self.cert)
        self.context = ctx
        log.info("live video: certificate for %s until %s", self.name, facts["until"])
        self.start()
        return True

    # ── the listener ────────────────────────────────────────────────────────

    def start(self) -> None:
        if self.server is not None or not self.port:
            return
        if self.context is None:
            try:
                self.context = _context(self.cert, self.key)
            except (ssl.SSLError, OSError):
                return
        live = self

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                sock, addr = self.socket.accept()
                # the handshake on the handler's thread, never the listener's
                try:
                    context = live.context
                    if context is None:  # (stopping)
                        raise OSError("stopped")
                    return context.wrap_socket(
                        sock, server_side=True, do_handshake_on_connect=False
                    ), addr
                except (ssl.SSLError, OSError):
                    sock.close()
                    raise

            def verify_request(self, request, client_address):
                if live.slots.acquire(blocking=False):
                    return True
                log.debug("live video: too many connections at once")
                return False

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    live.slots.release()

            def handle_error(self, request, client_address):
                # a failed handshake or a viewer gone: anyone on the network can
                # knock, so a line at debug, never a traceback in the log
                log.debug("live video: a connection from %s ended badly", client_address[0])

        try:
            self.server = Server(("0.0.0.0", self.port), _handler(self))
        except OSError as e:
            log.warning("live video: port %s isn't free (%s): pictures only", self.port, e)
            return
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        log.info("live video on https://%s:%s", self.name, self.port)

    def stop(self) -> None:
        self.secret, self.context = None, None  # (no ticket opens anything now)
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    # ── tickets ─────────────────────────────────────────────────────────────

    def check(self, ticket: str) -> str | None:
        """The camera address a ticket opens, once; None if it doesn't."""
        if self.secret is None or not isinstance(ticket, str) or len(ticket) > 2048:
            return None
        body, _, sig = ticket.partition(".")
        want = base64.urlsafe_b64encode(
            hmac.new(self.secret, body.encode(), hashlib.sha256).digest()
        ).rstrip(b"=")
        if not hmac.compare_digest(want, sig.encode()):
            return None
        try:
            data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("b") != self.ref:
            return None
        url, until, nonce = data.get("u"), data.get("x"), data.get("n")
        now = time.time()
        if not (isinstance(url, str) and isinstance(nonce, str) and isinstance(until, int)):
            return None
        if not now < until <= now + LONGEST_TICKET:
            return None
        with self.lock:
            self.used = {n: x for n, x in self.used.items() if x > now}
            if nonce in self.used:
                return None
            self.used[nonce] = until
        return url

    def watch(self, url: str) -> bool:
        with self.lock:
            if self.watching.get(url, 0) >= VIEWERS:
                return False
            self.watching[url] = self.watching.get(url, 0) + 1
            return True

    def done(self, url: str) -> None:
        with self.lock:
            self.watching[url] = max(0, self.watching.get(url, 1) - 1)


def _handler(live: Live):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Ordryx-Bridge"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(15)
            try:
                self.connection.do_handshake()
            except (ssl.SSLError, OSError):
                self.close_connection = True
                raise

        def _head(self, status: int, kind: str = "application/json", length: int | None = None):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            # (what a camera sends is never a page, opened alone or not)
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
            if live.origin and self.headers.get("Origin") == live.origin:
                self.send_header("Access-Control-Allow-Origin", live.origin)
            self.send_header("Vary", "Origin")
            if length is not None:
                self.send_header("Content-Length", str(length))
            self.end_headers()

        def _json(self, status: int, data: dict):
            raw = json.dumps(data).encode()
            self._head(status, length=len(raw))
            self.wfile.write(raw)

        def do_OPTIONS(self):  # a browser asking before it reaches a private address
            self.send_response(204)
            if live.origin and self.headers.get("Origin") == live.origin:
                self.send_header("Access-Control-Allow-Origin", live.origin)
                self.send_header("Access-Control-Allow-Methods", "GET")
                self.send_header("Access-Control-Allow-Private-Network", "true")
            self.send_header("Vary", "Origin")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            if u.path == "/health":
                return self._json(200, {"ok": True})
            if u.path != "/cam":
                return self._json(404, {"detail": "not here"})
            ticket = dict(urllib.parse.parse_qsl(u.query)).get("t", "")
            url = live.check(ticket)
            if url is None:
                return self._json(403, {"detail": "that ticket isn't good (any more)"})
            try:
                u = calls.check("GET", url, live.reach())
                if (("GET", u.path) in calls.ALLOWED) or not live.known.camera_host(u.hostname):
                    raise calls.Refused("not allowed: no camera there")
            except calls.Refused as e:
                return self._json(403, {"detail": str(e)})
            if not live.watch(url):
                return self._json(429, {"detail": "that camera has enough viewers now"})
            try:
                self._relay(url)
            finally:
                live.done(url)

        def _relay(self, url: str):
            req = urllib.request.Request(url, headers={"User-Agent": "Ordryx-Bridge"})
            try:
                r = calls._opener.open(req, timeout=8)
            except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError):
                return self._json(502, {"detail": "the camera isn't answering"})
            with contextlib.closing(r):
                kind = r.headers.get("Content-Type") or ""
                base = kind.split(";")[0].strip().lower()
                if base not in STREAMS and base not in calls.PICTURES:
                    return self._json(502, {"detail": "that isn't a camera"})
                self._head(200, kind)
                until = time.monotonic() + STREAM_SECONDS
                try:
                    # (a removed bridge's secret is gone: its viewers end with it)
                    host = urllib.parse.urlsplit(url).hostname or ""
                    looked = time.monotonic()
                    while time.monotonic() < until and live.secret is not None:
                        if time.monotonic() - looked > REACH_EVERY:
                            looked = time.monotonic()
                            # (its reach tightened since it opened: this viewer too)
                            if not calls.may_reach(host, live.reach()):
                                break
                        chunk = r.read1(64 * 1024) if hasattr(r, "read1") else r.read(65536)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                except (OSError, http.client.HTTPException):
                    pass  # the viewer left, or the camera dropped
            self.close_connection = True

        def log_message(self, *a):
            pass

    return Handler


def _context(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _facts(path: Path) -> dict | None:
    """The first certificate's names and dates."""
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        start, end = _when(cert, "not_valid_before"), _when(cert, "not_valid_after")
    except Exception:  # (whatever is odd about it: not one this bridge serves)
        return None
    until = datetime.fromtimestamp(end, timezone.utc).date().isoformat()
    return {"names": names, "not_before": start, "not_after": end, "until": until}


def _when(cert, field: str) -> float:
    """A certificate's date, in seconds (an older ``cryptography`` has only the
    naive one, in UTC)."""
    when = getattr(cert, field + "_utc", None)
    if when is None:
        when = getattr(cert, field).replace(tzinfo=timezone.utc)
    return when.timestamp()


def _openssl(*args: str) -> str:
    try:
        out = subprocess.run(
            ["openssl", *args], capture_output=True, text=True, timeout=30, check=False
        )
    except subprocess.TimeoutExpired:
        raise OSError(f"openssl {args[0]}: no answer in 30 seconds") from None
    if out.returncode != 0:
        raise OSError(f"openssl {args[0]}: {out.stderr.strip()[:200]}")
    return out.stdout


def port_from_env() -> int:
    """ORDRYX_BRIDGE_HTTPS_PORT (7443 by default; 0: no live video)."""
    raw = os.environ.get("ORDRYX_BRIDGE_HTTPS_PORT", "")
    try:
        port = int(raw) if raw else PORT
    except ValueError:
        return PORT
    return port if 0 <= port <= 65535 else PORT
