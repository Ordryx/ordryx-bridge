"""The bridge's life: pair through the Ordryx account (a code
shown here, entered in the shop), then keep a connection out to the shop and
answer its calls.

Files, in its folder (ORDRYX_BRIDGE_DIR, default ~/.ordryx-bridge; never in
printer_data, whose files Mainsail lets anyone on the network download):
``link.key`` (its Ed25519 key, 0600, never sent) and ``state.json`` (the
shop it's paired with, or the code it's showing). Its settings file
(ORDRYX_BRIDGE_CONF, default ~/printer_data/config/ordryx-bridge.conf when
that folder exists) may set a limit Ordryx can tighten but never loosen:
``reach: this-computer`` or ``discovery: off``.

Standard library, ``websockets`` and ``cryptography`` (keys.py), nothing of
Ordryx's: it installs on its own. Python 3.9.
"""

from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import contextlib
import http.client
import json
import logging
import os
import platform
import shutil
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import PROTOCOL, __version__, calls, feed, keys, live, scan

log = logging.getLogger("ordryx_bridge")

ACCOUNT = "https://account.ordryx.com"
CLAIM_SECONDS = 3.0
PING_SECONDS = 30.0
TICK_SECONDS = 30.0  # how often a connection looks at its settings file and offers
RENEW_SECONDS = 12 * 3600.0  # how often a connected bridge checks its certificate
AT_ONCE = 32  # calls being carried at once (each printer limited by the shop too)
OFFERS_MOST = 16
WATCH_SECONDS = 2.0  # how often each of its printers is asked what it's doing
WATCH_MOST = 64
REMOVED = 4403  # (the shop's close code: it no longer knows this bridge)
# The longest wait between tries. A shop that's updated is away a few minutes,
# and says "Bridge lost" two checks (two minutes) after it's back.
LONGEST_WAIT = 60.0


class Paths:
    def __init__(self) -> None:
        self.dir = Path(os.environ.get("ORDRYX_BRIDGE_DIR") or Path.home() / ".ordryx-bridge")
        conf = os.environ.get("ORDRYX_BRIDGE_CONF")
        default = Path.home() / "printer_data" / "config"
        self.conf = (
            Path(conf)
            if conf
            else (
                default / "ordryx-bridge.conf"
                if default.is_dir()
                else self.dir / "ordryx-bridge.conf"
            )
        )
        self.state = self.dir / "state.json"
        self.said_unreadable = False
        self.offers = self.dir / "offers.json"

    def key(self):
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        k = keys.load(self.dir)
        if k is None:
            k = keys.new_key()
            keys.save(self.dir, k)
        return k

    def leave(self, account: str) -> None:
        """Not this shop's any more: nothing of it stays. A new key, so a shop
        it once belonged to holds nothing that speaks for it at the next, and
        its name and certificate go."""
        keys.forget(self.dir)
        shutil.rmtree(self.dir / "https", ignore_errors=True)
        self.offers.unlink(missing_ok=True)
        self.write({"account": account})

    def read(self) -> dict:
        """What it knows. No file: nothing yet. A failed read raises (OSError):
        taken for "not paired", the code it shows next would overwrite its pairing."""
        try:
            data = json.loads(self.state.read_text())
        except (FileNotFoundError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def write(self, data: dict) -> None:
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.state.with_suffix(f".{os.getpid()}.tmp")
        tmp.unlink(missing_ok=True)
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
            out.write(json.dumps(data, indent=2))
        tmp.replace(self.state)


def ceiling(paths: Paths) -> str | None:
    """The tightest reach its settings file allows, if it sets one. A limit is
    someone's decision: a file that can't be read, or a value that isn't one of
    the choices, is the tightest there is, never none."""
    try:
        lines = paths.conf.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        if not paths.said_unreadable:  # (asked on every call: said once)
            paths.said_unreadable = True
            log.warning("%s can't be read (%s): this computer only until it can", paths.conf, e)
        return calls.THIS_COMPUTER
    got = None
    for line in lines:
        # (either separator, as Klipper's and Moonraker's own files take)
        k, _, v = line.replace("=", ":", 1).partition(":")
        k, v = k.strip().lower(), v.split("#", 1)[0].strip().lower()
        if k == "reach":
            limit = v if v in calls.REACHES else calls.THIS_COMPUTER
        elif k == "discovery" and v in ("on", "yes", "true"):
            continue
        elif k == "discovery":
            limit = calls.TYPED if v in ("off", "no", "false") else calls.THIS_COMPUTER
        else:
            continue
        got = calls.tighter(got, limit) if got else limit
    return got


def shop_url_ok(url) -> bool:
    """Its shop's address, wherever it came from: HTTPS, or plain only to this
    computer (development). The connection carries printers' keys and calls."""
    if not isinstance(url, str) or len(url) > 300:
        return False
    try:
        u = urllib.parse.urlsplit(url)
        u.port  # noqa: B018 (raises on one that isn't a port)
    except ValueError:
        return False
    if u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        return False
    if u.scheme == "https":
        return bool(u.hostname)
    return u.scheme == "http" and u.hostname == "127.0.0.1"


def lan_address() -> str | None:
    """This computer's address on the shop's network (nothing is sent)."""
    with contextlib.suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # (TEST-NET: no packet leaves for a UDP connect)
        ip = s.getsockname()[0]
        return ip if keys.private_ipv4(ip) else None
    return None


def facts() -> dict:
    here = scan.probe("127.0.0.1", 7125) is not None
    if os.environ.get("ORDRYX_BRIDGE_KIND") in ("pi", "linux", "docker"):
        kind = os.environ["ORDRYX_BRIDGE_KIND"]
    elif Path("/.dockerenv").exists():
        kind = "docker"
    else:
        kind = "pi" if here else "linux"
    name = os.environ.get("ORDRYX_BRIDGE_NAME") or socket.gethostname().removesuffix(".local")
    return {"moonraker_here": here, "kind": kind, "hostname": name[:60]}


_ACCOUNT_OPENER = urllib.request.build_opener(calls._NoRedirects)


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Ordryx-Request": "1",
            "User-Agent": f"Ordryx-Bridge/{__version__}",
        },
        method="POST",
    )
    try:
        with _ACCOUNT_OPENER.open(req, timeout=15) as r:
            raw, status = r.read(65536), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(65536), e.code
    except (OSError, ValueError, http.client.HTTPException) as e:
        return 0, {"detail": f"no answer: {type(e).__name__}"}
    try:
        data = json.loads(raw or b"{}")
    except (ValueError, RecursionError):
        data = {}
    return status, data if isinstance(data, dict) else {}


def banner(code: str, fingerprint: str) -> None:
    print(
        "\n  Connect it to your shop\n\n"
        "    In Ordryx, open  Printers › Printer setup › Add a bridge\n"
        "    and enter:\n\n"
        f"                  {code}\n\n"
        f"    Fingerprint {fingerprint} (Ordryx shows the same)\n",
        flush=True,
    )


def pair(paths: Paths, account: str, key, stop=lambda: False) -> dict:
    """Show a code and wait until a shop approves it: the shop it's paired with."""
    pub = keys.public_b64(key)
    f = facts()
    kept = paths.read()  # (a restart keeps showing the code it had, while it's good)
    while not stop():
        if kept.get("code") and kept.get("request"):
            status, got = 200, kept
            kept = {}
        else:
            status, got = _post(
                account + "/api/bridges/v1/requests",
                {
                    "public_key": pub,
                    "label": f["hostname"],
                    "version": __version__,
                    "moonraker_here": f["moonraker_here"],
                    "kind": f["kind"],
                },
            )
        if (
            status != 200
            or not isinstance(got.get("code"), str)
            or not isinstance(got.get("request"), str)
        ):
            log.warning(
                "couldn't get a code (%s): trying again in a minute", got.get("detail") or status
            )
            time.sleep(60)
            continue
        paths.write({"account": account, "code": got["code"], "request": got["request"]})
        banner(got["code"], keys.fingerprint(pub))
        print("  Waiting…  (Ctrl-C to stop; the service keeps waiting)", flush=True)
        while not stop():
            time.sleep(CLAIM_SECONDS)
            at = datetime.now(timezone.utc).isoformat()
            status, said = _post(
                account + "/api/bridges/v1/claim",
                {
                    "request": got["request"],
                    "signed_at": at,
                    "signature": keys.sign(key, "bridge-claim", got["request"], at),
                },
            )
            if status == 404:
                break  # ran out: a new code
            if status == 401 and said.get("clock") == "off":
                log.warning("this computer's clock is off: set its date and time right")
            elif status == 401:
                break  # (a code asked with another key, kept from before: a new one)
            if status == 200 and said.get("state") == "approved":
                if not shop_url_ok(said.get("shop_url")) or not isinstance(said.get("bridge"), str):
                    log.warning("the shop's address isn't one this bridge connects to: a new code")
                    break
                state = {
                    "account": account,
                    "shop_url": said["shop_url"],
                    "bridge": said["bridge"],
                    "name": said.get("name") or "",
                }
                paths.write(state)
                print(f"  ✓ Approved as {state['name']} for {state['shop_url']}", flush=True)
                return state
    return {}


class Connection:
    def __init__(self, paths: Paths, state: dict, key) -> None:
        self.paths, self.state, self.key = paths, state, key
        self.reach = calls.THIS_COMPUTER  # until the shop's welcome says
        self.told: str | None = None
        self.lan: str | None = None  # (at each connection: it can change)
        self.facts = facts()
        self.known = calls.Known()
        u = urllib.parse.urlsplit(state["shop_url"])
        self.live = live.Live(
            paths.dir,
            live.port_from_env(),
            self.allowed,
            self.known,
            origin=f"{u.scheme}://{u.netloc}",
        )
        self.pool = concurrent.futures.ThreadPoolExecutor(AT_ONCE, thread_name_prefix="bridge")
        self.looking: asyncio.Lock | None = None  # (made on its event loop)

    def allowed(self) -> str:
        return calls.tighter(self.reach, ceiling(self.paths))

    async def run(self) -> str:
        """Keep connected; returns "removed" when the shop forgot this bridge."""
        from websockets.asyncio.client import connect
        from websockets.exceptions import ConnectionClosed, WebSocketException

        class connect_here(connect):
            """Its shop's address, or nowhere: never where an answer redirects."""

            def process_redirect(self, exc):
                return exc

        self.looking = asyncio.Lock()
        u = urllib.parse.urlsplit(self.state["shop_url"])
        scheme = "wss" if u.scheme == "https" else "ws"
        url = f"{scheme}://{u.netloc}/api/printers/bridge/connect"
        wait = 5.0
        while True:
            try:
                if not self.paths.read().get("bridge"):  # (ordryx-bridge unpair, here)
                    return "left"
                # (what the shop sends is small: the largest is a certificate)
                async with connect_here(url, max_size=1024 * 1024, open_timeout=15) as ws:
                    first = json.loads(await asyncio.wait_for(ws.recv(), 10))
                    nonce = first.get("nonce") if isinstance(first, dict) else None
                    if not isinstance(nonce, str):
                        raise ConnectionError("no challenge")
                    ref = self.state["bridge"]
                    self.told = ceiling(self.paths)  # (ticker: what the shop last heard)
                    self.lan = lan_address()
                    await ws.send(
                        json.dumps(
                            {
                                "type": "hello",
                                "bridge": ref,
                                "protocol": PROTOCOL,
                                "version": __version__,
                                "ceiling": self.told,
                                "lan_address": self.lan,
                                "https_port": self.live.port or None,
                                **self.facts,
                                "signature": keys.sign(
                                    self.key, "bridge", nonce, ref, self.state["shop_url"]
                                ),
                            }
                        )
                    )
                    welcome = json.loads(await asyncio.wait_for(ws.recv(), 10))
                    if not isinstance(welcome, dict) or welcome.get("type") != "welcome":
                        raise ConnectionError("no welcome")
                    self.reach = (
                        welcome.get("reach")
                        if welcome.get("reach") in calls.REACHES
                        else calls.THIS_COMPUTER
                    )
                    log.info(
                        "connected to %s as %s (reaches: %s)",
                        self.state["shop_url"],
                        welcome.get("name"),
                        self.allowed(),
                    )
                    print(f"  ✓ Connected to {self.state['shop_url']}", flush=True)
                    wait = 5.0
                    if await self._serve(ws) == "left":
                        return "left"
            except ConnectionClosed as e:
                code = e.rcvd.code if e.rcvd else None
                if code == REMOVED:
                    return "removed"
                log.info("connection closed (%s): again in %.0f s", code, wait)
            except (OSError, asyncio.TimeoutError, WebSocketException, ValueError) as e:
                log.info("can't reach the shop (%s): again in %.0f s", e, wait)
            await asyncio.sleep(wait)
            wait = min(wait * 2, LONGEST_WAIT)

    def _doing(self, base: str) -> str:
        """What the printer at ``base`` is doing now ("printing", "paused",
        "complete"…; "offline": it didn't say), asked as any call is: only of an
        address that answered as Moonraker, with the key the shop last sent."""
        u = urllib.parse.urlsplit(base)
        at = (u.hostname or "", 80 if u.port is None else u.port)
        with self.known.lock:
            key = self.known.keys.get(at)
        out = calls.call(
            {
                "method": "GET",
                "url": base + "/printer/objects/query?print_stats",
                "headers": {"X-Api-Key": key} if key else {},
                "timeout": 3.0,
            },
            self.allowed(),
            self.known,
        )
        if out.get("status") != 200:
            return "offline"
        try:
            stats = json.loads(base64.b64decode(out["body"]))["result"]["status"]["print_stats"]
            state = stats["state"]
        except (ValueError, KeyError, TypeError):
            return "offline"
        return state[:24] if isinstance(state, str) else "offline"

    def _offers(self) -> list:
        """What ``ordryx-bridge add`` left for the shop: taken once. Moved aside
        first, so one written while this reads starts a file of its own."""
        taking = self.paths.offers.with_suffix(".taking")
        try:
            self.paths.offers.replace(taking)
            data = json.loads(taking.read_text())
        except (OSError, ValueError):
            return []
        finally:
            taking.unlink(missing_ok=True)
        return data[:OFFERS_MOST] if isinstance(data, list) else []

    async def _serve(self, ws) -> str | None:
        from websockets.exceptions import ConnectionClosed

        loop = asyncio.get_running_loop()
        left = asyncio.Event()

        async def pinger():
            while True:
                await asyncio.sleep(PING_SECONDS)
                await ws.send(json.dumps({"type": "ping"}))

        async def ticker():
            """The computer's own say, while connected: a limit in its settings
            file, a printer offered there, an unpair."""
            while True:
                await asyncio.sleep(TICK_SECONDS)
                try:
                    if await tick_once():
                        return
                except ConnectionClosed:
                    return
                except Exception:  # (one odd tick never stops the next)
                    log.exception("a look at this computer's own say didn't finish")

        async def tick_once() -> bool:
            try:
                paired = self.paths.read().get("bridge")
            except OSError:
                return False  # (asked again in a moment)
            if not paired:
                left.set()
                await ws.close()
                return True
            now = ceiling(self.paths)
            if now != self.told:
                self.told = now
                log.info("now reaches: %s", self.allowed())
                await ws.send(json.dumps({"type": "ceiling", "ceiling": now}))
            offers = await loop.run_in_executor(self.pool, self._offers)
            if offers:
                await ws.send(json.dumps({"type": "offer", "found": offers}))
            return False

        async def answer(msg: dict):
            try:
                await carried(msg)
            except ConnectionClosed:
                pass  # (the connection went while it was asked)
            except Exception:  # one odd call never takes the others with it
                log.exception("a call didn't finish")
                with contextlib.suppress(ConnectionClosed):
                    await ws.send(
                        json.dumps({"type": "answer", "id": msg.get("id"), "error": "unreachable"})
                    )

        async def carried(msg: dict):
            kind = msg.get("type")
            if kind == "call":
                out = await loop.run_in_executor(
                    self.pool, calls.call, msg, self.allowed(), self.known
                )
            elif kind == "scan":
                if self.allowed() == calls.TYPED:
                    out = {"found": [], "other": 0, "error": "looking is off on this bridge"}
                else:
                    async with self.looking:  # (one at a time, whatever's asked)
                        out = await loop.run_in_executor(
                            self.pool, scan.look, self.allowed(), self.lan, self.known
                        )
            else:
                return
            await ws.send(json.dumps({**out, "type": "answer", "id": msg.get("id")}))

        async def certificate():
            """Asks for one when it has none or it's two-thirds through its life."""
            while True:
                if self.live.name and not self.live.fresh():
                    try:
                        pem = await loop.run_in_executor(self.pool, self.live.csr)
                    except OSError as e:
                        log.warning("live video: no certificate request (%s)", e)
                    else:
                        await ws.send(json.dumps({"type": "csr", "pem": pem}))
                elif self.live.name:
                    await loop.run_in_executor(self.pool, self.live.start)
                await renew.wait()
                renew.clear()

        async def clock():
            while True:
                await asyncio.sleep(RENEW_SECONDS)
                renew.set()

        async def watcher():
            """What each of the shop's printers is doing, asked here (a short hop)
            and said the moment it changes: the shop records a finished print,
            and alerts a failed one, then and not at its next look."""
            said: dict[str, str] = {}
            while True:
                await asyncio.sleep(WATCH_SECONDS)
                for base in list(watching):
                    try:
                        now = await loop.run_in_executor(self.pool, self._doing, base)
                    except Exception:  # (one odd printer never stops the rest)
                        log.exception("a printer wasn't asked what it's doing")
                        continue
                    if said.get(base) != now:
                        said[base] = now
                        await ws.send(json.dumps({"type": "state", "printer": base, "state": now}))
                for gone in set(said) - set(watching):
                    del said[gone]

        def feeding(sid, url, stopped):
            """One camera's pictures, up the connection (a thread of its own)."""

            def out(frame: bytes) -> bool:
                payload = json.dumps(
                    {"type": "frame", "id": sid, "data": base64.b64encode(frame).decode()}
                )
                try:
                    asyncio.run_coroutine_threadsafe(ws.send(payload), loop).result(timeout=10)
                except Exception:  # (the connection went, or is too slow for pictures)
                    return False
                return True

            why = "unreachable"
            try:
                why = feed.send(url, self.allowed, self.known, out, stopped)
            except Exception:
                log.exception("a camera's pictures stopped")
            finally:
                feeds.pop(sid, None)
                end = json.dumps({"type": "stream_end", "id": sid, "error": why})
                with contextlib.suppress(Exception):
                    asyncio.run_coroutine_threadsafe(ws.send(end), loop).result(timeout=5)

        watching: list[str] = []  # the shop's printers here, as it last listed them
        feeds: dict[int, threading.Event] = {}  # cameras being sent, each with its stop
        renew = asyncio.Event()
        ping = asyncio.create_task(pinger())
        watch = asyncio.create_task(watcher())
        tick = asyncio.create_task(ticker())
        certs = asyncio.create_task(certificate())
        ticking = asyncio.create_task(clock())
        working: set[asyncio.Task] = set()  # (answers under way, kept till done)
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(msg, dict):
                    continue
                if msg.get("type") == "reach" and msg.get("reach") in calls.REACHES:
                    self.reach = msg["reach"]
                    log.info("now reaches: %s", self.allowed())
                elif msg.get("type") == "https" and self.live.port:
                    name, secret = msg.get("name"), msg.get("tickets")
                    if (
                        isinstance(name, str)
                        and isinstance(secret, str)
                        and len(secret) >= 32
                        and self.live.configure(name, self.state["bridge"], secret)
                    ):
                        renew.set()
                elif msg.get("type") == "cert":
                    ok = await loop.run_in_executor(self.pool, self.live.take, msg.get("pem"))
                    if not ok:
                        log.warning("live video: the shop's certificate didn't fit")
                elif msg.get("type") == "cert_error":
                    log.info("live video: no certificate yet (%s)", str(msg.get("error"))[:200])
                elif msg.get("type") == "watch" and isinstance(msg.get("printers"), list):
                    watching[:] = [p for p in msg["printers"] if isinstance(p, str)][:WATCH_MOST]
                elif msg.get("type") == "stream":
                    sid, url = msg.get("id"), msg.get("url")
                    if not isinstance(sid, int) or not isinstance(url, str) or len(url) > 2000:
                        continue
                    if sid in feeds or len(feeds) >= feed.AT_ONCE:
                        busy = {"type": "stream_end", "id": sid, "error": "timeout"}
                        await ws.send(json.dumps(busy))
                        continue
                    feeds[sid] = threading.Event()
                    threading.Thread(
                        target=feeding, args=(sid, url, feeds[sid]), daemon=True
                    ).start()
                elif msg.get("type") == "stream_stop":
                    stop = feeds.get(msg.get("id")) if isinstance(msg.get("id"), int) else None
                    if stop is not None:
                        stop.set()
                elif msg.get("type") in ("call", "scan"):
                    task = asyncio.create_task(answer(msg))
                    working.add(task)
                    task.add_done_callback(working.discard)
        finally:
            for stop in list(feeds.values()):  # (no connection: no pictures to send)
                stop.set()
            watch.cancel()
            ping.cancel()
            tick.cancel()
            certs.cancel()
            ticking.cancel()
        return "left" if left.is_set() else None


def only_one(paths: Paths):
    """This folder's one running bridge: a lock held for as long as it runs
    (the open file; None: another has it). Two would each show a code and
    write over the other's pairing: ``ordryx-bridge`` run by hand beside the
    service, say."""
    import fcntl

    paths.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    held = open(paths.dir / "running.lock", "w")  # noqa: SIM115 (kept open: that's the lock)
    try:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        held.close()
        return None
    return held


def run(account: str) -> int:
    paths = Paths()
    held = only_one(paths)
    if held is None:
        print(
            "The bridge is already running on this computer (its service, most likely).\n"
            "Its state: ordryx-bridge status. Its code: ordryx-bridge code."
        )
        return 1
    key = paths.key()
    while True:
        state = paths.read()
        if not state.get("bridge"):
            state = pair(paths, state.get("account") or account, key)
        if not shop_url_ok(state.get("shop_url")):
            print("  This bridge's shop address isn't one it connects to. Showing a new code.")
            paths.leave(state.get("account") or account)
            key = paths.key()
            continue
        conn = Connection(paths, state, key)
        result = asyncio.run(conn.run())
        conn.live.stop()
        conn.pool.shutdown(wait=False)
        print(
            f"  This bridge left {state.get('shop_url')}. Showing a new code.",
            flush=True,
        )
        if result == "removed":  # (an unpair at the computer already cleared its files)
            paths.leave(state.get("account") or account)
        key = paths.key()


def status() -> int:
    paths = Paths()
    state = paths.read()
    try:
        key = keys.load(paths.dir)
    except (OSError, ValueError) as e:
        print(f"\n  Its key at {paths.dir / keys.KEY_FILE} can't be read: {e}")
        key = None
    print(f"\n  Ordryx Bridge {__version__} (protocol {PROTOCOL}) on {platform.node()}")
    if key is not None:
        print(f"  Fingerprint  {keys.fingerprint(keys.public_b64(key))}")
    if state.get("bridge"):
        print(f"  Shop         {state.get('shop_url')}  as {state.get('name') or state['bridge']}")
    elif state.get("code"):
        print(f"  Not paired yet. Code: {state['code']}")
    else:
        print("  Not paired yet.")
    c = ceiling(paths)
    print(f"  Limit        {c or 'none'} (set in {paths.conf})")
    port = live.port_from_env()
    cert = live._facts(paths.dir / "https" / "cert.pem") if port else None
    if not port:
        print("  Live video   off (ORDRYX_BRIDGE_HTTPS_PORT=0): pictures only")
    elif cert and cert["names"]:
        print(f"  Live video   https://{cert['names'][0]}:{port} until {cert['until']}")
    else:
        print(f"  Live video   no certificate yet (port {port}): pictures until then")
    print()
    return 0


def code() -> int:
    state = Paths().read()
    if state.get("bridge"):
        print(f"Already paired with {state.get('shop_url')}. To pair again: ordryx-bridge unpair")
        return 1
    if not state.get("code"):
        print("No code yet: is the bridge running? (systemctl status ordryx-bridge)")
        return 1
    print(state["code"])
    return 0


def unpair() -> int:
    paths = Paths()
    state = paths.read()
    if not state.get("bridge"):
        print("This bridge isn't paired with a shop.")
        return 0
    paths.leave(state.get("account") or ACCOUNT)
    print("Unpaired, with a new key. A running bridge shows a new code within a minute.")
    print("Remove it from the shop's Printer setup too, if it's still listed there.")
    return 0


def add(address: str) -> int:
    """``ordryx-bridge add <address>``: this computer checks it and offers it to
    the shop, for a person to add there. Nothing is added by itself."""
    paths = Paths()
    try:
        u = urllib.parse.urlsplit(address if "://" in address else f"http://{address}")
        port = u.port or (80 if "://" in address else 7125)
    except ValueError:
        print("That isn't an address: use one like 192.168.1.50 or 192.168.1.50:7125.")
        return 1
    limit = calls.tighter(calls.LOOK, ceiling(paths))
    if not calls.may_reach(u.hostname or "", limit):
        print(f"This bridge doesn't reach {u.hostname} (it reaches: {limit}).")
        return 1
    found = scan.probe(u.hostname, port)
    if found is None:
        print(f"Nothing at {u.hostname}:{port} answers as a printer's Moonraker.")
        return 1
    try:
        have = json.loads(paths.offers.read_text())
    except (OSError, ValueError):
        have = []
    have = have if isinstance(have, list) else []
    paths.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = paths.offers.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(json.dumps([*have, found][-OFFERS_MOST:]))
    tmp.replace(paths.offers)
    print(f"  ✓ Offered {found['address']} to the shop: add it in Printer setup › Add a printer.")
    return 0


def _plain(text: str) -> str:
    """What a printer said, fit for a terminal: nothing that could move its
    cursor or recolour it."""
    return "".join(c for c in text if c.isprintable() and c.isascii())


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="ordryx-bridge")
    p.add_argument(
        "command",
        nargs="?",
        default="run",
        choices=("run", "status", "code", "unpair", "scan", "add", "version"),
    )
    p.add_argument("address", nargs="?", help="for add: the printer's address on this network")
    args = p.parse_args(argv)
    if args.command == "version":
        print(f"{__version__} (protocol {PROTOCOL})")
        return 0
    if args.command == "add":
        if not args.address:
            p.error("add needs the printer's address")
        return add(args.address)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", stream=sys.stderr)
    account = (os.environ.get("ORDRYX_BRIDGE_ACCOUNT") or ACCOUNT).rstrip("/")
    if args.command == "run":
        try:
            return run(account)
        except KeyboardInterrupt:
            return 0
    if args.command == "scan":
        out = scan.look(calls.tighter(calls.LOOK, ceiling(Paths())), lan_address())
        for f in out["found"]:
            print(
                f"  ✓ {_plain(f['hostname']) or '?':12} {f['address']:28} "
                f"{_plain(f['klipper']) or 'needs a key'}"
                f"  {f['cameras']} camera(s)"
            )
        print(f"  · {out['other']} other device(s), left alone")
        return 0
    return {"status": status, "code": code, "unpair": unpair}[args.command]()
