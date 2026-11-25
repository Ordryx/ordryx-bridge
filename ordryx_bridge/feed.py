"""A camera's pictures sent up to the shop, for someone watching away from the
shop's network (on it, live.py serves the stream itself). The bridge reads the
camera's MJPEG stream here, where it's a short hop, and sends single pictures
up its connection: the newest one, a few a second, never more bytes a second
than ``BYTES_A_SECOND``. Pictures it has no room to send are dropped, so what
arrives is always now, never a backlog.

The camera's address is checked as any camera call's is (calls.py): on a host
that answered as Moonraker, never one of Moonraker's own paths, and only a
stream of JPEG pictures is passed on.

Standard library only. Python 3.9.
"""

from __future__ import annotations

import contextlib
import http.client
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import calls

FRAMES_A_SECOND = 5.0
BYTES_A_SECOND = 600_000  # per camera, up the connection (a hosted shop passes it on)
MOST_FRAME = 1024 * 1024
MOST_BUFFER = 4 * MOST_FRAME
MOST_SECONDS = 15 * 60  # the shop stops a feed nobody watches; this is the backstop
AT_ONCE = 4  # cameras being sent at once
STREAMS = ("multipart/x-mixed-replace",)
SOI, EOI = b"\xff\xd8", b"\xff\xd9"
LENGTH = re.compile(rb"content-length:\s*(\d{1,8})\s*\r\n", re.I)


class Frames:
    """JPEG pictures out of an MJPEG stream, as its bytes come: by each part's
    Content-Length where the camera says it (every common one does), else from
    one picture's start to its end mark."""

    def __init__(self) -> None:
        self.buffer = b""
        self.since = 0  # bytes read since the last picture

    def feed(self, data: bytes) -> list[bytes]:
        self.buffer += data
        self.since += len(data)
        out = []
        while True:
            frame = self._next()
            if frame is None:
                break
            if frame:
                out.append(frame)
        if out:
            self.since = 0
        elif self.since > MOST_BUFFER:  # (whatever this is, it isn't a camera's pictures)
            raise ValueError("no picture in what the camera sent")
        return out

    def _next(self) -> bytes | None:
        """A picture, b"" for one skipped (too big), None when more is needed."""
        buf = self.buffer
        head = buf.find(b"\r\n\r\n")
        start = buf.find(SOI)
        if head != -1 and (start == -1 or head < start):
            said = LENGTH.search(buf[: head + 4] + b"\r\n")
            body = head + 4
            if said:
                n = int(said.group(1))
                if n > MOST_FRAME:
                    if len(buf) < body + n:
                        return None
                    self.buffer = buf[body + n :]
                    return b""
                if len(buf) < body + n:
                    return None
                frame, self.buffer = buf[body : body + n], buf[body + n :]
                return frame if frame.startswith(SOI) else b""
            start = buf.find(SOI, body)
        if start == -1:
            # (nothing of a picture yet: keep only what could be the start of one)
            self.buffer = buf[-3:] if head == -1 else buf[head:]
            return None
        end = buf.find(EOI, start + 2)
        if end == -1:
            self.buffer = buf[start:]
            return None
        frame, self.buffer = buf[start : end + 2], buf[end + 2 :]
        return frame if len(frame) <= MOST_FRAME else b""


def send(
    url, reach, known: calls.Known, out, stopped: threading.Event, clock=time.monotonic
) -> str:
    """Read the camera at ``url`` and hand ``out`` each picture to send, until
    ``stopped``, the camera ends, or the bridge may no longer reach it.
    ``reach``: () -> the bridge's reach now. Returns why it ended, a word for
    the shop ("" when it was asked to stop)."""
    try:
        u = calls.check("GET", url, reach())
        if ("GET", u.path) in calls.ALLOWED or not known.camera_host(u.hostname or ""):
            return "not allowed: no camera there"
    except calls.Refused as e:
        return str(e)
    except calls._Failed as e:
        return str(e)
    req = urllib.request.Request(url, headers={"User-Agent": "Ordryx-Bridge"})
    try:
        r = calls._opener.open(req, timeout=8)
    except (urllib.error.URLError, OSError, http.client.HTTPException, ValueError):
        return "unreachable"
    with contextlib.closing(r):
        kind = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if kind not in STREAMS:
            return "not allowed: only a camera's stream"
        frames, host = Frames(), u.hostname or ""
        until, looked, next_at = clock() + MOST_SECONDS, clock(), 0.0
        try:
            while not stopped.is_set() and clock() < until:
                if clock() - looked > 5.0:  # (its reach tightened since: this feed too)
                    looked = clock()
                    if not calls.may_reach(host, reach()):
                        return "not allowed: that address isn't one this bridge reaches"
                chunk = r.read1(64 * 1024) if hasattr(r, "read1") else r.read(65536)
                if not chunk:
                    return "unreachable"
                got = frames.feed(chunk)
                if not got or clock() < next_at:
                    continue  # (nothing whole yet, or no room: this one is dropped)
                frame = got[-1]  # the newest
                if not out(frame):
                    return ""
                next_at = clock() + max(1.0 / FRAMES_A_SECOND, len(frame) / BYTES_A_SECOND)
        except (OSError, http.client.HTTPException):
            return "unreachable"
        except ValueError:
            return "not allowed: only a camera's stream"
    return ""
