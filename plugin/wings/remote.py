"""Open another machine's Hermes TUI in this terminal, over Wings, with that Hermes's own login.

Uses Hermes's own remote terminal (the WebSocket the dashboard's Chat tab uses): sign in, get a
single-use ticket, open /api/pty. No SSH. Standard library only, so it runs wherever Hermes does.
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import select
import shutil
import signal
import socket
import ssl
import struct
import sys
import termios
import time
import tty
import urllib.parse
import urllib.request


class RemoteError(Exception):
    pass


def _opener(jar):
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def sign_in(base: str, username: str, password: str, jar=None, provider: str = "basic"):
    """Password login. Returns the cookie jar holding the session; the password is not kept."""
    jar = jar if jar is not None else http.cookiejar.CookieJar()
    body = json.dumps({"provider": provider, "username": username, "password": password}).encode()
    req = urllib.request.Request(base + "/auth/password-login", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with _opener(jar).open(req, timeout=15) as r:
            r.read()
    except urllib.error.HTTPError as e:
        raise RemoteError("that login didn't work" if e.code == 401 else f"sign-in failed ({e.code})") from e
    return jar


def auto_sign_in(base: str, jar) -> bool:
    """Sign in to another computer in this wing net with the wing net key: no password. False if this
    machine has no key, or that machine doesn't accept wing net sign-in (older Wings, or trust off)."""
    from urllib.parse import urlparse
    from . import trust
    note = trust.note_for(urlparse(base).hostname or "")
    if not note:
        return False
    try:
        sign_in(base, trust.me(), note, jar, provider=trust.PROVIDER)
        return True
    except (RemoteError, OSError):
        return False


def ws_ticket(base: str, jar) -> str:
    req = urllib.request.Request(base + "/api/auth/ws-ticket", data=b"{}", method="POST",
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with _opener(jar).open(req, timeout=15) as r:
            return json.load(r)["ticket"]
    except urllib.error.HTTPError as e:
        raise RemoteError("signed out" if e.code in (401, 403) else f"ticket refused ({e.code})") from e


def sessions(base: str, jar, limit: int = 8) -> list[dict]:
    req = urllib.request.Request(f"{base}/api/sessions?limit={limit}", headers={"Origin": base})
    try:
        with _opener(jar).open(req, timeout=15) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        raise RemoteError(f"sessions unavailable ({e.code})") from e
    return data.get("sessions", data) if isinstance(data, dict) else data


class WebSocket:
    """A minimal RFC 6455 client: enough for a terminal stream."""

    def __init__(self, url: str, origin: str):
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == "wss" else 80)
        raw = socket.create_connection((u.hostname, port), timeout=15)
        if u.scheme == "wss":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
        self.sock = raw
        key = base64.b64encode(os.urandom(16)).decode()
        path = u.path + (f"?{u.query}" if u.query else "")
        host = u.hostname if u.port in (None, 443, 80) else f"{u.hostname}:{u.port}"
        self.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nOrigin: {origin}\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RemoteError("the remote Hermes closed the connection")
            head += chunk
        status, _, rest = head.partition(b"\r\n\r\n")
        if b" 101 " not in status.split(b"\r\n")[0]:
            raise RemoteError("the remote Hermes refused the terminal: " + status.split(b"\r\n")[0].decode(errors="replace"))
        self.buf = rest
        self.sock.settimeout(None)

    def send(self, data: bytes, opcode: int = 0x2) -> None:
        mask = os.urandom(4)
        n = len(data)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", n)
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def _need(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv(self) -> tuple[int, bytes]:
        b1, b2 = self._need(2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._need(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._need(8))[0]
        if b2 & 0x80:
            mask = self._need(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(self._need(n)))
        else:
            data = self._need(n)
        op = b1 & 0x0F
        if op == 0x9:
            self.send(data, 0xA)
            return self.recv()
        return op, data

    def pending(self) -> bool:
        return bool(self.buf)

    def close(self) -> None:
        try:
            self.send(b"", 0x8)
            self.sock.close()
        except OSError:
            pass


def open_terminal(base: str, jar, resume: str = "", fresh: bool = False, profile: str = "") -> WebSocket:
    q = {"ticket": ws_ticket(base, jar)}
    if profile:
        q["profile"] = profile
    if resume:
        q["resume"] = resume
    if fresh:
        q["fresh"] = "1"
    url = base.replace("https://", "wss://").replace("http://", "ws://") + "/api/pty?" + urllib.parse.urlencode(q)
    return WebSocket(url, base)


def resize_message() -> bytes:
    cols, rows = shutil.get_terminal_size((100, 30))
    return f"\x1b[RESIZE:{cols};{rows}]".encode()


def attach(ws: WebSocket) -> int:
    """Bridge this terminal to the remote TUI until it ends. Ctrl-] detaches."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    resized = [True]
    queued = getattr(ws, "pending_input", b"")
    quiet_since = None
    # A resize must wake the wait at once (Python resumes select after a signal), or the remote Hermes keeps
    # drawing at the old size and leaves old text on screen.
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_w, False)

    def on_winch(*_):
        resized[0] = True
        try:
            os.write(wake_w, b"x")
        except OSError:
            pass
    signal.signal(signal.SIGWINCH, on_winch)
    try:
        tty.setraw(fd)
        while True:
            if resized[0]:
                resized[0] = False
                ws.send(resize_message())
            ready, _, _ = select.select([fd, ws.sock, wake_r], [], [], 0.4 if queued else 20)
            if wake_r in ready:
                os.read(wake_r, 64)
                ready = [r for r in ready if r is not wake_r]
                if not ready:
                    continue
            if not ready:
                if queued and quiet_since and time.time() - quiet_since > 1.2:
                    ws.send(queued)
                    queued = b""
                elif not queued:
                    ws.send(resize_message())
                continue
            if fd in ready:
                data = os.read(fd, 4096)
                if not data or b"\x1d" in data:
                    return 0
                ws.send(data)
            if ws.sock in ready or ws.pending():
                try:
                    op, data = ws.recv()
                except (EOFError, OSError):
                    return 0
                if op == 0x8:
                    return 0
                if op in (0x1, 0x2):
                    os.write(sys.stdout.fileno(), data)
                    quiet_since = time.time()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        signal.signal(signal.SIGWINCH, signal.SIG_DFL)
        os.close(wake_r)
        os.close(wake_w)
        ws.close()
