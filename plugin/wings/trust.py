"""Computers in one wing net sign each other in: no passwords between your own machines.

The hub makes a random wing net key and hands it to each computer when it joins, inside the WireGuard
tunnel. Phones added by QR never get it: they sign in by being on the tunnel (see device_provider).

To open another machine's Hermes, the cockpit sends that machine a short-lived note signed with the
key: "<this machine> wants in to <that machine's address>, at <time>, <random nonce>". The other
machine's Wings sign-in provider checks the signature, the address, the time (60 s either way) and
that the nonce is new, then issues an ordinary Hermes session. No password is stored or sent.

Each machine can refuse: `hermes wings trust off` makes it ask for its password again.
Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import socket
import threading
import time
from typing import Optional
from urllib.parse import urlparse

from . import core

PROVIDER = "wings"
DEVICE_PROVIDER = "wings-device"
SKEW = 60
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_seen: dict[str, float] = {}
_seen_lock = threading.Lock()


# ---------------------------------------------------------------- the key

def netkey() -> Optional[bytes]:
    p = core.home() / "netkey"
    try:
        h = p.read_text().strip()
    except OSError:
        return None
    return bytes.fromhex(h) if _HEX64.match(h) else None


def save_netkey(h: str) -> bool:
    if not isinstance(h, str) or not _HEX64.match(h):
        return False
    core._write_private(core.home() / "netkey", (h + "\n").encode())
    return True


def ensure_netkey() -> str:
    """The hub's key, made on first use."""
    k = netkey()
    if k is None:
        save_netkey(secrets.token_hex(32))
        k = netkey()
    return k.hex()


def enabled() -> bool:
    return not (core.home() / "trust-off").exists()


def set_enabled(on: bool) -> None:
    p = core.home() / "trust-off"
    if on:
        p.unlink(missing_ok=True)
    else:
        core._write_private(p, b"computers in the wing net must sign in with the Hermes password\n")


def me() -> str:
    return socket.gethostname().split(".")[0][:40] or "computer"


# ---------------------------------------------------------------- the note one machine signs

def _mac(key: bytes, *parts: str) -> str:
    return hmac.new(key, "|".join(parts).encode(), hashlib.sha256).hexdigest()


def note_for(host: str, user: str = "") -> Optional[str]:
    """The password field for signing in to `host` (e.g. vps.wings). None without a key."""
    key = netkey()
    if key is None:
        return None
    ts, nonce = str(int(time.time())), secrets.token_hex(12)
    return f"w1.{ts}.{nonce}.{_mac(key, 'wings-login', host.lower(), user or me(), ts, nonce)}"


def check_note(user: str, note: str) -> bool:
    key = netkey()
    if key is None or not enabled() or not isinstance(note, str) or not isinstance(user, str):
        return False
    parts = note.split(".")
    if len(parts) != 4 or parts[0] != "w1" or not parts[1].isdigit():
        return False
    _, ts, nonce, mac = parts
    if abs(time.time() - int(ts)) > SKEW or not re.fullmatch(r"[0-9a-f]{24}", nonce):
        return False
    hosts = {h for h in (core.get_address(), "localhost", "127.0.0.1") if h}
    if not any(hmac.compare_digest(mac, _mac(key, "wings-login", h.lower(), user, ts, nonce)) for h in hosts):
        return False
    now = time.time()
    with _seen_lock:
        for n in [n for n, t in _seen.items() if now - t > 2 * SKEW]:
            del _seen[n]
        if nonce in _seen:
            return False
        _seen[nonce] = now
    return True


# ---------------------------------------------------------------- phones and browsers on the wing net
#
# A phone has no wing net key, but WireGuard has already proved which device it is. The port on the tunnel
# address sees that device connect and writes a short note saying so, signed with a key only this machine has.

def _approve_key() -> Optional[bytes]:
    try:
        return hashlib.sha256(b"wings-approve\0" + (core.home() / "tls" / "leaf.key").read_bytes()).digest()
    except OSError:
        return None


def check_device_code(code: str, state: str) -> Optional[str]:
    """The tunnel address of the device this code vouches for, or None."""
    key = _approve_key()
    if key is None or not enabled() or not isinstance(code, str) or not isinstance(state, str):
        return None
    parts = code.split(".")
    if len(parts) != 6:  # time, the four parts of the address, signature
        return None
    ts, peer, mac = parts[0], ".".join(parts[1:5]), parts[5]
    if not ts.isdigit() or abs(time.time() - int(ts)) > 2 * SKEW or not re.fullmatch(r"10\.77\.0\.\d{1,3}", peer):
        return None
    want = hmac.new(key, f"wings-device|{state}|{peer}|{ts}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, want):
        return None
    now = time.time()
    with _seen_lock:
        for n in [n for n, t in _seen.items() if now - t > 4 * SKEW]:
            del _seen[n]
        if mac in _seen:
            return None
        _seen[mac] = now
    return peer


# ---------------------------------------------------------------- sessions this machine issues

def _session_key() -> bytes:
    """Signs this machine's Wings sessions. Tied to the wing net key, so a new key ends every session."""
    p = core.home() / "session.key"
    try:
        local = p.read_bytes()
    except OSError:
        local = b""
    if len(local) != 32:
        local = secrets.token_bytes(32)
        core._write_private(p, local)
    return hashlib.sha256(local + (netkey() or b"")).digest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(user: str, kind: str, ttl: int) -> tuple[str, int]:
    exp = int(time.time()) + ttl
    body = _b64(json.dumps({"u": user[:40], "k": kind, "e": exp, "n": secrets.token_hex(6)}).encode())
    return f"wings.{body}.{_b64(hmac.new(_session_key(), body.encode(), hashlib.sha256).digest())}", exp


def read(token: str, kind: str) -> Optional[dict]:
    if not isinstance(token, str) or not token.startswith("wings.") or not enabled():
        return None
    try:
        _, body, sig = token.split(".")
        want = _b64(hmac.new(_session_key(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, want):
            return None
        d = json.loads(_unb64(body))
    except (ValueError, TypeError):
        return None
    if d.get("k") != kind or d.get("e", 0) < time.time():
        return None
    return d


def _hermes():
    from hermes_cli.dashboard_auth import base  # exists only inside Hermes
    return base


def _session(user: str, name: str):
    at, exp = mint(user, "a", ACCESS_TTL)
    rt, _ = mint(user, "r", REFRESH_TTL)
    return _hermes().Session(user_id=f"wings:{user}", email="", display_name=f"{user} (wing net)", org_id="",
                             provider=name, expires_at=exp, access_token=at, refresh_token=rt)


def _verified(access_token: str, name: str):
    d = read(access_token, "a")
    if not d:
        return None
    return _hermes().Session(user_id=f"wings:{d['u']}", email="", display_name=f"{d['u']} (wing net)", org_id="",
                             provider=name, expires_at=int(d["e"]), access_token=access_token, refresh_token="")


def _refreshed(refresh_token: str, name: str):
    d = read(refresh_token, "r")
    if not d:
        raise _hermes().RefreshExpiredError("not a Wings session")
    return _session(d["u"], name)


def provider():
    """Computers sign each other in: a note signed with the wing net key, from the picker. Never on a login page."""
    b = _hermes()

    class WingsSignIn(b.DashboardAuthProvider):
        name = PROVIDER
        display_name = "Wings (your own computers)"
        supports_password = True
        interactive_login = False

        def start_login(self, *, redirect_uri):
            raise NotImplementedError("Wings signs in computers from the picker only")

        def complete_login(self, *, code, state, code_verifier, redirect_uri):
            raise NotImplementedError("Wings signs in computers from the picker only")

        def complete_password_login(self, *, username, password):
            if not check_note(username, password):
                raise b.InvalidCredentialsError("not a wing net computer")
            return _session(username, PROVIDER)

        def verify_session(self, *, access_token):
            return _verified(access_token, PROVIDER)

        def refresh_session(self, *, refresh_token):
            return _refreshed(refresh_token, PROVIDER)

        def revoke_session(self, *, refresh_token):
            return None

    return WingsSignIn()


def device_provider():
    """Phones and browsers on the wing net: no password, because the tunnel already proved the device."""
    b = _hermes()

    class WingsDevice(b.DashboardAuthProvider):
        name = DEVICE_PROVIDER
        display_name = "Wings"

        def start_login(self, *, redirect_uri):
            host = urlparse(redirect_uri).hostname or ""
            if not host.endswith(".wings"):
                raise b.ProviderError("Wings sign-in only works on a .wings address")
            state = secrets.token_urlsafe(24)
            # Relative on purpose: the same address and port the device is already using.
            return b.LoginStart(redirect_url=f"/wings-approve?state={state}",
                                cookie_payload={"hermes_session_pkce": f"state={state};verifier=wings"})

        def complete_login(self, *, code, state, code_verifier, redirect_uri):
            peer = check_device_code(code, state)
            if not peer:
                raise b.InvalidCodeError("not a device on this wing net")
            return _session(f"device-{peer.rsplit('.', 1)[1]}", DEVICE_PROVIDER)

        def verify_session(self, *, access_token):
            return _verified(access_token, DEVICE_PROVIDER)

        def refresh_session(self, *, refresh_token):
            return _refreshed(refresh_token, DEVICE_PROVIDER)

        def revoke_session(self, *, refresh_token):
            return None

    return WingsDevice()
