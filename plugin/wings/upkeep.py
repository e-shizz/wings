"""What a joined computer keeps current so every machine on the wing net can open every other:
the other computers' names, and a certificate signed by the hub. Standard library only.

It asks the hub's Hermes over the wing net, signing in with the wing net key. An older hub, or one that is
asleep, simply means nothing changes this time."""
from __future__ import annotations

import http.cookiejar
import json
import threading
import time
import urllib.error
import urllib.request

from . import core, remote

_jar = http.cookiejar.CookieJar()
_lock = threading.Lock()
_seen: dict = {"roster_at": 0.0, "rows": None, "cert_at": 0.0, "started": False}


def call(base: str, path: str, body: dict | None = None, timeout: int = 6):
    """GET, or POST when there is a body, from another machine's Hermes."""
    def send():
        data = None if body is None else json.dumps(body).encode()
        headers = {"Origin": base, **({"Content-Type": "application/json"} if body is not None else {})}
        req = urllib.request.Request(base + path, data=data, headers=headers, method="GET" if body is None else "POST")
        with remote._opener(_jar).open(req, timeout=timeout) as r:
            return json.load(r)

    try:
        return send()
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403) or not remote.auto_sign_in(base, _jar):
            raise
        return send()


def roster(max_age: float = 15) -> list[dict] | None:
    """Who else is on the wing net, as the hub sees it. None on a hub, or when the hub is quiet."""
    member = core.load().get("member") or {}
    if not member.get("hub_url"):
        return None
    if time.time() - _seen["roster_at"] < max_age:
        return _seen["rows"]
    _seen["roster_at"] = time.time()
    own = str(member.get("address", "")).split("/")[0]
    try:
        data = call(member["hub_url"], "/api/plugins/wings/status")
        _seen["hub_label"] = str((data.get("hub") or {}).get("label", ""))[:32]
        _seen["rows"] = [
            {"name": d["name"], "label": d.get("label", ""), "kind": d.get("kind", "device"),
             "online": bool(d.get("online")), "last_handshake": d.get("last_handshake", 0),
             "address": str(d.get("address", "")).split("/")[0],
             "self": bool(own) and str(d.get("address", "")).split("/")[0] == own}
            for d in data.get("devices", []) if d.get("name")]
    except Exception:  # noqa: BLE001 - an older hub, or one that is asleep
        _seen["rows"] = None
    return _seen["rows"]


def hub_label() -> str:
    """What the owner calls the hub, as last heard from it. Empty when it has no label."""
    return _seen.get("hub_label", "")


def run(force: bool = False, wait: bool = False) -> dict:
    """One pass (wait: stay until the root side has been asked to apply it, for one-off commands). Returns what is true afterwards: {"names": the list is current, "cert": the hub signed ours}."""
    out = {"names": False, "cert": False, "mesh": False}
    member = core.load().get("member") or {}
    if not member.get("hub_url"):
        return out
    changed = False
    with _lock:
        rows = roster(0 if force else 15)
        if rows is not None:
            try:
                changed = core.write_peers({f"{core._dns_label(d['name'])}.wings": d["address"] for d in rows
                                  if d["kind"] != "phone" and not d["self"] and d["address"] and core._dns_label(d["name"])})
                out["names"] = True
            except Exception:  # noqa: BLE001
                pass
        # Direct links: tell the hub where we are at home, and learn where the other computers are.
        try:
            port = int(core.live().get("port") or 0)
            lan = core.lan_ip()
            here = f"{lan}:{port}" if port and not lan.startswith("127.") else ""
            got = call(member["hub_url"], "/api/plugins/wings/mesh", {"public_key": member.get("public_key", ""), "lan": here})
            _seen["mesh"] = got.get("computers", [])
            core.write_mesh(_seen["mesh"], member.get("public_key", ""))
            out["mesh"] = True
        except Exception:  # noqa: BLE001 - an older hub: everything keeps going through it
            pass
        name = core.get_address()
        if name and core.hub_signed():
            out["cert"] = True
        elif name and (force or time.time() - _seen["cert_at"] >= 600):
            _seen["cert_at"] = time.time()
            try:
                key, request = core.new_cert_request(name)
                answer = call(member["hub_url"], "/api/plugins/wings/sign", {"request": request}, timeout=10)
                core.install_hub_cert(name, key, answer["cert"])
                out["cert"] = changed = True
            except Exception:  # noqa: BLE001 - tried again later
                pass
    if changed:
        _nudge(wait)
    return out


def _nudge(wait: bool = False) -> None:
    """Two files changing within a moment can reach the root side as one event, and it then applies only
    the first. Ask it for one more pass once things have settled."""
    def later():
        time.sleep(4)
        try:
            core._write_private(core.home() / "refresh", str(time.time()).encode())
        except Exception:  # noqa: BLE001
            pass
    if wait:
        later()
    else:
        threading.Thread(target=later, daemon=True).start()


def start() -> None:
    """Keep it current in the background while Hermes runs: soon after start, then every few minutes."""
    if _seen["started"]:
        return
    _seen["started"] = True

    def loop():
        time.sleep(30)
        while True:
            try:
                run()
            except Exception:  # noqa: BLE001 - never let this trouble Hermes
                pass
            time.sleep(60)

    threading.Thread(target=loop, name="wings-upkeep", daemon=True).start()


def direct_names() -> list[str]:
    """The computers this one is talking to directly right now."""
    keys = set(core.live().get("direct", []))
    return [r["name"] for r in _seen.get("mesh") or [] if r.get("public_key") in keys]
