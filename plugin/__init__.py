"""Wings — give your Hermes wings.

QR-paired WireGuard for Hermes: every Hermes computer you own and your phone on one private
network. No account, no coordination server, no third party.

Surfaces registered here:
  CLI       hermes wings (cockpit)|setup|status|doctor|connect|attach|name|add|invite|join|relay|address|login|safety|trust|qr|revoke|endpoint|router|refresh|upkeep|uninstall
  Slash     /wings [status|add <name>|revoke <name>]
  Tools     wings_status (read only; adding or removing a device is for a person, not the agent)
  Dashboard dashboard/ (tab + /api/plugins/wings/ routes) — also shows in the Hermes app
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.request
import shlex
import shutil
import subprocess
from pathlib import Path

from .wings import core

_TOOLSET = "wings"


# ---------------------------------------------------------------- helpers

def _qr_file(name: str) -> Path:
    d = core.home() / "qr"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return core.pairing_qr_png(name, d / f"{safe}.png")


def _summary() -> str:
    s = core.status()
    if s["member"]:
        m = s["member"]
        t = max(core.handshakes().values(), default=0)
        seen = "online" if t and time.time() - t < 180 else ("seen" if t else "never connected")
        via = "through the HTTPS relay" if core.live_mode() == "relay" else "direct"
        return (f"Wings member of {m['hub_name']} — this machine is {m['address']}, hub at {m['endpoint']}: {seen} ({via})\n"
                + (f"Hub's Hermes: {m['hub_url']}\n" if m.get("hub_url") else "")
                + (f"This machine's Hermes: https://{core.get_address()}\n" if core.get_address() else "") +
                f"wings0 {'up' if s['interface_up'] else 'down'}")
    if not s["initialized"]:
        return "Wings is not set up yet. Run: hermes wings setup"
    h = s["hub"]
    relay = (h.get("relay") or {}).get("port")
    lines = [f"Wings hub {h['name']} — {h['address']} on UDP {h['port']}"
             + (f", HTTPS relay on TCP {relay}" if relay else "") + f" (devices dial {h['endpoint']})",
             f"root unit installed: {'yes' if s['installed'] else 'NO (run hermes wings setup)'}; "
             f"wings0 {'up' if s['interface_up'] else 'down'}"]
    if s["installed"] and not s["helper_current"]:
        lines.append("root helper out of date: run hermes wings setup")
    for d in s["devices"]:
        seen = "online" if d["online"] else ("seen" if d["last_handshake"] else "never connected")
        lines.append(f"  {d['name']:<16} {d['address']:<12} {d['kind']:<9} {seen}")
    if not s["devices"]:
        lines.append("  no devices yet — hermes wings add <name>")
    return "\n".join(lines)


def _touch_refresh(wait: float = 0.0) -> None:
    """Ask the root unit for fresh handshakes; optionally wait until it has written them."""
    before = core.live_updated()
    p = core.home() / "refresh"
    p.write_text(str(os.getpid()))
    os.chmod(p, 0o600)
    deadline = time.monotonic() + wait
    while core.installed() and time.monotonic() < deadline and core.live_updated() == before:
        time.sleep(0.1)


def _show_qr(name: str, png: str = "") -> None:
    """Terminals get the QR on screen. Anything else (agent tools, pipes, logs) gets a private
    file instead, because the QR holds the device's private key and output like that is stored."""
    if png:
        print(core.pairing_qr_png(name, Path(png)))
    elif sys.stdout.isatty():
        print(core.pairing_qr_terminal(name))
    else:
        print(f"QR saved to {_qr_file(name)} (private, holds the device key). Not printed: this output isn't a terminal.")


# ---------------------------------------------------------------- tools

def _tool_status(args: dict, **_kw) -> str:
    _touch_refresh(wait=3)
    return json.dumps(core.status())


_STATUS_SCHEMA = {
    "name": "wings_status",
    "description": "Show the Wings private network: hub address, devices, which are online.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}


# ---------------------------------------------------------------- slash command

def _slash(raw: str) -> str:
    parts = raw.strip().split(maxsplit=1)
    cmd = parts[0].lower() if parts else "status"
    arg = parts[1].strip() if len(parts) > 1 else ""
    try:
        if cmd in ("status", ""):
            _touch_refresh()
            return _summary()
        if cmd == "add" and arg:
            dev = core.add_device(arg)
            png = _qr_file(dev["name"])
            return (f"Added {dev['name']} ({dev['address']}). Its QR holds the device's key, so it stays out of "
                    f"this chat. On this machine, open {png} and scan it with the WireGuard app.")
        if cmd == "revoke" and arg:
            core.revoke(arg)
            return f"Revoked {arg}. Its key no longer works."
    except Exception as e:
        return f"Wings: {e}"
    return "Usage: /wings [status | add <name> | revoke <name>]"


# ---------------------------------------------------------------- CLI

def _approve(args) -> bool:
    if getattr(args, "yes", False):
        return True
    if not sys.stdin.isatty():
        print("This needs admin rights and nobody is here to approve it. Run it in a terminal, or add -y.")
        return False
    return input("Approve? [y/N] ").strip().lower() in ("y", "yes")


def _show_preflight(hub: bool, port: int) -> bool:
    errors, notes = core.preflight(hub, port)
    for n in notes:
        print(f"Note: {n}")
    for e in errors:
        print(f"Stopped: {e}")
    return not errors


def _cli_doctor(args) -> int:
    bad = 0

    def line(ok, text):
        nonlocal bad
        bad += 0 if ok else 1
        print(f"{'ok ' if ok else 'BAD'}  {text}")

    state = core.load()
    m, h = state.get("member"), state.get("hub")
    if not m and not h:
        print("Wings isn't set up here. Start with: hermes wings setup, or hermes wings join <code>")
        return 1
    errors, notes = core.preflight(False)
    line(not errors, errors[0] if errors else f"Nothing else is using {core.SUBNET}")
    for n in notes:
        print(f"     {n}")
    line(core.installed(), "Root helper installed" if core.installed() else "Root helper missing: hermes wings setup")
    line(core.helper_current(), "Root helper is current" if core.helper_current() else "Root helper out of date: hermes wings setup")
    line(core.interface_up(), f"{core.IFACE} is up" if core.interface_up() else f"{core.IFACE} is down")
    _touch_refresh(wait=3)
    if m:
        t = max(core.handshakes().values(), default=0)
        fresh = bool(t) and time.time() - t < 180
        line(fresh, f"Hub answered {int(time.time() - t)}s ago ({core.live_mode()})" if t else "Hub has never answered")
        hub_host = m["endpoint"].rpartition(":")[0]
        for port in (core.DEFAULT_DASH_PORT, core.ENROLL_PORT):
            with socket.socket() as c:
                c.settimeout(3)
                closed = c.connect_ex((hub_host, port)) != 0
            line(closed, f"Must fail: hub's {hub_host}:{port} from outside the tunnel is {'closed' if closed else 'OPEN'}")
    addr = core.address_settings()
    if addr.get("Name"):
        url = core.public_url(addr["Name"], int(addr.get("HttpsPort", 443)))
        try:
            with urllib.request.urlopen(url + "/api/status", timeout=6) as r:
                info = json.load(r)
            line(info.get("auth_required") is True, f"{url} answers, certificate trusted, login "
                 f"{'required' if info.get('auth_required') else 'NOT REQUIRED'}")
        except Exception as e:  # noqa: BLE001 - doctor reports whatever went wrong
            line(False, f"{url} failed: {e}")
    print("\nAll good." if not bad else f"\n{bad} problem(s) above.")
    return 1 if bad else 0


def _ensure_hermes_running() -> None:
    """A fresh install has no Hermes service yet, so there's nothing to reach. One that's already running is left alone."""
    try:
        if subprocess.run(["systemctl", "--user", "is-active", "--quiet", "hermes-gateway"], timeout=10).returncode == 0:
            print("Hermes is already running. Restart it when convenient so it picks up Wings: hermes gateway restart")
            return
        hermes = shutil.which("hermes") or "hermes"
        print("Getting Hermes's web interface ready. This takes a minute or two the first time...")
        subprocess.run([hermes, "webapp", "--build-only"], capture_output=True, text=True, timeout=600)
        subprocess.run([hermes, "gateway", "install", "--if-missing", "--start-now"], capture_output=True, text=True, timeout=120)
        # --if-missing leaves a stopped service stopped, so a machine that already had one needs this too.
        subprocess.run([hermes, "gateway", "start"], capture_output=True, text=True, timeout=120)
        up = subprocess.run(["systemctl", "--user", "is-active", "--quiet", "hermes-gateway"], timeout=10).returncode == 0
        print("Started Hermes as a background service." if up else "Couldn't start Hermes by itself. Run: hermes gateway install")
    except (OSError, subprocess.TimeoutExpired):
        print("Couldn't start Hermes by itself. Run: hermes gateway install")


def _next_steps(url: str, user: str) -> None:
    print("\nNext:")
    print("  Add a computer running Hermes:  hermes wings invite laptop")
    print("  Add a phone (WireGuard app):    hermes wings add phone")
    if url:
        print(f"  Open this Hermes:               {url}  (your devices sign in through Wings)")


def _cli_router(args) -> int:
    """Only on request: ask the home router to pass the Wings port to this hub."""
    from .wings import upnp
    hub = core.load().get("hub")
    if not hub:
        print("Run this on your hub (the computer you ran hermes wings setup on).")
        return 1
    port, me = int(hub["port"]), core.lan_ip()
    try:
        router = upnp.find()
        if args.action == "close":
            print("The router no longer passes the Wings port to this machine." if upnp.close_port(port, me, router)
                  else "The router was not passing the Wings port to this machine.")
            return 0
        if args.action == "open":
            print(f"Asking your router to pass UDP {port} from outside to this machine, and nothing else.")
            upnp.open_port(port, me, router)
            address = upnp.public_address(router)
            if upnp._private(address):
                print("Done, but your router is itself behind another router, so devices outside still cannot reach it.")
                return 1
            core.set_endpoint(f"{address}:{port}")
            print("Done. Devices outside your home now dial your home's public address. Undo with: hermes wings router close")
            print("If your internet provider changes that address, run this again, or use your router's dynamic-DNS name: "
                  "hermes wings endpoint <name>:" + str(port))
            return 0
        holder = upnp.mapped(port, router)
        print("Your router answers." + (" It passes the Wings port to this machine." if holder == me else
              " It passes the Wings port to another machine." if holder else " It does not pass the Wings port to anyone yet: hermes wings router open"))
        return 0
    except upnp.RouterError as e:
        print(f"Stopped: {e}")
        return 1


def _upkeep_timer(on: bool = True) -> None:
    """A joined computer keeps its place on the wing net current (the others' names, its certificate, its
    direct links) once a minute, as this user, with no admin rights. A timer of its own, so it does not
    depend on how Hermes happens to load plugins. Never fatal: without it, things are just refreshed less."""
    d = Path.home() / ".config" / "systemd" / "user"
    try:
        if not on:
            subprocess.run(["systemctl", "--user", "disable", "--now", "wings-upkeep.timer"], capture_output=True, timeout=20)
            for n in ("wings-upkeep.timer", "wings-upkeep.service"):
                (d / n).unlink(missing_ok=True)
            return
        hermes = shutil.which("hermes") or str(Path.home() / ".local" / "bin" / "hermes")
        d.mkdir(parents=True, exist_ok=True)
        (d / "wings-upkeep.service").write_text(
            "[Unit]\nDescription=Wings: keep this computer's place on the wing net current\n\n"
            f"[Service]\nType=oneshot\nExecStart={shlex.quote(hermes)} wings upkeep\nTimeoutStartSec=90\nNice=10\n")
        (d / "wings-upkeep.timer").write_text(
            "[Unit]\nDescription=Wings: once a minute\n\n[Timer]\nOnBootSec=45\nOnUnitActiveSec=60\nAccuracySec=5\n\n"
            "[Install]\nWantedBy=timers.target\n")
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=20)
        subprocess.run(["systemctl", "--user", "enable", "--now", "wings-upkeep.timer"], capture_output=True, timeout=20)
    except Exception:  # noqa: BLE001
        pass


def _cli_setup(args) -> int:
    if core.load().get("member"):
        if core.installed() and core.helper_current():
            _upkeep_timer()
            print("This machine is a member of a wing net and its root helper is current.")
            return 0
        print("This machine is a member of a wing net. Updating its root helper only (admin rights needed).")
        if not _approve(args):
            print("Not installed.")
            return 1
        r = core.run_root(core.setup_command())
        print((r.stdout or "").strip() or (r.stderr or "").strip())
        if r.returncode == 0:
            _upkeep_timer()
        return r.returncode
    if not _show_preflight(True, args.port):
        return 1
    state = core.init(args.name or "", args.endpoint or "", args.port, args.dash_port)
    h = state["hub"]
    host = h["endpoint"].rpartition(":")[0]
    try:
        if ipaddress.ip_address(host).is_private:
            print(f"Note: devices will dial {host}, which only works on this network. "
                  "For a VPS use: hermes wings endpoint <public-ip>:" + str(h["port"]))
    except ValueError:
        pass
    if not args.no_relay and not h.get("relay"):
        if core.port_in_use(core.DEFAULT_RELAY_PORT):
            print(f"TCP {core.DEFAULT_RELAY_PORT} is in use, so the HTTPS relay stays off "
                  "(hermes wings relay on --port N).")
        else:
            core.relay_on()
            state = core.load()
            h = state["hub"]
    core.write_hub_conf(state)
    print(f"Hub: {h['name']}  {h['address']}  UDP {h['port']}  devices dial {h['endpoint']}")
    if core.installed() and core.helper_current() and core.installed_role() == "hub":
        print("Root unit already installed — nothing needs admin rights.")
    else:
        cmd = core.setup_command()
        if core.installed():
            print("\nThis plugin version ships a changed root helper, so it needs admin rights once more.")
        print("\nWings needs admin rights ONCE to install its root helper. It will:")
        print("  • copy root/wings-root.sh to /usr/local/libexec/wings-root (root-owned)")
        print("  • write /etc/wings/settings and systemd units named wings-* (sync, watch, HTTPS fallback, HTTPS address, name server)")
        print(f"  • create the WireGuard interface wings0 ({h['address']}/24, UDP {h['port']})")
        print(f"  • install wstunnel {core.WST_VERSION} (official release, checksum pinned) as the HTTPS fallback")
        print(f"  • open UDP {h['port']} and allow the dashboard port {h['dash_port']} from the tunnel only")
        print(f"\nCommand: {' '.join(shlex.quote(c) for c in cmd)}")
        if not _approve(args):
            print("Not installed.")
            return 1
        r = core.run_root(cmd)
        print((r.stdout or "").strip() or (r.stderr or "").strip())
        if r.returncode != 0:
            return r.returncode
    if h.get("relay"):
        print(f"\nOn a cloud VPS, also allow UDP {h['port']} and TCP {h['relay']['port']} in your provider's firewall.")
    url, user = "", ""
    if not args.no_address and not core.get_address():
        slug = re.sub(r"[^a-z0-9-]+", "-", h["name"].lower()).strip("-")[:32] or "hermes"
        if _cli_address(argparse.Namespace(off=False, name=f"{slug}.wings", port=None, force=False)) == 0:
            pass
    if core.get_address():
        a = core.address_settings()
        url, user = core.public_url(a["Name"], int(a.get("HttpsPort", 443))), _current_login()
    _ensure_hermes_running()
    print("\n" + _summary())
    _next_steps(url, user)
    return 0


def _hermes_config(*a) -> str:
    return subprocess.run(["hermes", "config", *a], capture_output=True, text=True).stdout.strip()


def _login_file() -> Path:
    return core.home() / "hermes-login.txt"


def _current_login() -> str:
    """The dashboard username Hermes already requires, if any."""
    return (_hermes_config("get", "dashboard.basic_auth.username")
            or os.environ.get("HERMES_DASHBOARD_BASIC_AUTH_USERNAME", ""))


def _cli_login(args) -> int:
    """Which login this Hermes asks for. Wings never writes a Hermes password: that is Hermes's own setting."""
    user = _current_login()
    old = _login_file()
    if not user:
        print("There's no Hermes password here. Your devices sign in through Wings, by their tunnel keys.")
    else:
        print(f"Your devices sign in through Wings. This Hermes also has a password login, username: {user}")
    print("A Hermes password is Hermes's own setting, so Wings doesn't make or change one. To set one, follow "
          "'Authentication' in Hermes's web dashboard guide (dashboard.basic_auth in config.yaml).")
    if old.exists():
        print(f"An older Wings saved a password it made at {old}. Save it in your password manager, then delete that file.")
    return 0


def _cli_address(args) -> int:
    if args.off:
        core.clear_address()
        _touch_refresh(wait=8)  # let the old front stop, so the next address doesn't see its ports as taken
        print(_hermes_config("set", "webapp.public_url", ""))
        print("Friendly address off. Run: hermes gateway restart")
        return 0
    if not args.name:
        print(core.get_address() or "No friendly address set.")
        return 0
    if not core.installed() or not core.helper_current():
        print("Update the root helper first: hermes wings setup")
        return 1
    existing = _hermes_config("get", "webapp.public_url").strip("'\" ")
    mine = core.get_address()
    if existing and (not mine or mine not in existing) and not args.force:
        print(f"Your Hermes already uses {existing} as its public address, maybe through your own reverse proxy.\n"
              "Wings left it alone. To replace it: hermes wings address <name> --force")
        return 1
    port = args.port
    if port is None:
        try:
            port = int(_hermes_config("get", "webapp.port") or 9120)
        except ValueError:
            port = 9120
    name, https_port = core.set_address(args.name, port)
    url = core.public_url(name, https_port)
    if https_port != 443:
        print(f"Port 443 is taken here by another web server, which Wings leaves alone. Using {https_port}.")
    _hermes_config("set", "webapp.enabled", "true")
    _hermes_config("set", "webapp.public_url", url)
    print(f"\nYour Hermes is at {url}")
    return 0


def _cli_connect(args) -> int:
    if not core.load().get("hub"):
        print("New devices are added on your hub, the computer you ran hermes wings setup on. Run this there, or use hermes wings to open it.")
        return 1
    print("Connect a new device:\n  1) a phone or tablet (WireGuard app, scan a code)\n  2) a computer running Hermes")
    pick = (args.kind or input("Which? [1/2] ").strip())
    name = args.name or input("A name for it: ").strip()
    if pick in ("1", "phone"):
        dev = core.add_device(name, "phone")
        print("\n1. Install the WireGuard app from your app store.\n2. In it, tap + and scan this:\n")
        _show_qr(dev["name"])
        print(f"\n{dev['name']} → {dev['address']}. This code is private: it holds the device's key.")
        return 0
    return _cli_invite(argparse.Namespace(name=name, kind="computer", code_file=""))


def _cli_invite(args) -> int:
    code, dev = core.create_invite(args.name, args.kind)
    minutes = core.get_settings()["invite_minutes"]
    if args.code_file:
        fd = os.open(args.code_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(code + "\n")
        print(f"Invite saved to {args.code_file} (secret, one use, {minutes} minutes).")
    else:
        print(f"On {dev['name']}, run this. It works once, for {minutes} minutes:\n\n  hermes wings join {code}\n")
    print(f"Waiting for {dev['name']} to join as {dev['address']}...", flush=True)
    try:
        ok = core.wait_for_join(dev, login_user=_current_login())
    except KeyboardInterrupt:
        print("\nInvite cancelled.")
        return 1
    print(f"{dev['name']} joined. The hub never saw its private key." if ok
          else "Nobody joined in time. The invite no longer works.")
    return 0 if ok else 1


def _finish_join(m: dict) -> int:
    core.finish_join()
    if not core.hub_reachable():
        print("Your key is enrolled, but your hub doesn't answer yet. Check hermes wings status.")
        return 1
    print(f"Joined. {m['hub_name']} answers at {core.HUB_IP}, using a key only this machine has.")
    joined = core.load()["member"]
    if joined.get("hub_url"):
        # Root applies the name and certificate a moment after the key swap. Don't hand over a dead link.
        for _ in range(20):
            try:
                with urllib.request.urlopen(joined["hub_url"] + "/api/status", timeout=3):
                    break
            except Exception:  # noqa: BLE001 - still settling
                time.sleep(1)
        print(f"\nOpen {m['hub_name']}'s Hermes: {joined['hub_url']}, in your browser or under Settings, Gateways in Hermes Desktop.")
        print("This computer signs in through Wings.")
    # So your phone and your other computers can open this one, by the name the hub already answers for it.
    if not core.get_address():
        slug = core._dns_label(m.get("my_name") or socket.gethostname().split(".")[0]) or "hermes"
        _cli_address(argparse.Namespace(off=False, name=f"{slug}.wings", port=None, force=False))
    # Every computer on the wing net trusts the hub, so the hub signs this one's certificate and tells it
    # the others' names. An older hub just leaves things as they were.
    try:
        from .wings import upkeep
        done = upkeep.run(force=True, wait=True)
        if done["cert"]:
            print("Your other computers on this wing net can open this one, and it can open them.")
    except Exception:  # noqa: BLE001
        pass
    _upkeep_timer()
    _ensure_hermes_running()
    return 0


def _cli_join(args) -> int:
    if args.resume:
        m = core.load().get("member")
        if not m or m.get("enrolled"):
            print("There's no unfinished join on this machine.")
            return 1
    else:
        if not _show_preflight(False, core.DEFAULT_PORT):
            return 1
        code = args.code
        if args.code_file:
            code = Path(args.code_file).read_text()
        m = core.begin_join(code, args.replace_hub)
        print(f"Joining {m['hub_name']} at {m['endpoint']} as {m['address']}")
    if not (core.installed() and core.helper_current() and core.installed_role() == "member"):
        print("Downloading wstunnel (official release, checksum pinned) for networks that block UDP...")
        cmd = core.setup_command()
        print("Wings needs admin rights once to install its root helper "
              f"(/usr/local/libexec/wings-root, wings0 at {m['address']}, no open ports).")
        if not _approve(args):
            print("Not installed. Finish later with: hermes wings join --resume")
            return 1
        r = core.run_root(cmd)
        if r.returncode != 0:
            print((r.stderr or r.stdout).strip())
            return r.returncode
    return _finish_join(m)


def _cli(args) -> int:
    sub = getattr(args, "wings_cmd", None)
    if sub is None:
        sub = "cockpit" if sys.stdout.isatty() else "status"
    try:
        if sub == "cockpit":
            from .wings import cockpit
            return cockpit.run()
        if sub == "attach":
            from .wings import cockpit
            return cockpit.attach_cli(args.url, args.resume, args.profile, args.say)
        if sub == "router":
            return _cli_router(args)
        if sub == "upkeep":
            from .wings import upkeep
            upkeep.run(force=True, wait=True)
            return 0
        if sub == "connect":
            return _cli_connect(args)
        if sub == "name":
            core.set_label(args.device, " ".join(args.label))
            print(f"{args.device} is now shown as {' '.join(args.label)}")
            return 0
        if sub == "doctor":
            return _cli_doctor(args)
        if sub == "safety":
            if args.change:
                key, _, val = args.change.partition("=")
                value = int(val) if val.isdigit() else val.lower() in ("on", "yes", "true")
                core.update_settings({key: value})
            for k, v in core.get_settings().items():
                print(f"{k}: {'on' if v is True else 'off' if v is False else v}")
            return 0
        if sub == "address":
            return _cli_address(args)
        if sub == "login":
            return _cli_login(args)
        if sub == "trust":
            return _cli_trust(args)
        if sub == "relay":
            if args.action == "on":
                r = core.relay_on(args.port)
                print(f"HTTPS relay on TCP {r['port']}. Allow it in your provider's firewall too. New invites include it.")
            elif args.action == "off":
                core.relay_off()
                print("HTTPS relay off.")
            else:
                r = (core.public_hub().get("relay") or (core.load().get("member") or {}).get("relay") or {})
                print(f"HTTPS relay on TCP {r['port']}" if r else "HTTPS relay off")
            return 0
        if sub == "invite":
            return _cli_invite(args)
        if sub == "join":
            return _cli_join(args)
        if sub == "setup":
            return _cli_setup(args)
        if sub == "status":
            _touch_refresh(wait=3)
            print(_summary())
        elif sub == "add":
            dev = core.add_device(args.name, args.kind, args.public_key)
            if args.public_key:
                print(core.merge_lines(dev["name"]))
                return 0
            print("1. Install the WireGuard app from your app store.\n2. In it, tap + and scan this:\n")
            _show_qr(dev["name"])
            print(f"\n{dev['name']} → {dev['address']}. This code is private: it holds the device's key.")
            print("Phones run one VPN at a time, so this tunnel replaces any other while it's on. "
                  "To keep an existing tunnel, use: hermes wings add <name> --public-key <its public key>")
        elif sub == "qr":
            _show_qr(args.name, args.png)
        elif sub == "revoke":
            core.revoke(args.name)
            print(f"revoked {args.name}")
        elif sub == "endpoint":
            print(core.set_endpoint(args.endpoint)["endpoint"])
        elif sub == "refresh":
            _touch_refresh()
        elif sub == "uninstall":
            cmd = [str(core.ROOT_HELPER_SRC), "uninstall"]
            print("This stops wings0 and removes the root helper, units and /etc/wireguard/wings0.conf.\n"
                  "Your hub identity and device list stay in " + str(core.home()))
            if not _approve(args):
                print("Not uninstalled.")
                return 1
            else:
                _upkeep_timer(False)
                r = core.run_root(cmd)
                print((r.stdout or r.stderr).strip())
                if r.returncode != 0:
                    print("The uninstall did not finish. Run it again; nothing else was changed.")
                    return r.returncode
                # Don't leave Hermes pointing at an address that's gone.
                if ".wings" in _hermes_config("get", "webapp.public_url"):
                    _hermes_config("set", "webapp.public_url", "")
                    print("Cleared webapp.public_url. Run: hermes gateway restart")
                core.clear_address()
                return r.returncode
        return 0
    except (ValueError, RuntimeError) as e:
        print(f"wings: {e}")
        return 1


def _cli_args(p) -> None:
    subs = p.add_subparsers(dest="wings_cmd")
    s = subs.add_parser("setup", help="make this computer the hub of your wing net: your phone and your other computers connect to it (asks for admin rights once)")
    s.add_argument("--name", default="")
    s.add_argument("--endpoint", default="", help="host:port devices dial (default: this machine's LAN IP)")
    s.add_argument("--port", type=int, default=core.DEFAULT_PORT)
    s.add_argument("--dash-port", type=int, default=core.DEFAULT_DASH_PORT)
    s.add_argument("--no-address", action="store_true", help="don't set up an https://<name>.wings address for this Hermes")
    s.add_argument("--no-relay", action="store_true", help="don't offer WireGuard over HTTPS on TCP 443")
    s.add_argument("-y", "--yes", action="store_true")
    subs.add_parser("status", help="your wing net: the hub and everything joined to it")
    rl = subs.add_parser("relay", help="WireGuard over HTTPS, for networks that block UDP")
    rl.add_argument("action", choices=["on", "off", "status"])
    rl.add_argument("--port", type=int, default=core.DEFAULT_RELAY_PORT)
    a = subs.add_parser("add", help="add a device and show its pairing QR")
    a.add_argument("name")
    a.add_argument("--kind", default="phone", choices=["phone", "computer", "server", "tablet", "device"])
    a.add_argument("--public-key", default="", help="add to an existing tunnel: that tunnel's public key")
    ad = subs.add_parser("address", help="give this machine's Hermes a friendly address like hermes.wings")
    ad.add_argument("name", nargs="?", default="")
    ad.add_argument("--port", type=int, default=None, help="local port of the Hermes Webapp (default: from config)")
    ad.add_argument("--off", action="store_true")
    ad.add_argument("--force", action="store_true", help="replace a public address this Hermes already uses")
    subs.add_parser("cockpit", help="pick a machine and a session, then you are in Hermes (also: hermes wings)")
    at = subs.add_parser("attach", help="open another machine's Hermes TUI here, over Wings")
    at.add_argument("url")
    at.add_argument("--resume", default="")
    at.add_argument("--profile", default="")
    at.add_argument("--say", default="", help="send this message once it opens")
    cn = subs.add_parser("connect", help="connect a new phone or computer (asks which)")
    cn.add_argument("name", nargs="?", default="")
    cn.add_argument("--kind", choices=["phone", "computer"], default="")
    nm = subs.add_parser("name", help="give a device a friendly name, like 'home Linux box'")
    nm.add_argument("device")
    nm.add_argument("label", nargs="+")
    sf = subs.add_parser("safety", help="show or change safety options, e.g. isolate_devices=on")
    sf.add_argument("change", nargs="?", default="")
    subs.add_parser("doctor", help="check this machine, including that what should be blocked is")
    tr = subs.add_parser("trust", help="whether your own computers sign in to this one through Wings")
    tr.add_argument("action", nargs="?", choices=["on", "off"])
    lg = subs.add_parser("login", help="whether this Hermes also has a password login")
    i = subs.add_parser("invite", help="invite another Hermes computer to this wing net; waits for it to join")
    i.add_argument("name")
    i.add_argument("--kind", default="server", choices=["computer", "server", "device"])
    i.add_argument("--code-file", default="", help="write the invite to a private file instead of the screen")
    j = subs.add_parser("join", help="join a wing net with an invite code")
    j.add_argument("code", nargs="?", default="")
    j.add_argument("--code-file", default="", help="read the invite from a file")
    j.add_argument("--resume", action="store_true", help="retry a join that was interrupted")
    j.add_argument("--replace-hub", action="store_true", help="set aside this machine's own hub and join")
    j.add_argument("-y", "--yes", action="store_true")
    q = subs.add_parser("qr", help="show a device's pairing QR again")
    q.add_argument("name")
    q.add_argument("--png", default="")
    r = subs.add_parser("revoke", help="remove a device")
    r.add_argument("name")
    e = subs.add_parser("endpoint", help="set the host:port devices dial (VPS IP, DNS name)")
    e.add_argument("endpoint")
    subs.add_parser("refresh", help="refresh live handshake data")
    ro = subs.add_parser("router", help="on a hub at home: ask the router to pass the Wings port (only when you say so)")
    ro.add_argument("action", nargs="?", choices=["status", "open", "close"], default="status")
    subs.add_parser("upkeep", help="refresh this computer's place on the wing net now (runs by itself every minute)")
    u = subs.add_parser("uninstall", help="remove the root helper and wings0 (keeps your keys)")
    u.add_argument("-y", "--yes", action="store_true")
    p.set_defaults(func=_cli)


# ---------------------------------------------------------------- register

def _cli_trust(args) -> int:
    from .wings import trust
    if args.action:
        trust.set_enabled(args.action == "on")
    st = core.load()
    if st.get("hub"):
        trust.ensure_netkey()
    has = trust.netkey() is not None
    on = trust.enabled()
    print(f"Wing net sign-in here: {'on' if on else 'off'}")
    if not has:
        print("  This computer has no wing net key yet. It arrives when it joins a hub with `hermes wings join`.")
    elif on:
        print("  Your devices in this wing net sign in to this Hermes through Wings.")
        print("  Turn it off with: hermes wings trust off")
    else:
        print("  Devices must sign in with this Hermes's password, if it has one. Turn it back on: hermes wings trust on")
    print("  A gateway restart is needed for Hermes to pick up a change here: hermes gateway restart")
    return 0


def register(ctx) -> None:
    ctx.register_tool(name="wings_status", toolset=_TOOLSET, schema=_STATUS_SCHEMA,
                      handler=_tool_status, emoji="🪽", description="Wings network status")
    ctx.register_command("wings", handler=_slash, description="Wings private network",
                         args_hint="[status|add <name>|revoke <name>]")
    ctx.register_cli_command(name="wings", help="Wings: a private network between your Hermes computers and your phone",
                             setup_fn=_cli_args, handler_fn=_cli)
    # Your own computers sign in to this Hermes with the wing net key (see wings/trust.py). Older Hermes
    # without plugin sign-in providers simply keeps asking for the password.
    if hasattr(ctx, "register_dashboard_auth_provider"):
        try:
            from .wings import trust
            if core.load().get("hub"):
                trust.ensure_netkey()
            ctx.register_dashboard_auth_provider(trust.provider())
            ctx.register_dashboard_auth_provider(trust.device_provider())
        except Exception:  # never let sign-in setup break Hermes startup
            pass
    # A joined computer keeps the other machines' names and its hub-signed certificate current while the
    # gateway runs. Not in one-off commands: they are gone before it would do anything.
    try:
        if sys.argv[1:2] == ["gateway"] or "dashboard" in sys.argv[1:2]:
            from .wings import upkeep
            upkeep.start()
    except Exception:  # noqa: BLE001
        pass
