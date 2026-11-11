"""Wings dashboard API — mounted by Hermes at /api/plugins/wings/ (dashboard auth applies).

    GET    /status               hub (no private key), devices, interface state
    POST   /devices              {"name": "...", "kind": "phone"} -> device (no key material)
    GET    /devices/{name}/qr    pairing QR as SVG (holds the device private key: shown, not logged)
    GET    /devices/{name}/qr.json  the same, as a data URL, for the Desktop page
    GET    /settings             safety options
    POST   /settings             change safety options
    DELETE /devices/{name}       revoke
    POST   /refresh              ask the root unit to refresh live handshake data
    POST   /invite               {"name": "..."} -> one-time code for another Hermes computer; waits in the background
"""
from __future__ import annotations

import base64
import http.cookiejar
import io
import importlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse, Response

router = APIRouter()
_MOD = "hermes_dashboard_plugin_wings_core"


def _core():
    mod = sys.modules.get(_MOD)
    if mod is not None:
        return mod
    path = Path(__file__).resolve().parent.parent / "wings" / "core.py"
    spec = importlib.util.spec_from_file_location(_MOD, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_MOD] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(_MOD, None)
        raise
    return mod


def _refresh() -> None:
    p = _core().home() / "refresh"
    p.write_text(str(os.getpid()))
    os.chmod(p, 0o600)


_lan_seen: dict = {}


def _net_computer(request: Request) -> None:
    session = getattr(getattr(request, "state", None), "session", None)
    if getattr(session, "provider", "") != _pkg("trust").PROVIDER:
        raise HTTPException(status_code=403, detail="Only a computer on this wing net can ask for that.")


@router.post("/mesh")
def mesh(request: Request, body: dict = Body(...)):
    """The hub introduces its computers to each other so they can connect directly. A computer says where it
    is on its own home network (useful to others in the same house) and gets the list back."""
    _net_computer(request)
    core = _core()
    key, lan = str(body.get("public_key", "")), str(body.get("lan", ""))
    known = {d["public_key"] for d in core.load().get("devices", []) if not d.get("revoked")}
    if key in known:
        import re as _re
        if _re.fullmatch(r"(10|192\.168|172\.(1[6-9]|2\d|3[01]))(\.\d{1,3}){2,3}:\d{2,5}", lan):
            _lan_seen[key] = lan
        else:
            _lan_seen.pop(key, None)
    return {"computers": core.mesh_roster(_lan_seen)}


@router.post("/sign")
def sign(request: Request, body: dict = Body(...)):
    """The hub signs a joined computer's certificate. Only a computer on the wing net may ask (it signed in
    with the wing net key), and only for a computer's own kind of name."""
    _net_computer(request)
    try:
        return _core().sign_for_computer(body.get("request", ""))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status")
def status():
    _refresh()
    out = _core().status()
    if (out.get("member") or {}).get("hub_url"):
        upkeep = _pkg("upkeep")
        rows = upkeep.roster()
        if rows is not None:
            out["net"] = [{k: v for k, v in d.items() if k != "address"} for d in rows]
        out["direct"] = upkeep.direct_names()
        out["hub_label"] = upkeep.hub_label()
        threading.Thread(target=upkeep.run, daemon=True).start()
    return out


@router.post("/devices")
def add_device(body: dict = Body(...)):
    try:
        return _core().add_device(str(body.get("name", "")), str(body.get("kind", "phone")))
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/devices/{name}/qr")
def device_qr(name: str):
    try:
        svg = _core().pairing_qr_svg(name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.delete("/devices/{name}")
def revoke(name: str):
    try:
        return _core().revoke(name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e


@router.get("/devices/{name}/qr.json")
def device_qr_json(name: str):
    try:
        svg = _core().pairing_qr_svg(name)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    data = base64.b64encode(svg.encode()).decode()
    core = _core()
    hub = core.load().get("hub") or {}
    where = f"http://{core.get_address()}" if hub and core.hub_answers_names(hub["address"]) else ""
    return JSONResponse({"qr": f"data:image/svg+xml;base64,{data}", "app_address": where},
                        headers={"Cache-Control": "no-store"})


@router.get("/settings")
def get_settings():
    return _core().get_settings()


@router.post("/settings")
def set_settings(body: dict = Body(...)):
    try:
        return _core().update_settings(body)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/refresh")
def refresh():
    _refresh()
    return {"ok": True}


@router.post("/invite")
def invite(body: dict = Body(...)):
    """A one-time join code for another computer running Hermes. The code holds a short-lived invite key:
    it is shown to the person who asked, never logged, and stops working once used or after the invite time."""
    core = _core()
    try:
        code, dev = core.create_invite(str(body.get("name", "")), "computer")
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    threading.Thread(target=core.wait_for_join, args=(dev,), daemon=True, name=f"wings-invite-{dev['name']}").start()
    minutes = core.get_settings()["invite_minutes"]
    return JSONResponse({"name": dev["name"], "minutes": minutes,
                         "command": f"hermes plugins install e-shizz/wings#plugin --enable && hermes wings join {code}"},
                        headers={"Cache-Control": "no-store"})


_job_lock = threading.Lock()
_job: dict = {"running": False, "ok": None, "stage": "", "note": "", "error": ""}

_STAGES = (
    ("admin rights", "Waiting for you to approve the admin box on this computer."),
    ("Joining ", "Joining your network."),
    ("Downloading wstunnel", "Fetching the fallback for networks that block WireGuard."),
    ("Joined.", "Connected. Finishing up."),
    ("web interface", "Getting Hermes's web interface ready. This takes a minute or two the first time."),
)


def _hermes() -> str:
    """Desktop often starts without the user's PATH, so also look where Hermes installs itself."""
    home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
    for p in (shutil.which("hermes"), Path.home() / ".local/bin/hermes", home / "hermes-agent/.hermes/bin/hermes",
              Path.home() / ".hermes/hermes-agent/.hermes/bin/hermes"):
        if p and os.access(p, os.X_OK):
            return str(p)
    return "hermes"


def _wings_cmd(*args: str) -> list[str]:
    return [_hermes(), "wings", *args]


def _plain_failure(lines: list[str]) -> str:
    text = "\n".join(lines)
    if "a password is required" in text or "no askpass" in text:
        return "This Hermes can't show an admin box. In a terminal, run: hermes wings setup"
    if "dismissed" in text.lower() or "Not authorized" in text:
        return "The admin box was closed, so nothing was installed."
    for line in lines:
        if line.startswith("Stopped:"):
            return line.removeprefix("Stopped:").strip()
    return lines[-1] if lines else "Setup stopped without saying why. Try hermes wings doctor."


def _run_job(cmd: list[str], secret: str = "") -> None:
    lines: list[str] = []
    ok = False
    try:
        env = dict(os.environ, PYTHONUNBUFFERED="1", PATH=f"{Path(cmd[0]).parent}{os.pathsep}{os.environ.get('PATH', '')}")
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        killer = threading.Timer(900, proc.kill)
        killer.start()
        try:
            for raw in proc.stdout:
                line = raw.strip()
                if not line:
                    continue
                lines.append(line)
                if line.startswith("Note: devices will dial"):
                    _job["note"] = "Devices can reach this computer only on this network. To reach it from anywhere, run: hermes wings router open"
                for needle, stage in _STAGES:
                    if needle in line:
                        _job["stage"] = stage
            ok = proc.wait() == 0
        finally:
            killer.cancel()
    except OSError as e:
        lines.append(str(e))
    finally:
        if secret:
            Path(secret).unlink(missing_ok=True)
        _job.update(running=False, ok=ok, error="" if ok else _plain_failure(lines))


@router.get("/start")
def start_status():
    return {k: _job[k] for k in ("running", "ok", "stage", "note", "error")}


@router.post("/start")
def start(body: dict = Body(...)):
    """The Turn on button: the same setup and join as the terminal. Root is still granted only by the person, in the
    system's own admin box. The invite goes through a private file, so it is never on a command line or in a log."""
    action, secret = str(body.get("action", "")), ""
    if action not in ("setup", "join"):
        raise HTTPException(status_code=400, detail="Unknown action.")
    with _job_lock:
        if _job["running"]:
            raise HTTPException(status_code=409, detail="Wings is already being set up.")
        cmd = _wings_cmd("setup", "-y")
        if action == "join":
            code = str(body.get("code", "")).strip().split(" ")[-1]
            if not code:
                raise HTTPException(status_code=400, detail="Paste the invite first.")
            fd, secret = tempfile.mkstemp(prefix="wings-invite-")
            with os.fdopen(fd, "w") as f:
                f.write(code)
            cmd = _wings_cmd("join", "--code-file", secret, "-y")
        _job.update(running=True, ok=None, stage="Starting.", note="", error="")
    threading.Thread(target=_run_job, args=(cmd, secret), daemon=True, name="wings-start").start()
    return {"started": True}


@router.get("/emblems")
def emblems():
    art = Path(__file__).resolve().parent.parent / "art"
    return {p.stem: "data:image/webp;base64," + base64.b64encode(p.read_bytes()).decode() for p in sorted(art.glob("*.webp"))}


_net_lock = threading.Lock()
_net_cache: dict = {"at": 0.0, "agents": {}}
_jars: dict = {}


def _pkg(name: str):
    """remote.py and trust.py import each other as a package, so load them as one."""
    root = "hermes_dashboard_plugin_wings_pkg"
    if root not in sys.modules:
        d = Path(__file__).resolve().parent.parent / "wings"
        spec = importlib.util.spec_from_file_location(root, d / "__init__.py", submodule_search_locations=[str(d)])
        mod = importlib.util.module_from_spec(spec)
        sys.modules[root] = mod
        spec.loader.exec_module(mod)
    return importlib.import_module(f"{root}.{name}")


def _session_row(r: dict) -> dict:
    return {"id": r.get("id") or r.get("session_id") or "", "title": r.get("display_name") or r.get("title") or "Untitled",
            "last": r.get("last_active") or r.get("started_at") or 0}


def _local_sessions(profile_home: Path) -> tuple[int, list[dict]]:
    """How many sessions a bot on this machine has and its latest few, read from its own store."""
    from contextlib import closing
    db_path = profile_home / "state.db"
    if not db_path.is_file():
        return 0, []
    try:
        from hermes_state import SessionDB
        try:
            from hermes_state_sessions import INTERNAL_LISTING_SOURCES
            # One-question chats count: another machine's list (read over its API) shows them too.
            skip = [x for x in INTERNAL_LISTING_SOURCES if x != "oneshot"]
        except ImportError:
            skip = []
        with closing(SessionDB(db_path=db_path, read_only=True)) as db:
            rows = db.list_sessions_rich(exclude_sources=skip, limit=15, order_by_last_active=True)
            rows = [r for r in rows if r.get("message_count", 1) and not r.get("archived")]
            try:
                total = db.session_count(exclude_sources=skip, min_message_count=1)
            except Exception:  # noqa: BLE001
                total = len(rows)
        return total, [_session_row(r) for r in rows[:5]]
    except Exception:  # noqa: BLE001 - an older Hermes: the bot still shows, without its sessions
        return 0, []


def _local_bots() -> list[dict]:
    try:
        from hermes_cli.profiles import list_profiles
        out = []
        for p in list_profiles(lazy_skill_count=True):
            total, recent = _local_sessions(Path(p.path))
            out.append({"name": p.name, "up": bool(p.gateway_running), "model": p.model or "", "sessions": total,
                        "last": max((r["last"] for r in recent), default=0), "recent": recent})
        return out
    except Exception:  # noqa: BLE001 - an older Hermes just shows no agents here
        return []


def _remote_get(base: str, path: str):
    """GET from another machine's Hermes, signing in with the wing net key when it asks."""
    remote = _pkg("remote")
    jar = _jars.setdefault(base, http.cookiejar.CookieJar())

    def fetch():
        req = urllib.request.Request(base + path, headers={"Origin": base})
        with remote._opener(jar).open(req, timeout=4) as r:
            return json.load(r)

    try:
        return fetch()
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403) or not remote.auto_sign_in(base, jar):
            raise
        return fetch()


def _remote_bots(base: str) -> list[dict] | None:
    """Ask a machine's Hermes who lives there and what they've been doing. None if it doesn't answer."""
    def get(path: str):
        return _remote_get(base, path)

    try:
        data = get("/api/profiles")
        out = []
        for p in data.get("profiles", []) if isinstance(data, dict) else data:
            name = p.get("name")
            if not name:
                continue
            page = get("/api/sessions?limit=5&profile=" + urllib.parse.quote(name))
            recent = [_session_row(r) for r in page.get("sessions", [])]
            out.append({"name": name, "up": bool(p.get("gateway_running")), "model": p.get("model") or "",
                        "sessions": page.get("total", len(recent)), "last": max((r["last"] for r in recent), default=0), "recent": recent})
        return out
    except Exception:  # noqa: BLE001 - asleep or unreachable is normal on a network like this
        return None


def _gather() -> dict:
    core = _core()
    state = core.load()
    hub, member = state.get("hub") or {}, state.get("member") or {}
    agents: dict = {"self": _local_bots()}
    targets: dict = {}
    own = core.get_address()
    if hub:
        agents[hub["name"]] = agents["self"]
        if own:
            targets[hub["name"]] = f"https://{own}"
        for d in core.devices():
            if d.get("kind") != "phone" and d.get("online"):
                targets[d["name"]] = f"https://{core._dns_label(d['name'])}.wings"
    elif member.get("hub_url"):
        targets[member["hub_name"]] = member["hub_url"]
        for d in _pkg("upkeep").roster() or []:
            if d["kind"] != "phone" and d["online"] and not d["self"]:
                targets[d["name"]] = f"https://{core._dns_label(d['name'])}.wings"
    styled: dict = {"self": looks()}
    if hub:
        styled[hub["name"]] = styled["self"]
    with ThreadPoolExecutor(max_workers=6) as pool:
        for name, found in zip(targets, pool.map(_remote_looks, targets.values())):
            if found:
                styled[name] = found
        for name, bots in zip(targets, pool.map(_remote_bots, targets.values())):
            if bots is not None:
                agents[name] = bots
                if hub and name == hub["name"]:
                    agents["self"] = bots
    return agents, styled


def _avatar_uri(path: Path) -> str:
    """A bot's own picture, made small. Without an image library, small files go as they are and big ones are skipped."""
    try:
        from PIL import Image
        with Image.open(path) as im:
            im.thumbnail((360, 360))
            out = io.BytesIO()
            im.convert("RGB").save(out, "WEBP", quality=70)
        return "data:image/webp;base64," + base64.b64encode(out.getvalue()).decode()
    except ImportError:
        pass
    except Exception:  # noqa: BLE001 - a broken picture just means the default portrait
        return ""
    try:
        return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode() if path.stat().st_size < 400_000 else ""
    except OSError:
        return ""


def _read_look(home: Path) -> dict:
    """The look a person already gave this bot in Hermes: its Bot Mode title and picture."""
    look: dict = {}
    try:
        import yaml
        doc = yaml.safe_load((home / "profile.yaml").read_text()) or {}
        meta = (doc.get("ui_meta") or {}).get("hermes-bots") or {}
    except Exception:  # noqa: BLE001 - no profile.yaml is the usual case
        doc, meta = {}, {}
    for title in (meta.get("title"), doc.get("display_name")):
        if isinstance(title, str) and title.strip():
            look["title"] = title.strip()
            break
    if isinstance(meta.get("image"), str) and meta["image"].startswith("data:image/"):
        look["image"] = meta["image"]
    elif (home / "assets" / "avatar.png").is_file():
        uri = _avatar_uri(home / "assets" / "avatar.png")
        if uri:
            look["image"] = uri
    return look


@router.get("/looks")
def looks():
    """This machine's bots as their owner styled them. Read by the owner's other machines over the wing net."""
    try:
        from hermes_cli.profiles import list_profiles
        out = {}
        for p in list_profiles(lazy_skill_count=True):
            look = _read_look(Path(p.path))
            # Hermes already knows the name its owner gave this bot; use it when the file could not be read here.
            for title in (getattr(p, "bot_title", ""), getattr(p, "display_name", "")):
                if "title" not in look and isinstance(title, str) and title.strip():
                    look["title"] = title.strip()
            out[p.name] = look
        return out
    except Exception:  # noqa: BLE001 - an older Hermes just keeps the default portraits
        return {}


def _remote_looks(base: str) -> dict:
    try:
        found = _remote_get(base, "/api/plugins/wings/looks")
        return found if isinstance(found, dict) else {}
    except Exception:  # noqa: BLE001 - older Wings or asleep
        return {}


def _memory_path() -> Path:
    return _core().home() / "last-seen-agents.json"


def _remember(agents_now: dict, looks_now: dict) -> tuple[dict, dict]:
    """A sleeping machine can't say who lives there, so it shows who was there when it was last awake."""
    try:
        old = json.loads(_memory_path().read_text())
    except (OSError, ValueError):
        old = {}
    agents_all = {**old.get("agents", {}), **agents_now}
    looks_all = {**old.get("looks", {}), **looks_now}
    p = _memory_path()
    p.write_text(json.dumps({"agents": agents_all, "looks": looks_all}))
    os.chmod(p, 0o600)
    return agents_all, looks_all


def _net_now() -> dict:
    """Who lives where, and how they look. Answers at once from what was last known (this run's, or the
    copy on disk from an earlier run) and catches up in the background, so the page never waits on a
    machine that is slow or asleep. Only the very first look on a new install has to wait."""
    with _net_lock:
        if "looks" not in _net_cache:
            try:
                old = json.loads(_memory_path().read_text())
                _net_cache["agents"], _net_cache["looks"] = old.get("agents", {}), old.get("looks", {})
            except (OSError, ValueError):
                _net_cache["looks"] = {}
        stale = time.time() - _net_cache["at"] > 30 and not _net_cache.get("busy")
        empty = not _net_cache["agents"]
        if stale:
            _net_cache["busy"] = True

    def catch_up():
        try:
            found, styled = _gather()
            agents_all, looks_all = _remember(found, styled)
            with _net_lock:
                _net_cache["agents"], _net_cache["looks"], _net_cache["at"] = agents_all, looks_all, time.time()
        finally:
            with _net_lock:
                _net_cache["busy"] = False

    if stale and empty:
        catch_up()
    elif stale:
        threading.Thread(target=catch_up, daemon=True).start()
    with _net_lock:
        return {"agents": _net_cache["agents"], "looks": _net_cache["looks"]}


@router.get("/agent-looks")
def agent_looks():
    """Pictures and titles, apart from /agents so the page's regular refresh stays small."""
    demo = os.environ.get("WINGS_NET_FILE")
    if demo:
        return json.loads(Path(demo + ".looks").read_text())
    return _net_now()["looks"]


@router.get("/agents")
def agents():
    """Which Hermes agents live on which machine, and their latest sessions."""
    demo = os.environ.get("WINGS_NET_FILE")
    if demo:
        return json.loads(Path(demo).read_text())
    return _net_now()["agents"]
