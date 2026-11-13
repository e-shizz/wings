"""`hermes wings`: every Hermes you can reach, on one simple screen.

Pick a machine, pick a session or start a new one, and the screen is gone: you're in Hermes, in this
terminal, like always. Your own computers sign each other in by themselves (trust.py). Standard
library curses only.
"""
from __future__ import annotations

import curses
import http.cookiejar
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import core
from . import remote

DEFAULT_LABELS = {"phone": "mobile", "tablet": "tablet", "computer": "computer", "server": "server", "device": "device"}


# ---------------------------------------------------------------- data

def _jar_path(base: str) -> Path:
    d = core.home() / "sessions"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    return d / (re.sub(r"[^a-z0-9.-]+", "_", base.lower()) + ".cookies")


def load_jar(base: str) -> http.cookiejar.LWPCookieJar:
    jar = http.cookiejar.LWPCookieJar(str(_jar_path(base)))
    try:
        jar.load(ignore_discard=True, ignore_expires=True)
    except (OSError, http.cookiejar.LoadError):
        pass
    return jar


def save_jar(jar: http.cookiejar.LWPCookieJar) -> None:
    jar.save(ignore_discard=True, ignore_expires=True)
    os.chmod(jar.filename, 0o600)


def _get(base: str, jar, path: str):
    """GET JSON from a Hermes. Signed out? Sign in with the wing net key (no password) and try once more."""
    def once():
        req = urllib.request.Request(base + path, headers={"Origin": base})
        with remote._opener(jar).open(req, timeout=8) as r:
            return json.load(r)
    try:
        return once()
    except urllib.error.HTTPError as e:
        if e.code not in (401, 403) or not remote.auto_sign_in(base, jar):
            raise
        save_jar(jar)
        return once()


def _ago(ts) -> str:
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return ""
    s = max(0, time.time() - ts)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{int(s // n)}{unit} ago"
    return "just now"


class Machine:
    def __init__(self, key, label, host, address, kind, online, url="", user="", here=False, seen=0):
        self.key, self.label, self.host, self.address, self.kind = key, label, host, address, kind
        self.online, self.url, self.user, self.here, self.seen = online, url, user, here, seen
        self.open = False
        self.sessions: list[dict] = []
        self.profiles: list[str] = []
        self.note = ""
        self.loaded = False

    @property
    def has_hermes(self) -> bool:
        return self.here or bool(self.url)


def _title(d: dict) -> str:
    """What to call a machine: the name its owner gave it, else its own. Short ones are initials (VPS, NAS)."""
    name = d.get("name", "")
    return d.get("label") or (name.upper() if len(name) <= 3 else name[:1].upper() + name[1:])


def _address(d: dict) -> str:
    """Where another computer's Hermes answers on the wing net. Phones have none."""
    label = core._dns_label(d.get("name", ""))
    return f"https://{label}.wings" if label and d.get("kind") != "phone" else ""


def fleet() -> tuple[list[Machine], str]:
    """This machine, the hub and every device the hub knows. Returns (machines, problem)."""
    state = core.load()
    me = socket.gethostname().split(".")[0]
    out, problem = [], ""
    mine = core.address_settings()
    my_url = core.public_url(mine["Name"], int(mine.get("HttpsPort", 443))) if mine.get("Name") else ""
    if state.get("hub"):
        h = state["hub"]
        out.append(Machine("hub", h.get("label") or _title(h), h["name"], h["address"], "hub", True,
                           my_url, here=True))
        st = core.status()
        for d in st["devices"]:
            out.append(Machine(d["name"], _title(d), d["name"], d["address"], d["kind"], d["online"],
                               _address(d), seen=d["last_handshake"]))
        return out, problem
    m = state.get("member")
    if not m:
        return out, "Wings isn't set up here yet. Run: hermes wings setup  or  hermes wings join <code>"
    t = max(core.handshakes().values(), default=0)
    hub = Machine("hub", _title({"name": m["hub_name"]}), m["hub_name"], core.HUB_IP and str(core.HUB_IP), "hub",
                  bool(t) and time.time() - t < 180, m.get("hub_url", ""), m.get("hub_user", ""), seen=t)
    out.append(hub)
    if hub.url:
        jar = load_jar(hub.url)
        try:
            st = _get(hub.url, jar, "/api/plugins/wings/status")
            if st.get("hub", {}).get("label"):
                hub.label = st["hub"]["label"]
            for d in st.get("devices", []):
                here = d["address"] == m["address"]
                out.append(Machine(d["name"], _title(d), d["name"], d["address"], d["kind"], d["online"],
                                   my_url if here else _address(d), here=here, seen=d["last_handshake"]))
        except urllib.error.HTTPError as e:
            problem = ("the hub doesn't know this computer's wing net key yet: hermes wings doctor"
                       if e.code in (401, 403) else f"hub said {e.code}")
        except OSError as e:
            problem = f"can't reach the hub's Hermes ({e.__class__.__name__})"
    if not any(x.here for x in out):
        out.insert(0, Machine("self", "This computer", me, m["address"], "computer", True, my_url, here=True))
    out.sort(key=lambda x: (not x.here, x.key != "hub", x.label))
    return out, problem


# Sessions Hermes makes for itself rather than for a person (board tasks, tool runs, one-question chats).
SKIP_SOURCES = ("kanban", "tool", "oneshot")


def local_sessions(limit: int = 5) -> list[dict]:
    """This machine's recent sessions, read straight from Hermes's own store: no web, no sign-in."""
    from contextlib import closing
    from hermes_state import SessionDB
    with closing(SessionDB(read_only=True)) as db:
        rows = db.list_sessions_rich(exclude_sources=list(SKIP_SOURCES), limit=limit * 3, order_by_last_active=True)
    return [r for r in rows if r.get("message_count", 1) and not r.get("archived")][:limit]


def load_details(mc: Machine) -> None:
    mc.loaded = True
    if mc.here:
        try:
            mc.sessions, mc.profiles, mc.note = local_sessions(), [], ""
            return
        except Exception:
            if not mc.url:
                mc.note = "opens this machine's Hermes"
                return
    if not mc.url:
        mc.note = "no Hermes address shared with this machine yet" if mc.kind != "phone" else "a phone: nothing to open"
        return
    jar = load_jar(mc.url)
    try:
        got = _get(mc.url, jar, "/api/sessions?limit=20").get("sessions") or []
        mc.sessions = [x for x in got if x.get("message_count", 1) and not x.get("archived")][:5]
        profs = _get(mc.url, jar, "/api/profiles").get("profiles") or []
        mc.profiles = [p.get("name", p) if isinstance(p, dict) else str(p) for p in profs][:6]
        mc.note = ""
    except urllib.error.HTTPError as e:
        mc.note = ("this one doesn't know your wing net yet: press enter to sign in once"
                   if e.code in (401, 403) else f"error {e.code}")
    except OSError:
        mc.note = "can't reach it right now"


# ---------------------------------------------------------------- the picker
#
# One screen. Pick a machine, pick a session (or a new one), and the picker is gone: you're in Hermes,
# in this same terminal, like always. Signing in happens by itself (wing net key, see trust.py).

def hermes_bin() -> str:
    return shutil.which("hermes") or "hermes"


def cells(s: str) -> int:
    import unicodedata
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 0 if unicodedata.combining(ch) else 1 for ch in s)


def cut(s: str, n: int) -> str:
    if n <= 0:
        return ""
    if cells(s) <= n:
        return s
    out = ""
    for ch in s:
        if cells(out + ch) > n - 1:
            break
        out += ch
    return out + "…"


def session_title(s: dict) -> str:
    t = (s.get("title") or s.get("preview") or s.get("first_message") or "").strip()
    if t:
        return t.splitlines()[0]
    n = s.get("message_count")
    return f"untitled · {n} messages" if n else "untitled session"


def hex256(h: str) -> int:
    r, g, b = (int(h[i:i + 2], 16) for i in (1, 3, 5))
    steps = [0, 95, 135, 175, 215, 255]
    near = lambda v: min(range(6), key=lambda i: abs(steps[i] - v))
    ci = (near(r), near(g), near(b))
    cube = 16 + 36 * ci[0] + 6 * ci[1] + ci[2]
    dc = sum((steps[i] - v) ** 2 for i, v in zip(ci, (r, g, b)))
    gi = max(0, min(23, round(((r + g + b) / 3 - 8) / 10)))
    dg = sum((8 + 10 * gi - v) ** 2 for v in (r, g, b))
    return 232 + gi if dg < dc else cube


class Picker:
    def __init__(self, scr):
        self.scr = scr
        self.sel = 0
        self.msg, self.bad = "", False
        self.machines: list[Machine] = []
        self.problem = ""
        self.go = None  # what to open once the screen is gone: (machine, resume id)

    # ---------------------------------------------------------- look

    def colours(self):
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        rich = curses.COLORS >= 256
        pal = {"text": ("#c0bfbb", curses.COLOR_WHITE), "muted": ("#92908d", curses.COLOR_WHITE),
               "faint": ("#5c5a56", curses.COLOR_BLACK), "copper": ("#c9987d", curses.COLOR_YELLOW),
               "green": ("#9db48a", curses.COLOR_GREEN), "red": ("#c97d7d", curses.COLOR_RED)}
        selbg = hex256("#3d3b37") if rich else curses.COLOR_BLACK
        self.C = {}
        for i, (name, (hx, basic)) in enumerate(pal.items(), start=1):
            fg = (180 if name == "copper" else hex256(hx)) if rich else basic
            curses.init_pair(i, fg, bg)
            curses.init_pair(i + 20, fg, selbg)
            self.C[name] = curses.color_pair(i)
            self.C["sel_" + name] = curses.color_pair(i + 20)
        if not rich:
            self.C["faint"] = self.C["muted"] | curses.A_DIM

    def put(self, y, x, text, colour="text", bold=False, sel=False):
        H, W = self.scr.getmaxyx()
        if 0 <= y < H and 0 <= x < W - 1:
            attr = self.C[("sel_" if sel else "") + colour] | (curses.A_BOLD if bold else 0)
            try:
                self.scr.addstr(y, x, cut(text, W - x - 1), attr)
            except curses.error:
                pass

    def say(self, text, bad=False):
        self.msg, self.bad = text, bad

    # ---------------------------------------------------------- data

    def refresh(self):
        old = {m.key: m for m in self.machines}
        self.machines, self.problem = fleet()
        for m in self.machines:
            o = old.get(m.key)
            if o:
                m.open, m.loaded, m.sessions, m.note = o.open, o.loaded, o.sessions, o.note
        # This computer first and already open: most of the time you want your own Hermes.
        if not old:
            for m in self.machines:
                if m.here:
                    m.open = True
                    load_details(m)
                    rows = self.rows()
                    if ("new", m, None) in rows:
                        self.sel = rows.index(("new", m, None))  # enter = a new session here

    def rows(self):
        out = []
        for mc in self.machines:
            out.append(("machine", mc, None))
            if mc.open and mc.has_hermes:
                out.append(("new", mc, None))
                out += [("session", mc, s) for s in mc.sessions]
                if mc.note:
                    out.append(("note", mc, mc.note))
        return out

    # ---------------------------------------------------------- draw

    def draw(self):
        s = self.scr
        s.erase()
        H, W = s.getmaxyx()
        width = min(W - 4, 76)
        x0 = max(2, (W - width) // 2)
        right = x0 + width
        self.put(1, x0, "🪽  W I N G S", "copper", True)
        online = sum(1 for m in self.machines if m.online)
        tag = f"{online} of {len(self.machines)} online"
        self.put(1, right - cells(tag), tag, "faint")
        self.put(2, x0, "─" * width, "faint")
        rows = self.rows()
        self.sel = min(self.sel, max(0, len(rows) - 1))
        y = 4
        top = max(0, self.sel - (H - 10))
        for i, (kind, mc, extra) in enumerate(rows):
            if i < top:
                continue
            if y >= H - 4:
                break
            sel = i == self.sel
            if kind == "machine" and i and y > 4:
                y += 1  # air between machines
            if sel:
                try:
                    s.addstr(y, x0 - 1, " " * (width + 2), self.C["sel_text"])
                except curses.error:
                    pass
            if kind == "machine":
                arrow = ("▾" if mc.open else "▸") if mc.has_hermes else " "
                dot, dc = ("●", "green") if mc.online else ("○", "faint")
                self.put(y, x0, arrow, "faint", sel=sel)
                self.put(y, x0 + 2, dot, dc, sel=sel)
                self.put(y, x0 + 4, mc.label, "copper" if mc.here else "text", True, sel)
                if mc.here:
                    what = "this computer"
                elif mc.kind == "phone":
                    what = "phone · uses the WireGuard app"
                elif mc.key == "hub":
                    what = "hub"
                else:
                    what = "computer"
                self.put(y, x0 + 22, what, "muted", sel=sel)
                state = "online" if mc.online else (f"seen {_ago(mc.seen)}" if mc.seen else "off")
                self.put(y, right - cells(state), state, "green" if mc.online else "faint", sel=sel)
            elif kind == "new":
                self.put(y, x0 + 4, "+  new session", "copper", sel=sel)
            elif kind == "session":
                age = _ago(extra.get("last_active") or extra.get("updated_at") or extra.get("started_at"))
                self.put(y, x0 + 4, "↺", "muted", sel=sel)
                self.put(y, x0 + 7, cut(session_title(extra), width - 9 - cells(age) - 2), "text", sel=sel)
                self.put(y, right - cells(age), age, "faint", sel=sel)
            elif kind == "note":
                self.put(y, x0 + 4, extra, "muted", sel=sel)
            y += 1
        if not rows:
            self.put(4, x0, self.problem or "No machines yet.", "muted")
        self.put(H - 3, x0, "─" * width, "faint")
        if self.msg:
            self.put(H - 2, x0, self.msg, "red" if self.bad else "copper")
        else:
            x = x0
            for k, v in (("↑↓", "choose"), ("enter", "open"), ("q", "quit")):
                self.put(H - 2, x, k, "copper")
                self.put(H - 2, x + cells(k) + 1, v, "muted")
                x += cells(k) + cells(v) + 4
            if self.problem:
                self.put(H - 2, x + 2, cut(self.problem, right - x - 2), "red")
        s.refresh()

    # ---------------------------------------------------------- act

    def ask(self, prompt: str, secret: bool = False) -> str:
        H, W = self.scr.getmaxyx()
        x0 = max(2, (W - min(W - 4, 76)) // 2)
        self.scr.move(H - 2, 0)
        self.scr.clrtoeol()
        self.put(H - 2, x0, prompt, "copper")
        curses.curs_set(1)
        if not secret:
            curses.echo()
        self.scr.timeout(-1)
        try:
            val = self.scr.getstr(H - 2, x0 + cells(prompt) + 1, 120).decode(errors="replace").strip()
        except curses.error:
            val = ""
        finally:
            curses.noecho()
            curses.curs_set(0)
        return val

    def password_fallback(self, mc: Machine) -> bool:
        """Only for a machine that doesn't know your wing net yet (older Wings there)."""
        user = mc.user or self.ask(f"{mc.label} wants its Hermes login. Username:")
        if not user:
            return False
        pw = self.ask(f"Password for {user} (not saved):", secret=True)
        if not pw:
            return False
        jar = load_jar(mc.url)
        try:
            remote.sign_in(mc.url, user, pw, jar)
        except remote.RemoteError as e:
            self.say(str(e), bad=True)
            return False
        save_jar(jar)
        return True

    def toggle(self, mc: Machine):
        if not mc.has_hermes:
            self.say("a phone connects with the WireGuard app; there's no Hermes to open on it"
                     if mc.kind == "phone" else f"{mc.label} hasn't shared its Hermes with this computer yet")
            return
        mc.open = not mc.open
        if mc.open and not mc.loaded:
            self.say(f"connecting to {mc.label}…")
            self.draw()
            load_details(mc)
            if mc.note.startswith("this one doesn't know"):
                if self.password_fallback(mc):
                    load_details(mc)
            self.say("")
        if mc.open:
            self.sel = self.rows().index(("new", mc, None)) if ("new", mc, None) in self.rows() else self.sel

    def act(self):
        rows = self.rows()
        if not rows:
            return
        kind, mc, extra = rows[self.sel]
        if kind == "machine":
            self.toggle(mc)
        elif kind == "new":
            self.go = (mc, "")
        elif kind == "session":
            self.go = (mc, extra.get("id", ""))
        elif kind == "note" and mc.url and self.password_fallback(mc):
            load_details(mc)

    def loop(self):
        curses.curs_set(0)
        self.colours()
        self.say("looking for your machines…")
        self.draw()
        self.refresh()
        self.say("")
        while self.go is None:
            self.draw()
            self.scr.timeout(-1)
            try:
                ch = self.scr.get_wch()
            except curses.error:
                continue
            self.say("")
            n = len(self.rows())
            if ch in (curses.KEY_DOWN, "j", "\t"):
                self.sel = (self.sel + 1) % max(1, n)
            elif ch in (curses.KEY_UP, "k", curses.KEY_BTAB):
                self.sel = (self.sel - 1) % max(1, n)
            elif ch in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
                self.act()
            elif ch in (curses.KEY_LEFT, "h"):
                mc = self.rows()[self.sel][1] if n else None
                if mc:
                    mc.open = False
                    self.sel = self.rows().index(("machine", mc, None))
            elif ch == "r":
                for m in self.machines:
                    m.loaded = False
                    if m.open:
                        load_details(m)
                self.refresh()
            elif ch in ("q", "\x1b"):
                return None
        return self.go


def run() -> int:
    """`hermes wings`: pick a machine and a session, then you're simply in Hermes."""
    if not sys.stdout.isatty():
        print("hermes wings needs a terminal. For a plain list: hermes wings status")
        return 1
    import locale
    locale.setlocale(locale.LC_ALL, "")
    os.environ.setdefault("ESCDELAY", "25")
    picked = curses.wrapper(lambda scr: Picker(scr).loop())
    if not picked:
        return 0
    mc, resume = picked
    if mc.here:
        argv = [hermes_bin(), "--tui"] + (["--resume", resume] if resume else [])
        os.execvp(argv[0], argv)
    print(f"🪽 {mc.label} — Ctrl-] to leave\n")
    return attach_cli(mc.url, resume=resume)


def attach_cli(url: str, resume: str = "", profile: str = "", say: str = "") -> int:
    """`hermes wings attach <url>`: the remote Hermes TUI in this terminal."""
    jar = load_jar(url)
    try:
        ws = remote.open_terminal(url, jar, resume=resume, fresh=not resume, profile=profile)
    except remote.RemoteError as e:
        if "signed out" not in str(e):
            print(f"wings: {e}")
            return 1
        ws = None
        if remote.auto_sign_in(url, jar):
            save_jar(jar)
            try:
                ws = remote.open_terminal(url, jar, resume=resume, fresh=not resume, profile=profile)
            except remote.RemoteError:
                ws = None
    if ws is None:
        import getpass
        user = input(f"Hermes login for {url}, username: ").strip()
        try:
            remote.sign_in(url, user, getpass.getpass("password (not saved): "), jar)
        except remote.RemoteError as e2:
            print(f"wings: {e2}")
            return 1
        save_jar(jar)
        ws = remote.open_terminal(url, jar, resume=resume, fresh=not resume, profile=profile)
    save_jar(jar)
    if say:
        ws.pending_input = say.encode() + b"\r"
    return remote.attach(ws)
