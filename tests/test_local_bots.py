"""The Wings tab's list of this machine's bots, when Hermes's own routes can't be asked as the person (Hermes
Desktop signs each request with a one-use ticket): the same answers have to come from disk.
Needs Hermes's own Python. Run: python3 tests/test_local_bots.py (it finds Hermes, or skips)."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
# A throwaway Hermes home, set before Hermes starts up (it works out its home once).
home = Path(os.environ.get("WINGS_TEST_HOME") or tempfile.mkdtemp())
os.environ["HERMES_HOME"] = os.environ["WINGS_TEST_HOME"] = str(home)

src = Path(os.environ.get("HERMES_AGENT_DIR") or Path.home() / ".hermes/hermes-agent")
if (src / "hermes_state.py").is_file():
    sys.path.insert(0, str(src))
try:
    try:
        import hermes_bootstrap  # noqa: F401 - sets up Hermes's own packages, as its launcher does
    except ImportError:
        pass
    import hermes_state  # noqa: F401
except ImportError:
    # Not Hermes's Python: ask the launcher which one it runs, and start again under it.
    py = os.environ.get("HERMES_PYTHON")
    if not py and shutil.which("hermes"):
        try:
            import json
            out = subprocess.run(["hermes", "--print-runtime-command", "x"], capture_output=True, text=True, timeout=30).stdout
            py = json.loads(out.strip().splitlines()[-1])[0]
        except Exception:  # noqa: BLE001
            py = None
    if py and Path(py).is_file() and os.environ.get("WINGS_TEST_REEXEC") != "1":
        os.execve(py, [py, "-I", __file__], {**os.environ, "WINGS_TEST_REEXEC": "1"})
    shutil.rmtree(home, ignore_errors=True)
    print("skip: Hermes isn't installed here, so its session store can't be used")
    sys.exit(0)

(home / "config.yaml").write_text("model:\n  default: glm-5.3\n")
(home / "profiles" / "scout").mkdir(parents=True)
(home / "profiles" / "scout" / "config.yaml").write_text("model: deepseek-v4.1\n")
(home / "profiles" / "scout" / "profile.yaml").write_text("display_name: Scout the Bold\n")
(home / "profiles" / "ghost").mkdir()  # an empty folder is not a bot

from contextlib import closing  # noqa: E402
from hermes_state import SessionDB  # noqa: E402

with closing(SessionDB(db_path=home / "state.db")) as db:
    db.create_session("s-chat", "cli")
    db.append_message("s-chat", "user", "hello")
    db.create_session("s-empty", "cli")
    db.create_session("s-board", "kanban")
    db.append_message("s-board", "user", "a board task")

import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("wings_api", root / "plugin/dashboard/plugin_api.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
fails = 0


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


def refused(path):
    raise OSError("401 Unauthorized")  # what this Hermes answers to a request whose ticket was already used


here = api._here(refused)
bots = {b["name"]: b for b in api._bots(here) or []}
check("this machine's bots are listed though its routes refused", set(bots) == {"default", "scout"})
check("with their models", bots.get("default", {}).get("model") == "glm-5.3" and bots.get("scout", {}).get("model") == "deepseek-v4.1")
check("a person's chat is counted", bots.get("default", {}).get("sessions") == 1)
recent = bots.get("default", {}).get("recent", [])
check("empty sessions and board tasks are left out", [r["id"] for r in recent] == ["s-chat"])
check("a bot whose gateway is off shows as asleep", bots.get("default", {}).get("up") is False)
looks = api._looks(here)
check("the look its owner gave a bot is found", looks.get("scout", {}).get("title") == "Scout the Bold")

calls = []


def answers(path):
    calls.append(path)
    if path.startswith("/api/profiles"):
        return {"profiles": [{"name": "default", "gateway_running": True, "model": "m"}]}
    return {"sessions": [{"id": "x", "title": "t", "last_active": 5}], "total": 1}


bots = api._bots(api._here(answers))
check("when the routes answer, their answer is used", bots == [{"name": "default", "up": True, "model": "m", "sessions": 1, "last": 5,
                                                              "recent": [{"id": "x", "title": "t", "last": 5}]}])
check("and sessions are asked for by latest activity, people's chats only",
      any("order=recent" in c and "min_messages=1" in c and "exclude_sources=kanban,tool" in c for c in calls))

shutil.rmtree(home)
print(f"{fails} failed")
sys.exit(1 if fails else 0)
