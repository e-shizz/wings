"""The Turn on button's background job. Run: python3 tests/test_start_job.py."""
import importlib.util, os, stat, sys, tempfile, time
from pathlib import Path

import types


class HTTPException(Exception):
    def __init__(self, status_code, detail=""):
        self.status_code, self.detail = status_code, detail


class APIRouter:
    def get(self, _):
        return lambda f: f
    post = delete = get


fa = types.ModuleType("fastapi")
fa.APIRouter, fa.HTTPException, fa.Body = APIRouter, HTTPException, lambda *a, **k: None
fa.Request = object
resp = types.ModuleType("fastapi.responses")
resp.JSONResponse = resp.Response = object
sys.modules.update({"fastapi": fa, "fastapi.responses": resp})

root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("wings_api", root / "plugin/dashboard/plugin_api.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
fails = 0


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


def run(script, body):
    d = tempfile.mkdtemp()
    fake = Path(d) / "fake"
    fake.write_text("#!/bin/sh\n" + script)
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    seen = {}
    def cmd(*a):
        seen["args"] = a
        return [str(fake), *a]
    api._wings_cmd = cmd
    api.start(body)
    for _ in range(200):
        if not api._job["running"]:
            break
        time.sleep(0.02)
    return seen["args"], api.start_status()


_, j = run("echo Wings needs admin rights once\necho done\n", {"action": "setup"})
check("setup success", j["ok"] is True and not j["error"] and "approve" in j["stage"])
_, j = run("echo 'Note: devices will dial 192.168.1.2, x'\n", {"action": "setup"})
check("private address gets a plain note", "only on this network" in j["note"])
_, j = run("echo 'Stopped: 10.77.0.0/24 is in use'\nexit 1\n", {"action": "setup"})
check("stop reason shown", j["ok"] is False and j["error"] == "10.77.0.0/24 is in use")
_, j = run("echo 'sudo: a password is required'\nexit 1\n", {"action": "setup"})
check("no admin box is explained", "terminal" in j["error"])
a, j = run('cat "$3" | grep -q SECRET || exit 9\n', {"action": "join", "code": "hermes wings join SECRET"})
check("invite goes through a file, not argv", j["ok"] is True and "SECRET" not in " ".join(a))
check("invite file is removed", not os.path.exists(a[2]))
api._job["running"] = True
try:
    api.start({"action": "setup"})
    check("second start refused", False)
except Exception as e:
    check("second start refused", getattr(e, "status_code", 0) == 409)
api._job["running"] = False
print(f"{fails} failed")
sys.exit(1 if fails else 0)
