"""Wing net sign-in: what must work and what must fail. Run: python3 tests/test_trust.py"""
import os
import sys
import tempfile
import time
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "plugin"
sys.path.insert(0, str(root))
os.environ["WINGS_HOME"] = tempfile.mkdtemp()

from wings import core, trust  # noqa: E402

fails = 0


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


core.get_address = lambda: "vps.wings"
key = trust.ensure_netkey()
check("hub makes a 32-byte key", len(bytes.fromhex(key)) == 32)
check("key file is private", oct(os.stat(core.home() / "netkey").st_mode & 0o777) == "0o600")
check("the same key on the next call", trust.ensure_netkey() == key)

note = trust.note_for("vps.wings", "desk")
check("a fresh note for this machine is accepted", trust.check_note("desk", note))
check("must fail: the same note twice (replay)", not trust.check_note("desk", note))
check("must fail: a note for another machine", not trust.check_note("desk", trust.note_for("den.wings", "desk")))
check("must fail: a note claiming another user", not trust.check_note("mallory", trust.note_for("vps.wings", "desk")))
check("must fail: garbage", not trust.check_note("desk", "w1.1.2.3"))
check("must fail: empty", not trust.check_note("desk", ""))

real_time = time.time
time.time = lambda: real_time() - 600
old = trust.note_for("vps.wings", "desk")
time.time = real_time
check("must fail: a note ten minutes old", not trust.check_note("desk", old))

saved = (core.home() / "netkey").read_text()
other = trust.note_for("vps.wings", "desk")
trust.save_netkey("ab" * 32)
check("must fail: a note signed with another wing net's key", not trust.check_note("desk", other))
(core.home() / "netkey").write_text(saved)

at, _ = trust.mint("desk", "a", 3600)
rt, _ = trust.mint("desk", "r", 3600)
check("access token reads back", (trust.read(at, "a") or {}).get("u") == "desk")
check("must fail: refresh token used as access", trust.read(rt, "a") is None)
check("must fail: tampered token", trust.read(at[:-3] + "AAA", "a") is None)
exp, _ = trust.mint("desk", "a", -5)
check("must fail: expired token", trust.read(exp, "a") is None)
trust.save_netkey("cd" * 32)
check("must fail: tokens from before the key changed", trust.read(at, "a") is None)
(core.home() / "netkey").write_text(saved)
check("tokens work again with the old key back", trust.read(at, "a") is not None)

trust.set_enabled(False)
check("must fail: trust off refuses notes", not trust.check_note("desk", trust.note_for("vps.wings", "desk")))
check("must fail: trust off refuses sessions", trust.read(at, "a") is None)
trust.set_enabled(True)

(core.home() / "netkey").unlink()
check("no key: no note to send", trust.note_for("vps.wings") is None)
check("must fail: no key, nothing accepted", not trust.check_note("desk", note))
(core.home() / "netkey").write_text(saved)

# The provider against Hermes's real interface, when Hermes is importable.
hermes = Path.home() / ".hermes" / "hermes-agent"
if hermes.exists():
    sys.path.insert(0, str(hermes))
    try:
        from hermes_cli.dashboard_auth.base import (InvalidCredentialsError, RefreshExpiredError,
                                                    assert_protocol_compliance)
        p = trust.provider()
        assert_protocol_compliance(type(p))
        check("provider meets Hermes's protocol", True)
        check("provider stays off the login page", p.interactive_login is False and p.supports_password)
        dp = trust.device_provider()
        assert_protocol_compliance(type(dp))
        check("device sign-in is offered and takes no password", dp.interactive_login and not dp.supports_password)
        ls = dp.start_login(redirect_uri="https://vps.wings/auth/callback")
        check("device sign-in stays on the same address", ls.redirect_url.startswith("/wings-approve?state="))
        s = p.complete_password_login(username="desk", password=trust.note_for("vps.wings", "desk"))
        check("provider signs in a good note", s.provider == "wings" and s.user_id == "wings:desk")
        check("provider verifies its own session", p.verify_session(access_token=s.access_token) is not None)
        check("provider refreshes", p.refresh_session(refresh_token=s.refresh_token).user_id == "wings:desk")
        try:
            p.complete_password_login(username="desk", password="hunter2")
            check("must fail: provider takes a plain password", False)
        except InvalidCredentialsError:
            check("must fail: provider takes a plain password", True)
        try:
            p.refresh_session(refresh_token="some-other-providers-token")
            check("must fail: provider refreshes a foreign token", False)
        except RefreshExpiredError:
            check("must fail: provider refreshes a foreign token", True)
        check("must fail: provider verifies a foreign token", p.verify_session(access_token="eyJhbGciOi") is None)
    except ImportError as e:
        print(f"skip Hermes provider checks ({e})")

# Device sign-in: the note the tunnel port writes, checked the way Hermes will check it.
import hashlib  # noqa: E402
import hmac  # noqa: E402

(core.home() / "tls").mkdir(exist_ok=True)
(core.home() / "tls" / "leaf.key").write_bytes(b"pretend private key")
akey = hashlib.sha256(b"wings-approve\0pretend private key").digest()


def device_code(state, peer, ts=None, k=akey):
    ts = str(int(time.time()) if ts is None else ts)
    return f"{ts}.{peer}." + hmac.new(k, f"wings-device|{state}|{peer}|{ts}".encode(), hashlib.sha256).hexdigest()


c = device_code("s" * 20, "10.77.0.4")
check("a device on the tunnel is vouched for", trust.check_device_code(c, "s" * 20) == "10.77.0.4")
check("must fail: the same code twice", trust.check_device_code(c, "s" * 20) is None)
check("must fail: a code for another sign-in", trust.check_device_code(device_code("s" * 20, "10.77.0.4"), "t" * 20) is None)
check("must fail: a code three minutes old", trust.check_device_code(device_code("s" * 20, "10.77.0.4", time.time() - 180), "s" * 20) is None)
check("must fail: signed with another key", trust.check_device_code(device_code("s" * 20, "10.77.0.4", k=b"x" * 32), "s" * 20) is None)
check("must fail: claims an address outside the tunnel", trust.check_device_code(device_code("s" * 20, "8.8.8.8"), "s" * 20) is None)
check("must fail: garbage", trust.check_device_code("1.2.3", "s" * 20) is None)
trust.set_enabled(False)
check("must fail: trust off refuses devices", trust.check_device_code(device_code("s" * 20, "10.77.0.4"), "s" * 20) is None)
trust.set_enabled(True)

print(f"{fails} failed")
sys.exit(1 if fails else 0)
