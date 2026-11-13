"""The no-password sign-in: who counts as a device on the wing net, and who must not.

Builds a small wing net out of two network namespaces, without root (a user namespace): this machine
(the hub, 10.77.0.1 on wings0) and a device (10.77.0.2) joined by a cable (a veth pair). The real web
front from the root helper runs on the hub. The device must be signed in; a program on the hub itself must
never be, whatever address it uses. Run: python3 tests/test_device_signin.py"""
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

if os.environ.get("WINGS_TEST_NS") != "1":
    if not shutil.which("unshare") or subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode:
        print("skip: this system doesn't allow user namespaces, so the wing net can't be built here")
        sys.exit(0)
    os.execvpe("unshare", ["unshare", "-rn", sys.executable, "-I", __file__], {**os.environ, "WINGS_TEST_NS": "1"})

root = Path(__file__).resolve().parent.parent
helper = root / "plugin" / "root" / "wings-root.sh"
tmp = Path(tempfile.mkdtemp())
fails = 0
HUB, DEV = "10.77.0.1", "10.77.0.2"


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


def sh(*cmd):
    subprocess.run(cmd, check=True)


# ---------------------------------------------------------------- the wing net

device_ns = subprocess.Popen(["unshare", "-n", "sleep", "600"])
time.sleep(0.2)
sh("ip", "link", "set", "lo", "up")
sh("ip", "link", "add", "wings0", "type", "veth", "peer", "name", "dev0")
sh("ip", "link", "set", "dev0", "netns", str(device_ns.pid))
sh("ip", "addr", "add", f"{HUB}/24", "dev", "wings0")
sh("ip", "link", "set", "wings0", "up")
OTHER = "10.77.0.9"  # a second wing net address this machine happens to have (on loopback)
sh("ip", "addr", "add", f"{OTHER}/32", "dev", "lo")
inside = ["nsenter", "-t", str(device_ns.pid), "-n"]
sh(*inside, "ip", "link", "set", "lo", "up")
sh(*inside, "ip", "addr", "add", f"{DEV}/24", "dev", "dev0")
sh(*inside, "ip", "link", "set", "dev0", "up")

hub_ns = os.open("/proc/self/ns/net", os.O_RDONLY)
dev_ns = os.open(f"/proc/{device_ns.pid}/ns/net", os.O_RDONLY)


def socket_on(ns):
    """A socket that lives in the given namespace (the device's, or the hub's own)."""
    os.setns(ns, os.CLONE_NEWNET)
    try:
        return socket.socket()
    finally:
        os.setns(hub_ns, os.CLONE_NEWNET)


# ---------------------------------------------------------------- Hermes, and the web front

seen = []


class FakeHermes(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                ch = self.rfile.read(1)
                if not ch:
                    return
                head += ch
            n = next((int(l.split(b":")[1]) for l in head.lower().split(b"\r\n") if l.startswith(b"content-length:")), 0)
            body = self.rfile.read(n) if n else b""
            seen.append(head + body)
            keep = b"connection: close" not in head.lower()
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n" + (b"" if keep else b"Connection: close\r\n") + b"\r\nhermes")
            self.wfile.flush()
            if not keep:
                return


hermes = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeHermes)
hermes.daemon_threads = True
threading.Thread(target=hermes.serve_forever, daemon=True).start()

creds = tmp / "creds"
creds.mkdir()
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=vps.wings", "-days", "1",
                "-keyout", str(creds / "key"), "-out", str(creds / "cert")], check=True, capture_output=True)
subprocess.run(["bash", "-c", f'source "{helper}"; write_tls_proxy "{tmp / "proxy"}"'], check=True)
(tmp / "proxy").chmod(0o755)
tport, pport = 8443, 8080
proxy = subprocess.Popen([str(tmp / "proxy"), HUB, "vps.wings", str(hermes.server_address[1]), str(tport), str(pport),
                          "10.77.0."], env={**os.environ, "CREDENTIALS_DIRECTORY": str(creds)})
for _ in range(100):
    with socket.socket() as c:
        if c.connect_ex((HUB, pport)) == 0:
            break
    time.sleep(0.05)


def ask(ns, path, *headers, source=None, freebind=False, requests=None):
    """Send requests on one connection from a namespace; return each raw reply, or None if it can't connect."""
    c = socket_on(ns)
    c.settimeout(3)
    try:
        if freebind:
            c.setsockopt(socket.IPPROTO_IP, 15, 1)  # IP_FREEBIND: claim an address this machine doesn't have
        if source:
            c.bind((source, 0))
        c.connect((HUB, pport))
    except OSError:
        c.close()
        return None
    out = []
    with c:
        for r in requests or [f"GET {path} HTTP/1.1\r\nHost: vps.wings\r\n".encode()
                              + b"".join(h.encode() + b"\r\n" for h in headers) + b"\r\n"]:
            c.sendall(r)
            data = b""
            try:
                while b"\r\n\r\n" not in data or not (data.endswith(b"hermes") or b"Content-Length: 0" in data):
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
            out.append(data)
    return out if requests else out[0]


STATE = "a" * 24
APPROVE = f"/wings-approve?state={STATE}"
APP = "User-Agent: okhttp/5.0.0"
DESK = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"

# ---------------------------------------------------------------- a device on the tunnel

r = ask(dev_ns, APPROVE, APP)
loc = [l for l in r.split(b"\r\n") if l.startswith(b"Location:")]
check("a device on the tunnel is signed in", r.startswith(b"HTTP/1.1 302") and bool(loc))
code = loc[0].split(b"code=")[1].split(b"&")[0].decode() if loc else ""
check("the note names that device", ".".join(code.split(".")[1:5]) == DEV)
check("it returns to the address the device came from", bool(loc) and loc[0].startswith(f"Location: http://vps.wings:{pport}/auth/callback?".encode()))
check("must fail: a malformed sign-in", ask(dev_ns, "/wings-approve?state=short", APP).startswith(b"HTTP/1.1 404"))
r = ask(dev_ns, APPROVE + "%0d%0aSet-Cookie:x", APP)
check("must fail: header injection", r.startswith(b"HTTP/1.1 404") and b"Set-Cookie" not in r)

keep = b"GET /a HTTP/1.1\r\nHost: vps.wings\r\nUser-Agent: okhttp\r\n\r\n"
post = b"POST /b HTTP/1.1\r\nHost: vps.wings\r\nContent-Length: 5\r\n\r\nhello"
approve = f"GET {APPROVE} HTTP/1.1\r\nHost: vps.wings\r\n\r\n".encode()
n = len(seen)
a1, a2, a3 = ask(dev_ns, None, requests=[keep, post, approve])
check("two requests on one open connection both reach Hermes", a1.endswith(b"hermes") and a2.endswith(b"hermes") and len(seen) == n + 2)
check("the body arrives whole", seen[-1].endswith(b"\r\n\r\nhello"))
check("sign-in works on a connection the browser kept open", a3.startswith(b"HTTP/1.1 302"))
n = len(seen)
ask(dev_ns, None, requests=[b"POST /c HTTP/1.1\r\nHost: vps.wings\r\nContent-Length: 4\r\n\r\nGET "])
check("a body is never mistaken for a request", len(seen) == n + 1 and seen[-1].endswith(b"\r\n\r\nGET "))

n = len(seen)
r = ask(dev_ns, "/login", DESK)
check("Desktop's sign-in window skips the chooser", r.startswith(b"HTTP/1.1 302") and b"Location: /auth/login?provider=wings-device\r\n" in r and len(seen) == n)
ask(dev_ns, "/login?next=%2Fchat", DESK)
check("a sign-in page with something to say is left alone", seen[-1].startswith(b"GET /login?next=%2Fchat"))
ask(dev_ns, "/login", DESK, "Referer: https://vps.wings/chat")
check("signing out stays signed out", seen[-1].startswith(b"GET /login HTTP/1.1"))
ask(dev_ns, "/auth/native/authorize?code_challenge=x&redirect_uri=y", APP)
check("the app skips the chooser", b"provider=wings-device&code_challenge=x" in seen[-1])
ask(dev_ns, "/auth/native/authorize?provider=basic&x=1", APP)
check("a choice already made is left alone", b"?provider=basic&x=1" in seen[-1] and b"wings-device" not in seen[-1])

# ---------------------------------------------------------------- programs on the hub itself

r = ask(hub_ns, "/api/status", APP)
check("this machine's own browser still reaches Hermes", r is not None and r.endswith(b"hermes"))
n = len(seen)
r = ask(hub_ns, APPROVE, APP)
check("must fail: a program on this machine asks for a device sign-in", r is not None and r.startswith(b"HTTP/1.1 404"))
check("and it never reaches Hermes", len(seen) == n)
r = ask(hub_ns, APPROVE, APP, source=HUB)
check("must fail: the same, from this machine's own tunnel address", r is not None and r.startswith(b"HTTP/1.1 404"))
r = ask(hub_ns, APPROVE, APP, source=OTHER)
check("must fail: the same, from another wing net address this machine has", r is not None and r.startswith(b"HTTP/1.1 404"))
r = ask(hub_ns, APPROVE, APP, source=DEV, freebind=True)
check("must fail: a program on this machine pretends to be the device", r is None or r.startswith(b"HTTP/1.1 404"))
r = ask(hub_ns, "/login", DESK)
check("must fail: a program on this machine skips the chooser", r is not None and seen[-1].startswith(b"GET /login HTTP/1.1"))
ask(hub_ns, "/auth/native/authorize?code_challenge=x&redirect_uri=y", APP)
check("must fail: a program on this machine gets the app's device sign-in", b"provider=wings-device" not in seen[-1])

# A program on the hub that sends out through the tunnel itself: nobody on the other end answers for the hub's
# own address, so it can't come back in that way (on a real wing net, WireGuard drops it too).
c = socket_on(hub_ns)
c.settimeout(2)
c.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wings0")
try:
    c.connect((HUB, pport))
    c.sendall(f"GET {APPROVE} HTTP/1.1\r\nHost: vps.wings\r\n\r\n".encode())
    r = c.recv(4096)
except OSError:
    r = None
c.close()
check("must fail: a program on this machine loops out through the tunnel", r is None or r.startswith(b"HTTP/1.1 404"))

# Some servers (load balancers, failover pairs) let programs bind any address. The answer must not change.
Path("/proc/sys/net/ipv4/ip_nonlocal_bind").write_text("1")
check("with ip_nonlocal_bind on, a device on the tunnel is still signed in", ask(dev_ns, APPROVE, APP).startswith(b"HTTP/1.1 302"))
r = ask(hub_ns, APPROVE, APP, source=OTHER)
check("must fail: and a program on this machine still isn't", r is not None and r.startswith(b"HTTP/1.1 404"))

proxy.terminate()
proxy.wait()
device_ns.kill()
print(f"{fails} failed")
sys.exit(1 if fails else 0)
