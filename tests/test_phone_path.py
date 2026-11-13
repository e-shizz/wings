"""What a phone needs from a hub: .wings names, and Hermes over plain HTTP inside the tunnel.
Runs the real programs from the root helper on localhost, on high ports. Run: python3 tests/test_phone_path.py"""
import os
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

root = Path(__file__).resolve().parent.parent
helper = root / "plugin" / "root" / "wings-root.sh"
tmp = Path(tempfile.mkdtemp())
fails = 0


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def program(fn, dest):
    subprocess.run(["bash", "-c", f'source "{helper}"; {fn} "{dest}"'], check=True)
    dest.chmod(0o755)


def wait_port(port):
    for _ in range(100):
        with socket.socket() as c:
            c.settimeout(0.2)
            if c.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.05)
    return False


def query(name, kind=1, qid=b"\x12\x34"):
    q = qid + b"\x01\0\0\1\0\0\0\0\0\0"
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", kind, 1)
    return q


def udp(port, q, timeout=3.0):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(q, ("127.0.0.1", port))
        try:
            return s.recv(4096)
        except socket.timeout:
            return b""


def rcode(a):
    return a[3] & 15


def answers(a):
    return struct.unpack("!H", a[6:8])[0]


# ---------------------------------------------------------------- names

class FakeResolver(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data[:2] + b"\x81\x80\0\1\0\1\0\0\0\0" + data[12:] + b"\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4\x08\x08\x04\x04", self.client_address)


resolver = socketserver.ThreadingUDPServer(("127.0.0.1", 0), FakeResolver)
threading.Thread(target=resolver.serve_forever, daemon=True).start()
up = resolver.server_address[1]

(tmp / "names").write_text("10.77.0.1 vps.wings\n10.77.0.3 desk.wings\n")
program("write_dns_server", tmp / "dns")
dport = free_port()
dns = subprocess.Popen([str(tmp / "dns"), "127.0.0.1", str(tmp / "names"), str(dport), f"127.0.0.1:{up}"])
check("name server starts", wait_port(dport))

a = udp(dport, query("vps.wings"))
check("vps.wings answers 10.77.0.1", rcode(a) == 0 and answers(a) == 1 and a[-4:] == bytes([10, 77, 0, 1]))
check("the reply keeps the query's id", a[:2] == b"\x12\x34")
a = udp(dport, query("DESK.wings"))
check("names don't care about case", answers(a) == 1 and a[-4:] == bytes([10, 77, 0, 3]))
a = udp(dport, query("vps.wings", 28))
check("IPv6 for a known name: no data, not 'no such name'", rcode(a) == 0 and answers(a) == 0)
a = udp(dport, query("nobody.wings"))
check("an unknown .wings name doesn't exist", rcode(a) == 3 and answers(a) == 0)
a = udp(dport, query("example.com"))
check("other names go to this machine's resolver", answers(a) == 1 and a[-4:] == bytes([8, 8, 4, 4]))
check("must fail: a reply to a reply gets no answer", udp(dport, b"\x12\x34\x81\x80" + b"\0" * 12, 0.5) == b"")
check("must fail: garbage gets no answer", udp(dport, b"\xff" * 40, 0.5) == b"")
check("must fail: a cut-off name gets no answer", udp(dport, b"\x12\x34\x01\0\0\1\0\0\0\0\0\0\x3f" + b"a", 0.5) == b"")

with socket.create_connection(("127.0.0.1", dport), timeout=3) as c:
    q = query("desk.wings")
    c.sendall(struct.pack("!H", len(q)) + q)
    n = struct.unpack("!H", c.recv(2))[0]
    a = c.recv(n)
check("names over TCP too", answers(a) == 1 and a[-4:] == bytes([10, 77, 0, 3]))
dns.terminate()

# ---------------------------------------------------------------- port 80

seen = []


class FakeHermes(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            head = b""
            while not head.endswith(b"\r\n\r\n"):
                line = self.rfile.readline()
                if not line:
                    return
                head += line
            body = b""
            for h in head.lower().split(b"\r\n"):
                if h.startswith(b"content-length:"):
                    body = self.rfile.read(int(h.split(b":")[1]))
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
program("write_tls_proxy", tmp / "proxy")
tport, pport, aport = free_port(), free_port(), free_port()
proxy = subprocess.Popen([str(tmp / "proxy"), "127.0.0.1", "vps.wings", str(hermes.server_address[1]), str(tport), str(pport), str(aport)],
                         env={**os.environ, "CREDENTIALS_DIRECTORY": str(creds)})
check("web front starts", wait_port(pport))


def web(*headers, path="/api/status"):
    req = f"GET {path} HTTP/1.1\r\nHost: vps.wings\r\nConnection: close\r\n" + "".join(h + "\r\n" for h in headers) + "\r\n"
    with socket.create_connection(("127.0.0.1", pport), timeout=3) as c:
        c.sendall(req.encode())
        out = b""
        try:
            while chunk := c.recv(4096):
                out += chunk
        except socket.timeout:
            pass
    return out


APP = "User-Agent: okhttp/5.0.0"
DESK = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"
PHONE = "User-Agent: Mozilla/5.0 (Linux; Android 16) Chrome/140 Mobile Safari/537.36"
UPGRADE = "Upgrade-Insecure-Requests: 1"

r = web(APP)
check("the Hermes app reaches Hermes", r.endswith(b"hermes") and b" 200 " in r.split(b"\r\n")[0])
check("Hermes gets the request unchanged", seen and seen[-1].startswith(b"GET /api/status HTTP/1.1\r\nHost: vps.wings\r\n"))
r = web(PHONE, UPGRADE)
check("a phone's browser reaches Hermes", r.endswith(b"hermes"))
r = web(DESK, UPGRADE, path="/chat?x=1")
check("a computer's browser goes to HTTPS", r.startswith(b"HTTP/1.1 301") and f"Location: https://vps.wings:{tport}/chat?x=1\r\n".encode() in r)
n = len(seen)
r = web(DESK, UPGRADE)
check("and that redirect never reaches Hermes", len(seen) == n)
with socket.create_connection(("127.0.0.1", pport), timeout=12) as c:
    c.sendall(b"GET / HTTP/1.1\r\nHost: slow")
    c.settimeout(12)
    check("must fail: a request that never finishes is dropped", c.recv(100) == b"")

# ---------------------------------------------------------------- no-password sign-in

STATE = "a" * 24


def on_one_connection(port, *requests):
    """Send requests one after another on a single kept-open connection; return each raw reply."""
    out = []
    with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
        for r in requests:
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
    return out


ask = b"GET /wings-approve?state=" + STATE.encode() + b" HTTP/1.1\r\nHost: vps.wings\r\n\r\n"
web(DESK, path="/login")
check("off the tunnel, the sign-in page is Hermes's own", seen[-1].startswith(b"GET /login HTTP/1.1"))
r = web(APP, path=f"/wings-approve?state={STATE}")
check("must fail: a connection that isn't on the tunnel", r.startswith(b"HTTP/1.1 404"))
n = len(seen)
r = web(APP, path=f"/wings-approve?state={STATE}")
check("and it never reaches Hermes", len(seen) == n)
proxy.terminate()
proxy.wait()

# The sign-in that says yes, and the must-fail cases from this machine itself: tests/test_device_signin.py

print(f"{fails} failed")
sys.exit(1 if fails else 0)
