"""Pure checks for living alongside other setups. Run: python3 tests/test_core.py"""
import base64, json, os, sys, tempfile, importlib.util
from pathlib import Path

os.environ["WINGS_HOME"] = tempfile.mkdtemp(prefix="wings-test.")
spec = importlib.util.spec_from_file_location("core", Path(__file__).parent.parent / "plugin/wings/core.py")
c = importlib.util.module_from_spec(spec); sys.modules["core"] = c; spec.loader.exec_module(c)
fails = 0

def check(name, ok):
    global fails
    fails += 0 if ok else 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}")

print("existing networks:")
check("another WireGuard on the same subnet is caught", c.subnet_conflicts([{"dst": "10.77.0.0/24", "dev": "wg0"}], []))
check("a wider route over it is caught", c.subnet_conflicts([{"dst": "10.0.0.0/8", "dev": "wg0"}], []))
check("an address inside it is caught", c.subnet_conflicts([], [{"ifname": "eth0", "addr_info": [{"local": "10.77.0.9", "prefixlen": 24}]}]))
check("our own interface is not a clash", not c.subnet_conflicts([{"dst": "10.77.0.0/24", "dev": "wings0"}], [{"ifname": "wings0", "addr_info": [{"local": "10.77.0.3", "prefixlen": 32}]}]))
check("neighbours are fine", not c.subnet_conflicts([{"dst": "10.50.0.0/24", "dev": "wg0"}, {"dst": "192.168.1.0/24", "dev": "wlan0"}, {"dst": "default", "dev": "wlan0"}], []))
check("other tunnels are listed", c.other_tunnels([{"ifname": "wg0"}, {"ifname": "wings0"}, {"ifname": "eth0"}]) == ["wg0"])
check("a full-tunnel VPN is noticed", c.full_tunnel_devices([{"dst": "default", "dev": "wg0-mullvad"}]) == ["wg0-mullvad"])
check("a normal default route is not", not c.full_tunnel_devices([{"dst": "default", "dev": "wlp2s0"}]))

print("existing web servers:")
ss = "LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 511 [::]:80 [::]:*\n"
check("443 and 80 taken: moves aside", c.web_ports(c.listeners(ss), "10.77.0.3") == (8443, 8080))
check("free: uses the normal ports", c.web_ports(c.listeners("LISTEN 0 5 127.0.0.1:443 0.0.0.0:*"), "10.77.0.3") == (443, 80))
check("443 on another address is no clash", c.web_ports(c.listeners("LISTEN 0 5 192.168.1.5:443 0.0.0.0:*"), "10.77.0.1") == (443, 80))
check("443 on our own address is a clash", c.web_ports(c.listeners("LISTEN 0 5 10.77.0.3:443 0.0.0.0:*"), "10.77.0.3")[0] == 8443)
check("the URL carries a moved port", c.public_url("a.wings", 8443) == "https://a.wings:8443")

print("invites:")
good = {"v": 1, "n": "vps", "h": "A" * 43 + "=", "e": "1.2.3.4:51877", "a": "10.77.0.3", "k": "B" * 43 + "="}
enc = lambda d: "wings1:" + base64.urlsafe_b64encode(json.dumps(d).encode()).decode()
check("a real invite parses", c.parse_invite(enc(good))["a"] == "10.77.0.3")
for label, bad in (("address off the tunnel", {"a": "1.2.3.4"}), ("claims the hub address", {"a": "10.77.0.1"}),
                   ("hostile endpoint", {"e": "$(id):51877"}), ("bad key", {"k": "x"}), ("hostile relay secret", {"r": {"port": 443, "secret": "--x"}})):
    try:
        c.parse_invite(enc({**good, **bad})); check(f"rejects {label}", False)
    except ValueError:
        check(f"rejects {label}", True)
try:
    c.parse_invite("not an invite"); check("rejects junk", False)
except ValueError:
    check("rejects junk", True)

print("devices that keep their own key:")
state = c.init("t", "1.2.3.4:51877")
d = c.add_device("own", "phone", "C" * 43 + "=")
s = c.load()
check("hub stores no private key", next(x for x in s["devices"] if x["name"] == "own")["private_key"] == "")
check("merge text has address and peer", d["address"] in c.merge_lines("own") and s["hub"]["public_key"] in c.merge_lines("own"))
try:
    c.add_device("bad", "phone", "nope"); check("rejects a bad public key", False)
except ValueError:
    check("rejects a bad public key", True)

print("safety settings:")
check("defaults", c.get_settings()["forget_phone_keys"] is True and c.get_settings()["isolate_devices"] is False)
c.update_settings({"isolate_devices": True}); check("isolation writes the rule file", (c.home() / "net.conf").exists())
c.update_settings({"isolate_devices": False}); check("turning it off removes the file", not (c.home() / "net.conf").exists())
for bad in ({"invite_minutes": 9999}, {"isolate_devices": "yes"}, {"relay": 1}):
    try:
        c.update_settings(bad); check(f"rejects {bad}", False)
    except ValueError:
        check(f"rejects {bad}", True)
n = c.add_device("keyed", "phone")
c._status_file = lambda: Path(os.environ["WINGS_HOME"]) / "live.json"
pub = next(d for d in c.load()["devices"] if d["name"] == "keyed")["public_key"]
(Path(os.environ["WINGS_HOME"]) / "live.json").write_text(json.dumps({"handshakes": {pub: 123}}))
saved_qr = Path(os.environ["WINGS_HOME"]) / "qr" / "keyed.png"
saved_qr.parent.mkdir(exist_ok=True)
saved_qr.write_bytes(b"pretend picture")
c.status()
check("a connected phone's saved QR picture is deleted too", not saved_qr.exists())
check("a connected phone's key is forgotten", next(d for d in c.load()["devices"] if d["name"] == "keyed")["private_key"] == "")
try:
    c.device_conf("keyed"); check("its QR stops working", False)
except ValueError:
    check("its QR stops working", True)

print(f"{fails} failed"); sys.exit(1 if fails else 0)
