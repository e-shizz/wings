"""Direct links between joined computers. Run: python3 tests/test_mesh.py"""
import importlib.util, json, os, subprocess, sys, tempfile
from pathlib import Path

HOME = tempfile.mkdtemp(prefix="wings-mesh.")
os.environ["WINGS_HOME"] = HOME
os.environ["WINGS_STATUS_FILE"] = HOME + "/live.json"
root = Path(__file__).parent.parent
spec = importlib.util.spec_from_file_location("core", root / "plugin/wings/core.py")
c = importlib.util.module_from_spec(spec); sys.modules["core"] = c; spec.loader.exec_module(c)
fails = 0


def check(name, ok):
    global fails
    fails += 0 if ok else 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}")


K = lambda ch: ch * 43 + "="
print("the hub introduces its computers:")
c.init(name="always-on", endpoint="1.2.3.4:51877")
a = c.add_device("desk", kind="computer", public_key=K("A"))
b = c.add_device("den", kind="server", public_key=K("B"))
r = c.add_device("relayed", kind="computer", public_key=K("C"))
c.add_device("pocket", kind="phone", public_key=K("D"))
Path(HOME, "live.json").write_text(json.dumps({"endpoints": {K("A"): "203.0.113.7:41000", K("B"): "203.0.113.7:42000", K("C"): "127.0.0.1:5555", K("D"): "198.51.100.9:7"}}))
rows = c.mesh_roster({K("A"): "192.168.1.20:41000", K("B"): "192.168.1.30:42000"})
by = {x["name"]: x for x in rows}
check("computers only, never phones", sorted(by) == ["den", "desk", "relayed"])
check("where the hub hears each one", by["desk"]["endpoint"] == "203.0.113.7:41000")
check("a computer on the HTTPS relay has no address to dial", by["relayed"]["endpoint"] == "")
check("no private key ever leaves", all(set(x) == {"name", "address", "public_key", "endpoint", "lan"} for x in rows))
c.update_settings({"isolate_devices": True})
check("devices kept apart: nobody is introduced", c.mesh_roster({}) == [])
c.update_settings({"isolate_devices": False})

print("where to try another computer:")
me = by["desk"]
check("same house: its address at home", c.choose_endpoint(me, by["den"]) == "192.168.1.30:42000")
away = {**by["den"], "endpoint": "198.51.100.50:42000"}
check("different networks: where the hub hears it", c.choose_endpoint(me, away) == "198.51.100.50:42000")
moved = {**away, "endpoint": "198.51.100.50:31999"}
check("the router changed the port: its own port first, then what the hub sees", c.endpoint_candidates(me, moved) == ["198.51.100.50:42000", "198.51.100.50:31999"])
check("nothing known: no direct try", c.choose_endpoint(me, by["relayed"]) == "")
check("both relayed, same home network: worth a try", c.choose_endpoint({"endpoint": "", "lan": "192.168.1.20:1"}, {"endpoint": "", "lan": "192.168.1.30:2"}) == "192.168.1.30:2")
check("both relayed, different networks: no", c.choose_endpoint({"endpoint": "", "lan": "192.168.1.20:1"}, {"endpoint": "", "lan": "172.16.9.5:2"}) == "")

print("the list a joined computer keeps:")
check("written", c.write_mesh(rows, K("A")))
text = Path(HOME, "mesh.conf").read_text()
check("the others it can try, never itself", text == f"{K('B')} {b['address']} 192.168.1.30:42000,203.0.113.7:42000\n")
check("unchanged means untouched", not c.write_mesh(rows, K("A")))
hostile = rows + [{"name": "x", "address": "10.77.0.9", "public_key": K("E"), "endpoint": "evil.example:1; rm -rf /", "lan": ""},
                  {"name": "y", "address": "8.8.8.8", "public_key": K("F"), "endpoint": "5.5.5.5:5555", "lan": ""}]
c.write_mesh(hostile, K("A"))
check("a hostile endpoint or address never reaches the file", Path(HOME, "mesh.conf").read_text() == text)
check("not on the hub's list ourselves: no links", c.write_mesh(rows, K("Z")) and not Path(HOME, "mesh.conf").exists())

print("the root side checks every line again:")
helper = (root / "plugin/root/wings-root.sh").read_text()
fn = helper[helper.index("validate_mesh() {"):helper.index("mesh_apply() {")]
def root_accepts(lines, own="10.77.0.2"):
    f = Path(HOME, "m.conf"); f.write_text(lines)
    script = 'die() { exit 3; }\n' + fn + f'\nvalidate_mesh "{f}" "{own}"\n'
    return subprocess.run(["bash", "-c", script], capture_output=True).returncode == 0
good = f"{K('B')} 10.77.0.3 192.168.1.30:42000\n"
check("up to three places to try", root_accepts(f"{K('B')} 10.77.0.3 192.168.1.30:42000,1.2.3.4:42000,1.2.3.4:31999\n"))
check("must fail: four places", not root_accepts(f"{K('B')} 10.77.0.3 1.1.1.1:10,1.1.1.2:10,1.1.1.3:10,1.1.1.4:10\n"))
check("a good list passes", root_accepts(good))
for label, bad in (("a host name", f"{K('B')} 10.77.0.3 evil.example:42000\n"), ("a shell character", f"{K('B')} 10.77.0.3 1.2.3.4:1;id\n"),
                   ("the hub's address", f"{K('B')} 10.77.0.1 1.2.3.4:5000\n"), ("this machine's own address", f"{K('B')} 10.77.0.2 1.2.3.4:5000\n"),
                   ("an address off the tunnel", f"{K('B')} 10.78.0.3 1.2.3.4:5000\n"), ("a bad key", f"short 10.77.0.3 1.2.3.4:5000\n"),
                   ("one computer twice", good + f"{K('B')} 10.77.0.4 1.2.3.4:5000\n"), ("one address twice", good + f"{K('C')} 10.77.0.3 1.2.3.4:5000\n"),
                   ("an octet over 255", f"{K('B')} 10.77.0.3 1.2.3.999:5000\n"), ("an extra field", f"{K('B')} 10.77.0.3 1.2.3.4:5000 x\n")):
    check(f"must fail: {label}", not root_accepts(bad))

print(f"{fails} failed")
sys.exit(1 if fails else 0)
