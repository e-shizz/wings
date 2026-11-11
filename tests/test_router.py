"""Asking a home router for one port, against a pretend router. Run: python3 tests/test_router.py
This checks our side of the conversation. It has not been run against a real router yet."""
import importlib, importlib.util, re, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

d = Path(__file__).parent.parent / "plugin/wings"
spec = importlib.util.spec_from_file_location("wpkg", d / "__init__.py", submodule_search_locations=[str(d)])
m = importlib.util.module_from_spec(spec); sys.modules["wpkg"] = m; spec.loader.exec_module(m)
u = importlib.import_module("wpkg.upnp")
fails = 0


def check(name, ok):
    global fails
    fails += 0 if ok else 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}")


maps, asked = {}, []
KIND = "urn:schemas-upnp-org:service:WANIPConnection:1"
DESC = f"<root><device><serviceList><service><serviceType>urn:x:other:1</serviceType><controlURL>/no</controlURL></service><service><serviceType>{KIND}</serviceType><controlURL>/ctl</controlURL></service></serviceList></device></root>"


class Router(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(DESC.encode())
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        action = self.headers["SOAPAction"].strip('"').split("#")[1]; asked.append(action)
        get = lambda k: (re.search(f"<{k}>(.*?)</{k}>", body) or [None, ""])[1]
        out, code = "", 200
        if action == "GetExternalIPAddress": out = "<NewExternalIPAddress>203.0.113.9</NewExternalIPAddress>"
        elif action == "AddPortMapping": maps[get("NewExternalPort")] = (get("NewInternalClient"), get("NewProtocol"), get("NewPortMappingDescription"))
        elif action == "DeletePortMapping": maps.pop(get("NewExternalPort"), None)
        elif action == "GetSpecificPortMappingEntry":
            if get("NewExternalPort") in maps: out = f"<NewInternalClient>{maps[get('NewExternalPort')][0]}</NewInternalClient>"
            else: code, out = 500, "<errorCode>714</errorCode>"
        self.send_response(code); self.end_headers()
        self.wfile.write(f'<s:Envelope xmlns:s="x"><s:Body><u:{action}Response xmlns:u="{KIND}">{out}</u:{action}Response></s:Body></s:Envelope>'.encode())


srv = HTTPServer(("127.0.0.1", 0), Router); threading.Thread(target=srv.serve_forever, daemon=True).start()
loc = f"http://127.0.0.1:{srv.server_port}/desc.xml"
u._search = lambda timeout=2.5: [loc]
real_private = u._private
u._private = lambda h: h == "127.0.0.1" or real_private(h)
router = u.find()
check("finds the port-mapping service, not the others", router == (f"http://127.0.0.1:{srv.server_port}/ctl", KIND))
check("reads the home's public address from the router", u.public_address(router) == "203.0.113.9")
check("nothing is mapped to start with", u.mapped(51877, router) == "")
u.open_port(51877, "192.168.1.30", router)
check("opens exactly one UDP port to this machine, labelled Wings", maps == {"51877": ("192.168.1.30", "UDP", "Wings")})
maps["40000"] = ("192.168.1.99", "UDP", "someone else")
try:
    u.open_port(40000, "192.168.1.30", router); ok = False
except u.RouterError:
    ok = True
check("must fail: a port the router already gives another machine", ok and maps["40000"][0] == "192.168.1.99")
check("must fail: closing a mapping that is not ours", u.close_port(40000, "192.168.1.30", router) is False and "40000" in maps)
check("closes its own", u.close_port(51877, "192.168.1.30", router) is True and "51877" not in maps)
for label, port, me in (("a low port", 80, "192.168.1.30"), ("a machine with no home address", 51877, "8.8.8.8")):
    try:
        u.open_port(port, me, router); ok = False
    except u.RouterError:
        ok = True
    check(f"must fail: {label}", ok)
u._private = real_private
u._search = lambda timeout=2.5: ["http://93.184.216.34/desc.xml", "https://192.168.1.1/desc.xml"]
try:
    u.find(); ok = False
except u.RouterError:
    ok = True
check("must fail: a 'router' that is not on this machine's own private network", ok)
check("only the four standard actions were ever asked", set(asked) <= {"GetExternalIPAddress", "AddPortMapping", "DeletePortMapping", "GetSpecificPortMappingEntry"})
print(f"{fails} failed"); sys.exit(1 if fails else 0)
