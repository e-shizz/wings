"""One certificate authority for the wing net: the hub signs each computer's certificate.
Run: python3 tests/test_net_trust.py (with a Python that has `cryptography`)"""
import importlib.util, os, subprocess, sys, tempfile
from pathlib import Path

HUB, MEMBER, STRANGER = (tempfile.mkdtemp(prefix=f"wings-{n}.") for n in ("hub", "member", "stranger"))
os.environ["WINGS_HOME"] = HUB
spec = importlib.util.spec_from_file_location("core", Path(__file__).parent.parent / "plugin/wings/core.py")
c = importlib.util.module_from_spec(spec); sys.modules["core"] = c; spec.loader.exec_module(c)
fails = 0


def check(name, ok):
    global fails
    fails += 0 if ok else 1
    print(f"  {'ok  ' if ok else 'FAIL'}  {name}")


def at(home):
    os.environ["WINGS_HOME"] = home


def refused(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        return True
    return False


def address(name, ip):
    c.address_conf_path().write_text(f"Name = {name}\nAddress = {ip}\nPort = 9119\nHttpsPort = 443\nHttpPort = 80\n")


from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

print("the hub signs a joined computer's certificate:")
at(HUB)
c.init(name="vps", endpoint="1.2.3.4:51877")
c.ensure_tls("vps.wings"); address("vps.wings", "10.77.0.1")
server = c.add_device("Home Server", kind="server", public_key="A" * 43 + "=")
phone = c.add_device("pocket", kind="phone", public_key="B" * 43 + "=")
hub_ca = (Path(HUB) / "tls" / "ca.crt").read_bytes()
check("computers are named, phones are not", c.computer_names() == {"home-server.wings": server["address"]})

at(MEMBER)
(Path(MEMBER) / "hub-ca.crt").write_bytes(hub_ca)
address("home-server.wings", server["address"])
c.ensure_tls("home-server.wings")
check("a computer starts with a certificate only it trusts", not c.hub_signed())
key, request = c.new_cert_request("home-server.wings")
at(HUB); answer = c.sign_for_computer(request)
at(MEMBER); c.install_hub_cert("home-server.wings", key, answer["cert"])
check("after the hub signs it, the hub's authority vouches for it", c.hub_signed())
check("it stops running an authority of its own", not (Path(MEMBER) / "tls" / "ca.key").exists())
check("the authority it presents is the hub's", (Path(MEMBER) / "tls" / "ca.crt").read_bytes() == hub_ca)
v = subprocess.run(["openssl", "verify", "-CAfile", str(Path(HUB) / "tls" / "ca.crt"), "-verify_hostname", "home-server.wings",
                    str(Path(MEMBER) / "tls" / "leaf.crt")], capture_output=True, text=True)
check("openssl accepts it under the hub's authority, for that name", v.returncode == 0)
before = (Path(MEMBER) / "tls" / "leaf.crt").read_bytes()
c.ensure_tls("home-server.wings")
check("setting the address again keeps the hub's certificate", (Path(MEMBER) / "tls" / "leaf.crt").read_bytes() == before)

print("what the hub must refuse:")
at(HUB)
for label, name in (("the hub's own name", "vps.wings"), ("a phone's name", "pocket.wings"), ("a name nobody has", "bank.wings"),
                    ("a name outside .wings", "example.com")):
    _, req = c.new_cert_request(name)
    check(f"must fail: {label}", refused(lambda: c.sign_for_computer(req)))
k = ec.generate_private_key(ec.SECP256R1())
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "home-server.wings")])
extra = (x509.CertificateSigningRequestBuilder().subject_name(subj)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("vps.wings")]), critical=False).sign(k, hashes.SHA256()))
check("must fail: a request that smuggles a second name", refused(lambda: c.sign_for_computer(extra.public_bytes(ser.Encoding.PEM).decode())))
ca_ask = (x509.CertificateSigningRequestBuilder().subject_name(subj)
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(k, hashes.SHA256()))
check("must fail: a request to become an authority", refused(lambda: c.sign_for_computer(ca_ask.public_bytes(ser.Encoding.PEM).decode())))
weak = x509.CertificateSigningRequestBuilder().subject_name(subj).sign(rsa.generate_private_key(65537, 2048), hashes.SHA256())
check("must fail: another kind of key", refused(lambda: c.sign_for_computer(weak.public_bytes(ser.Encoding.PEM).decode())))
check("must fail: rubbish", refused(lambda: c.sign_for_computer("hello")) and refused(lambda: c.sign_for_computer("x" * 5000)))
cert = x509.load_pem_x509_certificate(answer["cert"].encode())
check("what it signs cannot sign anything itself", cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False)
at(MEMBER)
check("must fail: a joined computer signing for others", refused(lambda: c.sign_for_computer(request)))

print("what a joined computer must refuse:")
at(STRANGER)
c.init(name="evil", endpoint="6.6.6.6:51877"); c.ensure_tls("evil.wings"); address("evil.wings", "10.77.0.1")
c.add_device("Home Server", kind="server", public_key="C" * 43 + "=")
key2, request2 = c.new_cert_request("home-server.wings")
forged = c.sign_for_computer(request2)["cert"]
at(MEMBER)
check("must fail: a certificate signed by some other hub", refused(lambda: c.install_hub_cert("home-server.wings", key2, forged)))
check("must fail: a certificate for another key", refused(lambda: c.install_hub_cert("home-server.wings", key2, answer["cert"])))
check("must fail: a certificate for another name", refused(lambda: c.install_hub_cert("laptop.wings", key, answer["cert"])))
check("and none of that replaced the good one", c.hub_signed() and (Path(MEMBER) / "tls" / "leaf.crt").read_bytes() == before)

print("names of the other computers:")
check("the list is written", c.write_peers({"laptop.wings": "10.77.0.4", "home-server.wings": "10.77.0.3", "bad name": "10.77.0.9"}))
text = (Path(MEMBER) / "peers.conf").read_text()
check("it leaves out this computer and anything that is not a .wings name", text == "10.77.0.4 laptop.wings\n")
check("unchanged means untouched", not c.write_peers({"laptop.wings": "10.77.0.4"}))
check("nobody left means no file", c.write_peers({}) and not (Path(MEMBER) / "peers.conf").exists())
at(HUB)
c.write_names(c.load())
check("a hub lists its computers for itself too", (Path(HUB) / "peers.conf").read_text() == f"{server['address']} home-server.wings\n")

print(f"{fails} failed")
sys.exit(1 if fails else 0)
