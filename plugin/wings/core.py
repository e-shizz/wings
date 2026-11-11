"""Wings core: hub identity, device peers, configs and pairing QR codes.

Pure Python on Hermes' own environment: X25519 keys via `cryptography` (a Hermes core
dependency), QR codes via `qrcode`. No `wg`/`qrencode` binaries needed to create keys
or codes. Root is only needed once, in `setup` (see root/wings-root.sh).

Nothing here prints private keys. Callers that show a pairing code to a human use
`pairing_qr_svg()`/`pairing_qr_png()`; logs get names and addresses only.
"""
from __future__ import annotations

import base64
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

IFACE = "wings0"
SUBNET = ipaddress.ip_network("10.77.0.0/24")
HUB_IP = ipaddress.ip_address("10.77.0.1")
DEFAULT_PORT = 51877
DEFAULT_DASH_PORT = 9120
ENROLL_PORT = 9121
INVITE_TTL = 600
MTU = 1280  # the size every path carries: cellular, nested tunnels, WireGuard inside TCP
DEFAULT_RELAY_PORT = 443
WST_VERSION = "11.1.0"
WST_SHA256 = {
    "x86_64": ("amd64", "512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23"),
    "aarch64": ("arm64", "148895f957a68be39e2b65d28c5f2065b9c58c4a0cfd48c560b2b3267f398464"),
}
SECRET_RE = re.compile(r"^[0-9a-f]{32,64}$")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
ENDPOINT_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}:\d{2,5}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$")

PLUGIN_DIR = Path(__file__).resolve().parent.parent
ROOT_HELPER_SRC = PLUGIN_DIR / "root" / "wings-root.sh"
ROOT_HELPER_INSTALLED = Path("/usr/local/libexec/wings-root")

_lock = threading.Lock()


# ---------------------------------------------------------------- storage

def home() -> Path:
    """Profile-scoped data dir: <HERMES_HOME>/plugin-data/wings (survives plugin updates)."""
    override = os.environ.get("WINGS_HOME")
    if override:
        p = Path(override)
    else:
        try:
            from plugins.plugin_storage import plugin_data_dir  # type: ignore
            p = Path(plugin_data_dir("wings"))
        except Exception:
            base = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
            p = base / "plugin-data" / "wings"
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def _state_path() -> Path:
    return home() / "state.json"


def hub_conf_path() -> Path:
    return home() / f"{IFACE}.conf"


def load() -> dict:
    p = _state_path()
    return json.loads(p.read_text()) if p.exists() else {}


def _save(state: dict) -> None:
    p = _state_path()
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    tmp.replace(p)


# ---------------------------------------------------------------- keys

def keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization as s

    k = X25519PrivateKey.generate()
    priv = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    pub = k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


# ---------------------------------------------------------------- network facts

def lan_ip() -> str:
    """The address this machine uses to reach the internet (no packets are sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ---------------------------------------------------------------- hub + devices

def public_hub(state: dict | None = None) -> dict:
    state = state if state is not None else load()
    h = dict(state.get("hub") or {})
    h.pop("private_key", None)
    return h


def init(name: str = "", endpoint: str = "", port: int = DEFAULT_PORT,
         dash_port: int = DEFAULT_DASH_PORT) -> dict:
    """Create the hub identity once. Idempotent."""
    with _lock:
        state = load()
        if state.get("hub"):
            return state
        priv, pub = keypair()
        state = {
            "version": 1,
            "hub": {
                "name": name or socket.gethostname().split(".")[0].capitalize(),
                "private_key": priv,
                "public_key": pub,
                "address": str(HUB_IP),
                "port": int(port),
                "endpoint": endpoint or f"{lan_ip()}:{port}",
                "dash_port": int(dash_port),
                "created": int(time.time()),
            },
            "devices": [],
        }
        _save(state)
        write_hub_conf(state)
        return state


def set_endpoint(endpoint: str) -> dict:
    """Change the address devices dial (e.g. a VPS public IP or DNS name)."""
    host, _, port = endpoint.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("endpoint must look like host:port")
    with _lock:
        state = load()
        state["hub"]["endpoint"] = endpoint
        _save(state)
    return public_hub(state)


def _next_ip(state: dict) -> str:
    used = {str(HUB_IP)} | {d["address"] for d in state["devices"]
                             if not d.get("revoked") and not _expired(d)}
    for host in SUBNET.hosts():
        if str(host) not in used:
            return str(host)
    raise RuntimeError("all 253 device addresses are in use")


def devices(include_revoked: bool = False) -> list[dict]:
    hs = handshakes()
    now = int(time.time())
    out = []
    for d in load().get("devices", []):
        if d.get("revoked") and not include_revoked:
            continue
        if _expired(d):
            continue
        t = hs.get(d["public_key"], 0)
        out.append({
            "name": d["name"], "label": d.get("label", ""), "kind": d.get("kind", "device"), "address": d["address"],
            "created": d["created"], "revoked": d.get("revoked", 0),
            "last_handshake": t, "online": bool(t and now - t < 180),
        })
    return out


def add_device(name: str, kind: str = "phone", public_key: str = "") -> dict:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("name: 1-32 letters, digits, space, dot, dash or underscore")
    if kind not in {"phone", "computer", "server", "tablet", "device"}:
        kind = "device"
    with _lock:
        state = load()
        if not state.get("hub"):
            raise RuntimeError("run setup first (hermes wings setup)")
        if any(d["name"].lower() == name.lower() and not d.get("revoked") for d in state["devices"]):
            raise ValueError(f"a device named {name!r} already exists")
        if public_key:
            if not KEY_RE.match(public_key):
                raise ValueError("that isn't a WireGuard public key")
            priv, pub = "", public_key
        else:
            priv, pub = keypair()
        dev = {"name": name, "kind": kind, "address": _next_ip(state), "private_key": priv,
               "public_key": pub, "created": int(time.time())}
        state["devices"].append(dev)
        _save(state)
        write_hub_conf(state)
    return {k: v for k, v in dev.items() if k != "private_key"}


def set_label(name: str, label: str) -> None:
    """A friendly name like "home Linux box", shown in the cockpit and pages."""
    label = " ".join(label.split())[:32]
    if not label or any(ch in label for ch in "<>&\"'"):
        raise ValueError("label: up to 32 plain characters")
    with _lock:
        state = load()
        if name in ("hub", state.get("hub", {}).get("name")):
            state["hub"]["label"] = label
        else:
            dev = next((d for d in state.get("devices", []) if d["name"].lower() == name.lower() and not d.get("revoked")), None)
            if dev is None:
                raise ValueError(f"no device named {name!r}")
            dev["label"] = label
        _save(state)


def revoke(name: str) -> dict:
    with _lock:
        state = load()
        for d in state["devices"]:
            if d["name"].lower() == name.lower() and not d.get("revoked"):
                d["revoked"] = int(time.time())
                d["private_key"] = ""
                _save(state)
                write_hub_conf(state)
                return {k: v for k, v in d.items() if k != "private_key"}
    raise ValueError(f"no active device named {name!r}")


# ---------------------------------------------------------------- configs

def _expired(d: dict) -> bool:
    return bool(d.get("pending_until")) and d["pending_until"] < time.time()


def hub_conf(state: dict) -> str:
    h = state["hub"]
    lines = ["[Interface]", f"PrivateKey = {h['private_key']}", f"Address = {h['address']}/24",
             f"ListenPort = {h['port']}", f"MTU = {MTU}", ""]
    for d in state["devices"]:
        if d.get("revoked") or _expired(d):
            continue
        lines += ["[Peer]", f"PublicKey = {d['public_key']}", f"AllowedIPs = {d['address']}/32", ""]
    return "\n".join(lines)


def _dns_label(name: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:32].strip("-")


def write_names(state: dict) -> None:
    """The .wings names a hub answers for phones: itself and every computer. No phones: nothing to open on them."""
    pairs: dict[str, str] = {}
    me = get_address()
    if me:
        pairs[me] = state["hub"]["address"]
    for d in state["devices"]:
        label = _dns_label(d["name"])
        if label and d.get("kind") != "phone" and not d.get("revoked") and not _expired(d):
            pairs.setdefault(f"{label}.wings", d["address"])
    p = home() / "names.conf"
    if pairs:
        _write_private(p, "".join(f"{ip} {n}\n" for n, ip in pairs.items()).encode())
    else:
        p.unlink(missing_ok=True)
    write_peers({n: ip for n, ip in pairs.items() if n != me})


def write_hub_conf(state: dict) -> Path:
    """Write the hub config. The root path unit installed by setup applies it automatically."""
    write_names(state)
    p = hub_conf_path()
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(hub_conf(state))
    tmp.replace(p)
    return p


# ---------------------------------------------------------------- HTTPS relay (wstunnel)
#
# Networks that block UDP usually still pass HTTPS, so a hub can also carry WireGuard inside a
# WebSocket. The same idea as Tailscale's DERP fallback, but on your own machine. The secret only
# stops strangers using the relay: everything inside is still WireGuard-encrypted.

DEFAULT_SETTINGS = {"isolate_devices": False, "forget_phone_keys": True, "invite_minutes": 10}


def get_settings() -> dict:
    state = load()
    out = {**DEFAULT_SETTINGS, **(state.get("settings") or {})}
    out["relay"] = bool((state.get("hub") or {}).get("relay"))
    return out


def update_settings(patch: dict) -> dict:
    if not isinstance(patch, dict):
        raise ValueError("bad settings")
    if "relay" in patch:
        if not isinstance(patch["relay"], bool):
            raise ValueError("relay must be on or off")
        relay_on() if patch["relay"] else relay_off()
    with _lock:
        state = load()
        if not state.get("hub"):
            raise RuntimeError("safety settings live on the hub")
        cur = {**DEFAULT_SETTINGS, **(state.get("settings") or {})}
        for key in ("isolate_devices", "forget_phone_keys"):
            if key in patch:
                if not isinstance(patch[key], bool):
                    raise ValueError(f"{key} must be on or off")
                cur[key] = patch[key]
        if "invite_minutes" in patch:
            if patch["invite_minutes"] not in (5, 10, 30):
                raise ValueError("invites can last 5, 10 or 30 minutes")
            cur["invite_minutes"] = patch["invite_minutes"]
        state["settings"] = cur
        _save(state)
        write_net_conf(state)
    return get_settings()


def write_net_conf(state: dict) -> None:
    """Hub rules root applies. Written only when isolation is on, so the default leaves no file."""
    p = home() / "net.conf"
    if (state.get("settings") or {}).get("isolate_devices"):
        _write_private(p, b"Isolate = yes\n")
    else:
        p.unlink(missing_ok=True)
        (home() / "refresh").write_text(str(os.getpid()))


def forget_connected_keys() -> None:
    """Once a phone has connected, the hub has no more use for the key in its QR."""
    if not get_settings().get("forget_phone_keys"):
        return
    hs = handshakes()
    with _lock:
        state = load()
        changed = False
        for d in state.get("devices", []):
            if d.get("private_key") and hs.get(d.get("public_key"), 0):
                d["private_key"] = ""
                changed = True
                safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in d["name"])
                (home() / "qr" / f"{safe}.png").unlink(missing_ok=True)  # the saved picture holds the same key
        if changed:
            _save(state)


def relay_conf_path() -> Path:
    return home() / "relay.conf"


def write_relay_conf(state: dict) -> None:
    p = relay_conf_path()
    m = state.get("member")
    relay = (m or {}).get("relay") or (state.get("hub") or {}).get("relay")
    if not relay:
        p.unlink(missing_ok=True)
        return
    lines = [f"Port = {relay['port']}", f"Secret = {relay['secret']}"]
    if m:
        lines.append(f"Host = {m['endpoint'].rpartition(':')[0]}")
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    tmp.replace(p)


def relay_on(port: int = DEFAULT_RELAY_PORT) -> dict:
    with _lock:
        state = load()
        if not state.get("hub"):
            raise RuntimeError("only a hub runs the relay server")
        if not 80 <= int(port) <= 65535:
            raise ValueError("relay port must be 80-65535")
        old = state["hub"].get("relay") or {}
        state["hub"]["relay"] = {"port": int(port), "secret": old.get("secret") or secrets.token_hex(24)}
        _save(state)
        write_relay_conf(state)
    return state["hub"]["relay"]


def relay_off() -> None:
    with _lock:
        state = load()
        if state.get("hub"):
            state["hub"].pop("relay", None)
            _save(state)
        write_relay_conf(state)


def port_in_use(port: int) -> bool:
    with socket.socket() as c:
        c.settimeout(0.5)
        return c.connect_ex(("127.0.0.1", port)) == 0


def fetch_wstunnel() -> Path:
    """Download the official wstunnel release and check it. Root checks it again before installing."""
    import hashlib
    import platform
    import urllib.request

    arch = platform.machine()
    if arch not in WST_SHA256:
        raise RuntimeError(f"no pinned wstunnel release for {arch}")
    name, want = WST_SHA256[arch]
    dest = home() / f"wstunnel_{WST_VERSION}_linux_{name}.tar.gz"
    if not (dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == want):
        url = (f"https://github.com/erebe/wstunnel/releases/download/v{WST_VERSION}/"
               f"wstunnel_{WST_VERSION}_linux_{name}.tar.gz")
        with urllib.request.urlopen(url, timeout=120) as r:
            data = r.read()
        if hashlib.sha256(data).hexdigest() != want:
            raise RuntimeError("the wstunnel download does not match the pinned checksum")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    return dest


def wstunnel_installed() -> bool:
    return Path("/usr/local/libexec/wings-wstunnel").exists()


ADDRESS_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.wings$")


# ---------------------------------------------------------------- living alongside other setups
#
# Wings shares a machine with whatever is already there: other WireGuard networks, VPNs, web servers,
# an existing Hermes. Check first and change nothing if it would collide.

def _ip_json(*args) -> list:
    try:
        out = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=5).stdout
        return json.loads(out or "[]")
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def subnet_conflicts(routes: list, addrs: list) -> list[str]:
    """Other interfaces already using the Wings subnet. Pure, so the tests can feed it clashes."""
    found = []
    for r in routes:
        dst, dev = r.get("dst", ""), r.get("dev", "")
        if dev == IFACE or dst in ("default", ""):
            continue
        try:
            if ipaddress.ip_network(dst if "/" in dst else f"{dst}/32", strict=False).overlaps(SUBNET):
                found.append(f"{dst} on {dev}")
        except ValueError:
            continue
    for link in addrs:
        if link.get("ifname") == IFACE:
            continue
        for a in link.get("addr_info", []):
            try:
                net = ipaddress.ip_network(f"{a.get('local')}/{a.get('prefixlen')}", strict=False)
            except ValueError:
                continue
            if net.version == 4 and net.overlaps(SUBNET):
                found.append(f"{a.get('local')} on {link.get('ifname')}")
    return sorted(set(found))


VPN_PREFIXES = ("wg", "tun", "tap", "mullvad", "nordlynx", "proton", "utun", "tailscale", "zt", "ppp", "ipsec")


def other_tunnels(links: list) -> list[str]:
    return sorted(l.get("ifname", "") for l in links
                  if l.get("ifname", "") != IFACE and l.get("ifname", "").startswith(VPN_PREFIXES))


def full_tunnel_devices(default_routes: list) -> list[str]:
    """Default routes through a VPN: its kill switch may also block Wings."""
    return sorted({r.get("dev", "") for r in default_routes if r.get("dst") == "default"
                   and r.get("dev", "") != IFACE and r.get("dev", "").startswith(VPN_PREFIXES)})


def udp_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def preflight(hub: bool, port: int = DEFAULT_PORT) -> tuple[list[str], list[str]]:
    """(problems that stop setup, notes worth knowing). Reads only; changes nothing."""
    errors, notes = [], []
    clashes = subnet_conflicts(_ip_json("-4", "route"), _ip_json("-4", "addr"))
    if clashes:
        errors.append(f"{SUBNET} is already in use here ({', '.join(clashes)}). "
                      "Wings would break that network, so it stopped. Nothing was changed.")
    if not interface_up() and Path(f"/sys/class/net/{IFACE}").exists():
        errors.append(f"An interface named {IFACE} already exists and isn't from Wings.")
    if hub and not interface_up() and not udp_port_free(port):
        errors.append(f"UDP {port} is already in use, possibly by another WireGuard network. "
                      "Pick another with --port. Nothing was changed.")
    others = other_tunnels(_ip_json("link"))
    if others:
        notes.append(f"Other tunnels here stay as they are: {', '.join(others)}.")
    full = full_tunnel_devices(_ip_json("-4", "route", "show", "table", "all", "default"))
    if full:
        notes.append(f"{', '.join(full)} carries all this machine's traffic. If its kill switch blocks Wings, "
                     f"allow UDP {port} to your hub, or use split tunnelling.")
    return errors, notes


def listeners(text: str) -> set[tuple[str, int]]:
    """(address, port) pairs from `ss -Hltn`."""
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            host, _, port = parts[3].rpartition(":")
            if port.isdigit():
                out.add((host.strip("[]").split("%")[0], int(port)))
    return out


def web_ports(listening: set, addr: str) -> tuple[int, int]:
    """443 and 80 unless an existing web server has them; then 8443 and 8080."""
    def taken(port):
        return any(p == port and h in ("0.0.0.0", "*", "::", addr) for h, p in listening)
    return (8443 if taken(443) else 443), (8080 if taken(80) else 80)


def public_url(name: str, https_port: int) -> str:
    return f"https://{name}" if https_port == 443 else f"https://{name}:{https_port}"


def my_address(state: dict | None = None) -> str:
    state = state if state is not None else load()
    if state.get("member"):
        return state["member"]["address"]
    if state.get("hub"):
        return state["hub"]["address"]
    raise RuntimeError("join or set up a wing net first")


def address_conf_path() -> Path:
    return home() / "address.conf"


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    tmp.replace(path)


def ensure_tls(name: str) -> Path:
    """Make this machine's private CA (limited to .wings names) and a certificate for the name."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    d = home() / "tls"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    if hub_signed():   # a joined computer whose certificate the hub signed keeps it
        try:
            have = x509.load_pem_x509_certificate((d / "leaf.crt").read_bytes())
            if have.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == name:
                return d
        except Exception:  # noqa: BLE001
            pass
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(days=1)
    pem = ser.Encoding.PEM
    nokey = ser.NoEncryption()
    if (d / "ca.key").exists() and (d / "ca.crt").exists():
        ca_key = ser.load_pem_private_key((d / "ca.key").read_bytes(), None)
        ca = x509.load_pem_x509_certificate((d / "ca.crt").read_bytes())
    else:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Wings private CA {secrets.token_hex(4)}")])
        ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(start).not_valid_after(now + datetime.timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
              .add_extension(x509.NameConstraints([x509.DNSName("wings")], None), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))
        _write_private(d / "ca.key", ca_key.private_bytes(pem, ser.PrivateFormat.PKCS8, nokey))
        _write_private(d / "ca.crt", ca.public_bytes(pem))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = _leaf(name, key.public_key(), ca, ca_key)
    _write_private(d / "leaf.key", key.private_bytes(pem, ser.PrivateFormat.PKCS8, nokey))
    _write_private(d / "leaf.crt", leaf.public_bytes(pem))
    return d


def _leaf(name: str, public_key, ca, ca_key):
    """A web certificate for one .wings name, good for 397 days, signed by the given CA."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca.subject).public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=397))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))


# One certificate authority for the whole wing net: the hub's. Every computer already trusts it from the
# day it joined, so when the hub signs each computer's certificate they can all open each other.

def computer_names(state: dict | None = None) -> dict[str, str]:
    """On a hub: the .wings name of every joined computer (no phones) and its tunnel address."""
    state = state or load()
    out: dict[str, str] = {}
    for d in state.get("devices", []):
        label = _dns_label(d["name"])
        if label and d.get("kind") != "phone" and not d.get("revoked") and not _expired(d):
            out.setdefault(f"{label}.wings", d["address"])
    return out


def new_cert_request(name: str) -> tuple[bytes, str]:
    """A fresh key for this computer and a request for the hub to sign. The key never leaves this machine."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).sign(key, hashes.SHA256()))
    return (key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()),
            csr.public_bytes(ser.Encoding.PEM).decode())


def sign_for_computer(request_pem: str) -> dict:
    """On a hub: sign a joined computer's certificate. Only for the .wings name of a computer on this wing
    net, never the hub's own name, never anything else."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    state = load()
    d = home() / "tls"
    if not state.get("hub") or not (d / "ca.key").exists():
        raise ValueError("this machine is not a hub with an address")
    if not isinstance(request_pem, str) or len(request_pem) > 4096:
        raise ValueError("bad request")
    try:
        csr = x509.load_pem_x509_csr(request_pem.encode())
        names = [a.value for a in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    except Exception as e:  # noqa: BLE001 - anything unreadable is a bad request
        raise ValueError("bad request") from e
    pub = csr.public_key()
    if not csr.is_signature_valid or len(names) != 1 or len(list(csr.subject)) != 1 or len(csr.extensions) != 0:
        raise ValueError("bad request")
    if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(pub.curve, ec.SECP256R1):
        raise ValueError("bad request")
    name = names[0]
    if name == get_address() or name not in computer_names(state):
        raise ValueError("not a computer on this wing net")
    ca_key = ser.load_pem_private_key((d / "ca.key").read_bytes(), None)
    ca = x509.load_pem_x509_certificate((d / "ca.crt").read_bytes())
    pem = ser.Encoding.PEM
    return {"cert": _leaf(name, pub, ca, ca_key).public_bytes(pem).decode(), "ca": ca.public_bytes(pem).decode()}


def hub_signed() -> bool:
    """On a joined computer: is its certificate already signed by the hub?"""
    try:
        from cryptography import x509
        leaf = x509.load_pem_x509_certificate((home() / "tls" / "leaf.crt").read_bytes())
        ca = x509.load_pem_x509_certificate((home() / "hub-ca.crt").read_bytes())
        leaf.verify_directly_issued_by(ca)
        return True
    except Exception:  # noqa: BLE001 - missing, unreadable or signed by someone else
        return False


def install_hub_cert(name: str, key_pem: bytes, cert_pem: str) -> None:
    """On a joined computer: take the certificate the hub signed. It must be for this computer's name, match
    the key made here, and be signed by the same hub authority this computer learned when it joined."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser

    ca_pem = (home() / "hub-ca.crt").read_bytes()
    ca = x509.load_pem_x509_certificate(ca_pem)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = ser.load_pem_private_key(key_pem, None)
    cert.verify_directly_issued_by(ca)
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    same_key = cert.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo) == \
        key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    if sans != [name] or not same_key or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("the hub's certificate does not fit this computer")
    d = home() / "tls"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    (d / "ca.key").unlink(missing_ok=True)   # this computer no longer runs an authority of its own
    _write_private(d / "ca.crt", ca_pem)
    _write_private(d / "leaf.key", key_pem)
    _write_private(d / "leaf.crt", cert.public_bytes(ser.Encoding.PEM))   # last: the root side watches this file


def write_peers(pairs: dict[str, str]) -> bool:
    """The other computers' .wings names for this machine's name list. True when the file changed."""
    own = get_address()
    text = "".join(f"{ip} {n}\n" for n, ip in sorted(pairs.items()) if n != own and ADDRESS_RE.match(n))
    p = home() / "peers.conf"
    try:
        if p.read_text() == text:
            return False
    except OSError:
        if not text:
            return False
    if text:
        _write_private(p, text.encode())
    else:
        p.unlink(missing_ok=True)
    return True


def address_settings() -> dict:
    out = {}
    try:
        for line in address_conf_path().read_text().splitlines():
            k, _, v = line.partition(" = ")
            if v:
                out[k] = v
    except OSError:
        pass
    return out


def set_address(name: str, port: int) -> tuple[str, int]:
    name = name.strip().lower()
    if not ADDRESS_RE.match(name):
        raise ValueError("the address must look like hermes.wings")
    if not 1024 <= port <= 65535:
        raise ValueError("port must be 1024-65535")
    ensure_tls(name)
    addr = my_address()
    prior = address_settings()
    if prior.get("Address") == addr:  # those ports are held by our own front, not by someone else
        https_port, http_port = int(prior.get("HttpsPort", 443)), int(prior.get("HttpPort", 80))
    else:
        ss = subprocess.run(["ss", "-Hltn"], capture_output=True, text=True, timeout=5).stdout
        https_port, http_port = web_ports(listeners(ss), addr)
    p = address_conf_path()
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"Name = {name}\nAddress = {addr}\nPort = {port}\nHttpsPort = {https_port}\nHttpPort = {http_port}\n")
    tmp.replace(p)
    _refresh_names()
    return name, https_port


def clear_address() -> None:
    address_conf_path().unlink(missing_ok=True)
    _refresh_names()


def _refresh_names() -> None:
    state = load()
    if state.get("hub"):
        write_names(state)


def get_address() -> str:
    try:
        for line in address_conf_path().read_text().splitlines():
            if line.startswith("Name = "):
                return line[7:]
    except OSError:
        pass
    return ""


def live_mode() -> str:
    try:
        return json.loads(_status_file().read_text()).get("mode", "direct")
    except Exception:
        return "direct"


# ---------------------------------------------------------------- plugin-to-plugin pairing
#
# The hub never sees a joining machine's private key. The invite carries a one-time key that the
# hub accepts for one address for a few minutes. The joiner brings the tunnel up with it, so the
# enrolment below is encrypted and authenticated by WireGuard itself, sends the public half of a
# key it generated, and the hub swaps the peer. The invite key then stops working. The listener
# binds the tunnel address and exists only while `invite` waits, so nothing new faces the internet.

def _member_conf(m: dict, private_key: str) -> str:
    return "\n".join([
        "[Interface]", f"PrivateKey = {private_key}", f"Address = {m['address']}/32", f"MTU = {MTU}", "",
        "[Peer]", f"PublicKey = {m['hub_public_key']}", f"Endpoint = {m['endpoint']}",
        f"AllowedIPs = {SUBNET}", "PersistentKeepalive = 25", "",
    ])


def _write_conf(text: str) -> Path:
    p = hub_conf_path()
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    tmp.replace(p)
    return p


def create_invite(name: str, kind: str = "server") -> tuple[str, dict]:
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("name: 1-32 letters, digits, space, dot, dash or underscore")
    with _lock:
        state = load()
        if not state.get("hub"):
            raise RuntimeError("only a hub can invite (hermes wings setup)")
        if any(d["name"].lower() == name.lower() and not d.get("revoked") and not _expired(d)
               for d in state["devices"]):
            raise ValueError(f"a device named {name!r} already exists")
        state["devices"] = [d for d in state["devices"] if not _expired(d)]
        priv, pub = keypair()
        dev = {"name": name, "kind": kind, "address": _next_ip(state), "private_key": "",
               "public_key": pub, "created": int(time.time()),
               "pending_until": int(time.time()) + int((state.get("settings") or {}).get("invite_minutes", 10)) * 60}
        state["devices"].append(dev)
        _save(state)
        write_hub_conf(state)
    h = state["hub"]
    payload = {"v": 1, "n": h["name"], "m": dev["name"], "h": h["public_key"], "e": h["endpoint"],
               "a": dev["address"], "k": priv}
    if h.get("relay"):
        payload["r"] = h["relay"]
    code = "wings1:" + base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    return code, dev


def _drop_pending(name: str) -> None:
    with _lock:
        state = load()
        kept = [d for d in state["devices"] if not (d["name"] == name and d.get("pending_until"))]
        if len(kept) != len(state["devices"]):
            state["devices"] = kept
            _save(state)
            write_hub_conf(state)


def _finish_enrol(name: str, pub: str) -> None:
    with _lock:
        state = load()
        for d in state["devices"]:
            if d["name"] == name and d.get("pending_until"):
                d["public_key"] = pub
                d.pop("pending_until")
                _save(state)
                write_hub_conf(state)
                return
    raise RuntimeError("invite is gone")


def _trust():
    """The trust module, also when this file was loaded on its own (the dashboard API does that)."""
    try:
        from . import trust
        return trust
    except ImportError:
        import importlib.util
        name = __name__.rsplit("_core", 1)[0] + "_trust" if __name__.endswith("_core") else "wings_trust_standalone"
        if name in sys.modules:
            return sys.modules[name]
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name("trust.py"))
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        src = Path(__file__).with_name("trust.py").read_text().replace("from . import core", "")
        mod.core = sys.modules[__name__]
        exec(compile(src, str(Path(__file__).with_name("trust.py")), "exec"), mod.__dict__)
        return mod


def wait_for_join(dev: dict, timeout: int = 0, login_user: str = "") -> bool:
    """Serve one enrolment on the tunnel address. True once the joiner's own key is in place."""
    timeout = timeout or max(30, dev.get("pending_until", 0) - int(time.time()))
    deadline = time.time() + timeout
    srv = None
    try:
        while srv is None:
            try:
                srv = socket.create_server((str(HUB_IP), ENROLL_PORT), backlog=4)
            except OSError:
                if time.time() > deadline - timeout + 15:
                    raise RuntimeError("couldn't listen for the join. Is another invite still waiting, "
                                       "or is the hub's tunnel down? Check hermes wings status")
                time.sleep(0.5)
        while time.time() < deadline:
            srv.settimeout(max(0.1, min(2.0, deadline - time.time())))
            try:
                conn, addr = srv.accept()
            except TimeoutError:
                continue
            with conn:
                if addr[0] != dev["address"]:
                    continue
                conn.settimeout(10)
                try:
                    msg = json.loads(conn.recv(512).decode())
                    pub = msg["pub"]
                except (OSError, ValueError, KeyError, TypeError):
                    continue
                state = load()
                taken = {d["public_key"] for d in state["devices"] if not d.get("revoked")}
                if not isinstance(pub, str) or not KEY_RE.match(pub) or pub in taken \
                        or pub == state["hub"]["public_key"]:
                    conn.sendall(b'{"ok":false}\n')
                    continue
                reply = {"ok": True, "netkey": _trust().ensure_netkey()}
                name = get_address()
                ca = home() / "tls" / "ca.crt"
                if name and ca.exists():
                    reply.update({"name": name, "ca": ca.read_text(), "user": login_user,
                                  "https_port": int(address_settings().get("HttpsPort", 443))})
                conn.sendall(json.dumps(reply).encode() + b"\n")
            _finish_enrol(dev["name"], pub)
            return True
        return False
    finally:
        if srv is not None:
            srv.close()
        _drop_pending(dev["name"])


def parse_invite(code: str) -> dict:
    code = (code or "").strip()
    if not code.startswith("wings1:"):
        raise ValueError("that isn't a Wings invite code")
    try:
        d = json.loads(base64.urlsafe_b64decode(code[7:].encode()))
        addr = ipaddress.ip_address(d["a"])
        host_ok = ENDPOINT_RE.match(d["e"])
        ok = (d["v"] == 1 and addr in SUBNET and addr != HUB_IP and host_ok
              and KEY_RE.match(d["h"]) and KEY_RE.match(d["k"]) and NAME_RE.match(d["n"]))
        if "r" in d:
            ok = ok and isinstance(d["r"].get("port"), int) and SECRET_RE.match(d["r"].get("secret", ""))
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError("that Wings invite code is damaged") from e
    if not ok:
        raise ValueError("that Wings invite code is damaged")
    return d


def begin_join(code: str, replace_hub: bool = False) -> dict:
    """Store membership and write the invite-key config. Root applies it (setup or path unit)."""
    inv = parse_invite(code)
    with _lock:
        state = load()
        if state.get("hub"):
            active = [d for d in state["devices"] if not d.get("revoked")]
            if active and not replace_hub:
                raise RuntimeError(f"this machine is a hub with {len(active)} device(s); "
                                   "use --replace-hub to set that aside and join")
            shutil.copy2(_state_path(), home() / f"state.hub-{int(time.time())}.json")
        priv, pub = keypair()
        m = {"hub_name": inv["n"], "my_name": str(inv.get("m") or ""), "hub_public_key": inv["h"], "endpoint": inv["e"],
             "address": inv["a"], "private_key": priv, "public_key": pub, "enrolled": False}
        if inv.get("r"):
            m["relay"] = inv["r"]
        state = {"version": 1, "hub": None, "devices": [], "member": m}
        _save(state)
        _write_conf(_member_conf(m, inv["k"]))
        write_relay_conf(state)
    return m


def finish_join(timeout: int = 150) -> dict:
    """Over the invite-key tunnel, hand the hub our own public key, then switch to our own key."""
    state = load()
    m = state["member"]
    deadline = time.time() + timeout
    reply = b""
    while time.time() < deadline:
        try:
            with socket.create_connection((str(HUB_IP), ENROLL_PORT), timeout=4) as c:
                c.settimeout(10)
                c.sendall(json.dumps({"v": 1, "pub": m["public_key"]}).encode() + b"\n")
                chunks = []
                while len(b"".join(chunks)) < 16384:
                    part = c.recv(4096)
                    if not part:
                        break
                    chunks.append(part)
                    if part.endswith(b"\n"):
                        break
                reply = b"".join(chunks)
                break
        except OSError:
            time.sleep(1)
    if not reply:
        raise RuntimeError(f"couldn't reach the hub at {m['endpoint']}. Is `hermes wings invite` still "
                           "waiting there, and is UDP open in the provider's firewall?")
    answer = json.loads(reply.decode())
    if not answer.get("ok"):
        raise RuntimeError("the hub refused this join")
    with _lock:
        state = load()
        state["member"]["enrolled"] = True
        _trust().save_netkey(answer.get("netkey", ""))
        name, ca = answer.get("name"), answer.get("ca")
        if isinstance(name, str) and ADDRESS_RE.match(name) and isinstance(ca, str):
            hp = answer.get("https_port", 443)
            state["member"]["hub_url"] = public_url(name, hp if hp in (443, 8443) else 443)
            state["member"]["hub_user"] = str(answer.get("user") or "")[:64]
            _write_private(home() / "hub-ca.crt", ca.encode())
            _write_private(home() / "hub-name.conf", f"Name = {name}\nAddress = {HUB_IP}\n".encode())
        _save(state)
        _write_conf(_member_conf(state["member"], state["member"]["private_key"]))
    return state["member"]


def hub_reachable(timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if subprocess.run(["ping", "-c1", "-W2", str(HUB_IP)], capture_output=True).returncode == 0:
            return True
        time.sleep(1)
    return False


def merge_lines(name: str) -> str:
    """What to add to an existing phone tunnel, for a device that keeps its own key."""
    state = load()
    dev = next(d for d in state["devices"] if d["name"].lower() == name.lower() and not d.get("revoked"))
    h = state["hub"]
    return (f"In your existing tunnel, edit these. Android runs one VPN at a time, so this keeps both networks in one.\n\n"
            f"Addresses: add {dev['address']}/32\n\n"
            f"Add a peer:\n  Public key: {h['public_key']}\n  Endpoint: {h['endpoint']}\n"
            f"  Allowed IPs: {SUBNET}\n  Persistent keepalive: 25\n")


def hub_answers_names(address: str) -> bool:
    """A phone sends every lookup to the DNS server in its QR, so only name the hub if it really answers."""
    name = get_address()
    if not name:
        return False
    q = secrets.token_bytes(2) + b"\1\0\0\1\0\0\0\0\0\0"
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0\0\1\0\1"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.5)
            s.sendto(q, (address, 53))
            a = s.recv(512)
    except OSError:
        return False
    return a[:2] == q[:2] and a[3] & 15 == 0 and a[6:8] == b"\0\1"


def device_conf(name: str) -> str:
    state = load()
    dev = next((d for d in state.get("devices", [])
                if d["name"].lower() == name.lower() and not d.get("revoked")), None)
    if dev is None:
        raise ValueError(f"no active device named {name!r}")
    if not dev.get("private_key"):
        raise ValueError(f"{dev['name']} keeps its own key or has connected, so there's no code to show. "
                         "To pair again, remove it and add it again.")
    h = state["hub"]
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {dev['private_key']}",
        f"Address = {dev['address']}/32",
        *([f"DNS = {h['address']}"] if hub_answers_names(h["address"]) else []),
        f"MTU = {MTU}",
        "",
        "[Peer]",
        f"PublicKey = {h['public_key']}",
        f"Endpoint = {h['endpoint']}",
        f"AllowedIPs = {SUBNET}",
        "PersistentKeepalive = 25",
        "",
    ])


# ---------------------------------------------------------------- QR

def _qr(text: str):
    import qrcode
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=2)  # smaller: it's read off a clean screen
    q.add_data(text)
    q.make(fit=True)
    return q


def pairing_qr_svg(name: str) -> str:
    import qrcode.image.svg
    img = _qr(device_conf(name)).make_image(image_factory=qrcode.image.svg.SvgPathFillImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def pairing_qr_png(name: str, path: Path) -> Path:
    img = _qr(device_conf(name)).make_image()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        img.save(f)
    return path


def pairing_qr_terminal(name: str) -> str:
    buf = io.StringIO()
    _qr(device_conf(name)).print_ascii(out=buf, invert=True)
    return buf.getvalue()


# ---------------------------------------------------------------- live status

def _status_file() -> Path:
    return Path(os.environ.get("WINGS_STATUS_FILE") or "/run/wings/live.json")


def live_updated() -> int:
    try:
        return int(json.loads(_status_file().read_text()).get("updated", 0))
    except Exception:
        return 0


def live() -> dict:
    """What the root side last reported about the tunnel: handshakes, where peers were heard from, our port."""
    try:
        data = json.loads(_status_file().read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


MESH_KEY_RE = KEY_RE


def mesh_roster(reported: dict | None = None) -> list[dict]:
    """On a hub: its joined computers as they need to know each other to connect directly. Nothing here is
    secret from them (public keys and addresses), and the hub's own safety option still rules: with devices
    kept apart, nobody is introduced."""
    state = load()
    if not state.get("hub") or (state.get("settings") or {}).get("isolate_devices"):
        return []
    seen = live().get("endpoints", {})
    out = []
    for d in state.get("devices", []):
        if d.get("kind") == "phone" or d.get("revoked") or _expired(d) or d.get("pending_until"):
            continue
        ep = seen.get(d["public_key"], "")
        out.append({"name": d["name"], "address": d["address"], "public_key": d["public_key"],
                    # 127.0.0.1 is the HTTPS relay's local end: that computer has no address others can dial.
                    "endpoint": "" if ep.startswith("127.") else ep,
                    "lan": (reported or {}).get(d["public_key"], "")})
    return out


def endpoint_candidates(me: dict, peer: dict) -> list[str]:
    """Where to try another computer directly, best guess first; the root side takes turns until one answers.
    Same public address as us means the same home network: its address there. Otherwise its public address
    with its own port (home routers keep the port when they can), then exactly where the hub hears it.
    Empty: no direct try, traffic stays on the hub."""
    ip = lambda ep: ep.rsplit(":", 1)[0] if ep else ""
    port = lambda ep: ep.rsplit(":", 1)[1] if ep and ":" in ep else ""
    out = []
    seen, lan = peer.get("endpoint", ""), peer.get("lan", "")
    if seen and me.get("endpoint") and ip(me["endpoint"]) == ip(seen) and lan:
        out.append(lan)
    if seen and port(lan):
        out.append(f"{ip(seen)}:{port(lan)}")
    if seen:
        out.append(seen)
    # Both on the HTTPS relay: only worth trying when our home addresses look like one network.
    if not seen and lan and me.get("lan") and me["lan"].rsplit(".", 1)[0] == lan.rsplit(".", 1)[0]:
        out.append(lan)
    return list(dict.fromkeys(out))[:3]


def choose_endpoint(me: dict, peer: dict) -> str:
    return (endpoint_candidates(me, peer) or [""])[0]


def write_mesh(rows: list[dict], my_key: str) -> bool:
    """On a joined computer: the other computers to try directly. True when the list changed."""
    me = next((r for r in rows if r.get("public_key") == my_key), None)
    lines = []
    for r in rows:
        if me is None or r is me or not MESH_KEY_RE.match(str(r.get("public_key", ""))):
            continue
        eps = [e for e in endpoint_candidates(me, r) if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d{2,5}", e)]
        if eps and re.fullmatch(r"10\.77\.0\.\d{1,3}", str(r.get("address", ""))):
            lines.append(f"{r['public_key']} {r['address']} {','.join(eps)}")
    text = "".join(l + "\n" for l in sorted(lines))
    p = home() / "mesh.conf"
    try:
        if p.read_text() == text:
            return False
    except OSError:
        if not text:
            return False
    if text:
        _write_private(p, text.encode())
    else:
        p.unlink(missing_ok=True)
    return True


def handshakes() -> dict[str, int]:
    """Latest handshake per peer, written by the root unit on each apply/refresh."""
    try:
        data = json.loads(_status_file().read_text())
        return {k: int(v) for k, v in data.get("handshakes", {}).items()}
    except Exception:
        return {}


def installed() -> bool:
    return (ROOT_HELPER_INSTALLED.exists() and Path("/etc/systemd/system/wings-sync.path").exists()
            and wstunnel_installed())


def helper_current() -> bool:
    """False when the plugin ships a newer root helper than the installed one."""
    try:
        return ROOT_HELPER_INSTALLED.read_bytes() == ROOT_HELPER_SRC.read_bytes()
    except OSError:
        return False


def interface_up() -> bool:
    return Path(f"/sys/class/net/{IFACE}").exists()


def status() -> dict:
    if load().get("hub"):
        forget_connected_keys()
    state = load()
    return {
        "mode": live_mode(),
        "member": {k: v for k, v in (state.get("member") or {}).items() if k != "private_key"},
        "initialized": bool(state.get("hub")),
        "installed": installed(),
        "helper_current": helper_current(),
        "interface_up": interface_up(),
        "hub": public_hub(state),
        "devices": devices(),
    }


# ---------------------------------------------------------------- root (setup only)

def setup_command(user: str | None = None) -> list[str]:
    """The single privileged command, shown to the user before it runs."""
    state = load()
    user = user or os.environ.get("USER") or "root"
    if state.get("member"):
        return [str(ROOT_HELPER_SRC), "install", user, str(hub_conf_path()), str(DEFAULT_PORT),
                str(DEFAULT_DASH_PORT), "member", str(fetch_wstunnel())]
    h = state["hub"]
    return [str(ROOT_HELPER_SRC), "install", user, str(hub_conf_path()), str(h["port"]),
            str(h["dash_port"]), "hub", str(fetch_wstunnel())]


def installed_role() -> str:
    try:
        for line in Path("/etc/wings/settings").read_text().splitlines():
            if line.startswith("WINGS_ROLE="):
                return line.split("=", 1)[1]
    except OSError:
        return ""
    return "hub"


def run_root(args: list[str]) -> subprocess.CompletedProcess:
    """Run one root-helper invocation through the desktop's own admin prompt."""
    if os.geteuid() == 0:
        cmd = ["bash", *args]
    elif os.environ.get("SUDO_ASKPASS"):
        cmd = ["sudo", "-A", "bash", *args]
    elif (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and shutil.which("pkexec"):
        cmd = ["pkexec", "bash", *args]
    elif sys.stdin.isatty():
        cmd = ["sudo", "bash", *args]
    else:
        cmd = ["sudo", "-n", "bash", *args]
    try:
        # Waiting on a person must fail cleanly: this can run under an agent or with nobody there.
        return subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "Nobody approved the admin prompt in time. Nothing was installed.")
