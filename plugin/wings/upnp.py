"""Ask a home router to pass one port to this machine (UPnP IGD), and to say what the home's public address is.

Only ever run because a person asked: `hermes wings router open`. Standard library only. The router is found on
this machine's own network (its default gateway first), and everything asked of it is one of four standard
actions: what is your public address, is this port mapped, map it to me, unmap it."""
from __future__ import annotations

import re
import socket
import urllib.request
from urllib.parse import urljoin
from xml.etree import ElementTree as ET

SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1")
DESCRIPTION = "Wings"


class RouterError(Exception):
    pass


def gateway() -> str:
    """This machine's default gateway, read from the kernel's own table."""
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[1] == "00000000" and int(f[3], 16) & 2:
                return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
    except (OSError, ValueError, IndexError):
        pass
    return ""


def _search(timeout: float = 2.5) -> list[str]:
    """Description addresses of routers that answer. The gateway is asked directly first (a reply to that passes
    any local firewall), then the usual multicast question."""
    found: list[str] = []
    ask = lambda st: (f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n").encode()
    targets = [(g, 1900) for g in [gateway()] if g] + [("239.255.255.250", 1900)]
    for target in targets:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            for st in ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2", "upnp:rootdevice"):
                s.sendto(ask(st), target)
            while True:
                data, _ = s.recvfrom(4096)
                m = re.search(rb"(?im)^location:\s*(\S+)", data)
                if m and m[1].decode() not in found:
                    found.append(m[1].decode())
        except OSError:
            pass
        finally:
            s.close()
        if found:
            break
    return found


def _private(host: str) -> bool:
    return bool(re.fullmatch(r"(10\.\d+|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+", host))


def find() -> tuple[str, str]:
    """(control address, service type) of the router's port-mapping service. Routers off this machine's own
    private network are ignored."""
    for location in _search():
        host = re.sub(r"^https?://([^:/]+).*", r"\1", location)
        if not location.startswith("http://") or not _private(host):
            continue
        try:
            with urllib.request.urlopen(location, timeout=4) as r:
                tree = ET.fromstring(r.read(262144))
        except Exception:  # noqa: BLE001 - not a router we can read
            continue
        for el in tree.iter():
            if el.tag.endswith("service"):
                kind = next((c.text or "" for c in el if c.tag.endswith("serviceType")), "")
                control = next((c.text or "" for c in el if c.tag.endswith("controlURL")), "")
                if kind in SERVICES and control:
                    return urljoin(location, control), kind
    raise RouterError("no router here answered. UPnP may be switched off on it; forward the port by hand instead.")


def _call(control: str, kind: str, action: str, args: dict) -> dict:
    body = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    soap = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{kind}">{body}</u:{action}></s:Body></s:Envelope>').encode()
    req = urllib.request.Request(control, data=soap, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{kind}#{action}"'})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            tree = ET.fromstring(r.read(65536))
    except urllib.error.HTTPError as e:
        text = e.read(4096).decode(errors="replace")
        code = re.search(r"<errorCode>(\d+)</errorCode>", text)
        raise RouterError(f"the router said no ({code[1] if code else e.code})") from e
    except Exception as e:  # noqa: BLE001
        raise RouterError("the router did not answer") from e
    return {el.tag.split("}")[-1]: (el.text or "") for el in tree.iter() if len(el) == 0}


def public_address(router=None) -> str:
    control, kind = router or find()
    ip = _call(control, kind, "GetExternalIPAddress", {}).get("NewExternalIPAddress", "")
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        raise RouterError("the router did not say what its public address is")
    return ip


def mapped(port: int, router=None) -> str:
    """Which machine the router passes UDP <port> to, or '' when it passes it to nobody."""
    control, kind = router or find()
    try:
        got = _call(control, kind, "GetSpecificPortMappingEntry", {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": "UDP"})
    except RouterError:
        return ""
    return got.get("NewInternalClient", "")


def open_port(port: int, me: str, router=None) -> None:
    """Pass UDP <port> from outside to this machine. Refuses to take a port the router gives to another machine."""
    if not (1024 <= port <= 65535) or not _private(me):
        raise RouterError("this machine has no home address to pass the port to")
    router = router or find()
    holder = mapped(port, router)
    if holder and holder != me:
        raise RouterError(f"the router already passes that port to another machine on your network")
    _call(*router, "AddPortMapping", {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": "UDP", "NewInternalPort": port,
                                      "NewInternalClient": me, "NewEnabled": 1, "NewPortMappingDescription": DESCRIPTION, "NewLeaseDuration": 0})
    if mapped(port, router) != me:
        raise RouterError("the router accepted the request but the port is not passed on")


def close_port(port: int, me: str, router=None) -> bool:
    """Undo open_port. Only removes a mapping that points at this machine."""
    router = router or find()
    if mapped(port, router) != me:
        return False
    _call(*router, "DeletePortMapping", {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": "UDP"})
    return True
