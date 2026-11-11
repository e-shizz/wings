#!/usr/bin/env bash
# wings-root — the ONLY part of Wings that runs as root. Read it before approving.
#
# `install` runs once, through your desktop's admin prompt (pkexec / sudo -A). It:
#   0. installs wireguard-tools and nftables from your package manager if they're missing,
#   1. copies this script to /usr/local/libexec/wings-root (root-owned, so a user-level
#      process can never change what root runs),
#   2. writes /etc/wings/settings (user, config path, ports, role),
#   3. installs wings-sync.path + wings-sync.service and starts them.
#
# After that, Wings never asks for root again. When the plugin writes a new hub config
# (adding or revoking a device) or touches its `refresh` file, systemd runs `apply`, which:
#   - refuses symlinks and files not owned by the Wings user, copies the file somewhere only
#     root can write, and validates that copy line by line: no PostUp/PreUp hooks, no
#     DNS/Table/SaveConfig, and peers may only claim one 10.77.0.x/32 (nothing executes or reroutes),
#   - installs the copy as /etc/wireguard/wings0.conf (0600), brings wings0 up or syncs peers,
#   - keeps an nftables table "wings": the tunnel reaches only this machine's tunnel address and only
#     the ports Wings uses there, only the tunnel can address tunnel IPs, a hub forwards tunnel to tunnel only,
#   - opens UDP <port> on a hub, and adds matching firewalld/ufw rules where those run,
#   - writes peer handshake times to /run/wings/live.json for the device list,
#   - can give this machine a friendly HTTPS name: one marked line in /etc/hosts, a certificate
#     authority trusted system-wide but limited to .wings names, and ports 443 and 80 on the tunnel
#     address, forwarded to a local port. Port 80 sends a computer's browser to HTTPS, and hands the
#     Hermes app and phone browsers to Hermes directly, because they can't trust a private certificate,
#   - on a hub, answers <name>.wings for phones on port 53 of the tunnel address only, and passes
#     their other lookups to this machine's own resolver. It runs as an unprivileged throwaway user,
#   - those ports also sign in devices on the wing net without a password, by naming the tunnel peer that
#     connected. Hermes checks that signed note and issues an ordinary session,
#   - runs wstunnel (official release, checksum pinned below, unprivileged, reaches only the local
#     WireGuard port) so WireGuard also works over HTTPS on networks that block UDP. On a member a
#     timer tries direct UDP first and falls back to it by itself.
#
# `uninstall` stops wings0 and removes everything `install` created.
set -euo pipefail
umask 077

IFACE=wings0
SUBNET=10.77.0.0/24
HUB_IP=10.77.0.1
ENV_FILE=/etc/wings/settings
INSTALLED=/usr/local/libexec/wings-root
UNIT_DIR=/etc/systemd/system
DEST=/etc/wireguard/${IFACE}.conf
RUN_DIR=/run/wings
ENROLL_PORT=9121
RELAY_UNIT=/etc/systemd/system/wings-relay.service
WST_BIN=/usr/local/libexec/wings-wstunnel
RELAY_SECRET=/etc/wings/relay.secret
# wstunnel 11.1.0, from the official release. This root-owned copy decides what gets installed.
WST_SHA256_x86_64=512edf4e7bb64fc133522220123514868fae75b5bae4124b53e396787276aa23
WST_SHA256_aarch64=148895f957a68be39e2b65d28c5f2065b9c58c4a0cfd48c560b2b3267f398464

die() { echo "wings-root: $*" >&2; exit 2; }
need_port() { [[ "$1" =~ ^[0-9]{2,5}$ ]] && (( $1 >= 1024 && $1 <= 65535 )) || die "bad port: $1"; }
need_user() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && id "$1" &>/dev/null || die "bad user: $1"; }

# File checks on the user's copy. Advisory only: the user can swap the file afterwards, which
# is why apply validates a private root-owned copy (stage_conf), never the user's file.
check_source() {
  local f="$1" user="$2"
  [[ -e "$f" ]] || die "missing config"
  [[ ! -L "$f" ]] || die "config is a symlink"
  [[ -f "$f" ]] || die "config is not a regular file"
  [[ "$(stat -c %U "$f")" == "$user" ]] || die "config not owned by $user"
}

need_role() { [[ "$1" == hub || "$1" == member ]] || die "bad role: $1"; }

# Strict line-by-line check of what wg-quick will read. Only the exact lines the plugin writes
# pass: no hooks, no DNS/Table/SaveConfig, and every value is checked, because AllowedIPs turns
# into routes. Prints nothing from the file (it holds a private key).
validate_content() {
  local f="$1" role="${2:-hub}" line sec="" ifaces=0 peers=0 a_addr=0 a_priv=0 a_port=0 p_key=0 p_ips=0 p_end=0 v last
  local re_key='^[A-Za-z0-9+/]{43}=$'
  local -A seen=()
  [[ "$(stat -c %s "$f")" -le 262144 ]] || die "config too large"
  close_peer() {
    [[ $sec == p ]] || return 0
    [[ $p_key -eq 1 && $p_ips -eq 1 ]] || die "peer needs one PublicKey and one AllowedIPs"
    [[ $role != member || $p_end -eq 1 ]] || die "member peer needs one Endpoint"
  }
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
    case "$line" in
      "[Interface]") close_peer; sec=i; ifaces=$((ifaces+1)); continue ;;
      "[Peer]")      close_peer; sec=p; peers=$((peers+1)); p_key=0; p_ips=0; p_end=0; continue ;;
    esac
    [[ "$line" =~ ^([A-Za-z]+)\ =\ ([^[:space:]]+)$ ]] || die "config contains keys outside the allow-list"
    v="${BASH_REMATCH[2]}"
    case "$role:$sec:${BASH_REMATCH[1]}" in
      member:i:Address)
        [[ "$v" =~ ^10\.77\.0\.([0-9]{1,3})/32$ ]] || die "unexpected member address"
        last="${BASH_REMATCH[1]}"
        [[ ! "$last" =~ ^0[0-9] ]] && (( 10#$last >= 2 && 10#$last <= 254 )) || die "unexpected member address"
        a_addr=$((a_addr+1)) ;;
      member:i:ListenPort) die "member must not listen" ;;
      *:i:MTU) [[ "$v" =~ ^[0-9]{4}$ ]] && (( v >= 1280 && v <= 1420 )) || die "bad MTU" ;;
      member:p:AllowedIPs) [[ "$v" == "$SUBNET" ]] || die "peer address outside the tunnel"; p_ips=$((p_ips+1)) ;;
      member:p:Endpoint)
        [[ "$v" =~ ^[A-Za-z0-9.-]{1,253}:([0-9]{2,5})$ ]] || die "bad Endpoint"
        need_port "${BASH_REMATCH[1]}"; p_end=$((p_end+1)) ;;
      hub:p:Endpoint) die "config contains keys outside the allow-list" ;;
      *:i:PrivateKey) [[ "$v" =~ $re_key ]] || die "bad PrivateKey"; a_priv=$((a_priv+1)) ;;
      hub:i:Address) [[ "$v" == "$HUB_IP/24" ]] || die "unexpected hub address"; a_addr=$((a_addr+1)) ;;
      hub:i:ListenPort) need_port "$v"; a_port=$((a_port+1)) ;;
      *:p:PublicKey) [[ "$v" =~ $re_key ]] || die "bad PublicKey"; p_key=$((p_key+1)) ;;
      *:p:PresharedKey) [[ "$v" =~ $re_key ]] || die "bad PresharedKey" ;;
      *:p:PersistentKeepalive) [[ "$v" =~ ^[0-9]{1,5}$ ]] || die "bad PersistentKeepalive" ;;
      hub:p:AllowedIPs)
        [[ "$v" =~ ^10\.77\.0\.([0-9]{1,3})/32$ ]] || die "peer address outside the tunnel"
        last="${BASH_REMATCH[1]}"
        [[ ! "$last" =~ ^0[0-9] ]] && (( 10#$last >= 2 && 10#$last <= 254 )) || die "peer address outside the tunnel"
        [[ -z "${seen[$last]:-}" ]] || die "two peers share an address"
        seen[$last]=1; p_ips=$((p_ips+1)) ;;
      *) die "config contains keys outside the allow-list" ;;
    esac
  done < "$f"
  close_peer
  [[ $ifaces -eq 1 ]] || die "config contains keys outside the allow-list"
  [[ $a_addr -eq 1 ]] || die "unexpected hub address"
  [[ $a_priv -eq 1 ]] || die "config needs one PrivateKey"
  if [[ $role == hub ]]; then
    [[ $a_port -eq 1 ]] || die "hub config needs one ListenPort"
  else
    [[ $peers -eq 1 ]] || die "member config needs exactly one peer"
  fi
}

validate_conf() { check_source "$1" "$2"; validate_content "$1" "${3:-hub}"; }

# Copy the user's file into a directory only root can write, refusing symlinks at open time. Only
# that copy is ever validated or used, so a file swapped after the check reaches nothing that runs
# as root. Prints the staged path.
stage_file() {
  local src="$1" user="$2" dir="$3" max="${4:-1}" staged
  check_source "$src" "$user"
  staged=$(mktemp "$dir/.wings-stage.XXXXXX")
  if ! timeout 30 dd if="$src" of="$staged" iflag=nofollow bs=1M count="$max" status=none; then
    rm -f "$staged"; die "could not read $src"
  fi
  printf '%s\n' "$staged"
}

stage_conf() {
  local src="$1" user="$2" dir="$3" role="${4:-hub}" staged
  staged=$(stage_file "$src" "$user" "$dir") || exit 2
  if ! (validate_content "$staged" "$role"); then rm -f "$staged"; exit 2; fi
  printf '%s\n' "$staged"
}

# Relay settings written by the plugin. Fixed keys, checked values: these reach a command line.
validate_relay() {
  local f="$1" role="$2" line k v port=0 secret=0 host=0
  [[ "$(stat -c %s "$f")" -le 4096 ]] || die "relay settings too large"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([A-Za-z]+)\ =\ ([^[:space:]]+)$ ]] || die "bad relay settings"
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    case "$role:$k" in
      *:Port)   [[ "$v" =~ ^[0-9]{2,5}$ ]] && (( v >= 80 && v <= 65535 )) || die "bad relay port"; port=$((port+1)) ;;
      *:Secret) [[ "$v" =~ ^[0-9a-f]{32,64}$ ]] || die "bad relay secret"; secret=$((secret+1)) ;;
      member:Host) [[ "$v" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] || die "bad relay host"; host=$((host+1)) ;;
      *) die "bad relay settings" ;;
    esac
  done < "$f"
  [[ $port -eq 1 && $secret -eq 1 ]] || die "bad relay settings"
  [[ $role == hub || $host -eq 1 ]] || die "bad relay settings"
}

# The friendly-address settings. Fixed keys, checked values: these reach unit files and /etc/hosts.
validate_names() {
  local f="$1" line k v name=0 addr=0 port=0 last
  [[ "$(stat -c %s "$f")" -le 1024 ]] || die "address settings too large"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([A-Za-z]+)\ =\ ([^[:space:]]+)$ ]] || die "bad address settings"
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    case "$k" in
      Name) [[ "$v" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.wings$ ]] || die "bad address name"; name=$((name+1)) ;;
      Address)
        [[ "$v" =~ ^10\.77\.0\.([0-9]{1,3})$ ]] || die "address outside the tunnel"
        last="${BASH_REMATCH[1]}"
        [[ ! "$last" =~ ^0[0-9] ]] && (( 10#$last >= 1 && 10#$last <= 254 )) || die "address outside the tunnel"
        addr=$((addr+1)) ;;
      Port) [[ "$v" =~ ^[0-9]{4,5}$ ]] && (( v >= 1024 && v <= 65535 )) || die "bad address port"; port=$((port+1)) ;;
      HttpsPort) [[ "$v" == 443 || "$v" == 8443 ]] || die "bad https port" ;;
      HttpPort) [[ "$v" == 80 || "$v" == 8080 ]] || die "bad http port" ;;
      *) die "bad address settings" ;;
    esac
  done < "$f"
  [[ $name -eq 1 && $addr -eq 1 && $port -eq 1 ]] || die "bad address settings"
}

# Root is asked to trust this certificate system-wide, and the plugin's user wrote it. So it must be
# a CA limited to .wings names by a critical constraint: it can't vouch for any real website.
validate_ca() {
  local f="$1" out
  out=$(openssl x509 -in "$f" -noout -ext basicConstraints,nameConstraints 2>/dev/null) || die "bad certificate"
  grep -q 'X509v3 Basic Constraints: critical' <<<"$out" && grep -q 'CA:TRUE' <<<"$out" || die "not a CA certificate"
  grep -q 'X509v3 Name Constraints: critical' <<<"$out" || die "certificate has no critical name constraint"
  [[ "$(grep -c 'DNS:' <<<"$out")" -eq 1 ]] && grep -qE '^ *DNS:\.?wings$' <<<"$out" || die "certificate is not limited to .wings"
  ! grep -qE 'Excluded|IP:|email:|URI:' <<<"$out" || die "certificate is not limited to .wings"
}

ca_anchor() {
  if command -v update-ca-trust &>/dev/null; then echo /etc/pki/ca-trust/source/anchors/wings-ca.crt
  else echo /usr/local/share/ca-certificates/wings-ca.crt; fi
}
ca_refresh() {
  # The system rebuilds its whole trust list each time. A run that collides with another can fail once
  # (seen on Fedora: "ln: ... File exists"), so try again, and never let it stop an install or uninstall halfway.
  local tool="update-ca-certificates --fresh"
  if command -v update-ca-trust &>/dev/null; then tool="update-ca-trust extract"; fi
  $tool >/dev/null 2>&1 || { sleep 1; $tool >/dev/null 2>&1 || echo "note: the system trust list did not refresh; run '$tool' later" >&2; }
}
ca_remove() { local a; a=$(ca_anchor); if [[ -e "$a" ]]; then rm -f "$a"; ca_refresh; fi; }

write_tls_proxy() {
  cat > "$1" <<'PROXY'
#!/usr/bin/python3 -I
"""Wings: HTTPS on the tunnel address, forwarded to a local port, port 80 for the Hermes app, and
the no-password sign-in for devices on the wing net."""
import asyncio, hashlib, hmac, os, re, ssl, sys, time

addr, name, target = sys.argv[1], sys.argv[2], int(sys.argv[3])
tls_port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
plain_port = int(sys.argv[5]) if len(sys.argv) > 5 else 80
peers = sys.argv[6] if len(sys.argv) > 6 else "10.77.0."  # only the tests change this
creds = os.environ["CREDENTIALS_DIRECTORY"]
with open(os.path.join(creds, "key"), "rb") as f:
    approve_key = hashlib.sha256(b"wings-approve\0" + f.read()).digest()


async def pump(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, ssl.SSLError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def wants_https(head):
    """A computer's browser asks for HTTPS and trusts the Wings certificate. Phones can't trust it."""
    fields = dict(l.split(b":", 1) for l in head.lower().split(b"\r\n")[1:] if b":" in l)
    agent = fields.get(b"user-agent", b"")
    return b"upgrade-insecure-requests" in fields and not any(m in agent for m in (b"mobile", b"android", b"iphone", b"ipad"))


def origin(secure):
    if secure:
        return f"https://{name}" + ("" if tls_port == 443 else f":{tls_port}")
    return f"http://{name}" + ("" if plain_port == 80 else f":{plain_port}")


def reply(status, extra=""):
    return f"HTTP/1.1 {status}\r\n{extra}Cache-Control: no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()


def approval(head, peer, secure):
    """Sign-in for a device on the wing net. This address is on the tunnel only, so WireGuard has already
    proved who is connecting. Hermes gets a short signed note naming that device, and starts a normal session."""
    m = re.match(rb"GET /wings-approve\?state=([A-Za-z0-9_-]{16,128}) HTTP/1\.[01]\r\n", head)
    if not m or not peer.startswith(peers):
        return reply("404 Not Found")
    state, ts = m[1].decode(), str(int(time.time()))
    mac = hmac.new(approve_key, f"wings-device|{state}|{peer}|{ts}".encode(), hashlib.sha256).hexdigest()
    return reply("302 Found", f"Location: {origin(secure)}/auth/callback?code={ts}.{peer}.{mac}&state={state}\r\n")


def skips_chooser(head, peer):
    """A bare /login from a device on the wing net, opened directly (not after signing out, not with a
    message to show): go straight to the Wings sign-in."""
    first, _, rest = head.partition(b"\r\n")
    return (peer.startswith(peers) and re.fullmatch(rb"GET /login HTTP/1\.[01]", first) is not None
            and b"\r\nreferer:" not in b"\r\n" + rest.lower())


def body_of(head):
    """How much body follows this request. None: can't tell, so the rest of the connection is passed through."""
    fields = dict((l.split(b":", 1)[0].strip(), l.split(b":", 1)[1].strip()) for l in head.lower().split(b"\r\n")[1:] if b":" in l)
    if b"upgrade" in fields or b"transfer-encoding" in fields:
        return None
    try:
        return int(fields.get(b"content-length", b"0"))
    except ValueError:
        return None


async def copy(reader, up_w, n):
    while n > 0:
        data = await reader.read(min(n, 65536))
        if not data:
            raise ConnectionError
        up_w.write(data)
        await up_w.drain()
        n -= len(data)


async def serve(reader, writer, secure):
    """One client connection. Requests are read one at a time, so the sign-in can be answered here even
    on a connection the browser kept open. Everything else reaches Hermes unchanged."""
    peer = writer.get_extra_info("peername")[0]
    up_w = tail = None
    try:
        while True:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10 if up_w is None else 3600)
            if head.startswith(b"GET /wings-approve?"):
                writer.write(approval(head, peer, secure))
                await writer.drain()
                return
            if skips_chooser(head, peer):
                # The sign-in window Hermes Desktop opens: the tunnel already knows this device, so no button to press.
                writer.write(reply("302 Found", "Location: /auth/login?provider=wings-device\r\n"))
                await writer.drain()
                return
            if not secure and wants_https(head):
                path = head.split(b" ", 2)[1].decode("latin-1")
                path = path if path.startswith("/") else "/"
                writer.write(reply("301 Moved Permanently", f"Location: {origin(True)}{path}\r\n"))
                await writer.drain()
                return
            if not secure and head.startswith(b"GET /auth/native/authorize?") and b"provider=" not in head.split(b"\r\n", 1)[0]:
                # The Hermes app, on a phone: no need to choose a sign-in method, the tunnel already knows it.
                head = head.replace(b"/auth/native/authorize?", b"/auth/native/authorize?provider=wings-device&", 1)
            if up_w is None:
                up_r, up_w = await asyncio.open_connection("127.0.0.1", target)
                tail = asyncio.ensure_future(pump(up_r, writer))
            up_w.write(head)
            await up_w.drain()
            n = body_of(head)
            if n is None:
                await pump(reader, up_w)
                return
            await copy(reader, up_w, n)
    except (OSError, ssl.SSLError, EOFError, ValueError, asyncio.TimeoutError, asyncio.LimitOverrunError, asyncio.CancelledError):
        pass
    finally:
        for w in (writer, up_w):
            try:
                if w:
                    w.close()
            except Exception:
                pass
        if tail:
            tail.cancel()


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(creds, "cert"), os.path.join(creds, "key"))
    tls = await asyncio.start_server(lambda r, w: serve(r, w, True), addr, tls_port, ssl=ctx)
    web = await asyncio.start_server(lambda r, w: serve(r, w, False), addr, plain_port)
    async with tls, web:
        await asyncio.gather(tls.serve_forever(), web.serve_forever())

asyncio.run(main())
PROXY
}

write_dns_server() {
  cat > "$1" <<'DNS'
#!/usr/bin/python3 -I
"""Wings: answers <name>.wings on the tunnel address. Any other lookup goes to this machine's own resolver."""
import asyncio, re, socket, struct, sys

addr, names_file = sys.argv[1], sys.argv[2]
port = int(sys.argv[3]) if len(sys.argv) > 3 else 53
fixed = sys.argv[4] if len(sys.argv) > 4 else ""  # host:port, for the tests
names = {}
with open(names_file) as f:
    for line in f:
        ip, name = line.split()
        names[name] = socket.inet_aton(ip)
slots = asyncio.Semaphore(128)
tasks = set()


def servers():
    if fixed:
        host, _, p = fixed.rpartition(":")
        return [(host, int(p))]
    try:
        with open("/etc/resolv.conf") as f:
            found = re.findall(r"^nameserver\s+(\d+\.\d+\.\d+\.\d+)\s*$", f.read(), re.M)
    except OSError:
        return []
    return [(ip, 53) for ip in found if ip != addr]


def question(q):
    """(name, type, end of the question), or None if this isn't one plain query."""
    if len(q) < 12 or q[2] & 0x80 or q[4:6] != b"\0\1":
        return None
    i, labels = 12, []
    while True:
        if i >= len(q) or q[i] > 63 or i + 1 + q[i] > len(q):
            return None
        n = q[i]
        i += 1
        if n == 0:
            break
        labels.append(q[i:i + n])
        i += n
    if i + 4 > len(q):
        return None
    return b".".join(labels).decode("latin-1").lower(), struct.unpack("!H", q[i:i + 2])[0], i + 4


def reply(q, end, rcode=0, ip=None):
    head = q[:2] + bytes([0x84 | (q[2] & 1), 0x80 | rcode]) + struct.pack("!HHHH", 1, 1 if ip else 0, 0, 0)
    return head + q[12:end] + (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip if ip else b"")


async def ask_udp(q):
    loop = asyncio.get_running_loop()
    for server in servers():
        got = loop.create_future()

        class Answer(asyncio.DatagramProtocol):
            def datagram_received(self, data, _):
                if data[:2] == q[:2] and not got.done():
                    got.set_result(data)

        t, _ = await loop.create_datagram_endpoint(Answer, remote_addr=server)
        try:
            t.sendto(q)
            return await asyncio.wait_for(got, 2)
        except (OSError, asyncio.TimeoutError):
            continue
        finally:
            t.close()
    return None


async def ask_tcp(q):
    async def once(server):
        r, w = await asyncio.open_connection(*server)
        try:
            w.write(struct.pack("!H", len(q)) + q)
            await w.drain()
            n = struct.unpack("!H", await r.readexactly(2))[0]
            return await r.readexactly(n)
        finally:
            w.close()
    for server in servers():
        try:
            return await asyncio.wait_for(once(server), 3)
        except (OSError, EOFError, asyncio.TimeoutError):
            continue
    return None


async def resolve(q, ask):
    found = question(q)
    if found is None:
        return None
    name, kind, end = found
    if name == "wings" or name.endswith(".wings"):
        ip = names.get(name)
        # A known name with no answer of this type is "no data", not "no such name", or phones give up.
        return reply(q, end, 0 if ip else 3, ip if kind == 1 else None)
    async with slots:
        return await ask(q) or reply(q, end, 2)


class Udp(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, q, peer):
        if not slots.locked():
            t = asyncio.ensure_future(self.serve(q, peer))
            tasks.add(t)
            t.add_done_callback(tasks.discard)

    async def serve(self, q, peer):
        a = await resolve(q, ask_udp)
        if a:
            self.transport.sendto(a, peer)


async def tcp(r, w):
    try:
        while True:
            n = struct.unpack("!H", await asyncio.wait_for(r.readexactly(2), 10))[0]
            a = await resolve(await asyncio.wait_for(r.readexactly(n), 5), ask_tcp)
            if not a:
                break
            w.write(struct.pack("!H", len(a)) + a)
            await w.drain()
    except (OSError, EOFError, asyncio.TimeoutError):
        pass
    finally:
        w.close()


async def main():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(Udp, local_addr=(addr, port))
    server = await asyncio.start_server(tcp, addr, port)
    async with server:
        await server.serve_forever()

asyncio.run(main())
DNS
}

# Rewrite only our own marked lines in a hosts file, atomically.
hosts_set() {  # hosts-file address name [address name ...] (no pairs removes all)
  local file="$1" tmp; shift
  tmp=$(mktemp "$file.wings.XXXXXX")
  grep -v ' # wings$' "$file" > "$tmp" || true
  while [[ $# -ge 2 ]]; do
    if [[ -n "$2" ]]; then printf '%s %s # wings\n' "$1" "$2" >> "$tmp"; fi
    shift 2
  done
  chmod --reference="$file" "$tmp"; chown --reference="$file" "$tmp"
  mv -fT "$tmp" "$file"
}

# A friendly HTTPS address on this machine's tunnel address, forwarded to a local port. It adds no
# login bypass: Hermes must be set to require sign-in for this name. The service opens its ports
# itself as a plain system user, because SELinux stops PID 1 binding web ports and that rule stays.
names_apply() {  # settings-file user
  local src="$1" user="$2" dir staged name addr port svc=$UNIT_DIR/wings-address.service sock=$UNIT_DIR/wings-address.socket
  local tls=/etc/wings/tls stca stcrt stkey changed=0 anchor hport pport
  dir=$(dirname "$src")
  if [[ ! -e "$src" ]]; then
    if [[ -e "$sock" || -e "$svc" ]]; then
      systemctl disable --now wings-address.socket wings-address.service >/dev/null 2>&1 || true
      rm -f "$sock" "$svc"; systemctl daemon-reload
    fi
    rm -f "$tls/cert" "$tls/key" "$tls/tried"; rmdir "$tls" 2>/dev/null || true
    ca_remove
    return 0
  fi
  command -v openssl &>/dev/null || die "openssl is needed for HTTPS"
  if [[ ! -e "$dir/tls/leaf.crt" ]]; then
    echo "wings-root: address has no certificate yet; run hermes wings address again" >&2
    return 0
  fi
  install -d -m 0700 -o root -g root "$tls"
  staged=$(stage_file "$src" "$user" "$tls") || exit 2
  if ! (validate_names "$staged"); then rm -f "$staged"; exit 2; fi
  name=$(relay_value "$staged" Name); addr=$(relay_value "$staged" Address); port=$(relay_value "$staged" Port)
  hport=$(relay_value "$staged" HttpsPort); hport=${hport:-443}
  pport=$(relay_value "$staged" HttpPort); pport=${pport:-80}
  rm -f "$staged"
  stca=$(stage_file "$dir/tls/ca.crt" "$user" "$tls") || exit 2
  stcrt=$(stage_file "$dir/tls/leaf.crt" "$user" "$tls") || { rm -f "$stca"; exit 2; }
  stkey=$(stage_file "$dir/tls/leaf.key" "$user" "$tls") || { rm -f "$stca" "$stcrt"; exit 2; }
  install -m 0600 -o root -g root "$stcrt" "$tls/tried"
  if ! (validate_ca "$stca") || ! openssl verify -CAfile "$stca" -verify_hostname "$name" "$stcrt" >/dev/null 2>&1; then
    rm -f "$stca" "$stcrt" "$stkey"; die "certificate check failed"
  fi
  anchor=$(ca_anchor)
  if ! cmp -s "$stca" "$anchor"; then
    install -D -m 0644 -o root -g root "$stca" "$anchor"; ca_refresh; changed=1
  fi
  if ! cmp -s "$stcrt" "$tls/cert" || ! cmp -s "$stkey" "$tls/key"; then changed=1; fi
  mv -fT "$stcrt" "$tls/cert"; mv -fT "$stkey" "$tls/key"; rm -f "$stca"
  chmod 600 "$tls/cert" "$tls/key"
  id wings-net &>/dev/null || useradd -r -M -s /usr/sbin/nologin wings-net
  rm -f "$sock"
  cat > "$svc.new" <<EOF
[Unit]
Description=Wings: https://$name on the tunnel address
After=network-online.target

[Service]
ExecStart=/usr/local/libexec/wings-tls-proxy $addr $name $port $hport $pport
LoadCredential=cert:$tls/cert
LoadCredential=key:$tls/key
Restart=always
RestartSec=5
User=wings-net
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$svc.new"
  if cmp -s "$svc.new" "$svc" && [[ $changed -eq 0 ]] && systemctl -q is-active wings-address.service; then
    rm -f "$svc.new"
  else
    mv -fT "$svc.new" "$svc"
    systemctl daemon-reload
    systemctl enable wings-address.service >/dev/null 2>&1
    # A friendly address failing must never take the tunnel down with it.
    systemctl restart wings-address.service || echo "wings-root: friendly address did not start" >&2
  fi
  NAMES_ADDR="$addr"; NAMES_NAME="$name"; NAMES_HPORT="$hport"; NAMES_PPORT="$pport"
}

# The hub's own name and certificate, handed to a member when it joined over the authenticated
# tunnel. Same strict checks: the name must be .wings, on the tunnel, and the CA limited to .wings.
hub_name_apply() {  # data-dir user
  local dir="$1" user="$2" staged stca name addr anchor=/etc/pki/ca-trust/source/anchors/wings-hub-ca.crt
  command -v update-ca-trust &>/dev/null || anchor=/usr/local/share/ca-certificates/wings-hub-ca.crt
  if [[ ! -e "$dir/hub-name.conf" || ! -e "$dir/hub-ca.crt" ]]; then
    if [[ -e "$anchor" ]]; then rm -f "$anchor"; ca_refresh; fi
    return 0
  fi
  install -d -m 0755 /etc/wings
  staged=$(stage_file "$dir/hub-name.conf" "$user" /etc/wings) || exit 2
  if ! (validate_hub_name "$staged"); then rm -f "$staged"; exit 2; fi
  name=$(relay_value "$staged" Name); addr=$(relay_value "$staged" Address); rm -f "$staged"
  stca=$(stage_file "$dir/hub-ca.crt" "$user" /etc/wings) || exit 2
  if ! (validate_ca "$stca"); then rm -f "$stca"; exit 2; fi
  if ! cmp -s "$stca" "$anchor"; then install -D -m 0644 -o root -g root "$stca" "$anchor"; ca_refresh; fi
  rm -f "$stca"
  NAMES_HUB_ADDR="$addr"; NAMES_HUB_NAME="$name"
}

validate_hub_name() {
  local f="$1" line k v name=0 addr=0
  [[ "$(stat -c %s "$f")" -le 1024 ]] || die "hub name settings too large"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([A-Za-z]+)\ =\ ([^[:space:]]+)$ ]] || die "bad hub name settings"
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    case "$k" in
      Name) [[ "$v" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.wings$ ]] || die "bad hub name"; name=$((name+1)) ;;
      Address) [[ "$v" == "$HUB_IP" ]] || die "hub name must point at the hub"; addr=$((addr+1)) ;;
      *) die "bad hub name settings" ;;
    esac
  done < "$f"
  [[ $name -eq 1 && $addr -eq 1 ]] || die "bad hub name settings"
}

validate_dns_names() {
  local f="$1" line n=0 last
  [[ "$(stat -c %s "$f")" -le 16384 ]] || die "names file too large"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^10\.77\.0\.([0-9]{1,3})\ [a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\.wings$ ]] || die "bad name line"
    last="${BASH_REMATCH[1]}"
    [[ ! "$last" =~ ^0[0-9] ]] && (( 10#$last >= 1 && 10#$last <= 254 )) || die "name outside the tunnel"
    n=$((n+1))
  done < "$f"
  (( n >= 1 && n <= 254 )) || die "bad names file"
}

# The other computers on the wing net, by name, so this one can open them. Same strict lines as the hub's
# name list: a tunnel address and a .wings name, nothing else. A problem here never takes the tunnel down.
PEER_PAIRS=()
peers_apply() {  # data-dir user
  local src="$1/peers.conf" user="$2" staged ip name
  PEER_PAIRS=()
  if [[ ! -e "$src" ]]; then rm -f /etc/wings/peers.tried; return 0; fi
  install -d -m 0755 /etc/wings
  staged=$(stage_file "$src" "$user" /etc/wings) || return 0
  install -m 0600 -o root -g root "$staged" /etc/wings/peers.tried
  if ! (validate_dns_names "$staged"); then rm -f "$staged"; echo "wings-root: peer names not applied" >&2; return 0; fi
  while read -r ip name; do
    [[ "$name" == "${NAMES_NAME:-}" || "$name" == "${NAMES_HUB_NAME:-}" ]] || PEER_PAIRS+=("$ip" "$name")
  done < "$staged"
  rm -f "$staged"
}

# Has the root side seen the latest certificate and peer names? Two files changing within a moment can reach
# the path unit as one event, so the 15-second watch asks too. "Tried" counts as seen: a file that failed its
# checks is not retried until it changes.
names_settled() {  # data-dir
  local d="$1" f
  f="$d/tls/leaf.crt"
  if [[ -e "$d/address.conf" && -f "$f" && ! -L "$f" ]] && ! timeout 5 cmp -s "$f" /etc/wings/tls/tried; then return 1; fi
  f="$d/peers.conf"
  if [[ -f "$f" && ! -L "$f" ]]; then timeout 5 cmp -s "$f" /etc/wings/peers.tried || return 1
  elif [[ -e /etc/wings/peers.tried ]]; then return 1; fi
  return 0
}

# Phones have no hosts file, so a hub answers <name>.wings for them. A problem here must never take
# the tunnel down with it.
dns_apply() {  # names-file user
  local src="$1" user="$2" staged svc=$UNIT_DIR/wings-dns.service names=/etc/wings/names changed=0
  if [[ ! -e "$src" ]]; then
    if [[ -e "$svc" ]]; then
      systemctl disable --now wings-dns.service >/dev/null 2>&1 || true
      rm -f "$svc" "$names"; systemctl daemon-reload
    fi
    return 0
  fi
  [[ -x /usr/local/libexec/wings-dns ]] || { echo "wings-root: name server not installed; run hermes wings setup" >&2; return 0; }
  install -d -m 0755 /etc/wings
  staged=$(stage_file "$src" "$user" /etc/wings) || return 0
  if ! (validate_dns_names "$staged"); then rm -f "$staged"; echo "wings-root: names not applied" >&2; return 0; fi
  cmp -s "$staged" "$names" || changed=1
  chmod 0644 "$staged"; mv -fT "$staged" "$names"
  cat > "$svc.new" <<EOF
[Unit]
Description=Wings: .wings names for phones on the tunnel
After=network-online.target

[Service]
ExecStart=/usr/local/libexec/wings-dns $HUB_IP $names
Restart=always
RestartSec=5
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryMax=64M

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$svc.new"
  if cmp -s "$svc.new" "$svc" && [[ $changed -eq 0 ]] && systemctl -q is-active wings-dns.service; then
    rm -f "$svc.new"
  else
    mv -fT "$svc.new" "$svc"
    systemctl daemon-reload
    systemctl enable wings-dns.service >/dev/null 2>&1
    systemctl restart wings-dns.service || echo "wings-root: name server did not start" >&2
  fi
  NAMES_DNS=yes
}

relay_value() { sed -n "s/^$2 = //p" "$1" | head -1; }

# Hash a private copy of the download against the pin above, then unpack only the program from it.
install_wstunnel() {
  local src="$1" user="$2" dir staged arch want have
  arch=$(uname -m)
  case "$arch" in
    x86_64) want=$WST_SHA256_x86_64 ;;
    aarch64) want=$WST_SHA256_aarch64 ;;
    *) die "no pinned wstunnel for $arch" ;;
  esac
  dir=$(mktemp -d /run/wings-install.XXXXXX)
  staged=$(stage_file "$src" "$user" "$dir" 64) || { rm -rf "$dir"; exit 2; }
  have=$(sha256sum "$staged" | cut -d' ' -f1)
  if [[ "$have" != "$want" ]]; then rm -rf "$dir"; die "wstunnel download does not match the pinned checksum"; fi
  tar -xzf "$staged" -C "$dir" wstunnel
  install -m 0755 -o root -g root "$dir/wstunnel" "$WST_BIN"
  rm -rf "$dir"
}

uplink_zone() {
  local dev
  dev=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
  firewall-cmd --get-zone-of-interface="$dev" 2>/dev/null || firewall-cmd --get-default-zone
}

firewalld_on() { command -v firewall-cmd &>/dev/null && firewall-cmd --state &>/dev/null; }

# The tunnel ports in use on this machine: the hub's enrolment port, and an address's web ports.
# Nothing else, so an existing web server on all interfaces stays out of the tunnel.
tunnel_ports() {  # role
  local out=""
  if [[ "$1" == hub ]]; then out="$ENROLL_PORT"; fi
  if [[ -n "${NAMES_HPORT:-}" ]]; then out="${out:+$out }${NAMES_HPORT} ${NAMES_PPORT}"; fi
  if [[ "${NAMES_DNS:-}" == yes ]]; then out="${out:+$out }53"; fi
  printf '%s\n' "$out"
}

# Runtime rules, re-created by apply at every boot. Each address is allowed one fixed set of ports.
fw_rules() {  # local-address role
  local p
  for p in $(tunnel_ports "$2"); do
    printf 'rule family=ipv4 source address=%s destination address=%s port port=%s protocol=tcp accept\n' "$SUBNET" "$1" "$p"
  done
  if [[ "${NAMES_DNS:-}" == yes ]]; then
    printf 'rule family=ipv4 source address=%s destination address=%s port port=53 protocol=udp accept\n' "$SUBNET" "$1"
  fi
  printf 'rule family=ipv4 source address=%s destination address=%s icmp-type name=echo-request accept\n' "$SUBNET" "$1"
}

# The gate that holds on every host, firewalld or not. The tunnel reaches only the listed ports,
# nothing but the tunnel can address tunnel IPs, and a hub forwards tunnel to tunnel only, so a
# peer can never use it as an exit to the internet or the hub's own network.
nft_apply() {  # role local-address
  local ports isolate_rule="" port_rule="" dns_rule=""
  ports=$(tunnel_ports "$1" | tr ' ' ',')
  if [[ -n "$ports" ]]; then port_rule="iifname \"$IFACE\" tcp dport { $ports } accept"; fi
  if [[ "${NAMES_DNS:-}" == yes ]]; then dns_rule="iifname \"$IFACE\" udp dport 53 accept"; fi
  if [[ "${WINGS_ISOLATE:-no}" == yes ]]; then isolate_rule="iifname \"$IFACE\" oifname \"$IFACE\" drop"; fi
  command -v nft &>/dev/null || die "nftables missing (nft): refusing to run without the tunnel gate"
  nft delete table inet wings 2>/dev/null || true
  nft -f - <<EOF
table inet wings {
  chain input {
    type filter hook input priority -5; policy accept;
    iifname != { "$IFACE", "lo" } ip daddr $SUBNET drop
    iifname "$IFACE" ip daddr != $2 drop
    iifname "$IFACE" ct state established,related accept
    iifname "$IFACE" icmp type echo-request accept
    $port_rule
    $dns_rule
    iifname "$IFACE" drop
  }
  chain forward {
    type filter hook forward priority -5; policy accept;
    iifname "$IFACE" oifname != "$IFACE" drop
    oifname "$IFACE" iifname != "$IFACE" drop
    $isolate_rule
  }
}
EOF
  if [[ "$1" == hub ]]; then sysctl -q -w "net.ipv4.conf.$IFACE.forwarding=1"; fi
}

fw_apply() {  # role local-address port dash-port
  local role="$1" addr="$2" port="$3" dash="$4" zone rule p
  nft_apply "$role" "$addr"
  if firewalld_on; then
    zone=$(uplink_zone)
    if [[ $role == hub ]]; then
      firewall-cmd -q --zone="$zone" --query-port="$port/udp" || firewall-cmd -q --zone="$zone" --add-port="$port/udp"
    fi
    [[ "$(firewall-cmd --get-zone-of-interface=$IFACE 2>/dev/null || true)" == drop ]] || \
      firewall-cmd -q --zone=drop --change-interface="$IFACE"
    while IFS= read -r rule; do
      firewall-cmd -q --zone=drop --query-rich-rule="$rule" || firewall-cmd -q --zone=drop --add-rich-rule="$rule"
    done < <(fw_rules "$addr" "$role")
  elif command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    if [[ $role == hub ]]; then ufw allow "$port/udp" >/dev/null; fi
    for p in $(tunnel_ports "$role"); do
      ufw allow in on "$IFACE" from "$SUBNET" to "$addr" port "$p" proto tcp >/dev/null
    done
    if [[ "${NAMES_DNS:-}" == yes ]]; then ufw allow in on "$IFACE" from "$SUBNET" to "$addr" port 53 proto udp >/dev/null; fi
  fi
}

fw_remove() {  # local-address port dash-port
  local addr="$1" port="$2" dash="$3" zone rule p
  nft delete table inet wings 2>/dev/null || true
  # Clear every port Wings could have opened, whichever were in use.
  NAMES_HPORT="443 8443"; NAMES_PPORT="80 8080 $dash"; NAMES_DNS=yes
  if firewalld_on; then
    zone=$(uplink_zone)
    firewall-cmd -q --zone="$zone" --remove-port="$port/udp" 2>/dev/null || true
    while IFS= read -r rule; do
      firewall-cmd -q --zone=drop --remove-rich-rule="$rule" 2>/dev/null || true
    done < <(fw_rules "$addr" hub)
    firewall-cmd -q --zone=drop --remove-interface="$IFACE" 2>/dev/null || true
  elif command -v ufw &>/dev/null; then
    ufw delete allow "$port/udp" >/dev/null 2>&1 || true
    for p in $(tunnel_ports hub); do
      ufw delete allow in on "$IFACE" from "$SUBNET" to "$addr" port "$p" proto tcp >/dev/null 2>&1 || true
    done
    ufw delete allow in on "$IFACE" from "$SUBNET" to "$addr" port 53 proto udp >/dev/null 2>&1 || true
  fi
}

relay_fw() {  # add|remove port
  firewalld_on || { if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    if [[ $1 == add ]]; then ufw allow "$2/tcp" >/dev/null; else ufw delete allow "$2/tcp" >/dev/null 2>&1 || true; fi; fi; return 0; }
  local zone; zone=$(uplink_zone)
  if [[ $1 == add ]]; then
    firewall-cmd -q --zone="$zone" --query-port="$2/tcp" || firewall-cmd -q --zone="$zone" --add-port="$2/tcp"
  else
    firewall-cmd -q --zone="$zone" --remove-port="$2/tcp" 2>/dev/null || true
  fi
}

# Runs unprivileged and can only reach the local WireGuard port. Traffic inside is WireGuard either
# way, so the relay never sees plaintext. The secret stays out of command lines and logs.
relay_apply() {  # role wg-port settings-file user
  local uplink role="$1" wgport="$2" src="$3" user="$4" staged port secret host exec_line unit=$UNIT_DIR/wings-relay.service old local_line=""
  old=$(sed -n 's/^# wings-port: //p' "$unit" 2>/dev/null || true)
  if [[ ! -e "$src" ]]; then
    if [[ -e "$unit" ]]; then
      systemctl disable --now wings-relay.service >/dev/null 2>&1 || true
      rm -f "$unit" "$RELAY_SECRET"; systemctl daemon-reload
      if [[ -n "$old" ]]; then relay_fw remove "$old"; fi
    fi
    return 0
  fi
  [[ -x "$WST_BIN" ]] || die "wstunnel is not installed; run hermes wings setup"
  staged=$(stage_file "$src" "$user" /etc/wings) || exit 2
  if ! (validate_relay "$staged" "$role"); then rm -f "$staged"; exit 2; fi
  port=$(relay_value "$staged" Port); secret=$(relay_value "$staged" Secret); host=$(relay_value "$staged" Host)
  rm -f "$staged"
  if [[ $role == hub ]]; then
    # Bind the uplink address, not 0.0.0.0, so 443 on the tunnel address stays free for HTTPS names.
    uplink=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}')
    [[ "$uplink" =~ ^[0-9.]+$ ]] || die "no uplink address for the relay"
    exec_line="$WST_BIN server --log-lvl ERROR --restrict-to 127.0.0.1:$wgport wss://$uplink:$port"
    printf 'WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX=%s\n' "$secret" > "$RELAY_SECRET.new"
  else
    lp=$(relay_local_port "$unit")
    local_line="# wings-local: $lp"
    exec_line="$WST_BIN client --log-lvl ERROR -L udp://127.0.0.1:$lp:127.0.0.1:$wgport?timeout_sec=0 wss://$host:$port"
    printf 'WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX=%s\n' "$secret" > "$RELAY_SECRET.new"
  fi
  chmod 600 "$RELAY_SECRET.new"
  cat > "$unit.new" <<EOF
# wings-port: $port
$local_line
[Unit]
Description=Wings: WireGuard over HTTPS for networks that block UDP
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=$RELAY_SECRET
ExecStart=$exec_line
Restart=always
RestartSec=5
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$unit.new"
  if cmp -s "$unit.new" "$unit" && cmp -s "$RELAY_SECRET.new" "$RELAY_SECRET" && systemctl -q is-active wings-relay.service; then
    rm -f "$unit.new" "$RELAY_SECRET.new"
  else
    mv -fT "$RELAY_SECRET.new" "$RELAY_SECRET"; mv -fT "$unit.new" "$unit"
    systemctl daemon-reload
    systemctl enable wings-relay.service >/dev/null 2>&1
    systemctl restart wings-relay.service
  fi
  if [[ $role == hub ]]; then
    if [[ -n "$old" && "$old" != "$port" ]]; then relay_fw remove "$old"; fi
    relay_fw add "$port"
  fi
}

# Keep the port the relay already has, otherwise take the first free one. Other tools use local
# UDP relays too (wstunnel's own docs suggest common ports), and a clash stops the relay starting.
relay_local_port() {
  local unit="${1:-$RELAY_UNIT}" p
  p=$(sed -n 's/^# wings-local: //p' "$unit" 2>/dev/null | head -1)
  if [[ -n "$p" ]]; then printf '%s\n' "$p"; return 0; fi
  for p in $(seq 51878 51899); do
    if [[ -z "$(ss -Hlun "sport = :$p" 2>/dev/null)" ]]; then printf '%s\n' "$p"; return 0; fi
  done
  die "no free local port for the relay"
}

mode_file() { printf '%s/mode' "$RUN_DIR"; }
current_mode() { cat "$(mode_file)" 2>/dev/null || echo direct; }
set_mode() { install -d -m 0755 -o root -g root "$RUN_DIR"; printf '%s\n' "$1" > "$(mode_file)"; date +%s > "$RUN_DIR/mode_since"; }
# A joined computer's first peer in its config is always the hub; direct links to other computers come and go.
hub_key() { sed -n 's/^PublicKey = //p' "$DEST" | head -1; }
peer_endpoint() { wg set "$IFACE" peer "$(hub_key)" endpoint "$1"; }
direct_endpoint() { sed -n 's/^Endpoint = //p' "$DEST" | head -1; }

# Is what's in force what the plugin last wrote? Compares only; apply does the validating.
config_settled() { [[ ! -f "$1" || -L "$1" ]] || cmp -s "$1" "$2"; }

conf_address() { sed -n 's/^Address = \([0-9.]*\)\/[0-9]*$/\1/p' "$1" | head -1; }
live_address() { { ip -4 -o addr show dev "$IFACE" 2>/dev/null || true; } | awk '{print $4}' | cut -d/ -f1 | head -1; }

# Live status lives in a root-owned directory. Root never writes into the user's directory:
# anything it created there could be swapped for a symlink before chown followed it.
write_live() {
  local user="$1" tmp
  install -d -m 0755 -o root -g root "$RUN_DIR"
  tmp=$(mktemp "$RUN_DIR/.live.XXXXXX")
  {
    printf '{"updated": %s, "handshakes": {' "$(date +%s)"
    wg show "$IFACE" latest-handshakes 2>/dev/null | awk 'BEGIN{n=0} {printf "%s\"%s\": %s", (n++?", ":""), $1, $2}'
    # Where each peer was last heard from, so a hub can introduce its computers to each other.
    printf '}, "endpoints": {'
    wg show "$IFACE" endpoints 2>/dev/null | awk 'BEGIN{n=0} $2 ~ /^[0-9.]+:[0-9]+$/ {printf "%s\"%s\": \"%s\"", (n++?", ":""), $1, $2}'
    # Peers this machine talks to directly (a joined computer's links to other joined computers).
    printf '}, "direct": ['
    wg show "$IFACE" allowed-ips 2>/dev/null | awk 'BEGIN{n=0} $2 ~ /^10\.77\.0\.[0-9]+\/32$/ {printf "%s\"%s\"", (n++?", ":""), $1}'
    printf '], "port": %s, "mode": "%s"}\n' "$(wg show "$IFACE" listen-port 2>/dev/null || echo 0)" "$(current_mode)"
  } > "$tmp"
  chown "root:$(id -gn "$user")" "$tmp"; chmod 640 "$tmp"
  mv -fT "$tmp" "$RUN_DIR/live.json"
}

# ---------------------------------------------------------------- direct links between joined computers
#
# The hub introduces its computers to each other: who they are (public key, tunnel address) and where it last
# heard from them. Each computer then tries the others directly. Both sides send, which opens most home
# routers from the inside. A link that answers carries that computer's traffic; one that does not is left
# empty and the traffic keeps going through the hub, exactly as before. WireGuard's own keys decide who is
# who: a wrong address here can only fail to connect.

validate_mesh() {  # file own-address
  local f="$1" own="$2" line n=0 last key ep o port
  local -a eps=() octets=()
  local -A keys=() ips=()
  [[ "$(stat -c %s "$f")" -le 16384 ]] || die "mesh list too large"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([A-Za-z0-9+/]{43}=)\ 10\.77\.0\.([0-9]{1,3})\ ([0-9.:,]{9,65})$ ]] || die "bad mesh line"
    key="${BASH_REMATCH[1]}"; last="${BASH_REMATCH[2]}"
    IFS=, read -r -a eps <<<"${BASH_REMATCH[3]}"
    [[ "$last" != 0?* ]] && (( 10#$last >= 2 && 10#$last <= 254 )) || die "mesh peer outside the tunnel"
    [[ "10.77.0.$last" != "$own" ]] || die "mesh peer is this machine"
    (( ${#eps[@]} >= 1 && ${#eps[@]} <= 3 )) || die "bad mesh endpoint"
    for ep in "${eps[@]}"; do
      [[ "$ep" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{2,5})$ ]] || die "bad mesh endpoint"
      octets=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"); port="${BASH_REMATCH[5]}"
      for o in "${octets[@]}"; do (( 10#$o <= 255 )) || die "bad mesh endpoint"; done
      (( 10#$port >= 1 && 10#$port <= 65535 )) || die "bad mesh endpoint"
    done
    [[ -z "${keys[$key]:-}" && -z "${ips[$last]:-}" ]] || die "mesh peer listed twice"
    keys[$key]=1; ips[$last]=1; n=$((n+1))
  done < "$f"
  (( n <= 64 )) || die "mesh list too long"
}

mesh_apply() {  # data-dir user
  local src="$1/mesh.conf" user="$2" staged hub own key ip ep id turn rx_was quiet now dump line hs rx cur allowed alive
  local -a eps=()
  local -A want_ip=() want_ep=()
  ip link show "$IFACE" &>/dev/null || return 0
  hub=$(sed -n 's/^PublicKey = //p' "$DEST" | head -1)
  own=$(sed -n 's/^Address = \([0-9.]*\).*/\1/p' "$DEST" | head -1)
  [[ -n "$hub" && -n "$own" ]] || return 0
  if [[ -e "$src" ]]; then
    install -d -m 0755 /etc/wings
    if staged=$(stage_file "$src" "$user" /etc/wings); then
      if (validate_mesh "$staged" "$own"); then
        while read -r key ip ep; do [[ "$key" == "$hub" ]] || { want_ip[$key]=$ip; want_ep[$key]=$ep; }; done < "$staged"
      else
        echo "wings-root: direct links not applied" >&2
      fi
      rm -f "$staged"
    fi
  fi
  install -d -m 0700 -o root -g root "$RUN_DIR/mesh"
  while read -r key; do
    [[ "$key" == "$hub" || -n "${want_ip[$key]:-}" ]] || wg set "$IFACE" peer "$key" remove
  done < <(wg show "$IFACE" peers)
  now=$(date +%s)
  dump=$(wg show "$IFACE" dump | tail -n +2)
  for key in "${!want_ip[@]}"; do
    id=$(printf '%s' "$key" | sha256sum | cut -c1-24)
    IFS=, read -r -a eps <<<"${want_ep[$key]}"
    line=$(awk -v k="$key" '$1 == k' <<<"$dump")
    if [[ -z "$line" ]]; then
      wg set "$IFACE" peer "$key" endpoint "${eps[0]}" persistent-keepalive 4 allowed-ips ""
      printf '0 0 0\n' > "$RUN_DIR/mesh/$id"
      continue
    fi
    read -r _ _ cur allowed hs rx _ <<<"$line"
    read -r rx_was quiet turn < "$RUN_DIR/mesh/$id" 2>/dev/null || { rx_was=0; quiet=0; turn=0; }
    [[ "$turn" =~ ^[0-9]+$ ]] || turn=0
    if [[ "$rx" != "$rx_was" ]]; then quiet=0; else quiet=$((quiet+1)); fi
    alive=no
    # Answering now: a handshake both sides completed lately, and still hearing from it. It sends every 4 s and
    # this runs every 5 s, so two silent passes in a row mean the link is gone: back to the hub within ~10 s.
    if (( hs > 0 && now - hs < 150 && quiet < 2 )); then alive=yes; fi
    if [[ $alive == yes ]]; then
      [[ "$allowed" == "${want_ip[$key]}/32" ]] || wg set "$IFACE" peer "$key" allowed-ips "${want_ip[$key]}/32"
    else
      [[ "$allowed" == "(none)" ]] || wg set "$IFACE" peer "$key" allowed-ips ""
      # Quiet for a while: take the next place it might be.
      if (( quiet >= 4 )); then
        turn=$(( (turn + 1) % ${#eps[@]} ))
        wg set "$IFACE" peer "$key" endpoint "${eps[$turn]}"; quiet=0
      fi
    fi
    printf '%s %s %s\n' "$rx" "$quiet" "$turn" > "$RUN_DIR/mesh/$id"
  done
}

# WireGuard's own tools and the firewall tool, from this system's package manager, if they're missing.
ensure_tools() {
  command -v wg &>/dev/null && command -v wg-quick &>/dev/null && command -v nft &>/dev/null && return 0
  if command -v apt-get &>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends wireguard-tools nftables >/dev/null 2>&1 || true
  elif command -v dnf &>/dev/null; then dnf install -y -q wireguard-tools nftables >/dev/null 2>&1 || true
  elif command -v pacman &>/dev/null; then pacman -S --noconfirm --needed wireguard-tools nftables >/dev/null 2>&1 || true
  fi
}

# Sourced by the test suite: define functions only.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi

verb="${1:-}"; shift || true
case "$verb" in
  install)
    [[ $EUID -eq 0 ]] || die "install must run as root"
    user="${1:-}"; conf="${2:-}"; port="${3:-}"; dash="${4:-}"; role="${5:-hub}"; wst="${6:-}"
    need_user "$user"; need_port "$port"; need_port "$dash"; need_role "$role"
    ensure_tools
    command -v wg &>/dev/null && command -v wg-quick &>/dev/null || die "wireguard-tools missing (wg, wg-quick)"
    command -v nft &>/dev/null || die "nftables missing (nft)"
    validate_conf "$conf" "$user" "$role"
    install -d -m 0755 /usr/local/libexec
    if [[ -n "$wst" ]]; then install_wstunnel "$wst" "$user"; fi
    install -D -m 0755 -o root -g root "$0" "$INSTALLED"
    write_tls_proxy /usr/local/libexec/wings-tls-proxy; chmod 0755 /usr/local/libexec/wings-tls-proxy
    write_dns_server /usr/local/libexec/wings-dns; chmod 0755 /usr/local/libexec/wings-dns
    # One at a time: a machine without one of these must still restart the other.
    systemctl try-restart wings-address.service >/dev/null 2>&1 || true
    systemctl try-restart wings-dns.service >/dev/null 2>&1 || true
    install -d -m 0755 /etc/wings
    printf 'WINGS_USER=%s\nWINGS_CONF=%s\nWINGS_PORT=%s\nWINGS_DASH_PORT=%s\nWINGS_ROLE=%s\n' "$user" "$conf" "$port" "$dash" "$role" > "$ENV_FILE"
    chmod 0644 "$ENV_FILE"
    rm -f /etc/wings/wings.env
    dir=$(dirname "$conf")
    cat > "$UNIT_DIR/wings-sync.path" <<EOF
[Unit]
Description=Wings: apply hub config changes written by the Hermes Wings plugin

[Path]
PathChanged=$conf
PathChanged=$dir/refresh
PathChanged=$dir/relay.conf
PathChanged=$dir/address.conf
PathChanged=$dir/tls/leaf.crt
PathChanged=$dir/hub-name.conf
PathChanged=$dir/peers.conf
PathChanged=$dir/net.conf
Unit=wings-sync.service

[Install]
WantedBy=multi-user.target
EOF
    cat > "$UNIT_DIR/wings-sync.service" <<EOF
[Unit]
Description=Wings: validate and apply the hub config (wings0)
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=60
ExecStart=$INSTALLED apply

[Install]
WantedBy=multi-user.target
EOF
    cat > "$UNIT_DIR/wings-watch.service" <<EOF
[Unit]
Description=Wings: switch a member between direct UDP and the HTTPS relay

[Service]
Type=oneshot
ExecStart=$INSTALLED watch
EOF
    cat > "$UNIT_DIR/wings-watch.timer" <<EOF
[Unit]
Description=Wings: watch the connection to the hub

[Timer]
OnBootSec=20
OnUnitActiveSec=5
AccuracySec=1s
AccuracySec=5

[Install]
WantedBy=timers.target
EOF
    chmod 0644 "$UNIT_DIR/wings-sync.path" "$UNIT_DIR/wings-sync.service" "$UNIT_DIR/wings-watch.service" "$UNIT_DIR/wings-watch.timer"
    systemctl daemon-reload
    systemctl enable --now wings-watch.timer >/dev/null 2>&1
    systemctl enable --now wings-sync.path >/dev/null 2>&1
    systemctl enable wings-sync.service >/dev/null 2>&1
    systemctl start wings-sync.service
    echo "installed" ;;

  apply)
    [[ $EUID -eq 0 ]] || die "apply must run as root"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    need_user "$WINGS_USER"; need_port "$WINGS_PORT"; need_port "$WINGS_DASH_PORT"
    role="${WINGS_ROLE:-hub}"; need_role "$role"
    install -d -m 0700 -o root -g root "$(dirname "$DEST")"
    keychange=0
    if [[ -e "$DEST" ]] && ! cmp -s <(sed -n 's/^PrivateKey = //p' "$DEST") <(sed -n 's/^PrivateKey = //p' "$WINGS_CONF"); then keychange=1; fi
    staged=$(stage_conf "$WINGS_CONF" "$WINGS_USER" "$(dirname "$DEST")" "$role")
    chown root:root "$staged"; chmod 600 "$staged"
    mv -fT "$staged" "$DEST"
    addr=$(conf_address "$DEST")
    old=$(live_address)
    # A new key has no handshake yet. Give direct UDP its turn before the watcher reaches for the relay.
    if [[ $keychange -eq 1 && $role == member ]]; then
      if [[ "$(current_mode)" == relay ]] && ip link show "$IFACE" &>/dev/null; then set_mode direct; else set_mode "$(current_mode)"; fi
    fi
    if [[ -n "$old" && "$old" != "$addr" ]]; then
      # Role or address changed: syncconf can't move an address, and the old address's rules must go.
      fw_remove "$old" "$WINGS_PORT" "$WINGS_DASH_PORT"
      wg-quick down "$DEST" >/dev/null 2>&1 || ip link del "$IFACE" 2>/dev/null || true
    fi
    if ip link show "$IFACE" &>/dev/null; then
      # A joined computer also holds direct links to other computers, which are not in its config file.
      # Adding leaves those alone (a full sync would cut them every time); the direct-link pass that
      # follows removes any peer that is neither the hub nor on the list.
      if [[ $role == member && "$(current_mode)" == relay ]]; then
        wg addconf "$IFACE" <(wg-quick strip "$IFACE" | sed "s/^Endpoint = .*/Endpoint = 127.0.0.1:$(relay_local_port)/")
      elif [[ $role == member ]]; then
        wg addconf "$IFACE" <(wg-quick strip "$IFACE")
      else
        wg syncconf "$IFACE" <(wg-quick strip "$IFACE")
      fi
    else
      set_mode direct
      wg-quick up "$IFACE" >/dev/null
    fi
    mtu=$(sed -n 's/^MTU = //p' "$DEST" | head -1)
    if [[ -n "$mtu" ]]; then ip link set dev "$IFACE" mtu "$mtu"; fi
    relay_apply "$role" "$WINGS_PORT" "$(dirname "$WINGS_CONF")/relay.conf" "$WINGS_USER"
    NAMES_ADDR=""; NAMES_NAME=""; NAMES_HUB_ADDR=""; NAMES_HUB_NAME=""; NAMES_HPORT=""; NAMES_PPORT=""; NAMES_DNS=""
    if [[ $role == hub ]]; then dns_apply "$(dirname "$WINGS_CONF")/names.conf" "$WINGS_USER"; fi
    names_apply "$(dirname "$WINGS_CONF")/address.conf" "$WINGS_USER"
    hub_name_apply "$(dirname "$WINGS_CONF")" "$WINGS_USER"
    if [[ $role == member ]]; then mesh_apply "$(dirname "$WINGS_CONF")" "$WINGS_USER"; fi
    peers_apply "$(dirname "$WINGS_CONF")" "$WINGS_USER"
    hosts_set /etc/hosts "$NAMES_ADDR" "$NAMES_NAME" "$NAMES_HUB_ADDR" "$NAMES_HUB_NAME" "${PEER_PAIRS[@]}"
    WINGS_ISOLATE=no
    netconf="$(dirname "$WINGS_CONF")/net.conf"
    if [[ $role == hub && -e "$netconf" ]]; then
      stn=$(stage_file "$netconf" "$WINGS_USER" /etc/wings) || exit 2
      if [[ "$(cat "$stn")" == "Isolate = yes" ]]; then WINGS_ISOLATE=yes; fi
      rm -f "$stn"
    fi
    fw_apply "$role" "$addr" "$WINGS_PORT" "$WINGS_DASH_PORT"
    write_live "$WINGS_USER"
    # systemd can miss a change made while this was running, so look once more before leaving.
    if ! config_settled "$WINGS_CONF" "$DEST" && [[ "${WINGS_APPLY_DEPTH:-0}" -lt 3 ]]; then
      WINGS_APPLY_DEPTH=$(( ${WINGS_APPLY_DEPTH:-0} + 1 )) exec "$0" apply
    fi ;;

  watch)
    # Direct UDP first. If the hub goes quiet, try the HTTPS relay, and keep alternating until a
    # handshake lands. A new network starts from direct again.
    [[ $EUID -eq 0 ]] || die "watch must run as root"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    if ! config_settled "$WINGS_CONF" "$DEST" || ! names_settled "$(dirname "$WINGS_CONF")"; then systemctl start --no-block wings-sync.service; fi
    if [[ "${WINGS_ROLE:-hub}" != member ]]; then write_live "$WINGS_USER"; exit 0; fi
    ip link show "$IFACE" &>/dev/null || exit 0
    relay="$(dirname "$WINGS_CONF")/relay.conf"
    now=$(date +%s)
    gw=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="via") print $(i+1)}' || true)
    if [[ "$gw" != "$(cat "$RUN_DIR/gateway" 2>/dev/null || true)" ]]; then
      install -d -m 0755 -o root -g root "$RUN_DIR"
      printf '%s\n' "$gw" > "$RUN_DIR/gateway"
      if [[ "$(current_mode)" == relay ]]; then peer_endpoint "$(direct_endpoint)"; fi
      set_mode direct
    elif [[ -e "$relay" ]]; then
      t=$(wg show "$IFACE" latest-handshakes | awk -v k="$(hub_key)" '$1 == k {print $2}')
      since=$(cat "$RUN_DIR/mode_since" 2>/dev/null || echo 0)
      if (( now - ${t:-0} > 150 && now - since >= 25 )); then
        if [[ "$(current_mode)" == direct ]]; then
          peer_endpoint "127.0.0.1:$(relay_local_port)"; set_mode relay
        else
          peer_endpoint "$(direct_endpoint)"; set_mode direct
        fi
      fi
    elif [[ "$(current_mode)" == relay ]]; then
      peer_endpoint "$(direct_endpoint)"; set_mode direct
    fi
    mesh_apply "$(dirname "$WINGS_CONF")" "$WINGS_USER"
    write_live "$WINGS_USER" ;;

  uninstall)
    [[ $EUID -eq 0 ]] || die "uninstall must run as root"
    # shellcheck disable=SC1090
    if [[ -f "$ENV_FILE" ]]; then source "$ENV_FILE"; fi
    systemctl disable --now wings-sync.path wings-sync.service wings-watch.timer wings-relay.service wings-address.socket wings-address.service wings-dns.service >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/wings-address.socket" "$UNIT_DIR/wings-address.service" /usr/local/libexec/wings-tls-proxy
    rm -f "$UNIT_DIR/wings-dns.service" /usr/local/libexec/wings-dns /etc/wings/names
    rm -f /etc/wings/tls/cert /etc/wings/tls/key /etc/wings/tls/tried /etc/wings/peers.tried; rmdir /etc/wings/tls 2>/dev/null || true
    ca_remove
    rm -f /etc/pki/ca-trust/source/anchors/wings-hub-ca.crt /usr/local/share/ca-certificates/wings-hub-ca.crt; ca_refresh
    hosts_set /etc/hosts
    if id wings-net &>/dev/null; then userdel wings-net 2>/dev/null || true; fi
    relayport=$(sed -n 's/^# wings-port: //p' "$UNIT_DIR/wings-relay.service" 2>/dev/null || true)
    if [[ -n "$relayport" ]]; then relay_fw remove "$relayport"; fi
    rm -f "$UNIT_DIR/wings-watch.service" "$UNIT_DIR/wings-watch.timer" "$UNIT_DIR/wings-relay.service" "$RELAY_SECRET" "$WST_BIN"
    addr=$(live_address)
    if ip link show "$IFACE" &>/dev/null; then wg-quick down "$IFACE" >/dev/null 2>&1 || true; fi
    if [[ -n "${WINGS_PORT:-}" ]]; then fw_remove "${addr:-$HUB_IP}" "$WINGS_PORT" "$WINGS_DASH_PORT"; fi
    rm -f "$UNIT_DIR/wings-sync.path" "$UNIT_DIR/wings-sync.service" "$DEST" "$ENV_FILE" /etc/wings/wings.env "$INSTALLED"
    rm -f "$RUN_DIR/live.json" "$RUN_DIR/mode" "$RUN_DIR/mode_since" "$RUN_DIR/gateway"; rmdir "$RUN_DIR" 2>/dev/null || true
    rm -f /etc/wings/peers.tried /etc/wings/names
    rmdir /etc/wings 2>/dev/null || true
    systemctl daemon-reload
    echo "uninstalled" ;;

  *) die "usage: wings-root install <user> <conf> <port> <dash_port> [hub|member] [wstunnel.tar.gz] | apply | watch | uninstall" ;;
esac
