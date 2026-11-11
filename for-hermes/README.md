# For Hermes's developers

Small things we ran into in Hermes while building Wings, written up so they are easy to act on. None of this is
part of the Wings plugin (that is all in [`plugin/`](../plugin/)), and Wings works on stock Hermes v0.23 without
any of it. Take what is useful.

Tested on Hermes Agent v0.23.0 and v0.23.1, Hermes Desktop on Fedora 45 (Electron 44.9.3, Node 24.22.0).

## 1. Desktop on Linux does not trust the system's certificate authorities in its main process

**What you see:** in Settings, Gateways, Saved connections, **Test** says "Connection test failed … the live
WebSocket (/api/ws) connection failed" for a gateway that works, when its certificate chains to a private or
company authority the system trusts. Chat, sessions and sign-in are fine, because the renderer reads the system
list.

**Cause:** `apps/desktop/electron/system-ca.ts` merges the OS store into the main process's trust on Windows and
macOS only. Its comment says Linux's default trust already covers the system store. Under Electron it does not:
Node starts from its bundled list.

**Fix, tested:** add `'linux'` to `SYSTEM_CA_PLATFORMS`. With that one word the test says "Reachable".
Patch and write-up: [`linux-system-ca.patch`](linux-system-ca.patch).

## 2. Bots on other machines never show their picture

**What you see:** in the Bots bar, a bot that lives on another saved connection shows the default tile even
when it has an avatar on its own machine.

**Server half, tested on two machines:** `GET /api/profiles` leaves out `has_avatar`, so the roster across
connections cannot know. [`remote-avatars.patch`](remote-avatars.patch) adds it in
`hermes_cli/web_routers/profiles.py` (true when `<profile>/assets/avatar.{png,jpg,webp}` exists).

**Desktop half, not built:** `pullServerAvatars` in `apps/desktop/src/plugins/hermes-bots/profile-ops.ts` asks
with `host.request`, which goes to the active gateway rather than the bot's own connection. It needs to ask the
row's own source.

## 3. Desktop will not start when a systemd user-environment variable contains a backslash

**What you see:** "couldn't start", with `service_identity_unverified` in the log.

**Cause:** `environment_pairs` in `hermes_cli/gateway_runtime_service_identity.py` gives up on the whole
environment when one value has a backslash. Desktops that import the session environment into systemd (KDE
does) with something like `FZF_DEFAULT_OPTS` set will hit it. Only the variables the unit uses need to parse.

**Workaround:** `systemctl --user unset-environment <NAME>` for the offending variable.

## 4. A plugin cannot add a saved connection

A plugin that sets up a network (Wings, a Tailscale helper) can list `host.connections()` but has to send the
user through Settings to add one: four steps by hand. A `host.addConnection({ label, url, authMode })` behind a
confirmation the user sees would make it one click, and would keep plugins away from the private bridge.

## 5. A square-window option on Linux

`titleBarStyle: 'hidden'` windows get the engine's rounded corners and shadow, and a theme cannot change that.
`hasShadow: false, roundedCorners: false` on the main window, behind a setting, lets square themes be square.

## 6. The Hermes app could carry the tunnel itself

**What you see:** to reach a Hermes at home, a phone needs the separate WireGuard app. The user installs it, scans
the Wings code there, switches the tunnel on, comes back to the Hermes app and types `http://<name>.wings`. Two
apps and some typing.

**Idea, compiled but not run on a phone:** put the WireGuard tunnel inside the Hermes app, so **Add instance**,
**Scan Wings code** and Android's one-time VPN prompt are the whole flow. [`android/`](android/) has a drop-in Java
class (`WingsTunnel.java`) built on WireGuard's own Android library, a minimal sample app, the exact format of the
code, and notes on sign-in, limits and licences. The sample builds into an APK; it has not been installed on a
phone yet.

## 7. A Hermes Cloud instance as the hub

A hosted instance that is always on would be the ideal hub: nothing to keep running at home and nothing to
forward on a router. **It cannot be one today.** We checked from inside one instance (Hermes Agent v0.23.0,
Nov 11 2026):

- the agent runs as an ordinary user (`uid=10000(hermes)`) with no `sudo` and no capabilities;
- the container's first process is `s6-svscan`, so there is no systemd;
- the kernel has WireGuard loaded, but `ip link add ... type wireguard` is refused;
- `/dev/net/tun` exists and belongs to root only.

A Wings hub needs admin rights once (to create the WireGuard interface and install a small root helper with
systemd units) and one UDP port that the user's devices can reach. The same limits stop an instance joining a
wing net as an ordinary member.

Two ways it could work:

- **On the platform side:** give an instance `NET_ADMIN` and one forwarded UDP port. Then Wings runs as it is.
- **On our side:** a mode where a member runs WireGuard entirely in user space, with no interface and no
  privileges, and reaches out to a hub elsewhere. That would put a cloud agent on the user's wing net as a
  member (not as the hub, because nothing can dial in). We have not built it.
