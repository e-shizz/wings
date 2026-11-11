# 🪽 Wings

**Link every Hermes you own, and your phone, into one wing net.** A private network between your own devices: no account, no coordination server, no third party.

Every machine that is switched on can see every other, with its bots and its sessions. In Hermes Desktop they sit in the Bots and Sessions bars beside your own. In a terminal, `hermes wings` takes you into any of them. On your phone, they are in the Hermes app.

## What you need

**Two devices are enough: a computer that runs Hermes, and your phone.** Run `setup` on the computer, scan one code with the phone, and the phone talks to that computer alone. Nothing else is involved.

The computer you run `setup` on is called the **hub**: your phone, and any computers you add later, connect to it. Any Linux computer can be the hub: your only computer, a home server, an old PC or a VPS. If you have a machine that stays on all the time, make it the hub: that is the best setup, because phones and new devices connect through the hub. If you do not, use the computer you most want to reach; the wing net then works whenever that computer is on. Your devices have to be able to reach it:

- **A computer at home** (your desktop, a home server, an old PC, a Pi). On your home network it just works. To reach it from outside, one UDP port (51877) has to be forwarded on your router to it, the same as for any WireGuard tunnel into your home. If your router has UPnP switched on, `hermes wings router open` asks it to do that for you (one port, to this machine, undone with `hermes wings router close`). Wings never does this unless you run that command. This has only been tested against a pretend router so far.
- **A cloud machine (VPS).** Reachable from anywhere with nothing to forward. Allow **UDP 51877** and **TCP 443** in the provider's firewall.

### With more than two: what the hub does

Computers you add first reach each other through the hub, then link directly when their networks allow it. The hub is needed to add a device, for phones (a phone always connects to the hub), and for any pair of computers that cannot link directly.

Tested with the hub cut off for four minutes: two computers that had a direct link kept reaching each other, in both directions, the whole time. Machines without a direct link, and the hub itself, could not be reached. When it came back, everything returned by itself within 40 seconds. So while the hub is off, you cannot add a device, phones are cut off, and computers that cannot link directly lose each other. Computers already linked directly are not affected.

## Set it up

**On the computer that will be the hub:**

```bash
hermes plugins install e-shizz/wings#plugin --enable
hermes wings setup
hermes wings endpoint <public-ip>:51877     # if it found a private address and devices should reach it from outside
hermes gateway restart
```

In Hermes Desktop or the Webapp you can do this step with the **Turn on Wings** button on the Wings page. It runs the same setup, and your computer's own admin box still has to approve it.

**Add your phone:** open the **Wings** tab and press **Add a phone**, or run `hermes wings add phone` on the hub. Install the [WireGuard app](https://www.wireguard.com/install/), tap +, and scan the code. Then in the Hermes app, add the server `http://<hub name>.wings`, choose **Browser** as the sign-in method, and press Connect. That is a complete wing net: the phone and the hub.

The phone uses plain HTTP because Android apps can't trust a private certificate. It's still encrypted: that address exists only inside the WireGuard tunnel. If your phone's browser is set to HTTPS only, it warns once per machine during sign-in: choose to continue to the HTTP site. If the browser then stays on that page instead of returning to the Hermes app, go back to the app yourself; it is already signed in.

Every other computer on your wing net can be added to the app the same way (`http://<its name>.wings`). The app's Server filter then works as a machine picker.

**Add another computer:** on the hub, run

```bash
hermes wings invite laptop                  # prints a command for the other machine
```

On the other computer, install Hermes and the plugin, then paste the command it printed:

```bash
hermes wings join wings1:...
```

It asks for that computer's admin password once, then prints the link to open.

Or let your agent do it. Point it at [AGENTS.md](AGENTS.md). It stops whenever it needs you.

## Use it

**Hermes Desktop.** Open **Wings** in the sidebar. The page draws your wing net: the hub on top, a line down to every other machine. Point at a machine and its bots fold out; point at a bot and its latest sessions are there to open. A search box finds a machine or a bot. To have a machine's bots in Hermes's own **Bots** and **Sessions** bars, press **Add to Hermes** on it once and follow the four steps (Hermes's own Saved connections screen, with Wings signing you in).

**Terminal.** Run `hermes wings`. One screen lists your machines and their sessions. Pick a machine, then a session or **new session**, and the screen goes away: you are in normal Hermes, in the same terminal. On another machine, Ctrl-] brings you back.

**Phone.** In the Hermes app, your hub's bots and sessions are listed like any server's.

**Web.** Every machine has an address like `https://laptop.wings` that opens its Hermes in a browser on any of your computers. On a phone, use `http://laptop.wings`.

## How your machines connect

- **Through the hub first.** The moment a computer joins, every other device can reach it that way.
- **Then directly.** The hub tells your computers where it last heard from each other. Each one tries the others straight away: at home by their home addresses, across networks by both sides sending at once, which opens most home routers from the inside. A link that answers carries the traffic; a pair marked *direct link* on the Wings page is talking with nothing in between.
- **Back again when needed.** If a direct link goes quiet (a laptop changes network), traffic returns to the hub within about 15 seconds and goes direct again when it can.
- **Phones** use the stock WireGuard app, which cannot do this, so a phone always goes through the hub.

WireGuard's keys decide who is who throughout: a wrong address can only fail to connect.

## Signing in

Hermes won't open to another device without a sign-in, and Wings keeps that rule. It signs your devices in by what WireGuard already proved about them.

**Phones and browsers.** Hermes shows a **Sign in with Wings** option. The address it's on exists only inside the tunnel, so the machine knows exactly which of your devices connected. It writes a short signed note naming that device, and Hermes checks the note and starts a normal session.

**Your computers.** When a computer joins, the hub gives it a random wing net key, inside the tunnel. To open another machine's Hermes, your computer signs a short note with that key saying which machine it wants, when, and a one-time number. The other machine checks the signature, that the note names it, that it's under a minute old and that it hasn't seen it before. Then it starts a normal Hermes session.

- Wings signs your devices in with keys. It creates a Hermes password only if you ask for one (`hermes wings login --reset`), and keeps it in a file only you can read.
- **Every device you've added can open Hermes on every machine in your wing net.** That's the point, and it's also the risk: whoever has one of your devices unlocked, or a phone's QR code, can reach your Hermes. If you lose a device, press **Remove** in the Wings tab or run `hermes wings revoke <name>`. Its key stops working right away.
- If a Hermes already had a password login, it keeps working. Wings leaves it alone.
- `hermes wings trust off` makes a machine refuse wing net sign-in and end those sessions.

## Living with what you already have

Wings checks first, and stops without changing anything if it would collide.

| You already have | What happens |
|---|---|
| Another WireGuard network | Stays as it is. If it uses `10.77.0.0/24` or the same port, Wings stops and tells you. |
| Tailscale | Fine, different addresses. |
| A full VPN like Mullvad | Wings warns you: a kill switch may block it. Not tested with every VPN. |
| nginx or Caddy on 80 and 443 | Stays as it is. Wings uses 8443 and 8080, and your server isn't exposed to the tunnel. |
| A Hermes login | Kept. |
| Your own `webapp.public_url` | Left alone unless you pass `--force`. |

Only `10.77.0.0/24` goes through Wings. It doesn't touch a computer's default route or DNS. A phone uses the hub for DNS while its tunnel is on: see [below](#what-wings-does-to-your-machine).

**Phones run one VPN at a time.** That's an Android and iOS limit, so turning on Wings turns off your other tunnel. To keep both, add Wings to the tunnel you already have: `hermes wings add phone --public-key <that tunnel's public key>` prints the lines to add. This keeps the phone's key on the phone, though we haven't tested it on a real phone yet.

## Blocked networks

Some networks block WireGuard. A computer falls back by itself to carrying it over HTTPS on port 443, through wstunnel, and goes back to direct on the next network. The normal WireGuard app can't do this, so a phone on a blocked network needs cellular.

## Commands

| Command | What it does |
|---|---|
| `hermes wings` | Pick a machine and a session, then you're in Hermes |
| `hermes wings setup` | Make this computer the hub, with an HTTPS address for its Hermes |
| `hermes wings invite <name>` | Invite another Hermes machine. One use, 10 minutes |
| `hermes wings join <code>` | Join a hub. `--resume` retries |
| `hermes wings add <name>` | Add a phone by QR code. `--public-key` adds Wings to a tunnel the phone already has |
| `hermes wings qr <name>` | Show a device's pairing code again |
| `hermes wings name <device> <label>` | Give a device a display name |
| `hermes wings endpoint <host>:<port>` | The address devices dial (a public IP or a DNS name) |
| `hermes wings router open\|close` | On a hub at home: ask the router (UPnP) to forward UDP 51877, or undo it |
| `hermes wings status` | Who's connected |
| `hermes wings doctor` | Check everything, including that what should be blocked is |
| `hermes wings address <name>.wings` | Give this Hermes an HTTPS address |
| `hermes wings login` | Whether this Hermes also has a password login. `--reset` adds one, if you ever want it |
| `hermes wings safety` | Show or change safety options |
| `hermes wings relay on\|off` | The HTTPS fallback |
| `hermes wings trust on\|off` | Whether your devices sign in here through Wings |
| `hermes wings revoke <name>` | Remove a device right away |
| `hermes wings uninstall` | Remove everything Wings installed |

Hermes Desktop and the Webapp get a **Wings** page with devices and safety options, and the dashboard and the Hermes app get a tab. Hermes keeps a plugin's desktop page off until you turn it on, under Capabilities, Plugins.

## Safety options

| Option | Default | |
|---|---|---|
| `isolate_devices` | off | On: devices reach only the hub, not each other |
| `forget_phone_keys` | on | The hub drops a phone's key after it first connects |
| `relay` | on | The HTTPS fallback |
| `invite_minutes` | 10 | 5, 10 or 30 |

Always on:

- Hermes requires a signed-in session on these addresses. Wings provides it for your own devices.
- Tunnel addresses work only inside the tunnel.
- Devices can reach only the ports Wings uses, on the tunnel address.
- A hub never carries traffic out to the internet or its own network.

## What Wings does to your machine

Please read this before installing.

**Root, once per machine.** `setup` and `join` ask for your admin password to install a root helper, which you can read at [`root/wings-root.sh`](root/wings-root.sh). After that it doesn't ask again, except when an update changes the helper. It installs:

- `wireguard-tools` and `nftables` from your package manager, if they're missing
- `/usr/local/libexec/wings-root` and `wings-tls-proxy`
- `/usr/local/libexec/wings-wstunnel`
- systemd units named `wings-*`, which run in the background: the relay, a 5-second connection watcher (it also keeps direct links to your other computers), and the HTTPS proxy
- as your own user, with no admin rights: `wings-upkeep.timer`, which once a minute asks the hub who else is on the wing net
- `/etc/wings/` and `/etc/wireguard/wings0.conf`
- nftables table `inet wings`, and firewalld or ufw rules where those run
- a `wings-net` system user
- marked lines in `/etc/hosts`: this machine's `.wings` name, the hub's, and your other computers'
- on a hub, a small name server on the tunnel address, port 53, so phones can use `.wings` names

**Your phone's DNS.** Phones have no hosts file, so the code you scan points the phone at your hub for DNS while the tunnel is on. The hub answers `.wings` names itself and passes every other lookup to its own resolver, so your hub can see the names your phone looks up. It stores none of them. If the name server isn't answering when the code is made, the code leaves this out, and the phone keeps its normal DNS.

**A certificate authority, system-wide.** HTTPS addresses use a private CA that this machine trusts. It's limited to `.wings` names by a critical name constraint, so it can't vouch for any real website, and the helper refuses any CA that isn't limited this way. Joining a wing net also trusts the hub's CA, under the same check, and that machine then signs each joined computer's certificate (only for a computer's own `.wings` name) so your computers trust each other. Any computer on your wing net can ask for this; they are all yours and already hold the shared wing net key.

**Network calls.** The only third-party call is downloading [wstunnel](https://github.com/erebe/wstunnel) 11.1.0 from its official GitHub release, once per machine, checked against a pinned checksum. There's no telemetry, and nothing goes through us.

**Hermes settings it changes:** `webapp.enabled` and `webapp.public_url`. It won't restart your gateway unless you do.

**Stored secrets**, in `<HERMES_HOME>/plugin-data/wings/`, readable only by you:

- the WireGuard keys
- a phone's key, until it first connects
- the CA key
- the relay secret
- the wing net key, and a key that signs this machine's Wings sessions
- `hermes-login.txt`, only if you ran `hermes wings login --reset`

**Agents.** An agent can see status and remove devices. It can't add a device: pairing is for a person. QR codes and invites hold keys, so they're never returned to the agent or printed into logs. Admin prompts fail cleanly when nobody's there.

## Limits

- Hubs and computers need Linux. Other systems can connect as a phone would, using a WireGuard app.
- One of your Linux machines has to act as the hub, ideally the one that is on the most, and every device has to be able to reach it. It is needed to add a device, for phones, and for pairs of computers that cannot link directly. Computers link directly to each other when their networks allow it; some routers do not, and those pairs keep going through the hub. Phones always do.
- When a direct link breaks, requests to that computer can fail for about 10 to 15 seconds until traffic is back on the hub.
- There is no single command yet to turn a joined computer into the hub of its own wing net. Run `hermes wings uninstall`, move `<HERMES_HOME>/plugin-data/wings` aside, then run `hermes wings setup`.
- After the hub has been unreachable for a while, a computer may come back to it over the HTTPS path (slower) and stay on it until that computer's network changes, for example when it reconnects to Wi-Fi.
- Direct links are proven between two computers in one house (about 11 ms between them, where the round trip through a distant hub was about 80), and between a computer behind a home router and one on a public address. Two different home routers on different networks are built for but not yet tested.
- `.wings` names need a hub that can use port 53 on its tunnel address. If something else holds it, phones need the numeric address.
- A phone can't open HTTPS `.wings` addresses without installing the certificate, so it uses HTTP inside the tunnel. In a phone's browser, that turns off the microphone and the bot screen.
- With Android's Private DNS set to a specific provider, `.wings` names won't resolve on the phone.
- Hermes Cloud containers probably can't run it, because it needs root and a kernel interface. That's not confirmed.
- In Hermes Desktop's Saved connections, the **Test** button can say "Connection test failed" for a wing-net machine that works. That check runs in a part of the app that does not read the system's trusted certificates (Hermes v0.23.1). Saving, signing in and chatting are not affected.
- The machine you want to open has to be on, with Hermes running. Wings can reach a computer whose Hermes is stopped, but there's nothing there to answer.
- A device on the network can open Hermes on your other machines. Use `isolate_devices` if you don't want that: devices then reach only the hub.
- Android runs one VPN at a time, so another VPN on your phone goes off while Wings is on.

## Licence

MIT. wstunnel is BSD-3-Clause, by its authors. WireGuard is a registered trademark of Jason A. Donenfeld.

## Art

The bot portraits are original AI-generated images, made for Wings with GPT Image, in the style of ink engravings. A bot that has its own picture keeps it; one that has none gets a portrait so the page is never a row of blanks. They are based on figures from Greek myth, not on any game or company's characters.
