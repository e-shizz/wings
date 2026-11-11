# Setting up Wings: instructions for an agent

Wings makes a private WireGuard network between the user's own devices: every computer that runs Hermes, and their phone. Two devices are enough. Follow these steps. Tell the user what you're doing in plain words.

**Rules you must follow:**

- Never ask for, store or type the user's admin password. Stop and let them type it.
- Invite codes and QR codes hold keys. Don't print them into chat, read them, or send them over messaging. Use `--code-file`, and tell the user where the file is.
- Don't restart the gateway unless the user says yes, because it interrupts running work.
- If a command says `Stopped:`, tell the user why and don't try to get around it. It stopped to protect something they already have.

## 1. Find out what they have: ask, don't assume

One computer becomes the **hub**: the phone and any other computers connect to it. Which computer that should be depends on what the user has, so ask. One question at a time, and wait for each answer. Skip a question the user has already answered.

1. **"Which devices do you want on your wing net?"** Computers that run Hermes, and phones. Two devices are enough.
2. **"Do you have a machine that stays on all the time? A home server, a mini PC, an old PC in a corner, or a VPS?"**
   - **Yes:** that machine is the hub. This is the best setup: phones and new devices connect through the hub, so a hub that is always on means everything is always reachable.
   - **No:** the hub is the computer they most want to reach, usually their main computer. Say plainly what that means: the wing net works whenever that computer is on. While it is off or asleep, the phone cannot reach anything.
   - **Not sure:** ask which computer is switched on the most, and use that one.
3. **"Do you want to reach it when you are away from home?"** If yes and the hub is at home, one UDP port (51877) has to be forwarded on their router to the hub. `hermes wings router open` can ask the router to do it, only with the user's yes. A VPS needs nothing forwarded.

Then say back what you understood in one sentence ("Your home server will be the hub; your laptop and your phone will join it") and get a yes before you install anything.

Run `hermes wings status` on each machine. If Wings is already set up, go to step 4.

## 2. On the hub

```bash
hermes plugins install e-shizz/wings#plugin --enable
hermes wings setup
```

If the install says the dependency step was skipped, that is because you are not a person at a terminal. Wings needs one Python package (`qrcode`, to draw pairing codes). Tell the user, and with their yes run the install again with `--yes-deps --force` added.

The user approves the admin prompt. If it says "nobody is here to approve it", you are not at a terminal: tell the user what the helper will do (the command prints the list), and with their yes run it again with `-y`. The same goes for `join` below. If it says devices will dial a private address, find the public IP with the user and run `hermes wings endpoint <ip>:51877`.

If the hub is a cloud machine, tell them to allow UDP 51877 and TCP 443 in their cloud firewall. Only they can do that, unless you already have access to their provider.

Ask before running `hermes gateway restart`.

## 3. Invite a computer

Skip this step if the user only wants their phone connected. On the hub:

```bash
hermes wings invite laptop --code-file ~/wings-invite.txt
```

This waits for the join, so run it in the background. The invite works once, for 10 minutes. Move the file to the other machine in the way the user prefers, then delete it.

On the other machine, after installing the plugin:

```bash
hermes wings join --code-file ~/wings-invite.txt
```

The user approves the admin prompt. If it fails, retry with `hermes wings join --resume`.

## 4. Check it

```bash
hermes wings doctor
```

Then give the user the link that `join` printed. Their devices sign in through Wings.

## 5. A phone

Adding a device is for the user, so there's no agent tool for it. Ask them to run this in a terminal on the hub:

```bash
hermes wings add phone
```

They install the WireGuard app, tap +, and scan. Phones run one VPN at a time, so warn them it will replace any other tunnel while it's on. Then in the Hermes app they add the server `http://<hub name>.wings` with the **Browser** sign-in method.
