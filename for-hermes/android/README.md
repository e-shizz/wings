# A WireGuard tunnel inside the Hermes app

This folder is for whoever maintains the Hermes Android app (`ai.nousresearch.hermes.mobile`). We cannot see the
app's source, so this is a drop-in piece plus notes, not a patch.

- [`WingsTunnel.java`](WingsTunnel.java): one Java class with no UI. It checks a scanned Wings code and runs a
  WireGuard tunnel inside your app. Java, so it can be called from Kotlin, or from a React Native or Flutter
  native module.
- [`sample/`](sample/): the smallest app that uses it: scan, Android's VPN prompt, connect, show the state.

## Why

Wings is a Hermes plugin that puts a person's own machines on one private network, using plain WireGuard.
WireGuard is an open VPN protocol: each device has a key, and only devices with known keys can talk.
*VPN* here just means an encrypted tunnel between your devices.

Today a phone joins like this: install the separate WireGuard app, scan a code there, switch the tunnel on, then
come back to the Hermes app and type the machine's address. That is two apps and some typing. With the tunnel
inside Hermes it becomes one scan.

## What the user would see

1. In the Hermes app: **Add instance**, then **Scan Wings code**.
2. They point the camera at the code their hub shows (the Wings tab, or `hermes wings add phone`).
   The *hub* is the one of their machines that is on the most; Wings calls it the *hub* in code.
3. The first time only, Android asks: "Hermes wants to set up a VPN connection". They tap OK.
4. The tunnel comes up. The app adds the instance and signs in (see [Signing in](#signing-in-once-the-tunnel-is-up)).
5. The instance is listed like any other server.

## The pairing code, exactly

The code is a QR code holding a plain WireGuard config, the same text the WireGuard app scans. Nothing else is in
it. The plugin builds it in `device_conf()` in `plugin/wings/core.py`. This is its exact shape (the private key is
the only secret; the values are examples):

```
[Interface]
PrivateKey = <this phone's private key, base64>
Address = 10.77.0.2/32
DNS = 10.77.0.1
MTU = 1280

[Peer]
PublicKey = <the hub's public key, base64>
Endpoint = <its public address or name>:51877
AllowedIPs = 10.77.0.0/24
PersistentKeepalive = 25
```

What each line means:

- `Address`: the phone's own address on the wing net (the private network Wings makes). Always one address, `/32`.
- `DNS`: the hub, which answers `.wings` names. This line is **only there when that machine's name
  server answered** while the code was made. Without it, the phone keeps its normal DNS and `.wings` names do not
  work on it.
- `MTU = 1280`: a packet size that fits every path Wings uses.
- `Endpoint`: where to send packets. Port 51877 is the default; the user can change it.
- `AllowedIPs = 10.77.0.0/24`: the tunnel only carries the wing net's own addresses. Everything else stays on the
  phone's normal connection.
- `PersistentKeepalive = 25`: a tiny packet every 25 seconds so home routers keep the path open.

The hub is always `10.77.0.1`. The code does **not** carry its `.wings` name, so today the app has to
ask the user for it (for example `home.wings`). `WingsTunnel.hermesUrlFor("home.wings")` checks it and returns
`http://home.wings`. If you would like the name inside the code, tell us: we would add a comment line such as
`# wings: url=http://home.wings`. WireGuard ignores comment lines, and `WingsTunnel` already reads them
(`Pairing.metadata()`, `Pairing.hermesUrl()`), so older apps would not break. The current plugin does not write it.

One more thing to know: once the phone first connects, the hub by default forgets the private key in the code,
and the code cannot be shown again. To pair again, the user removes the phone in Wings and adds it again.

## Adding it to the app

**1. Gradle.** The version our proof of concept uses:

```groovy
dependencies {
    implementation "com.wireguard.android:tunnel:1.0.20260102"
    coreLibraryDesugaring "com.android.tools:desugar_jdk_libs:2.1.5"   // our build enables this; we did not try without it
}
android {
    compileOptions { coreLibraryDesugaringEnabled true }
}
```

The library is on Maven Central. It needs Android 7.0 (API 24) or newer. It ships WireGuard's native code for
four CPU types, about 3.5 MB each before compression, so the app grows by that much per CPU type you ship.

To scan, our sample uses `com.journeyapps:zxing-android-embedded:4.3.0`. If Hermes already scans QR codes, use
that instead: `WingsTunnel` only needs the text. The beta of the Hermes app we looked at did not ask for the camera
permission, so scanning would add it.

**2. Manifest.** You need the network, and the camera if you scan:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.CAMERA" />
```

The VPN service itself (`com.wireguard.android.backend.GoBackend$VpnService`, protected by
`android.permission.BIND_VPN_SERVICE`) is declared in the library's own manifest, so Android's manifest merger adds
it for you. We checked this in the built sample.

**3. Copy `WingsTunnel.java`** into your source tree (package `net.wings.tunnel`; rename it if you like).

**4. Wire it up.** In Kotlin:

```kotlin
val tunnel = WingsTunnel.get(context)
val file = WingsTunnel.defaultPairingFile(context)

// After a scan
val pairing = try { WingsTunnel.parse(scannedText) } catch (e: WingsTunnel.PairingException) {
    showError(e.message); return
}
WingsTunnel.savePairing(pairing, file)

// Android's one-time VPN prompt
val consent = WingsTunnel.consentIntent(activity)
if (consent != null) vpnLauncher.launch(consent)   // connect after RESULT_OK
else connect(pairing)

fun connect(p: WingsTunnel.Pairing) = scope.launch(Dispatchers.IO) {
    tunnel.connect(p)                              // blocks while WireGuard starts
    val url = p.hermesUrl() ?: WingsTunnel.hermesUrlFor(askUserForName())
    addInstance(url)                               // then sign in, below
}

// When the user removes the instance
scope.launch(Dispatchers.IO) { tunnel.disconnect(); WingsTunnel.forgetPairing(file) }
```

`tunnel.state()` says `UP` or `DOWN`. `tunnel.stats()` gives bytes in and out and the time of the last
handshake (the moment the two ends last proved their keys to each other); `stats.isReachable(now)` is true when
that was under three minutes ago, which is the rule Wings itself uses. `setStateListener` tells you when Android
stops the tunnel, for example because the user started another VPN.

**5. Where to connect and disconnect.** The simplest choice: connect when the user opens a Wings instance (or
when the app comes to the front with one selected) and disconnect when they remove it. Whether to leave the
tunnel up in the background is a product choice; see battery below.

## What `WingsTunnel` keeps safe

- It never writes to the Android log, and `Pairing.toString()` leaves out the private key.
- When a code fails to parse it does not repeat the library's error, which can quote the bad line.
- It refuses anything that is not a WireGuard config with one address, one peer, an endpoint and a route. It also
  refuses a code that would send **all** traffic through the tunnel (`0.0.0.0/0` or `::/0`). A Wings code never does,
  and a code from a stranger could.
- Where the pairing is stored is up to you. The helpers write only to a file you name, readable by the app alone.
  `defaultPairingFile()` puts it in the app's no-backup folder, so the key is left out of cloud backups.

## Signing in once the tunnel is up

This part already works with the stock Hermes app over the separate WireGuard app; we tested it on a real phone.

1. Add the instance as `http://<name>.wings`. Plain HTTP is on purpose: Android apps cannot trust Wings's private
   certificate, and the address only exists inside the encrypted tunnel.
2. Choose **Browser** as the sign-in method. The Wings plugin registers a Hermes sign-in provider called
   `wings-device` (shown as **Wings**).
3. On a `.wings` address, a phone on the wing net that opens `/login` goes straight to the Wings sign-in. The
   machine sees which tunnel address the request came from. WireGuard has already proved that address belongs to
   this phone, so the machine signs a short, one-time note naming it and sends the browser to
   `/auth/callback`. Hermes checks the note and starts a normal session.
4. The sign-in only works on a `.wings` address, so use the name, not `10.77.0.1`.

If the phone's browser is set to HTTPS only, it warns once per machine: the user chooses to continue. If the
browser stays open after sign-in, going back to the app is enough; it is already signed in.

## Honest limits

- **Android runs one VPN at a time.** Turning this tunnel on turns off any other VPN on the phone, and the other way
  round. You will see `DOWN` through the state listener when that happens.
- **Only the wing net goes through the tunnel**, because the code sets `AllowedIPs = 10.77.0.0/24`. Web browsing and
  other apps are untouched. One exception: when the code has a `DNS` line, the phone sends **all** its name lookups
  to the hub while the tunnel is up, so `.wings` names work. That machine answers `.wings` itself and
  passes everything else on; it does not store them. With Android's Private DNS set to a specific provider, `.wings`
  names will not resolve.
- **Phones always go through the hub.** Computers on a wing net can link to each other directly;
  phones cannot. So if that machine is off, the phone cannot reach anything.
- **No HTTPS fallback on the phone.** Wings computers fall back to carrying WireGuard over HTTPS on port 443 (with
  a tool called wstunnel) when a network blocks UDP. This tunnel, like the WireGuard app, does not. On such a
  network the phone needs cellular.
- **Battery.** The keepalive sends a small packet every 25 seconds while the tunnel is up. That is cheap but not
  free. Leaving it up all day costs some battery; connecting only while Hermes is in use costs almost none.
- **Always-on VPN.** Android's Settings, VPN, Hermes, **Always-on VPN** can keep the tunnel up across reboots.
  Call `WingsTunnel.enableAlwaysOn(context, file)` once in `Application.onCreate` so the system can start it from
  the saved code. We have not tested this. We also expect that **Block connections without VPN** would cut the
  phone off from everything outside the wing net, since only the wing net goes through this tunnel; we have not
  tested that either, so check before you suggest it to users.

## Licences

- `WingsTunnel.java` and the sample: MIT, like the rest of Wings. Take it, rename it, change it.
- `com.wireguard.android:tunnel`: Apache License 2.0, according to its published Maven metadata. It contains
  WireGuard's Go implementation as native libraries. "WireGuard" is a registered trademark; check the WireGuard
  project's trademark notes before naming a feature after it.
- `zxing-android-embedded` (sample only): Apache License 2.0.

## iPhone (not built or tested by us)

The same idea should work on iOS with **WireGuardKit**, the library inside the official WireGuard iOS app
(`wireguard-apple`). It runs as a *Network Extension* (a packet tunnel provider): a separate target inside the app.
That needs Apple's Network Extensions entitlement with `packet-tunnel-provider` on both the app and the
extension, and a shared app group so the extension can read the saved code. The pairing format above is the same.
We have not written or run any of this.

## What we tested, and what we did not

Tested on Nov 11 2026:

- The sample in `sample/` with this `WingsTunnel.java` **compiled and packaged into a debug APK** with
  `./gradlew --offline assembleDebug` (Gradle 9.8.2, Android Gradle Plugin 9.5.0, compile SDK 36). The merged
  manifest got the VPN service from the library.
- `WingsTunnel.parse()` on the JVM, against configs made by the plugin's own `device_conf()`, with and without the
  `DNS` line: both parsed, with the right phone address, hub address and route. It rejected a
  full-traffic code, a web link, a code with no endpoint, a code with two peers and a code with a broken key.
- Earlier (Nov 8), on a real Android phone with the separate WireGuard app: the stock Hermes app signed in at
  `http://<name>.wings` and its live connection worked. That is the path this class would replace.

This class was taken from a private proof-of-concept app that uses the same WireGuard library the same way. It
builds, but we have no record of running it on a phone, so we count it as untested.

Not tested:

- The sample app and this exact class have **not been installed on a phone**. Connecting, the VPN prompt, the
  state listener and the statistics were only compiled, not run.
- `enableAlwaysOn`, Always-on VPN and **Block connections without VPN**.
- Anything inside the Hermes app itself, which we cannot build.
- The iOS note above.

## Building the sample

The sample has no Gradle wrapper and no binaries. Open `sample/` in Android Studio, or run `gradle wrapper` in
`sample/` first and then `./gradlew assembleDebug`. Android Studio writes `local.properties` (where your Android
SDK is) for you. The build copies `../WingsTunnel.java` into `app/build/` before compiling, so there is one copy of
the class.
