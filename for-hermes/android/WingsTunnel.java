/*
 * WingsTunnel: an embedded WireGuard tunnel for an Android app, made for Wings pairing codes.
 *
 * MIT License, same as the rest of Wings. It uses the WireGuard tunnel library
 * (com.wireguard.android:tunnel, Apache License 2.0).
 */
package net.wings.tunnel;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;

import com.wireguard.android.backend.GoBackend;
import com.wireguard.android.backend.Statistics;
import com.wireguard.android.backend.Tunnel;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Interface;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * One WireGuard tunnel inside your app, brought up from a scanned Wings pairing code.
 *
 * <p>A Wings pairing code is a plain WireGuard config (the same text the WireGuard app scans). This class
 * checks it, keeps it out of logs, and runs it with WireGuard's own userspace backend ({@link GoBackend}),
 * so the user does not need the separate WireGuard app.</p>
 *
 * <p>Typical use:</p>
 * <pre>
 * WingsTunnel.Pairing p = WingsTunnel.parse(scannedText);      // throws PairingException if it is not a code
 * Intent consent = WingsTunnel.consentIntent(activity);         // null once the user has said yes
 * if (consent != null) launcher.launch(consent);                // then call connect() after RESULT_OK
 * WingsTunnel.get(context).connect(p);                          // on a background thread
 * </pre>
 *
 * <p>Threading: {@link #connect(Pairing)} and {@link #disconnect()} block while WireGuard starts or stops.
 * Call them off the main thread. The other methods are quick.</p>
 *
 * <p>Privacy: nothing in this class writes to the Android log, and {@link Pairing#toString()} never
 * includes the private key. Where the pairing text is stored is up to your app; the helpers here write
 * it only to a file you name, readable by your app alone.</p>
 */
public final class WingsTunnel {

    /** The largest pairing text accepted. A real Wings code is about 300 bytes. */
    public static final int MAX_PAIRING_BYTES = 4096;

    /** The name Android shows for this tunnel. WireGuard allows 1 to 15 letters, digits and {@code _=+.-}. */
    public static final String TUNNEL_NAME = "wings";

    private static final Pattern WINGS_NAME = Pattern.compile("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?\\.wings$");
    private static final String META_PREFIX = "# wings:";

    private static volatile WingsTunnel instance;

    private final GoBackend backend;
    private final Handle handle = new Handle();
    private volatile StateListener listener;
    private volatile Pairing current;

    private WingsTunnel(Context appContext) {
        backend = new GoBackend(appContext);
    }

    /**
     * The tunnel for this app process. WireGuard's backend must exist once per process, so always get it here.
     *
     * @param context any context; only its application context is kept
     * @return the shared instance
     */
    public static WingsTunnel get(Context context) {
        WingsTunnel t = instance;
        if (t == null) {
            synchronized (WingsTunnel.class) {
                t = instance;
                if (t == null) {
                    t = new WingsTunnel(context.getApplicationContext());
                    instance = t;
                }
            }
        }
        return t;
    }

    // ------------------------------------------------------------------ states

    /** Where the tunnel is. */
    public enum State {
        /** Not running. */
        DOWN,
        /** Running. Traffic for the wing net goes through it. It does not mean the other end answered: see {@link Stats}. */
        UP
    }

    /** Told when the tunnel goes up or down, including when Android stops it (for example another VPN started). */
    public interface StateListener {
        /**
         * Called on a WireGuard thread, not the main thread.
         *
         * @param state the new state
         */
        void onStateChanged(State state);
    }

    /**
     * Sets or clears the listener for state changes. Only one listener is kept.
     *
     * @param l the listener, or null to stop listening
     */
    public void setStateListener(StateListener l) {
        listener = l;
    }

    // ------------------------------------------------------------------ pairing

    /** Thrown when scanned text is not a usable Wings pairing code. Its message is safe to show to the user. */
    public static final class PairingException extends Exception {
        PairingException(String message) {
            super(message);
        }
    }

    /**
     * A checked Wings pairing code. Holds the private key, so treat it like a password: do not log it,
     * share it or keep it longer than needed.
     */
    public static final class Pairing {
        private final String text;
        private final Config config;
        private final Map<String, String> meta;

        private Pairing(String text, Config config, Map<String, String> meta) {
            this.text = text;
            this.config = config;
            this.meta = Collections.unmodifiableMap(meta);
        }

        /**
         * The pairing text exactly as scanned, for saving. It contains the private key.
         *
         * @return the WireGuard config text
         */
        public String text() {
            return text;
        }

        /**
         * This device's address inside the wing net, such as {@code 10.77.0.2}.
         *
         * @return the first interface address without its prefix length
         */
        public String deviceAddress() {
            InetNetwork n = config.getInterface().getAddresses().iterator().next();
            return n.getAddress().getHostAddress();
        }

        /**
         * The hub's address inside the wing net, such as {@code 10.77.0.1}. Taken from the DNS
         * line when the code has one (the hub is the DNS server), otherwise the first address of
         * the wing net range, which is where Wings always puts it.
         *
         * @return the address as text
         */
        public String hubAddress() {
            for (InetAddress a : config.getInterface().getDnsServers()) {
                return a.getHostAddress();
            }
            InetNetwork n = config.getPeers().get(0).getAllowedIps().iterator().next();
            byte[] b = n.getAddress().getAddress();
            int ip = ((b[0] & 0xff) << 24) | ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
            int mask = n.getMask() == 0 ? 0 : -1 << (32 - n.getMask());
            int first = (ip & mask) + 1;
            return ((first >>> 24) & 0xff) + "." + ((first >>> 16) & 0xff) + "." + ((first >>> 8) & 0xff) + "." + (first & 0xff);
        }

        /**
         * Whether the code points the phone at the hub for name lookups while the tunnel is up.
         * When true, {@code .wings} names work on the phone. When false, the code left DNS alone because the
         * hub's name server was not answering when the code was made.
         *
         * @return true if the code has a DNS line
         */
        public boolean usesWingsDns() {
            return !config.getInterface().getDnsServers().isEmpty();
        }

        /**
         * Where WireGuard sends its packets: the hub's public address and UDP port.
         *
         * @return {@code host:port}
         */
        public String endpoint() {
            return config.getPeers().get(0).getEndpoint().map(InetEndpoint::toString).orElse("");
        }

        /**
         * The address ranges the tunnel carries, such as {@code 10.77.0.0/24}. Everything else stays on the
         * phone's normal connection.
         *
         * @return the peer's allowed IPs as text
         */
        public List<String> routes() {
            List<String> out = new ArrayList<>();
            for (InetNetwork n : config.getPeers().get(0).getAllowedIps()) out.add(n.toString());
            return out;
        }

        /**
         * Extra {@code key=value} pairs from an optional {@code # wings:} comment line. The current Wings plugin
         * does not write this line, so today this map is empty. It is read so a later plugin version can add the
         * Hermes address (key {@code url}) and a display name (key {@code name}) without breaking older apps.
         *
         * @return an unmodifiable map, possibly empty
         */
        public Map<String, String> metadata() {
            return meta;
        }

        /**
         * The Hermes address to add as an instance, if the code carries one ({@code url} in {@link #metadata()}).
         * Today's codes do not, so ask the user for the hub's {@code .wings} name and use
         * {@link #hermesUrlFor(String)}.
         *
         * @return an {@code http://...wings} address, or null
         */
        public String hermesUrl() {
            String u = meta.get("url");
            if (u == null || !u.startsWith("http://")) return null;
            String host = u.substring("http://".length());
            int slash = host.indexOf('/');
            if (slash >= 0) host = host.substring(0, slash);
            return WINGS_NAME.matcher(host).matches() ? "http://" + host : null;
        }

        /**
         * The parsed WireGuard config, for apps that need more than the getters above. It holds the private key.
         *
         * @return the config
         */
        public Config config() {
            return config;
        }

        /**
         * A summary without secrets, safe for logs and debugging.
         *
         * @return device address, hub address and endpoint
         */
        @Override
        public String toString() {
            return "Pairing{device=" + deviceAddress() + ", hub=" + hubAddress() + ", endpoint=" + endpoint() + "}";
        }
    }

    /**
     * Checks scanned text and turns it into a {@link Pairing}. Accepts only a WireGuard config with one
     * interface address, a private key, and exactly one peer that has a public key, an endpoint and allowed
     * IPs. Refuses a config that would send all traffic through the tunnel ({@code 0.0.0.0/0} or {@code ::/0}),
     * because a Wings code never does that and a stranger's code could.
     *
     * @param text the scanned text
     * @return the checked pairing
     * @throws PairingException with a short, user-safe reason
     */
    public static Pairing parse(String text) throws PairingException {
        if (text == null || text.isEmpty()) throw new PairingException("The code is empty.");
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_PAIRING_BYTES) throw new PairingException("That code is too long to be a Wings code.");
        if (!firstSection(text).equals("[Interface]")) throw new PairingException("That is not a Wings code.");
        Config cfg;
        try {
            cfg = Config.parse(new ByteArrayInputStream(bytes));
        } catch (Exception e) {
            // The library's message can quote the bad line, which may hold a key. Keep it out.
            throw new PairingException("That is not a valid WireGuard code.");
        }
        Interface iface = cfg.getInterface();
        if (iface.getAddresses().isEmpty()) throw new PairingException("The code has no device address.");
        if (cfg.getPeers().size() != 1) throw new PairingException("A Wings code has exactly one peer.");
        Peer peer = cfg.getPeers().get(0);
        if (!peer.getEndpoint().isPresent()) throw new PairingException("The code does not say where to connect.");
        if (peer.getAllowedIps().isEmpty()) throw new PairingException("The code has no address range.");
        for (InetNetwork n : peer.getAllowedIps()) {
            if (n.getMask() == 0) throw new PairingException("This code would send all your traffic through it. Wings codes never do.");
            if (!(n.getAddress() instanceof Inet4Address)) throw new PairingException("Wings codes use IPv4 ranges only.");
        }
        return new Pairing(text, cfg, readMeta(text));
    }

    private static String firstSection(String text) {
        for (String line : text.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) return t;
        }
        return "";
    }

    private static Map<String, String> readMeta(String text) {
        Map<String, String> m = new HashMap<>();
        for (String line : text.split("\n")) {
            String t = line.trim();
            if (!t.startsWith(META_PREFIX)) continue;
            for (String tok : t.substring(META_PREFIX.length()).trim().split("\\s+")) {
                int eq = tok.indexOf('=');
                if (eq > 0) m.put(tok.substring(0, eq), tok.substring(eq + 1));
            }
        }
        return m;
    }

    /**
     * Builds the Hermes address for a machine on the wing net from its {@code .wings} name.
     *
     * @param wingsName a name like {@code home.wings}; {@code http://} in front is allowed
     * @return {@code http://home.wings}, or null if the name is not a valid {@code .wings} name
     */
    public static String hermesUrlFor(String wingsName) {
        if (wingsName == null) return null;
        String n = wingsName.trim().toLowerCase(java.util.Locale.ROOT);
        if (n.startsWith("http://")) n = n.substring(7);
        while (n.endsWith("/")) n = n.substring(0, n.length() - 1);
        return WINGS_NAME.matcher(n).matches() ? "http://" + n : null;
    }

    // ------------------------------------------------------------------ consent

    /**
     * Android asks the user once before any app can run a VPN. Launch this Intent with
     * {@code startActivityForResult} or an {@code ActivityResultLauncher}, and connect only after
     * {@code RESULT_OK}.
     *
     * @param context an Activity is best, so the dialog appears over it
     * @return the consent Intent, or null if the user already agreed and you can connect now
     */
    public static Intent consentIntent(Context context) {
        return VpnService.prepare(context);
    }

    // ------------------------------------------------------------------ connect

    /**
     * Brings the tunnel up with this pairing, replacing any pairing that was up. Blocks; call it off the
     * main thread. Needs consent first (see {@link #consentIntent(Context)}). Starting this tunnel stops any
     * other VPN on the phone, because Android runs one at a time.
     *
     * @param pairing a pairing from {@link #parse(String)}
     * @return the state after the call
     * @throws Exception if WireGuard could not start, for example without consent; the message holds no key
     */
    public State connect(Pairing pairing) throws Exception {
        if (pairing == null) throw new IllegalArgumentException("pairing is null");
        current = pairing;
        return map(backend.setState(handle, Tunnel.State.UP, pairing.config()));
    }

    /**
     * Takes the tunnel down. Blocks; call it off the main thread. Safe to call when it is already down.
     *
     * @return the state after the call, normally {@link State#DOWN}
     */
    public State disconnect() {
        try {
            return map(backend.setState(handle, Tunnel.State.DOWN, null));
        } catch (Exception e) {
            return state();
        }
    }

    /**
     * The tunnel's state now.
     *
     * @return {@link State#UP} or {@link State#DOWN}
     */
    public State state() {
        try {
            return map(backend.getState(handle));
        } catch (Exception e) {
            return State.DOWN;
        }
    }

    /**
     * The pairing last passed to {@link #connect(Pairing)} in this process, or null.
     *
     * @return the pairing, or null
     */
    public Pairing currentPairing() {
        return current;
    }

    // ------------------------------------------------------------------ statistics

    /** A snapshot of traffic through the tunnel. */
    public static final class Stats {
        /** Bytes received from the hub since the tunnel came up. */
        public final long rxBytes;
        /** Bytes sent to the hub since the tunnel came up. */
        public final long txBytes;
        /** When the last WireGuard handshake finished, in milliseconds since 1970, or 0 if none yet. */
        public final long lastHandshakeMillis;

        Stats(long rx, long tx, long hs) {
            rxBytes = rx;
            txBytes = tx;
            lastHandshakeMillis = hs;
        }

        /**
         * Whether the hub answered recently. WireGuard renews its handshake about every two
         * minutes while traffic flows, and the code's keepalive (25 s) keeps traffic flowing, so a handshake
         * in the last three minutes means the link works. This is the same rule the Wings plugin uses.
         *
         * @param nowMillis the current time, from {@link System#currentTimeMillis()}
         * @return true if the last handshake is under 180 seconds old
         */
        public boolean isReachable(long nowMillis) {
            return lastHandshakeMillis > 0 && nowMillis - lastHandshakeMillis < 180_000L;
        }
    }

    /**
     * Traffic and handshake numbers for the tunnel.
     *
     * @return a snapshot, or null if the tunnel is down
     */
    public Stats stats() {
        if (state() != State.UP) return null;
        try {
            Statistics st = backend.getStatistics(handle);
            long rx = 0, tx = 0, hs = 0;
            for (Key k : st.peers()) {
                Statistics.PeerStats ps = st.peer(k);
                if (ps == null) continue;
                rx += ps.rxBytes();
                tx += ps.txBytes();
                hs = Math.max(hs, ps.latestHandshakeEpochMillis());
            }
            return new Stats(rx, tx, hs);
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ storage helpers

    /**
     * A suggested place to keep the pairing: inside the app's no-backup folder, so it stays on this phone and
     * is left out of cloud backups and device transfers. You can store it anywhere else private to your app.
     *
     * @param context any context
     * @return {@code <no-backup dir>/wings/pairing.conf} (the folder is not created here)
     */
    public static File defaultPairingFile(Context context) {
        return new File(new File(context.getNoBackupFilesDir(), "wings"), "pairing.conf");
    }

    /**
     * Writes the pairing text to a file, replacing it in one step, readable only by this app.
     *
     * @param pairing the pairing to save
     * @param file where to save it; should be inside your app's private storage
     * @throws IOException if writing fails
     */
    public static void savePairing(Pairing pairing, File file) throws IOException {
        File dir = file.getAbsoluteFile().getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) throw new IOException("cannot create folder");
        File tmp = new File(dir, file.getName() + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(pairing.text().getBytes(StandardCharsets.UTF_8));
            out.getFD().sync();
        }
        tmp.setReadable(false, false);
        tmp.setReadable(true, true);
        tmp.setWritable(false, false);
        tmp.setWritable(true, true);
        if (!tmp.renameTo(file)) {
            tmp.delete();
            throw new IOException("cannot save pairing");
        }
    }

    /**
     * Reads and checks a saved pairing.
     *
     * @param file the file written by {@link #savePairing(Pairing, File)}
     * @return the pairing, or null if there is none or it no longer checks out
     */
    public static Pairing loadPairing(File file) {
        if (!file.isFile() || file.length() > MAX_PAIRING_BYTES) return null;
        try {
            return parse(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Deletes a saved pairing. Call this when the user removes the instance. It does not stop the tunnel;
     * call {@link #disconnect()} for that.
     *
     * @param file the saved pairing
     * @return true if the file is gone afterwards
     */
    public static boolean forgetPairing(File file) {
        return file.delete() || !file.exists();
    }

    /**
     * Lets the "Always-on VPN" switch in Android's settings start this tunnel. When the system starts the
     * VPN by itself (after a reboot, for example), this reads the saved pairing from the file and connects.
     * Call it once, early, for example in {@code Application.onCreate}.
     *
     * @param context any context
     * @param pairingFile where your app keeps the pairing
     */
    public static void enableAlwaysOn(Context context, File pairingFile) {
        final WingsTunnel t = get(context);
        GoBackend.setAlwaysOnCallback(() -> {
            Pairing p = loadPairing(pairingFile);
            if (p == null) return;
            new Thread(() -> {
                try {
                    t.connect(p);
                } catch (Exception ignored) {
                    // Nothing to tell: the app shows the state when it next opens.
                }
            }, "wings-always-on").start();
        });
    }

    // ------------------------------------------------------------------ internals

    private static State map(Tunnel.State s) {
        return s == Tunnel.State.UP ? State.UP : State.DOWN;
    }

    private final class Handle implements Tunnel {
        @Override
        public String getName() {
            return TUNNEL_NAME;
        }

        @Override
        public void onStateChange(Tunnel.State newState) {
            StateListener l = listener;
            if (l != null) l.onStateChanged(map(newState));
        }
    }
}
