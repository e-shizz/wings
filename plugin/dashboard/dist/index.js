/* Wings tab: shown in the Hermes dashboard, the Webapp and the Hermes app. Plain JS on the host's React. MIT. */
(() => {
  const SDK = window.__HERMES_PLUGIN_SDK__;
  const { React } = SDK;
  const { useState, useEffect, useCallback, useRef } = SDK.hooks;
  const { Card, CardHeader, CardTitle, CardContent, Badge, Button, Input } = SDK.components;
  const h = React.createElement;
  const API = "/api/plugins/wings";
  const LABEL = { phone: "mobile", tablet: "tablet", computer: "computer", server: "server", device: "device" };

  const ago = (ts) => {
    if (!ts) return "not connected yet";
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 180) return "online";
    if (s < 5400) return `seen ${Math.round(s / 60)} min ago`;
    if (s < 172800) return `seen ${Math.round(s / 3600)} h ago`;
    return `seen ${Math.round(s / 86400)} days ago`;
  };
  const say = (e) => String((e && (e.detail || e.message)) || e);

  const Muted = (props, ...kids) => h("p", { className: "text-sm text-muted-foreground", ...props }, ...kids);
  const Dot = ({ on }) => h("span", {
    "aria-hidden": true,
    style: { display: "inline-block", width: 9, height: 9, borderRadius: 9, flex: "none",
      background: on ? "#3fb950" : "transparent", border: on ? "none" : "1.5px solid #7d8590" } });

  function Steps({ items }) {
    return h("ol", { className: "space-y-1 text-sm", style: { paddingLeft: 18, listStyle: "decimal" } },
      items.map((t, i) => h("li", { key: i }, t)));
  }

  /* ---------------------------------------------------------------- add a phone */
  function PhoneCode({ name, onDone }) {
    const [qr, setQr] = useState(null);
    const [where, setWhere] = useState("");
    const [err, setErr] = useState(null);
    useEffect(() => {
      SDK.fetchJSON(`${API}/devices/${encodeURIComponent(name)}/qr.json`)
        .then((d) => { setQr(d.qr); setWhere(d.app_address || ""); }).catch((e) => setErr(say(e)));
    }, [name]);
    return h("div", { className: "space-y-4" },
      h(Steps, { items: [
        "On the phone, install the WireGuard app (free, from the app store).",
        "Tap +, then Scan from QR code, and scan this.",
        "Turn the new tunnel on. Your phone is in your wing net.",
        ...(where ? [`In the Hermes app, add a server: ${where} and sign in with your Hermes login.`] : []),
      ] }),
      err ? h("p", { className: "text-sm text-destructive" }, `Couldn't make the code: ${err}`)
        : qr ? h("div", { style: { display: "flex", justifyContent: "center" } },
            h("img", { src: qr, alt: `Wings code for ${name}`,
              style: { width: "min(300px, 100%)", aspectRatio: "1", background: "#fff", padding: 12, borderRadius: 10 } }))
        : Muted(null, "Making the code…"),
      Muted(null, "This code is the phone's key. Show it only to the phone, then close it."),
      h("div", { style: { display: "flex", justifyContent: "flex-end" } }, h(Button, { onClick: onDone }, "Done")));
  }

  /* ---------------------------------------------------------------- add a computer */
  function ComputerCode({ invite, onDone, joined }) {
    const [copied, setCopied] = useState(false);
    const copy = () => {
      try {
        navigator.clipboard.writeText(invite.command).then(() => setCopied(true));
      } catch (e) { setCopied(false); }
    };
    return h("div", { className: "space-y-4" },
      joined
        ? h("p", { className: "text-sm", style: { fontWeight: 600 } }, `✓ ${invite.name} joined your wing net.`)
        : h(React.Fragment, null,
            h(Steps, { items: [
              `On ${invite.name}, open a terminal where Hermes is installed.`,
              "Paste this and press enter. It installs Wings and joins, asking for the admin password once.",
            ] }),
            h("pre", { className: "rounded-md border p-3 text-xs",
              style: { whiteSpace: "pre-wrap", wordBreak: "break-all", userSelect: "all" } }, invite.command),
            h("div", { style: { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" } },
              h(Button, { variant: "outline", onClick: copy }, copied ? "Copied" : "Copy"),
              Muted({ style: { margin: 0 } }, `Works once, for ${invite.minutes} minutes. Waiting for ${invite.name}…`))),
      h("div", { style: { display: "flex", justifyContent: "flex-end" } }, h(Button, { onClick: onDone }, "Done")));
  }

  function AddCard({ onChanged, devices }) {
    const [mode, setMode] = useState(null);
    const [name, setName] = useState("");
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState(null);
    const [phone, setPhone] = useState(null);
    const [invite, setInvite] = useState(null);
    const start = (m) => { setMode(m); setErr(null); setName(m === "phone" ? "My phone" : "My computer"); };
    const reset = () => { setMode(null); setPhone(null); setInvite(null); setErr(null); onChanged(); };
    const go = () => {
      const n = name.trim();
      if (!n) return;
      setBusy(true);
      setErr(null);
      const req = mode === "phone"
        ? SDK.fetchJSON(`${API}/devices`, { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: n, kind: "phone" }) }).then((d) => setPhone(d.name))
        : SDK.fetchJSON(`${API}/invite`, { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: n }) }).then((d) => setInvite(d));
      req.then(onChanged).catch((e) => setErr(say(e))).finally(() => setBusy(false));
    };
    const joined = invite && devices.some((d) => d.name === invite.name && d.last_handshake);

    let body;
    if (phone) body = h(PhoneCode, { name: phone, onDone: reset });
    else if (invite) body = h(ComputerCode, { invite, joined, onDone: reset });
    else if (mode) body = h("div", { className: "space-y-3" },
      Muted(null, mode === "phone" ? "What should we call this phone?" : "What should we call this computer?"),
      h("div", { style: { display: "flex", gap: 8, flexWrap: "wrap" } },
        h(Input, { value: name, autoFocus: true, onChange: (e) => setName(e.target.value),
          onKeyDown: (e) => { if (e.key === "Enter") go(); }, style: { flex: "1 1 180px" } }),
        h(Button, { onClick: go, disabled: busy || !name.trim() }, busy ? "One moment…" : "Next"),
        h(Button, { variant: "ghost", onClick: () => setMode(null) }, "Cancel")),
      err && h("p", { className: "text-sm text-destructive" }, err));
    else body = h("div", { style: { display: "grid", gap: 10, gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" } },
      h(Button, { onClick: () => start("phone"), style: { height: 56 } }, "📱  Add a phone"),
      h(Button, { variant: "outline", onClick: () => start("computer"), style: { height: 56 } }, "💻  Add a computer"));

    return h(Card, null,
      h(CardHeader, null, h(CardTitle, null, phone ? `Scan this with ${phone}` : invite ? `Add ${invite.name}` : "Add a machine")),
      h(CardContent, null, body));
  }

  /* ---------------------------------------------------------------- machines */
  function Machines({ st, onChanged }) {
    const hub = st.hub || {};
    const devices = st.devices || [];
    const [showing, setShowing] = useState(null);
    const remove = (d) => {
      if (!window.confirm(`Remove ${d.label || d.name}? Its key stops working right away.`)) return;
      SDK.fetchJSON(`${API}/devices/${encodeURIComponent(d.name)}`, { method: "DELETE" }).then(onChanged);
    };
    const row = (key, on, title, sub, right, extra) => h("div", { key,
      style: { display: "flex", alignItems: "center", gap: 12, padding: "12px 0", borderTop: "1px solid var(--border, rgba(125,133,144,.25))" } },
      h(Dot, { on }),
      h("div", { style: { flex: 1, minWidth: 0 } },
        h("div", { style: { fontWeight: 600 } }, title),
        h("div", { className: "text-xs text-muted-foreground" }, sub)),
      h("div", { className: "text-xs text-muted-foreground", style: { textAlign: "right" } }, right),
      extra);
    return h(Card, null,
      h(CardHeader, null, h(CardTitle, null, "Your machines")),
      h(CardContent, null,
        row("hub", st.interface_up, hub.label || hub.name || "this hub", "this machine · the hub", st.interface_up ? "online" : "not running"),
        devices.length === 0 && Muted({ style: { paddingTop: 8 } }, "Nothing else yet. Add your phone or another computer below."),
        devices.map((d) => row(d.name, d.online, d.label || LABEL[d.kind] || d.name,
          `${d.kind}${d.label && d.label !== d.name ? " · " + d.name : ""}`, ago(d.last_handshake),
          h("div", { style: { display: "flex", gap: 6 } },
            h(Button, { variant: "ghost", size: "sm", onClick: () => remove(d) }, "Remove")))),
        showing && h("div", { style: { paddingTop: 12 } }, h(PhoneCode, { name: showing, onDone: () => setShowing(null) }))));
  }

  /* ---------------------------------------------------------------- safety */
  function Safety() {
    const [s, setS] = useState(null);
    const [err, setErr] = useState(null);
    useEffect(() => { SDK.fetchJSON(`${API}/settings`).then(setS).catch((e) => setErr(say(e))); }, []);
    const set = (patch) => SDK.fetchJSON(`${API}/settings`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch) }).then(setS).catch((e) => setErr(say(e)));
    if (!s) return null;
    const line = (title, text, on, flip) => h("div", { key: title,
      style: { display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderTop: "1px solid var(--border, rgba(125,133,144,.25))" } },
      h("div", { style: { flex: 1 } }, h("div", { style: { fontWeight: 600 } }, title), h("div", { className: "text-xs text-muted-foreground" }, text)),
      h(Button, { variant: on ? "default" : "outline", size: "sm", onClick: flip, style: { minWidth: 64 } }, on ? "On" : "Off"));
    return h(Card, null,
      h(CardHeader, null, h(CardTitle, null, "Safety")),
      h(CardContent, null,
        line("Keep devices apart", "Devices reach only this hub, not each other.", s.isolate_devices,
          () => set({ isolate_devices: !s.isolate_devices })),
        line("Forget phone keys", "After a phone is paired, its key is wiped from here.", s.forget_phone_keys,
          () => set({ forget_phone_keys: !s.forget_phone_keys })),
        line("Work on blocked Wi-Fi", "When a network blocks WireGuard, tunnel it through HTTPS.", s.relay,
          () => set({ relay: !s.relay })),
        h("div", { style: { display: "flex", alignItems: "center", gap: 12, padding: "10px 0", borderTop: "1px solid var(--border, rgba(125,133,144,.25))" } },
          h("div", { style: { flex: 1 } }, h("div", { style: { fontWeight: 600 } }, "Invites last"),
            h("div", { className: "text-xs text-muted-foreground" }, "How long a new code works.")),
          h("div", { style: { display: "flex", gap: 4 } }, [5, 10, 30].map((m) =>
            h(Button, { key: m, size: "sm", variant: s.invite_minutes === m ? "default" : "outline",
              onClick: () => set({ invite_minutes: m }) }, `${m} min`)))),
        err && h("p", { className: "text-sm text-destructive" }, err)));
  }

  /* ---------------------------------------------------------------- page */
  function WingsPage() {
    const [st, setSt] = useState(null);
    const [err, setErr] = useState(null);
    const timer = useRef(null);
    const load = useCallback(() => {
      SDK.fetchJSON(`${API}/status`).then((s) => { setSt(s); setErr(null); }).catch((e) => setErr(say(e)));
    }, []);
    useEffect(() => {
      load();
      timer.current = setInterval(load, 4000);
      return () => clearInterval(timer.current);
    }, [load]);

    const head = h("div", { className: "space-y-1" },
      h("h1", { className: "text-2xl font-semibold" }, "🪽 Wings"),
      Muted(null, "Your phone, computers and VPS on one private network with your Hermes. No account, no third party."));

    if (!st && !err) return h("div", { className: "space-y-6", style: { maxWidth: 720 } }, head, Muted(null, "Loading…"));
    if (err && !st) return h("div", { className: "space-y-6", style: { maxWidth: 720 } }, head,
      h("p", { className: "text-sm text-destructive" }, err));

    let body;
    if (st.member) {
      const m = st.member;
      body = h(Card, null,
        h(CardHeader, null, h(CardTitle, null, `Part of ${m.hub_name}'s wing net`)),
        h(CardContent, { className: "space-y-2" },
          h("div", { style: { display: "flex", alignItems: "center", gap: 10 } }, h(Dot, { on: st.interface_up }),
            h("span", null, st.interface_up ? "Connected" : "Not connected")),
          Muted(null, "Machines are added on the hub. In a terminal, ", h("code", null, "hermes wings"),
            " opens any of your machines' Hermes; Wings signs you in.")));
    } else if (!st.initialized) {
      body = h(Card, null,
        h(CardHeader, null, h(CardTitle, null, "Set up Wings")),
        h(CardContent, { className: "space-y-3" },
          h(Steps, { items: [
            "On the computer your devices will connect to (any computer that runs Hermes), open a terminal.",
            "Run the line below. It asks for the admin password once.",
            "Come back here and add your phone and other computers.",
          ] }),
          h("pre", { className: "rounded-md border p-3 text-xs", style: { userSelect: "all" } }, "hermes wings setup")));
    } else {
      body = h(React.Fragment, null,
        h(Machines, { st, onChanged: load }),
        h(AddCard, { onChanged: load, devices: st.devices || [] }),
        h(Safety, null));
    }
    return h("div", { className: "space-y-6", style: { maxWidth: 720 } }, head, body);
  }

  window.__HERMES_PLUGINS__.register("wings", WingsPage);
})();
