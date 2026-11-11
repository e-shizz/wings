// Wings for Hermes Desktop and the Webapp: set up the wing net and hand each machine to Hermes.
// After that Hermes's own switcher does the rest, so this page stays small and follows whichever theme is on.
import { Button, CopyButton, Input, ROUTES_AREA, SIDEBAR_NAV_AREA, Switch, THEMES_AREA, host, relativeTime } from '@hermes/plugin-sdk'
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

// Wings Paper: an optional theme. A paper reading surface with black ink, blue accents, square corners,
// no shadows, and a square blue frame around the window. Wings works the same without it.
const paper = {
  background: '#e7e3d9', foreground: '#12110e', card: '#dedacf', cardForeground: '#12110e', muted: '#d3cfc4',
  mutedForeground: '#4b4841', popover: '#e7e3d9', popoverForeground: '#12110e', primary: '#1d3fa3',
  primaryForeground: '#f4f2ea', secondary: '#d3cfc4', secondaryForeground: '#12110e', accent: '#c9d2e8',
  accentForeground: '#12110e', border: '#7d796f', input: '#7d796f', ring: '#1d3fa3', midground: '#1d3fa3',
  midgroundForeground: '#f4f2ea', composerRing: '#1d3fa3', destructive: '#8f2f2f', destructiveForeground: '#f6ecec',
  sidebarBackground: '#d9d5ca', sidebarBorder: '#7d796f', userBubble: '#d3cfc4', userBubbleBorder: '#7d796f'
}
const ink = {
  background: '#11100e', foreground: '#e2ded3', card: '#191815', cardForeground: '#e2ded3', muted: '#211f1c',
  mutedForeground: '#a19d92', popover: '#191815', popoverForeground: '#e2ded3', primary: '#7ea2f2',
  primaryForeground: '#0d0d0b', secondary: '#211f1c', secondaryForeground: '#e2ded3', accent: '#232c45',
  accentForeground: '#e2ded3', border: '#4a4740', input: '#4a4740', ring: '#7ea2f2', midground: '#7ea2f2',
  midgroundForeground: '#0d0d0b', composerRing: '#7ea2f2', destructive: '#c66a6a', destructiveForeground: '#fbeeee',
  sidebarBackground: '#0c0b0a', sidebarBorder: '#3a3832', userBubble: '#211f1c', userBubbleBorder: '#4a4740'
}
const WINGS_PAPER = {
  name: 'wings-paper',
  label: 'Wings Paper',
  description: 'Paper and black ink, blue accents, square, with a blue frame. Light and dark.',
  colors: paper,
  darkColors: ink,
  customCSS: `
    :root { --radius: 0px; }
    *, *::before, *::after { border-radius: 0 !important; box-shadow: none !important; }
    body::after { content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 2147483000;
      border: 5px solid; border-image: linear-gradient(135deg, #16307f, #2f5fd0 45%, #9dbcf5) 1; }
  `
}

const CSS = `
.wn { --lit: var(--ui-text-primary, currentColor); --dim: var(--ui-text-tertiary, currentColor); --cold: var(--ui-accent, currentColor);
  --line: var(--ui-stroke-secondary, color-mix(in srgb, currentColor 18%, transparent)); --wire: color-mix(in srgb, var(--cold) 70%, transparent);
  --wn-bg: var(--ui-bg-elevated, var(--popover, var(--background, Canvas))); height: 100%; overflow-y: auto; color: var(--lit); }
.wn-in { max-width: 1180px; margin: 0 auto; padding: clamp(20px, 4vh, 44px) clamp(18px, 4vw, 40px) 48px; display: flex; flex-direction: column; gap: 24px; }
.wn-title { font-size: 1.5rem; font-weight: 600; margin: 0 0 4px; }
.wn-eyebrow { font-size: .72rem; letter-spacing: .16em; text-transform: uppercase; color: var(--dim); }
.wn-note { color: var(--dim); font-size: .84rem; margin: 0; }
.wn-top { display: flex; align-items: flex-end; justify-content: space-between; gap: 12px 24px; flex-wrap: wrap; }
.wn-find { flex: 0 1 280px; }
.wn-web { position: relative; display: flex; flex-direction: column; gap: 44px; padding: 0 14px; }
.wn-lines { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; pointer-events: none; }
.wn-lines path { fill: none; stroke: var(--line); stroke-width: 1; stroke-dasharray: 3 4; }
.wn-lines path.on { stroke: var(--wire); stroke-dasharray: none; }
.wn-root { display: flex; justify-content: center; }
.wn-root > .wn-card { flex: 0 1 420px; }
.wn-tier { display: flex; flex-wrap: wrap; justify-content: center; gap: 44px 16px; }
.wn-tier > .wn-card { flex: 1 1 228px; max-width: 300px; min-width: 0; }
.wn-tier.phones > .wn-card { flex: 0 1 200px; }
.wn-card { position: relative; border: 1px solid var(--line); background: var(--wn-bg); display: flex; flex-direction: column; }
.wn-card.on { border-color: var(--wire); }
.wn-card.here { outline: 1px solid var(--wire); outline-offset: -3px; }
.wn-card.open { z-index: 5; }
.wn-mhead { display: flex; align-items: center; gap: 10px; width: 100%; min-height: 56px; padding: 8px 12px; background: none; border: 0; color: inherit; text-align: left; cursor: pointer; }
.wn-mhead:disabled, div.wn-mhead { cursor: default; }
.wn-card.on > button.wn-mhead:hover, .wn-card.open > .wn-mhead { background: color-mix(in srgb, var(--cold) 8%, transparent); }
.wn-dot { flex: none; width: 8px; height: 8px; border-radius: 50%; border: 1px solid var(--dim); }
.wn-dot.on { background: var(--cold); border-color: var(--cold); }
.wn-grow { flex: 1; min-width: 0; display: block; }
.wn-mname { display: block; font-weight: 600; letter-spacing: .02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.wn-card:not(.on) .wn-mname { color: var(--dim); }
.wn-sub { display: block; color: var(--dim); font-size: .76rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wn-stack { display: flex; flex: none; }
.wn-stack img { width: 26px; height: 26px; object-fit: cover; border: 1px solid var(--line); margin-left: -8px; background: var(--wn-bg); }
.wn-stack img:first-child { margin-left: 0; }
.wn-x { background: none; border: 0; color: var(--dim); cursor: pointer; font-size: .76rem; padding: 0; }
.wn-x:hover, .wn-x:focus-visible { color: var(--lit); }
.wn-mhead + .wn-x { position: absolute; right: 10px; top: 8px; opacity: 0; }
.wn-card:hover > .wn-x, .wn-mhead + .wn-x:focus-visible { opacity: 1; }
.wn-pop { position: absolute; top: calc(100% + 1px); left: -1px; width: min(392px, 92vw); border: 1px solid var(--wire); background: var(--wn-bg); padding: 10px 14px 12px; display: flex; flex-direction: column; gap: 10px; animation: wn-drop .18s ease-out; }
.wn-pop.right { left: auto; right: -1px; }
.wn-pop.mid { left: 50%; margin-left: calc(min(392px, 92vw) / -2); }
@keyframes wn-drop { from { opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .wn-pop { animation: none; } }
.wn-pophead { display: flex; align-items: center; gap: 12px; min-height: 24px; }
.wn-web.finding { gap: 12px; }
.wn-web.finding .wn-tier { flex-direction: column; flex-wrap: nowrap; gap: 12px; }
.wn-web.finding .wn-card { flex: none; max-width: none; }
.wn-card.inline .wn-pop { position: static; width: auto; margin: 0; border: 0; border-top: 1px solid var(--line); animation: none; }
.wn-bots { display: grid; grid-template-columns: repeat(auto-fill, minmax(78px, 1fr)); gap: 8px; }
.wn-card.inline .wn-bots { grid-template-columns: repeat(auto-fill, minmax(78px, 92px)); }
.wn-bot { background: none; border: 1px solid transparent; padding: 0 0 5px; color: inherit; cursor: pointer; text-align: left; display: flex; flex-direction: column; gap: 1px; min-width: 0; }
.wn-bot.sel, .wn-bot:focus-visible { border-color: var(--cold); outline: none; }
.wn-face { width: 100%; aspect-ratio: 1; object-fit: cover; display: block; border-bottom: 1px solid var(--line); }
.wn-botname { font-size: .82rem; font-weight: 500; padding: 4px 5px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wn-botmeta { font-size: .68rem; color: var(--dim); padding: 0 5px; }
.wn-sessions { display: flex; flex-direction: column; border-top: 1px solid var(--line); padding-top: 8px; }
.wn-sessions .wn-eyebrow { padding: 0 2px 4px; }
.wn-session { display: flex; justify-content: space-between; gap: 10px; background: none; border: 0; color: inherit; cursor: pointer; text-align: left; padding: 4px 2px; font-size: .82rem; }
.wn-session span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.wn-session small { color: var(--dim); white-space: nowrap; }
.wn-session:hover, .wn-session:focus-visible { color: var(--cold); outline: none; }
.wn-session.new { color: var(--cold); }
.wn-how .wn-steps { flex: none; }
.wn-how { padding: 12px 14px; border: 1px solid var(--line); display: flex; flex-direction: column; gap: 12px; }
.wn-add { display: flex; gap: 10px; flex-wrap: wrap; }
.wn-panel { padding: 8px 0; display: flex; gap: 28px; flex-wrap: wrap; align-items: flex-start; }
.wn-qr { width: min(320px, 100%); aspect-ratio: 1; background: #fff; padding: 14px; }
.wn-steps { flex: 1 1 240px; display: flex; flex-direction: column; gap: 12px; margin: 0; padding: 0; list-style: none; counter-reset: s; font-size: .9rem; }
.wn-steps li { padding-left: 28px; position: relative; }
.wn-steps li:not(.wn-note) { counter-increment: s; }
.wn-steps li:not(.wn-note)::before { content: counter(s); position: absolute; left: 0; color: var(--dim); font-variant-numeric: tabular-nums; }
.wn-code { font-family: var(--font-mono, monospace); font-size: .78rem; word-break: break-all; user-select: all; border: 1px solid var(--line); padding: 10px 12px; }
.wn-addr { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.wn-addr .wn-code { padding: 4px 8px; }
.wn-start { display: flex; flex-direction: column; gap: 16px; align-items: flex-start; }
.wn-on { width: 100%; background: none; border: 1px solid var(--line); color: inherit; padding: 24px; text-align: left; cursor: pointer; }
.wn-on:hover { border-color: var(--cold); }
.wn-on b { display: block; font-weight: 600; font-size: 1.2rem; margin-bottom: 4px; }
.wn-on span { font-size: .86rem; color: var(--dim); }
.wn-link { background: none; border: 0; padding: 0; color: var(--cold); cursor: pointer; font-size: .88rem; }
.wn-working { align-items: center; gap: 14px; }
.wn-pulse { width: 9px; height: 9px; border-radius: 50%; background: var(--cold); animation: wn-breathe 2.6s ease-in-out infinite; }
@keyframes wn-breathe { 50% { opacity: .3; } }
@media (prefers-reduced-motion: reduce) { .wn-pulse { animation: none; } }
.wn-safe summary { cursor: pointer; }
.wn-row { display: flex; justify-content: space-between; gap: 20px; align-items: center; padding: 12px 0; font-size: .88rem; }
.wn-row small { display: block; color: var(--dim); font-size: .76rem; margin-top: 2px; }
`

function plain(e) {
  const text = String(e?.message || e)
  const detail = text.match(/"detail"\s*:\s*"((?:[^"\\]|\\.)*)"/)
  if (/Plugin not found/i.test(text)) return 'Wings is not switched on for the profile you are in. Switch to the profile you installed it in (usually your main one), or turn Wings on for this profile under Capabilities, Plugins.'
  if (detail && detail[1] !== 'Not Found') return detail[1].replace(/\\"/g, '"')
  if (/ECONNREFUSED|ECONNRESET|socket hang up|Failed to fetch|fetch failed|network|timed? ?out/i.test(text))
    return "Hermes isn't answering on this computer. Start it with: hermes gateway start"
  if (/\b404\b/.test(text)) return "Hermes hasn't loaded Wings yet. Restart Hermes, then come back here."
  if (/\b401\b|\b403\b/.test(text)) return 'Hermes needs you to sign in again.'
  if (/\b5\d\d\b/.test(text)) return 'Hermes hit a problem doing that. hermes wings doctor will say what is wrong.'
  return text.replace(/^Error invoking remote method '[^']*':\s*/, '').replace(/^Error:\s*/, '')
}

// What the page showed last time, so it opens complete at once and then quietly catches up.
const kept = (k, fallback) => { try { const v = JSON.parse(localStorage.getItem('wings.page.' + k)); return v ?? fallback } catch { return fallback } }
const keep = (k, v) => { try { localStorage.setItem('wings.page.' + k, JSON.stringify(v)) } catch { /* full or blocked: just slower next time */ } }

const UNNAMED = /^phone-[a-z0-9]{4}$/

const nice = n => n === 'default' ? 'Hermes' : n.charAt(0).toUpperCase() + n.slice(1)
const when = m => m.online ? 'Awake' : m.seen ? `Seen ${relativeTime(m.seen * 1000)}` : 'Waiting'
// A machine's own name, unless its owner gave it another. Short ones are initials more often than words (VPS, NAS, PC).
const titleOf = m => m.label || (UNNAMED.test(m.name) ? 'Phone' : m.name.length <= 3 ? m.name.toUpperCase() : nice(m.name))

function useNet(ctx) {
  const [status, setStatus] = useState(() => kept('status', null))
  const [settings, setSettings] = useState(null)
  const [bots, setBots] = useState(() => kept('bots', {}))
  const [offline, setOffline] = useState(null)
  const reload = useCallback(async () => {
    try {
      const s = await ctx.rest('/status')
      setStatus(s)
      keep('status', s)
      if (s.hub?.name) setSettings(await ctx.rest('/settings'))
      setOffline(null)
      ctx.rest('/agents').then(b => { setBots(b); keep('bots', b) }).catch(() => {})
    } catch (e) {
      setOffline(plain(e))
    }
  }, [ctx])
  useEffect(() => {
    reload()
    const t = setInterval(reload, 8000)
    return () => clearInterval(t)
  }, [reload])
  const hub = status?.hub?.name ? status.hub : null
  const member = status?.member && Object.keys(status.member).length ? status.member : null
  const machines = []
  // The hub goes by the name its owner gave it; the line under it says what it is.
  const hubSub = () => 'Hub'
  if (hub) machines.push({ name: hub.name, label: hub.label, kind: 'hub', sub: hubSub(hub), online: !!status.interface_up, here: true })
  if (member) {
    const far = { name: member.hub_name, label: status.hub_label || '' }
    machines.push({ ...far, kind: 'hub', sub: hubSub(far), online: !!status.interface_up })
    machines.push({ name: 'self', label: 'This computer', kind: 'computer', sub: 'Computer', online: true, here: true })
  }
  // A joined computer learns the rest of the wing net from the hub.
  for (const d of (member && status?.net) || [])
    if (!d.self && (!UNNAMED.test(d.name) || d.online || d.last_handshake))
      machines.push({ name: d.name, label: d.label, kind: d.kind === 'phone' ? 'phone' : 'computer', sub: d.kind === 'phone' ? 'Phone' : 'Computer', online: d.online, seen: d.last_handshake })
  for (const d of status?.devices || [])
    if (!UNNAMED.test(d.name) || d.online || d.last_handshake)
      machines.push({ name: d.name, label: d.label, kind: d.kind === 'phone' ? 'phone' : 'computer', sub: d.kind === 'phone' ? 'Phone' : 'Computer', online: d.online, seen: d.last_handshake, removable: true })
  const roster = machines.flatMap(m => (bots[m.name] || []).map(b => ({ ...b, machine: m })))
  return { status, settings, bots, offline, reload, hub, member, machines, roster }
}

const SAVED = '/settings?tab=gateway&page=devices'
const addressOf = m => `https://${String(m.name).toLowerCase()}.wings`
const hostOf = u => { try { return new URL(u).hostname.toLowerCase() } catch { return '' } }

// What this Desktop already has: its own list of connections and the bots Hermes sees on each.
function useHermes() {
  const [state, setState] = useState({ connections: [], agents: [], registry: true })
  useEffect(() => {
    let live = true
    const look = async () => {
      // The Webapp has no connection list: there a machine simply opens at its address.
      const connections = await host.connections().catch(() => null)
      const agents = connections ? await host.agents().then(r => r?.agents || []).catch(() => []) : []
      if (live) setState({ connections: connections || [], agents, registry: !!connections })
    }
    look()
    const t = setInterval(look, 5000)
    return () => { live = false; clearInterval(t) }
  }, [])
  return state
}

const ORACLES = ['pythia', 'trophon', 'manto', 'phemonoe', 'sibyl', 'cassandra', 'calchas', 'themis', 'tiresias', 'mopsus', 'diotima', 'helenus', 'orpheus']
function emblemFor(name) {
  const n = String(name).toLowerCase()
  const known = ORACLES.find(k => n.includes(k))
  if (known) return known
  let h = 0
  for (const c of n) h = (h * 31 + c.charCodeAt(0)) >>> 0
  return ORACLES[h % ORACLES.length]
}

const botTitle = (b, look) => look?.title || nice(b.name)
const faceOf = (b, look, art) => look?.image || art[emblemFor(look?.title || b.name)]

// One machine on the wing net. Closed, it is a line with its bots' faces. Rest the pointer on it and it folds out
// underneath: its bots, and under whichever bot the pointer rests on, that bot's latest sessions. The fold-out hangs
// over the page instead of pushing it around, so nothing moves under the pointer.
function Machine({ m, net, hermes, art, looks, onRemove, inline, query, part }) {
  const [how, setHow] = useState(false)
  const [hot, setHotNow] = useState(false)
  const [pinned, setPinned] = useState(false)
  const [sel, setSel] = useState(null)
  const [side, setSide] = useState('left')
  const card = useRef(null)
  const leaving = useRef(null)
  const picking = useRef(null)
  // Both ways wait a moment: a pointer only passing over should not open a machine, and one that slips off
  // for an instant should not shut it.
  const setHot = v => { clearTimeout(leaving.current); leaving.current = setTimeout(() => setHotNow(v), v ? 260 : 380) }
  useEffect(() => () => { clearTimeout(leaving.current); clearTimeout(picking.current) }, [])
  const bots = net.bots[m.name] || []
  const here = !!m.here
  const link = !here ? hermes.connections.find(c => hostOf(c.url) === hostOf(addressOf(m))) : null
  const agents = link ? hermes.agents.filter(a => a.connectionId === link.id) : []
  const direct = (net.status?.direct || []).includes(m.name)
  const lookOf = b => looks[m.name]?.[b.name]
  const open = m.online && (inline || hot || pinned)
  const sought = query ? bots.find(b => botTitle(b, lookOf(b)).toLowerCase().includes(query)) : null
  const chosen = bots.find(b => b.name === sel) || sought || bots[0]
  // Which way the fold-out hangs, measured as it opens, so it never leaves the page.
  useLayoutEffect(() => {
    const box = card.current?.closest('.wn-web')?.getBoundingClientRect()
    if (!open || inline || !box) return
    const r = card.current.getBoundingClientRect()
    const mid = r.left + r.width / 2 - box.left
    setSide(r.width > 380 ? 'mid' : mid < box.width * 0.4 ? 'left' : mid > box.width * 0.6 ? 'right' : 'mid')
  }, [open, inline])
  const go = (b, session) => {
    if (here) return session ? host.openSession(session, { profile: b.name }) : host.newChat(b.name)
    if (!hermes.registry) return host.openExternal(addressOf(m))
    const a = agents.find(x => x.profile === b.name) || agents[0]
    if (a) {
      const route = { connectionId: a.connectionId, profile: a.profile, targetProfile: a.targetProfile || a.profile }
      return session ? host.openSession(session, { route, intent: 'in-place' }) : host.newChat(route)
    }
    if (link) return host.navigate(SAVED)
    setPinned(true)
    setHow(true)
  }
  const brief = !m.online ? when(m) : here ? 'You are here' : hermes.registry && !link ? 'Not in Hermes yet'
    : hermes.registry && !agents.length ? 'Sign-in needed' : direct ? 'Direct link' : m.sub
  const full = [m.sub, here ? 'you are here' : null, link && agents.length ? 'in Hermes' : null, direct ? 'direct link' : null,
    bots.length ? `${bots.length} ${bots.length === 1 ? 'bot' : 'bots'}` : null].filter(Boolean).join(' · ')
  return jsxs('div', {
    ref: card, className: `wn-card${m.online ? ' on' : ''}${here ? ' here' : ''}${open ? ' open' : ''}${inline ? ' inline' : ''}`,
    'data-wn-hub': part === 'hub' ? '' : undefined, 'data-wn-leaf': part === 'leaf' ? (m.online ? 'on' : 'off') : undefined,
    onMouseEnter: () => setHot(true), onMouseLeave: () => setHot(false),
    onFocus: () => setHot(true), onBlur: e => { if (!e.currentTarget.contains(e.relatedTarget)) setHot(false) },
    children: [
      jsxs('button', {
        className: 'wn-mhead', 'aria-expanded': open, disabled: !m.online, onClick: () => setPinned(v => !v),
        children: [
          jsx('i', { className: `wn-dot${m.online ? ' on' : ''}` }),
          jsxs('span', { className: 'wn-grow', children: [jsx('span', { className: 'wn-mname', children: titleOf(m) }), jsx('span', { className: 'wn-sub', children: brief })] }),
          bots.length > 0 && jsx('span', { className: 'wn-stack', children: bots.slice(0, 4).map(b => jsx('img', { src: faceOf(b, lookOf(b), art), alt: '' }, b.name)) })
        ]
      }),
      !m.online && onRemove && jsx('button', { className: 'wn-x', onClick: () => onRemove(m), 'aria-label': `Remove ${titleOf(m)}`, children: 'Remove' }),
      open && jsxs('div', {
        className: `wn-pop ${side}`,
        children: [
          jsxs('div', {
            className: 'wn-pophead',
            children: [
              jsx('span', { className: 'wn-sub wn-grow', children: full }),
              onRemove && jsx('button', { className: 'wn-x', onClick: () => onRemove(m), 'aria-label': `Remove ${titleOf(m)}`, children: 'Remove' }),
              !here && (!hermes.registry
                ? jsx(Button, { size: 'sm', variant: 'outline', onClick: () => host.openExternal(addressOf(m)), children: 'Open' })
                : link
                ? (agents.length ? null : jsx(Button, { size: 'sm', variant: 'outline', onClick: () => host.navigate(SAVED), children: 'Sign in' }))
                : jsx(Button, { size: 'sm', 'aria-expanded': how, onClick: () => { setPinned(true); setHow(h => !h) }, children: 'Add to Hermes' }))
            ]
          }),
          bots.length > 0
            ? jsx('div', {
                className: 'wn-bots',
                children: bots.map(b => jsxs('button', {
                  className: `wn-bot${chosen === b ? ' sel' : ''}`, 'aria-label': `New chat with ${botTitle(b, lookOf(b))}`,
                  onMouseEnter: () => { clearTimeout(picking.current); picking.current = setTimeout(() => setSel(b.name), 160) },
                  onMouseLeave: () => clearTimeout(picking.current), onFocus: () => setSel(b.name), onClick: () => go(b),
                  children: [
                    jsx('img', { className: 'wn-face', src: faceOf(b, lookOf(b), art), alt: '' }),
                    jsx('span', { className: 'wn-botname', children: botTitle(b, lookOf(b)) }),
                    jsx('span', { className: 'wn-botmeta', children: b.sessions ? `${b.sessions} ${b.sessions === 1 ? 'session' : 'sessions'}` : 'Ready' })
                  ]
                }, b.name))
              })
            : jsx('p', { className: 'wn-note', children: 'No bots seen here yet.' }),
          chosen && jsxs('div', {
            className: 'wn-sessions',
            children: [
              jsx('span', { className: 'wn-eyebrow', children: botTitle(chosen, lookOf(chosen)) }),
              jsx('button', { className: 'wn-session new', onClick: () => go(chosen), children: '+ New chat' }),
              (chosen.recent || []).slice(0, 4).map(r => jsxs('button', {
                className: 'wn-session', title: r.title, onClick: () => go(chosen, r.id),
                children: [jsx('span', { children: r.title }), r.last ? jsx('small', { children: relativeTime(r.last * 1000) }) : null]
              }, r.id))
            ]
          }),
          how && !link && jsxs('div', {
            className: 'wn-how',
            children: [
              jsxs('ol', {
                className: 'wn-steps',
                children: [
                  jsxs('li', { children: [jsxs('div', { className: 'wn-addr', children: ['Copy its address:', jsx('span', { className: 'wn-code', children: addressOf(m) }), jsx(CopyButton, { text: addressOf(m) })] })] }),
                  jsxs('li', { children: ['Open ', jsx('b', { children: 'Saved connections' }), ' and choose ', jsx('b', { children: 'Add connection' }), `. Name it ${titleOf(m)} and paste the address as the Gateway URL.`] }),
                  jsxs('li', { children: ['Under Authentication choose ', jsx('b', { children: 'Sign in' }), ' and press the sign-in button. Wings signs this computer in; if a window asks, press ', jsx('b', { children: 'Sign in with Wings' }), '.'] }),
                  jsxs('li', { children: ['Press ', jsx('b', { children: 'Save connection' }), '.'] }),
                  jsx('li', { className: 'wn-note', children: `After that, ${titleOf(m)} and its bots are in Hermes's own Bots and Sessions bars.` }),
                  jsx('li', { className: 'wn-note', children: "Hermes's Test button can report a failure for a wing-net machine that works: that check does not read your computer's list of trusted certificates. Saving and using the connection is fine." })
                ]
              }),
              jsx('div', { children: jsx(Button, { size: 'sm', onClick: () => host.navigate(SAVED), children: 'Open Saved connections' }) })
            ]
          })
        ]
      })
    ]
  })
}

// The wing net drawn as it is: the hub at the top, a line down to every machine that hangs off it.
// Solid for a machine that is awake, dotted for one that is asleep. The lines are measured from where the cards
// really are, so they stay true however the page wraps.
function Web({ net, hermes, art, looks, onRemove, query }) {
  const q = query.trim().toLowerCase()
  const web = useRef(null)
  const [lines, setLines] = useState([])
  const hit = m => !q || titleOf(m).toLowerCase().includes(q) || m.name.toLowerCase().includes(q)
    || (net.bots[m.name] || []).some(b => botTitle(b, looks[m.name]?.[b.name]).toLowerCase().includes(q))
  const hub = net.machines.find(m => m.kind === 'hub')
  const rest = net.machines.filter(m => m !== hub && m.kind !== 'phone' && hit(m))
  const phones = net.machines.filter(m => m.kind === 'phone' && hit(m))
  const top = hub && hit(hub) ? hub : null
  const shape = net.machines.map(m => m.name + (m.online ? 1 : 0)).join() + '|' + q
  useLayoutEffect(() => {
    const el = web.current
    if (!el || q) { setLines([]); return }
    const draw = () => {
      const box = el.getBoundingClientRect()
      const root = el.querySelector('[data-wn-hub]')?.getBoundingClientRect()
      if (!root) return setLines([])
      const x = v => Math.round(v - box.left) + 0.5
      const y = v => Math.round(v - box.top)
      const leaves = [...el.querySelectorAll('[data-wn-leaf]')].map(n => {
        const r = n.getBoundingClientRect()
        return { x: x(r.left + r.width / 2), top: y(r.top), on: n.dataset.wnLeaf === 'on' }
      })
      const rows = [...new Set(leaves.map(l => l.top))].sort((a, b) => a - b)
      const bus = t => t - 14.5
      const next = leaves.map(l => ({
        on: l.on,
        // First row: down from the hub, across, down. Later rows go round by the left edge.
        d: l.top === rows[0]
          ? `M${x(root.left + root.width / 2)} ${y(root.bottom)}V${bus(rows[0])}H${l.x}V${l.top}`
          : `M${x(root.left + root.width / 2)} ${y(root.bottom)}V${bus(rows[0])}H6.5V${bus(l.top)}H${l.x}V${l.top}`
      }))
      setLines(was => (JSON.stringify(was) === JSON.stringify(next) ? was : next))
    }
    draw()
    const watch = new ResizeObserver(draw)
    watch.observe(el)
    return () => watch.disconnect()
  }, [shape, q])
  const card = (m, part) => jsx(Machine, { m, net, hermes, art, looks, inline: !!q, query: q, part, onRemove: net.hub && m.removable ? onRemove : null }, m.name)
  if (q && !rest.length && !phones.length && !top) return jsx('p', { className: 'wn-note', children: 'Nothing on your wing net matches that.' })
  return jsxs('div', {
    ref: web, className: `wn-web${q ? ' finding' : ''}`,
    children: [
      !q && jsxs('svg', {
        className: 'wn-lines', 'aria-hidden': true,
        children: [...lines.filter(l => !l.on), ...lines.filter(l => l.on)].map((l, i) => jsx('path', { d: l.d, className: l.on ? 'on' : undefined }, i))
      }),
      top && jsx('div', { className: 'wn-root', children: card(top, 'hub') }),
      rest.length > 0 && jsx('div', { className: 'wn-tier', children: rest.map(m => card(m, 'leaf')) }),
      phones.length > 0 && jsx('div', {
        className: 'wn-tier phones',
        children: phones.map(m => jsxs('div', {
          className: `wn-card wn-phone${m.online ? ' on' : ''}`, 'data-wn-leaf': q ? undefined : (m.online ? 'on' : 'off'),
          children: [
            jsxs('div', { className: 'wn-mhead', children: [
              jsx('i', { className: `wn-dot${m.online ? ' on' : ''}` }),
              jsxs('span', { className: 'wn-grow', children: [jsx('span', { className: 'wn-mname', children: titleOf(m) }), jsx('span', { className: 'wn-sub', children: m.online ? 'Phone' : `Phone, ${when(m).toLowerCase()}` })] })
            ] }),
            net.hub && m.removable && jsx('button', { className: 'wn-x', onClick: () => onRemove(m), 'aria-label': `Remove ${titleOf(m)}`, children: 'Remove' })
          ]
        }, m.name))
      })
    ]
  })
}

function AddPhone({ ctx, onDone, setError }) {
  const [code, setCode] = useState(null)
  useEffect(() => {
    let live = true
    const n = `phone-${Math.random().toString(36).slice(2, 6)}`
    ctx.rest('/status')
      .then(s => (s.devices || []).find(d => UNNAMED.test(d.name) && !d.online && !d.last_handshake) || ctx.rest('/devices', { method: 'POST', body: { name: n, kind: 'phone' } }))
      .then(d => ctx.rest(`/devices/${encodeURIComponent(d.name)}/qr.json`))
      .then(c => live && setCode(c))
      .catch(e => setError(plain(e)))
    return () => { live = false }
  }, [ctx, setError])
  return jsxs('div', {
    className: 'wn-panel',
    children: [
      code ? jsx('img', { className: 'wn-qr', src: code.qr, alt: 'Pairing code for your phone' }) : jsx('div', { className: 'wn-qr' }),
      jsxs('ol', {
        className: 'wn-steps',
        children: [
          jsx('li', { children: 'Install WireGuard on your phone.' }),
          jsx('li', { children: 'Tap +, then Scan from QR code.' }),
          jsx('li', { children: 'Turn the tunnel on.' }),
          code?.app_address && jsxs('li', { children: ['In the Hermes app, add ', jsx('b', { children: code.app_address }), ' and choose Browser. Wings signs the phone in.'] }),
          jsx('li', { className: 'wn-note', children: 'This code is your phone\'s key. It stops working once the phone connects.' }),
          jsx('div', { children: jsx(Button, { size: 'sm', onClick: onDone, children: 'Done' }) })
        ]
      })
    ]
  })
}

function AddComputer({ ctx, onDone, setError }) {
  const [name, setName] = useState('')
  const [invite, setInvite] = useState(null)
  const make = () =>
    ctx.rest('/invite', { method: 'POST', body: { name: name.trim() } }).then(setInvite).catch(e => setError(plain(e)))
  if (!invite)
    return jsxs('div', {
      className: 'wn-panel',
      children: [
        jsx(Input, { value: name, placeholder: 'Name this computer', className: 'max-w-64', autoFocus: true, onChange: e => setName(e.target.value), onKeyDown: e => e.key === 'Enter' && name.trim() && make() }),
        jsx(Button, { disabled: !name.trim(), onClick: make, children: 'Next' }),
        jsx(Button, { variant: 'ghost', onClick: onDone, children: 'Cancel' })
      ]
    })
  return jsxs('div', {
    className: 'wn-panel',
    style: { flexDirection: 'column' },
    children: [
      jsx('div', { children: `On ${invite.name}, paste this into a terminal. It works once, for ${invite.minutes} minutes.` }),
      jsx('div', { className: 'wn-code', children: invite.command }),
      jsxs('div', {
        style: { display: 'flex', gap: 8 },
        children: [
          jsx(Button, { size: 'sm', variant: 'outline', onClick: () => navigator.clipboard?.writeText(invite.command), children: 'Copy' }),
          jsx(Button, { size: 'sm', onClick: onDone, children: 'Done' })
        ]
      })
    ]
  })
}

function TurnOn({ ctx, reload, setError }) {
  const [job, setJob] = useState(null)
  const [joining, setJoining] = useState(false)
  const [code, setCode] = useState('')
  const [waiting, setWaiting] = useState(false)

  useEffect(() => {
    let live = true
    const look = () => ctx.rest('/start').then(j => {
      if (!live) return
      setJob(j)
      if (j.running) setWaiting(true)
      else setWaiting(w => { if (w && j.ok) reload(); return false })
    }).catch(() => {})
    look()
    const t = setInterval(look, 1200)
    return () => { live = false; clearInterval(t) }
  }, [ctx, reload])

  const go = body => {
    setError(null)
    setWaiting(true)
    setJob({ running: true, stage: 'Starting.' })
    ctx.rest('/start', { method: 'POST', body }).catch(e => { setWaiting(false); setJob(null); setError(plain(e)) })
  }

  if (job?.running)
    return jsxs('div', { className: 'wn-panel wn-working', role: 'status', children: [jsx('i', { className: 'wn-pulse' }), jsx('span', { children: job.stage })] })

  return jsxs('div', {
    className: 'wn-start',
    children: [
      job?.error && jsx('p', { className: 'wn-note', role: 'alert', children: job.error }),
      job?.note && jsx('p', { className: 'wn-note', children: job.note }),
      !joining && jsxs('button', {
        className: 'wn-on',
        onClick: () => go({ action: 'setup' }),
        children: [jsx('b', { children: job?.error ? 'Try again' : 'Turn on Wings' }), jsx('span', { children: 'Makes this computer the hub of your wing net: your phone and your other computers connect to it. Any computer works. With several, pick the one that is on the most.' })]
      }),
      joining
        ? jsxs('div', {
            className: 'wn-panel',
            children: [
              jsx(Input, { value: code, placeholder: 'Paste the invite', autoFocus: true, className: 'max-w-96', onChange: e => setCode(e.target.value), onKeyDown: e => e.key === 'Enter' && code.trim() && go({ action: 'join', code }) }),
              jsx(Button, { disabled: !code.trim(), onClick: () => go({ action: 'join', code }), children: 'Join' }),
              jsx(Button, { variant: 'ghost', onClick: () => setJoining(false), children: 'Back' })
            ]
          })
        : jsx('button', { className: 'wn-link', onClick: () => setJoining(true), children: 'I already have a wing net. Join it with an invite.' }),
      jsx('p', { className: 'wn-note', children: 'Your computer asks for admin approval once, to add one private network connection. Your Hermes logins stay as they are.' })
    ]
  })
}

function Safety({ ctx, settings, reload, setError }) {
  const set = patch => ctx.rest('/settings', { method: 'POST', body: patch }).then(reload).catch(e => setError(plain(e)))
  const row = (title, detail, checked, key, flip) =>
    jsxs('div', {
      className: 'wn-row',
      children: [
        jsxs('div', { children: [title, jsx('small', { children: detail })] }),
        jsx(Switch, { checked, 'aria-label': title, onCheckedChange: v => set({ [key]: flip ? !v : v }) })
      ]
    })
  return jsxs('details', {
    className: 'wn-safe',
    children: [
      jsx('summary', { className: 'wn-eyebrow', children: 'Safety' }),
      row('Devices can reach each other', 'Off means devices reach only this computer.', !settings.isolate_devices, 'isolate_devices', true),
      row('Forget a phone\'s key once it connects', 'Its QR code stops working.', settings.forget_phone_keys, 'forget_phone_keys'),
      row('HTTPS relay', 'For networks that block WireGuard. Still encrypted.', settings.relay, 'relay')
    ]
  })
}

function WingsPage({ ctx }) {
  const net = useNet(ctx)
  const hermes = useHermes()
  const { status, settings, reload, hub, member, machines, offline } = net
  const [error, setError] = useState(null)
  const [adding, setAdding] = useState(null)
  const [query, setQuery] = useState('')
  const [art, setArt] = useState(() => kept('art', {}))
  const [looks, setLooks] = useState(() => kept('looks', {}))
  useEffect(() => { ctx.rest('/emblems').then(a => { setArt(a); keep('art', a) }).catch(() => {}) }, [ctx])
  useEffect(() => {
    // An empty answer means the backend has not caught up yet: keep what we have and ask again soon.
    const get = () => ctx.rest('/agent-looks').then(l => { if (l && Object.keys(l).length) { setLooks(l); keep('looks', l) } }).catch(() => {})
    get()
    const soon = [setTimeout(get, 4000), setTimeout(get, 12000)]
    const t = setInterval(get, 45000)
    return () => { clearInterval(t); soon.forEach(clearTimeout) }
  }, [ctx])

  const remove = async m => {
    if (!window.confirm(`Remove ${titleOf(m)}? Its key stops working right away.`)) return
    await ctx.rest(`/devices/${encodeURIComponent(m.name)}`, { method: 'DELETE' }).catch(e => setError(plain(e)))
    reload()
  }

  const inNet = hub || member
  return jsxs('div', {
    className: 'wn',
    children: [
      jsx('style', { children: CSS }),
      jsxs('div', {
        className: 'wn-in',
        children: [
          jsxs('header', {
            className: 'wn-top',
            children: [
              jsxs('div', { children: [
              jsx('h1', { className: 'wn-title', children: 'Wings' }),
              jsx('p', { className: 'wn-note', children: inNet ? 'Every Hermes machine you own that is on right now. Point at one to see its bots.' : 'Link every Hermes you own, and your phone, into one wing net. Two devices are enough. Your existing logins stay as they are.' })
              ] }),
              inNet && machines.length > 3 && jsx('div', { className: 'wn-find', children: jsx(Input, { value: query, placeholder: 'Find a machine or a bot', 'aria-label': 'Find a machine or a bot', onChange: e => setQuery(e.target.value) }) })
            ]
          }),
          (error || offline) && jsx('p', { className: 'wn-note', role: 'alert', children: error || offline }),
          status && !inNet && jsx(TurnOn, { ctx, reload, setError }),
          inNet && jsx(Web, { net, hermes, art, looks, query, onRemove: remove }),
          hub && !adding && jsxs('div', {
            className: 'wn-add',
            children: [
              jsx(Button, { variant: 'outline', onClick: () => setAdding('phone'), children: 'Add a phone' }),
              jsx(Button, { variant: 'outline', onClick: () => setAdding('computer'), children: 'Add a computer' })
            ]
          }),
          member && jsx('p', { className: 'wn-note', children: (t => (/hub/i.test(t) ? 'New phones and computers are added from your hub.' : `New phones and computers are added from ${t}, your hub.`))(titleOf({ name: member.hub_name, label: net.status?.hub_label || '' })) }),
          adding === 'phone' && jsx(AddPhone, { ctx, setError, onDone: () => { setAdding(null); reload() } }),
          adding === 'computer' && jsx(AddComputer, { ctx, setError, onDone: () => { setAdding(null); reload() } }),
          hub && settings && jsx(Safety, { ctx, settings, reload, setError })
        ]
      })
    ]
  })
}

export default {
  id: 'wings',
  name: 'Wings',
  register(ctx) {
    ctx.registerMany([
      { id: 'paper', area: THEMES_AREA, data: WINGS_PAPER },
      { id: 'page', area: ROUTES_AREA, data: { path: '/wings' }, render: () => jsx(WingsPage, { ctx }) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: '/wings', label: 'Wings', codicon: 'radio-tower' } }
    ])
  }
}
