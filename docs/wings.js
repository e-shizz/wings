// Wings: one drawing for the page and the explainer. Everything is a function of time, so a film
// renders the same way every run. No images, no libraries.
const REPO = 'https://github.com/e-shizz/wings'
const PROMPT = `Set up Wings for my Hermes by following ${REPO}/blob/main/plugin/AGENTS.md
Stop and ask me whenever you need my password or a decision.`

const C = { bg: '#0d1117', deep: '#161b22', ink: '#c9d1d9', dim: '#7d8590', accent: '#4a84fe', line: '#30363d', stop: '#f85149' }
const canvas = document.getElementById('c')
const g = canvas.getContext('2d')
let W = 0, H = 0, U = 1
const params = new URLSearchParams(location.search)
const film = params.has('film')
const calm = matchMedia('(prefers-reduced-motion: reduce)').matches
if (film) document.body.classList.add('film')

function resize() {
  const d = Math.min(devicePixelRatio || 1, 2)
  W = innerWidth; H = innerHeight; U = Math.min(W, H * 1.6) / 1000
  canvas.width = W * d; canvas.height = H * d
  g.setTransform(d, 0, 0, d, 0, 0)
}
addEventListener('resize', resize)
resize()

const ease = x => { x = Math.max(0, Math.min(1, x)); return x * x * (3 - 2 * x) }
const span = (t, a, b) => ease((t - a) / (b - a))
const mix = (a, b, k) => a + (b - a) * k

// Fixed scatter, so the texture never shimmers between frames.
function noise(i) { const s = Math.sin(i * 127.1) * 43758.5453; return s - Math.floor(s) }

// A feather: a curved spine with engraver's hatching down both sides.
function feather(x, y, ang, len, wide, reveal) {
  const n = Math.floor(30 * reveal)
  const tip = [x + Math.cos(ang) * len, y + Math.sin(ang) * len]
  const bend = wide * 1.3
  const nx = -Math.sin(ang), ny = Math.cos(ang)
  const spine = k => {
    const b = bend * k * k
    return [x + Math.cos(ang) * len * k + nx * b, y + Math.sin(ang) * len * k + ny * b]
  }
  const edge = (side, sc) => {
    const pts = []
    for (let i = 0; i <= n; i++) {
      const k = i / 30
      const p = spine(k)
      const body = Math.sin(Math.min(1, k * 1.04) * Math.PI) ** .6 * wide * sc
      pts.push([p[0] + Math.cos(ang + side * 1.05) * body, p[1] + Math.sin(ang + side * 1.05) * body])
    }
    return pts
  }
  if (n > 2) {
    const a = edge(1, 1), b = edge(-1, .62).reverse()
    g.fillStyle = C.deep
    g.beginPath()
    a.concat(b).forEach((p, i) => (i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1])))
    g.closePath(); g.fill()
    g.strokeStyle = C.ink; g.lineWidth = Math.max(.35, U * .45); g.globalAlpha = (g.globalAlpha || 1) * .55; g.stroke(); g.globalAlpha = 1
  }
  g.lineWidth = Math.max(.5, U * .7)
  g.strokeStyle = C.ink
  g.beginPath()
  for (let i = 0; i <= n; i++) { const p = spine(i / 30); i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]) }
  g.stroke()
  g.lineWidth = Math.max(.35, U * .4)
  for (let i = 2; i < n; i++) {
    const k = i / 30
    const p = spine(k)
    const body = Math.sin(Math.min(1, k * 1.04) * Math.PI) ** .6 * wide
    for (const side of [-1, 1]) {
      const sweep = ang + side * 1.05
      const l = body * (side > 0 ? 1 : .62) * (.86 + noise(i * 3 + side) * .2)
      g.globalAlpha = .34 + .5 * (1 - k) * (side > 0 ? 1 : .7)
      g.beginPath()
      g.moveTo(p[0], p[1])
      g.lineTo(p[0] + Math.cos(sweep) * l, p[1] + Math.sin(sweep) * l)
      g.stroke()
    }
  }
  g.globalAlpha = 1
  return tip
}

// The wing, rooted low and spreading up to the right. Returns where each feather ends.
function wing(cx, cy, s, reveal) {
  const tips = []
  const count = 11
  for (let i = 0; i < count; i++) {
    const k = i / (count - 1)
    const r = span(reveal, k * .55, k * .55 + .45)
    if (r <= 0) continue
    const ang = mix(-1.38, -.08, k)
    const len = mix(190, 330, Math.sin(k * Math.PI * .72)) * s
    tips.push(feather(cx + k * 30 * s, cy + k * 26 * s, ang, len, mix(24, 34, k) * s, r))
  }
  const q = span(reveal, 0, .4)
  g.globalAlpha = q
  for (let i = 0; i < 7; i++) {
    const k = i / 6
    feather(cx - 4 * s, cy - 2 * s, mix(-1.2, -.32, k), 118 * s, 15 * s, q)
  }
  g.globalAlpha = 1
  return tips
}

function wingTips(cx, cy, s) {
  const out = []
  for (let i = 0; i < 11; i++) {
    const k = i / 10
    const ang = mix(-1.38, -.08, k)
    const len = mix(190, 330, Math.sin(k * Math.PI * .72)) * s
    out.push([cx + k * 30 * s + Math.cos(ang) * len, cy + k * 26 * s + Math.sin(ang) * len])
  }
  return out
}

function thread(a, b, sag, reveal, color, alpha, dash) {
  if (reveal <= 0) return
  g.strokeStyle = color; g.globalAlpha = alpha
  g.lineWidth = Math.max(.5, U * .8)
  g.setLineDash(dash ? [6 * U, 6 * U] : [])
  g.beginPath()
  const steps = 40, n = Math.floor(steps * reveal)
  for (let i = 0; i <= n; i++) {
    const p = bez(a, b, sag, i / steps)
    i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1])
  }
  g.stroke()
  g.setLineDash([]); g.globalAlpha = 1
}

function bez(a, b, sag, k) {
  const mx = (a[0] + b[0]) / 2, my = (a[1] + b[1]) / 2 + sag
  const u = 1 - k
  return [u * u * a[0] + 2 * u * k * mx + k * k * b[0], u * u * a[1] + 2 * u * k * my + k * k * b[1]]
}

function packet(a, b, sag, k, color) {
  const p = bez(a, b, sag, k)
  g.fillStyle = color
  g.globalAlpha = Math.sin(Math.min(1, Math.max(0, k)) * Math.PI) ** .5
  g.beginPath(); g.arc(p[0], p[1], 3.4 * U, 0, 7); g.fill()
  g.globalAlpha = 1
}

function node(p, label, sub, a, shape) {
  if (a <= 0) return
  const r = 26 * U
  g.globalAlpha = a
  g.fillStyle = C.deep; g.strokeStyle = C.ink; g.lineWidth = Math.max(.8, U * 1.1)
  g.beginPath()
  if (shape === 'phone') g.roundRect(p[0] - r * .55, p[1] - r, r * 1.1, r * 2, 5 * U)
  else if (shape === 'laptop') { g.roundRect(p[0] - r, p[1] - r * .7, r * 2, r * 1.2, 3 * U); g.moveTo(p[0] - r * 1.25, p[1] + r * .72); g.lineTo(p[0] + r * 1.25, p[1] + r * .72) }
  else { g.roundRect(p[0] - r * .9, p[1] - r, r * 1.8, r * 2, 3 * U); for (const y of [-.4, .1, .6]) { g.moveTo(p[0] - r * .6, p[1] + r * y); g.lineTo(p[0] + r * .6, p[1] + r * y) } }
  g.fill(); g.stroke()
  g.textAlign = 'center'; g.fillStyle = C.ink
  g.font = `600 ${15 * U}px system-ui, sans-serif`
  g.fillText(label, p[0], p[1] + r * 1.75)
  if (sub) { g.fillStyle = C.dim; g.font = `${12.5 * U}px ui-monospace, monospace`; g.fillText(sub, p[0], p[1] + r * 1.75 + 18 * U) }
  g.globalAlpha = 1
}

const SCENES = [
  [0, 4.5, 'Give your Hermes wings', 'Your Hermes, on all your devices. Privately.'],
  [4.5, 9, 'Your devices can\'t see each other', 'Each one sits behind its own network.'],
  [9, 13.5, 'One machine becomes the hub', 'Usually a small VPS. It\'s yours, with no account and no third party.'],
  [13.5, 18, 'Scan a code. Paste one line.', 'Your phone and computers join over WireGuard.'],
  [18, 23, 'Blocked network? It finds a way', 'WireGuard falls back to HTTPS on port 443, still encrypted.'],
  [23, 28, 'Everything else stays out', 'You sign in. Only your devices reach it. Other networks are left alone.']
]
const FILM_LEN = 28

function caption(t) {
  const sc = SCENES.find(c => t >= c[0] && t < c[1]) || SCENES[SCENES.length - 1]
  const a = Math.min(span(t, sc[0], sc[0] + .6), 1 - span(t, sc[1] - .5, sc[1]))
  g.globalAlpha = a; g.textAlign = 'center'
  g.fillStyle = C.ink; g.font = `900 ${Math.min(58, 58 * U * 1.3)}px "Bodoni Moda", Georgia, serif`
  g.fillText(sc[2], W / 2, H - 92 * U)
  g.fillStyle = C.dim; g.font = `${21 * U}px system-ui, sans-serif`
  g.fillText(sc[3], W / 2, H - 52 * U)
  g.globalAlpha = 1
}

function drawFilm(t) {
  g.fillStyle = C.bg; g.fillRect(0, 0, W, H)
  const cx = W / 2, cy = H * .4
  const hub = [cx, cy - 130 * U], phone = [cx - 330 * U, cy + 120 * U], laptop = [cx + 330 * U, cy + 120 * U]
  const wingA = 1 - span(t, 3.4, 4.6)
  if (wingA > 0) { g.globalAlpha = wingA; wing(cx - 120 * U, cy + 150 * U, 1.05 * U, span(t, 0, 2.8)); g.globalAlpha = 1 }

  const show = span(t, 4.6, 5.4)

  if (t > 4.6 && t < 9.5) {
    const a = show * (1 - span(t, 8.6, 9.4))
    for (const p of [phone, laptop]) {
      g.strokeStyle = C.line; g.globalAlpha = a; g.lineWidth = U
      g.setLineDash([3 * U, 7 * U]); g.beginPath(); g.arc(p[0], p[1], 72 * U, 0, 7); g.stroke(); g.setLineDash([])
      g.globalAlpha = 1
    }
    thread(phone, laptop, -30 * U, a, C.line, .7, true)
  }

  if (t > 9.2 && t < 13.8) {
    const a = span(t, 9.6, 10.6) * (1 - span(t, 13, 13.8))
    for (let i = 0; i < 26; i++) {
      const th = (i / 26) * Math.PI * 2
      const rr = 54 * U
      g.strokeStyle = C.accent; g.globalAlpha = a * .45; g.lineWidth = Math.max(.4, U * .5); g.beginPath()
      g.moveTo(hub[0] + Math.cos(th) * rr, hub[1] + Math.sin(th) * rr)
      g.lineTo(hub[0] + Math.cos(th) * (rr + 24 * U), hub[1] + Math.sin(th) * (rr + 24 * U)); g.stroke()
    }
    g.globalAlpha = 1
  }

  const joinL = span(t, 15.2, 16.6), joinP = span(t, 13.8, 15.2)
  const strand = 7
  const blocked = t >= 18 && t < 23
  for (let i = 0; i < strand; i++) {
    const off = (i - strand / 2) * 5 * U
    thread(phone, hub, 34 * U + off, joinP, C.ink, .3)
    const direct = blocked ? 1 - span(t, 18.6, 19.6) : 1
    thread(laptop, hub, 34 * U + off, joinL * direct, C.ink, .3)
  }
  if (t >= 13.8) {
    for (let i = 0; i < 5; i++) {
      const k = (t * .32 + i / 5) % 1
      if (joinP >= 1) packet(phone, hub, 34 * U, k, C.accent)
      if (joinL >= 1 && !blocked) packet(hub, laptop, 34 * U, k, C.accent)
    }
  }

  if (blocked) {
    const wall = [mix(hub[0], laptop[0], .55), mix(hub[1], laptop[1], .55)]
    const a = span(t, 18.2, 18.8) * (1 - span(t, 22.4, 23))
    g.globalAlpha = a; g.strokeStyle = C.stop; g.lineWidth = 2 * U
    g.beginPath(); g.moveTo(wall[0] - 40 * U, wall[1] + 52 * U); g.lineTo(wall[0] + 40 * U, wall[1] - 40 * U); g.stroke()
    g.fillStyle = C.stop; g.textAlign = 'left'; g.font = `${13 * U}px ui-monospace, monospace`
    g.fillText('UDP blocked', wall[0] + 46 * U, wall[1] - 34 * U)
    g.globalAlpha = 1
    const r = span(t, 19.4, 20.6) * (1 - span(t, 22.4, 23))
    const sag = -110 * U
    thread(laptop, hub, sag, r, C.accent, .9)
    if (r > .98) {
      const m = bez(laptop, hub, sag, .5)
      g.fillStyle = C.accent; g.textAlign = 'left'; g.font = `${13 * U}px ui-monospace, monospace`
      g.fillText('HTTPS :443', m[0] + 12 * U, m[1] - 6 * U)
      for (let i = 0; i < 5; i++) packet(laptop, hub, sag, (t * .32 + i / 5) % 1, C.ink)
    }
  }

  if (t >= 23) {
    const a = span(t, 23, 24)
    for (let i = 0; i < 44; i++) {
      const th = (i / 44) * Math.PI * 2
      const rx = 520 * U, ry = 318 * U
      g.strokeStyle = C.accent; g.globalAlpha = a * .35; g.lineWidth = Math.max(.4, U * .6)
      g.beginPath()
      g.moveTo(cx + Math.cos(th) * rx, cy + 20 * U + Math.sin(th) * ry)
      g.lineTo(cx + Math.cos(th) * (rx + 18 * U), cy + 20 * U + Math.sin(th) * (ry + 18 * U)); g.stroke()
    }
    g.globalAlpha = 1
    for (let i = 0; i < 3; i++) {
      const th = 2.5 + i * .55
      const out = [cx + Math.cos(th) * 640 * U, cy + Math.sin(th) * 380 * U]
      const k = (t * .28 + i * .3) % 1
      const stop = .62
      const p = [mix(out[0], cx, Math.min(k, 1) * .2), mix(out[1], cy, Math.min(k, 1) * .2)]
      void stop
      g.fillStyle = C.stop; g.globalAlpha = a * .7 * (1 - k); g.beginPath(); g.arc(p[0], p[1], 3 * U, 0, 7); g.fill(); g.globalAlpha = 1
    }
  }
  node(phone, 'Phone', t > 13.5 ? '10.77.0.2' : '', show, 'phone')
  node(laptop, 'Computer', t > 13.5 ? '10.77.0.3' : '', show, 'laptop')
  node(hub, 'Hub', t > 13.5 ? '10.77.0.1' : 'your VPS', span(t, 9.2, 10), 'server')
  caption(t)
}

function drawPage(t) {
  g.fillStyle = C.bg; g.fillRect(0, 0, W, H)
  const portrait = H > W
  const s = U * (portrait ? .85 : .72)
  const cx = W / 2 - 110 * s, cy = H * (portrait ? .36 : .43)
  const r = calm ? 1 : span(t, 0, 2.6)
  const keep = []
  const probe = wingTips(cx, cy, s)
  if (r >= 1) {
    for (let i = 0; i < probe.length; i += 2) keep.push(probe[i])
  }
  const nodes = [[W * .14, H * .12], [W * .86, H * .1], [W * .88, H * .36], [W * .12, H * .36]]
  keep.forEach((tip, i) => {
    const n = nodes[i % nodes.length]
    thread(tip, n, 18 * s, calm ? 1 : span(t, 2.4 + i * .1, 3.6 + i * .1), C.ink, .16)
    if (!calm && t > 3.8) packet(tip, n, 18 * s, ((t * .08 + i * .26) % 1), C.accent)
  })
  wing(cx, cy, s, r)
  for (const n of nodes) {
    g.fillStyle = C.ink; g.globalAlpha = calm ? .7 : span(t, 3.2, 4) * .7
    g.beginPath(); g.arc(n[0], n[1], 3 * U, 0, 7); g.fill(); g.globalAlpha = 1
  }
}

// ?film&frames sends every frame to a local receiver, for making a video.
async function exportFrames() {
  await document.fonts.load('900 40px "Bodoni Moda"')
  const fps = 30
  for (let f = 0; f < FILM_LEN * fps; f++) {
    drawFilm(f / fps)
    const blob = await new Promise(r => canvas.toBlob(r, 'image/png'))
    await fetch(`/frame/${f}`, { method: 'PUT', body: blob })
  }
  await fetch('/done', { method: 'PUT' })
}

const forced = params.get('t')
window.renderAt = t => { resize(); film ? drawFilm(t) : drawPage(t) }
if (params.has('frames')) {
  exportFrames()
} else if (forced !== null) {
  document.fonts.load('900 40px "Bodoni Moda"').then(() => window.renderAt(parseFloat(forced)))
} else {
  const start = performance.now()
  const loop = now => {
    const t = (now - start) / 1000
    film ? drawFilm(t % FILM_LEN) : drawPage(t)
    if (!calm || film) requestAnimationFrame(loop)
  }
  requestAnimationFrame(loop)
}

if (!film) {
  document.getElementById('prompt').textContent = PROMPT
  document.getElementById('repo').href = REPO
  const hint = document.getElementById('hint')
  document.getElementById('wing').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(PROMPT)
      hint.textContent = 'Copied. Paste it to your agent.'
    } catch {
      hint.textContent = 'Copy the text below'
    }
  })
}
