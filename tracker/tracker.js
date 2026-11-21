// Live attack tracker. Everything in an event (usernames, paths, commands) comes from attackers:
// it reaches the page only through esc(), and the CSP allows no inline script.
"use strict";
const $ = id => document.getElementById(id);
// Same server by default; the copy on GitHub Pages names the honeypot's API here (LinkedIn distrusts sslip.io links)
const API = document.querySelector('meta[name="tracker-api"]')?.content ?? "";
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = n => Number(n).toLocaleString("en-US");
const regions = new Intl.DisplayNames(["en"], { type: "region" });
const countryName = cc => { try { return cc && cc !== "ZZ" ? regions.of(cc) : "Unknown"; } catch { return cc; } };
const flag = cc => /^[A-Z]{2}$/.test(cc || "") && cc !== "ZZ" ? String.fromCodePoint(...[...cc].map(c => 0x1f1e6 + c.charCodeAt(0) - 65)) : "";
const ago = iso => {
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  return s < 60 ? `${Math.round(s)} s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`;
};
let hours = 24, feed = [], lastEvent = null, live = false;

// ---------- charts ----------
function hbar(rows, { label = r => r.key, L = 170, color = "var(--s1)" } = {}) {
  if (!rows.length) return `<p class="empty">Nothing yet.</p>`;
  const W = 640, R = 60, bh = 16, rowH = 26, H = rows.length * rowH + 4, max = Math.max(...rows.map(r => r.count));
  const x = v => L + (W - L - R) * v / max;
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img">`;
  s += `<line x1="${L}" x2="${L}" y1="0" y2="${H}" stroke="var(--axis)"/>`;
  rows.forEach((r, i) => {
    const y = i * rowH + (rowH - bh) / 2, w = Math.max(1, x(r.count) - L), name = esc(label(r));
    const fit = Math.floor((L - 12) / 6.6);  // characters that fit left of the axis
    s += `<text x="${L - 8}" y="${y + bh / 2 + 4}" text-anchor="end">${name.length > fit ? name.slice(0, fit - 1) + "…" : name}</text>`;
    s += w > 4 ? `<path d="M${L},${y}h${w - 4}a4,4 0 0 1 4,4v${bh - 8}a4,4 0 0 1 -4,4h${-(w - 4)}z" fill="${color}"/>`
               : `<rect x="${L}" y="${y}" width="${w}" height="${bh}" fill="${color}"/>`;
    s += `<text class="val" x="${L + w + 6}" y="${y + bh / 2 + 4}">${fmt(r.count)}</text>`;
    s += `<rect x="0" y="${y - 3}" width="${W}" height="${bh + 6}" fill="transparent" data-tip="${esc(`<b>${esc(label(r))}</b><br>${fmt(r.count)} events`)}"/>`;
  });
  return s + "</svg>";
}

function timeline(byHour) {
  // Fill empty hours (or days for long ranges) with zero so gaps show as gaps
  const perDay = hours > 48, step = perDay ? 864e5 : 36e5, n = perDay ? hours / 24 : hours;
  const key = d => perDay ? d.toISOString().slice(0, 10) : d.toISOString().slice(0, 13);
  const counts = {};
  for (const r of byHour) { const k = perDay ? r.key.slice(0, 10) : r.key; counts[k] = (counts[k] || 0) + r.count; }
  const end = new Date(Math.floor(Date.now() / step) * step);
  const buckets = Array.from({ length: n }, (_, i) => { const d = new Date(end - (n - 1 - i) * step); return { d, v: counts[key(d)] || 0 }; });
  const W = 720, H = 180, L = 44, B = 22, bw = (W - L) / n, max = Math.max(4, ...buckets.map(b => b.v));
  const stepY = Math.pow(10, Math.floor(Math.log10(max))), top = Math.ceil(max / stepY) * stepY, y = v => (H - B) * (1 - v / top);
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Attacks per ${perDay ? "day" : "hour"}">`;
  for (const t of [0, top / 2, top]) s += `<line x1="${L}" x2="${W}" y1="${y(t)}" y2="${y(t)}" stroke="var(--grid)"/><text class="tick" x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${fmt(t)}</text>`;
  buckets.forEach((b, i) => {
    const x0 = L + i * bw + 1, h = (H - B) - y(b.v), when = perDay ? b.d.toLocaleDateString([], { month: "short", day: "numeric" })
      : b.d.toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });
    if (b.v) s += `<path d="M${x0},${H - B}v${-Math.max(0, h - 2)}a2,2 0 0 1 2,-2h${Math.max(0, bw - 6)}a2,2 0 0 1 2,2v${Math.max(0, h - 2)}z" fill="var(--s1)"/>`;
    s += `<rect x="${x0 - 1}" y="0" width="${bw}" height="${H - B}" fill="transparent" data-tip="${esc(`<b>${when}</b><br>${fmt(b.v)} events`)}"/>`;
    if (i % Math.ceil(n / 8) === 0) s += `<text class="tick" x="${x0 + bw / 2}" y="${H - 6}" text-anchor="middle">${perDay ? b.d.toLocaleDateString([], { month: "short", day: "numeric" }) : b.d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</text>`;
  });
  return s + "</svg>";
}

// Shadow mode: per service, the share of real attack flows the detector would ALERT on, send to REVIEW, or ALLOW
const DECISIONS = [["ALERT", "var(--critical)", "alert (known attack pattern)"], ["REVIEW", "var(--warning)", "analyst review"],
                   ["ALLOW", "var(--muted)", "allowed: missed"]];
function shadowChart(rows) {
  if (!rows.length) return `<p class="empty">Waiting for the first hourly run.</p>`;
  const W = 640, L = 110, R = 70, bh = 16, rowH = 26, H = rows.length * rowH + 4;
  let s = `<div class="legend">${DECISIONS.map(([d, c, t]) => `<span><i style="background:${c}"></i>${d}: ${t}</span>`).join("")}</div>`;
  s += `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Detector decisions per service">`;
  rows.forEach((r, i) => {
    const y = i * rowH + (rowH - bh) / 2;
    let x = L;
    s += `<text x="${L - 8}" y="${y + bh / 2 + 4}" text-anchor="end">${esc(r.key)}</text>`;
    DECISIONS.forEach(([d, c]) => {
      const w = (W - L - R) * r[d] / r.flows;
      if (w > 0) s += `<rect x="${x}" y="${y}" width="${Math.max(0, w - 2)}" height="${bh}" fill="${c}"/>`;  // 2px gap between segments
      x += w;
    });
    const flagged = (r.ALERT + r.REVIEW) / r.flows;
    s += `<text class="val" x="${W - R + 6}" y="${y + bh / 2 + 4}">${Math.round(flagged * 100)}% flagged</text>`;
    const tip = `<b>${esc(r.key)}</b><br>${fmt(r.flows)} flows<br>ALERT ${fmt(r.ALERT)} · REVIEW ${fmt(r.REVIEW)} · ALLOW ${fmt(r.ALLOW)}`;
    s += `<rect x="0" y="${y - 3}" width="${W}" height="${bh + 6}" fill="transparent" data-tip="${esc(tip)}"/>`;
  });
  return s + "</svg>";
}

async function loadShadow() {
  const s = await fetch(`${API}api/shadow?hours=${hours}`).then(r => r.json());
  const pct = v => `${Math.round(v * 100)}%`, d = s.decisions;
  $("shadow-summary").textContent = s.flows
    ? `Of ${fmt(s.flows)} attack flows, the detector would have flagged ${pct(s.flagged_share)} (${fmt(d.ALERT)} alerts, ${fmt(d.REVIEW)} for review) and let ${pct(d.ALLOW / s.flows)} through.`
    : "";
  $("shadow").innerHTML = shadowChart(s.by_service.slice(0, 12));
}

const table = (rows, head, cell) => rows.length
  ? `<table><thead><tr><th>${head}</th><th class="num">Times</th></tr></thead><tbody>${rows.map(r => `<tr><td class="mono wrap">${cell(r)}</td><td class="num">${fmt(r.count)}</td></tr>`).join("")}</tbody></table>`
  : `<p class="empty">Nothing yet.</p>`;

// ---------- data ----------
async function loadStats() {
  const s = await fetch(`${API}api/stats?hours=${hours}`).then(r => r.json());
  const range = hours === 24 ? "last 24 hours" : `last ${hours / 24} days`;
  const topService = s.by_service[0];
  lastEvent = s.last_event || lastEvent;
  $("tiles").innerHTML = [
    ["Attacks", fmt(s.events), range],
    ["Distinct sources", fmt(s.distinct_sources), "addresses, counted per day"],
    ["Countries", fmt(s.countries), "where the sources are"],
    ["Login attempts", fmt(s.login_attempts), "passwords guessed"],
    ["Most attacked", topService ? esc(topService.key) : "–", topService ? `${fmt(topService.count)} events` : "no events yet"],
    ["Last attack", lastEvent ? ago(lastEvent) : "–", lastEvent ? new Date(lastEvent).toLocaleString() : "waiting for the first one"],
  ].map(([l, v, n]) => `<div class="tile"><div class="label">${l}</div><div class="value">${v}</div><div class="note">${n}</div></div>`).join("");
  $("timeline-title").textContent = hours > 48 ? "Attacks per day" : "Attacks per hour";
  $("timeline").innerHTML = timeline(s.by_hour);
  $("countries").innerHTML = hbar(s.by_country, { label: r => `${flag(r.key)} ${countryName(r.key)}`.trim() });
  $("services").innerHTML = hbar(s.by_service);
  $("techniques").innerHTML = hbar(s.by_technique, { L: 290, color: "var(--s2)" });
  $("usernames").innerHTML = table(s.usernames, "Username", r => esc(r.key));
  $("paths").innerHTML = table(s.paths, "Path", r => esc(r.key));
  $("retention").textContent = s.retention_days;
}

function detail(e) {
  const d = e.username !== undefined ? `user <b>${esc(e.username)}</b>` : e.path !== undefined ? esc(e.path) : e.command !== undefined ? esc(e.command) : e.filename !== undefined ? esc(e.filename) : "";
  return `<span class="mono wrap">${d}</span>`;
}

function renderFeed(fresh = 0) {
  $("feed").innerHTML = feed.length ? feed.map((e, i) => `<tr class="${i < fresh ? "new" : ""}">
    <td class="nowrap">${esc(new Date(e.ts).toLocaleTimeString())}</td>
    <td class="nowrap" title="${esc(countryName(e.country))}">${flag(e.country)} ${esc(e.country)}</td>
    <td class="mono nowrap">${esc(e.src)}</td>
    <td class="nowrap">${esc(e.service)}<span class="dim">:${esc(e.port)}</span></td>
    <td class="nowrap">${esc(e.action)}</td>
    <td>${detail(e)}</td>
    <td class="nowrap dim" title="${esc(e.technique)}">${esc((e.technique || "").split(" ")[0])}</td></tr>`).join("")
    : `<tr><td colspan="7" class="empty">Waiting for the first attack. On a new honeypot it usually takes a few minutes.</td></tr>`;
}

function status(text, on) {
  $("status").className = "pill" + (on ? " on" : "");
  $("status").lastElementChild.textContent = text;
}

function connect() {
  const es = new EventSource(`${API}api/stream`);
  es.onopen = () => { live = true; status("Live", true); };
  es.onmessage = m => {
    const e = JSON.parse(m.data);
    feed.unshift(e); if (feed.length > 80) feed.pop();
    lastEvent = e.ts;
    renderFeed(1);
  };
  es.onerror = () => { live = false; status("Reconnecting…", false); };  // EventSource retries by itself
}

// ---------- tooltips and controls ----------
document.addEventListener("pointermove", ev => {
  const t = ev.target.closest?.("[data-tip]"), tip = $("tip");
  if (!t) { tip.style.opacity = 0; return; }
  tip.innerHTML = t.dataset.tip;  // built from esc()'d text above
  tip.style.left = Math.min(ev.clientX + 14, innerWidth - tip.offsetWidth - 8) + "px";
  tip.style.top = ev.clientY + 14 + "px";
  tip.style.opacity = 1;
});
$("range").onclick = ev => {
  const b = ev.target.closest("button"); if (!b) return;
  for (const x of $("range").children) x.setAttribute("aria-pressed", x === b);
  hours = +b.dataset.h; loadStats(); loadShadow().catch(() => {});
};

fetch(`${API}api/events?limit=80`).then(r => r.json()).then(rows => { feed = rows; renderFeed(); }).catch(() => renderFeed());
loadStats().catch(() => status("Tracker offline", false));
loadShadow().catch(() => {});
connect();
setInterval(() => { loadStats().catch(() => {}); loadShadow().catch(() => {}); }, 60000);
setInterval(() => {  // keep "Last attack" counting between stats refreshes
  const v = document.querySelector("#tiles .tile:last-child .value");
  if (v && lastEvent) v.textContent = ago(lastEvent);
}, 5000);
