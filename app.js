/* Roadbook nautique – single page app (offline-first PWA).
   Data: data.json (trip, tides, ports, charts catalogue), atlas.bin (SHOM tidal-current atlas subset), charts/*.jpg.
   Optional AES-GCM encryption of every data file (keys.json present). Weather from Open-Meteo on demand.
   All computations mirror the desktop pipeline (scripts/plan.py, currents.py, tides.py, weather.py). */
'use strict';

const TZ = 'Europe/Paris';
const KN = 3600 / 1852;
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const num = (x, n = 2) => (x == null || !isFinite(x)) ? '–' : x.toFixed(n).replace('.', ',');
const pad = n => String(n).padStart(2, '0');
const COMPASS = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
const compass = d => COMPASS[Math.round(((d % 360) + 360) % 360 / 22.5) % 16];
const fmtT = ms => new Date(ms).toLocaleTimeString('fr-FR', { timeZone: TZ, hour: '2-digit', minute: '2-digit' });
const fmtD = ms => new Date(ms).toLocaleDateString('fr-FR', { timeZone: TZ, weekday: 'short', day: '2-digit', month: '2-digit' });
const fmtDT = ms => fmtD(ms) + ' ' + fmtT(ms);
const dur = m => `${Math.floor(m / 60)} h ${pad(Math.round(m % 60))}`;
// November 2026 = CET = UTC+1
const cetMs = (dateStr, hh, mm) => { const [y, mo, d] = dateStr.split('-').map(Number); return Date.UTC(y, mo - 1, d, hh - 1, mm); };
const cetHM = ms => { const d = new Date(ms + 3600e3); return [d.getUTCHours(), d.getUTCMinutes()]; };

const S = { data: null, atlas: null, key: null, files: null, wx: null, prefs: {}, gps: null, gpsWatch: null,
            chartURL: {}, view: 'day', online: navigator.onLine };

/* ------------------------------------------------------------------ storage */
const DB = {
  db: null,
  open() {
    if (this.db) return Promise.resolve(this.db);
    return new Promise((res, rej) => {
      const r = indexedDB.open('roadbook', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => { this.db = r.result; res(this.db); };
      r.onerror = () => rej(r.error);
    });
  },
  async get(k) {
    try { const db = await this.open();
      return await new Promise((res, rej) => { const q = db.transaction('kv').objectStore('kv').get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
    } catch (e) { return undefined; }
  },
  async put(k, v) {
    const db = await this.open();
    return new Promise((res, rej) => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = () => res(); t.onerror = () => rej(t.error); });
  },
  async del(k) {
    const db = await this.open();
    return new Promise(res => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').delete(k); t.oncomplete = () => res(); });
  },
};
const Prefs = {
  load() { try { S.prefs = JSON.parse(localStorage.getItem('rb.prefs') || '{}'); } catch (e) { S.prefs = {}; } },
  save() { try { localStorage.setItem('rb.prefs', JSON.stringify(S.prefs)); } catch (e) { /* private mode */ } },
};

function toast(msg, ms = 3500) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.add('hidden'), ms);
}

/* ------------------------------------------------------------------ crypto + files */
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveKey(pass, k) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(k.salt), iterations: k.iter, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function decrypt(buf) {
  if (!S.files.encrypted) return buf;
  const u = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, S.key, u.slice(12));
}
function fileURL(path) {
  const f = S.files.files[path];
  return f ? `${f.url}?h=${f.hash}` : path;
}
async function fetchFile(path) {
  const r = await fetch(fileURL(path));
  if (!r.ok) throw new Error(`${path}: HTTP ${r.status}`);
  return decrypt(await r.arrayBuffer());
}
async function loadFilesManifest(network) {
  if (network) {
    const r = await fetch('files.json', { cache: 'no-store' });
    if (!r.ok) throw new Error('files.json ' + r.status);
    return r.json();
  }
  const r = await fetch('files.json');
  return r.json();
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  Prefs.load();
  applyTheme();
  setupChrome();
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').then(reg => {
      reg.addEventListener('updatefound', () => {
        const w = reg.installing; if (!w) return;
        w.addEventListener('statechange', () => {
          if (w.state === 'installed' && navigator.serviceWorker.controller) toast('Nouvelle version de l\'application : elle sera active au prochain lancement.', 6000);
        });
      });
    }).catch(() => {});
  }
  try {
    S.files = (await DB.get('files')) || await loadFilesManifest(false);
  } catch (e) {
    $('#loadMsg').textContent = 'Impossible de lire files.json : ouvrez l\'application une première fois avec une connexion.';
    return;
  }
  if (S.files.encrypted) {
    S.key = await DB.get('key');
    if (!S.key && S.prefs.pass) S.key = await deriveKey(S.prefs.pass, S.files.kdf);
    if (!S.key) return showLock();
  }
  await loadData();
}

function showLock() {
  $('#loading').classList.add('hidden'); $('#lock').classList.remove('hidden'); $('#tabs').classList.add('hidden');
  $('#lockForm').onsubmit = async ev => {
    ev.preventDefault();
    const pass = $('#pass').value; $('#lockMsg').textContent = 'Vérification…';
    try {
      const key = await deriveKey(pass, S.files.kdf);
      S.key = key;
      const chk = new TextDecoder().decode(await decrypt(b64(S.files.kdf.check).buffer));
      if (chk !== 'roadbook-ok') throw new Error('bad');
      try { await DB.put('key', key); } catch (e) { S.prefs.pass = pass; Prefs.save(); }   // fallback if CryptoKey not storable
      $('#lock').classList.add('hidden'); $('#loading').classList.remove('hidden');
      await loadData();
    } catch (e) { S.key = null; $('#lockMsg').textContent = 'Phrase de passe incorrecte.'; }
  };
}

async function loadData() {
  $('#loadMsg').textContent = 'Lecture des données…';
  const stored = await DB.get('data');
  if (stored && stored.version === S.files.version) {
    S.data = stored.data; S.atlas = stored.atlas;
  } else {
    try {
      const d = JSON.parse(new TextDecoder().decode(await fetchFile('data.json')));
      const a = new Int16Array(await fetchFile('atlas.bin'));
      S.data = d; S.atlas = a;
      await DB.put('data', { version: S.files.version, data: d, atlas: a });
      await DB.put('files', S.files);
    } catch (e) {
      if (stored) { S.data = stored.data; S.atlas = stored.atlas; toast('Données locales utilisées (mise à jour impossible).'); }
      else { $('#loadMsg').textContent = 'Données indisponibles hors connexion : ouvrez l\'application une première fois avec une connexion. ' + e.message; return; }
    }
  }
  S.wx = await DB.get('weather');
  initAtlas();
  S.prefs.deps = S.prefs.deps || {};
  S.prefs.speed = S.prefs.speed || 5.0;
  S.prefs.day = S.prefs.day || defaultDay();
  $('#loading').classList.add('hidden'); $('#tabs').classList.remove('hidden');
  buildDayChips(); buildSpeedSeg(); buildTideSelectors();
  show(S.prefs.view || 'trip');
  if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
}

function defaultDay() {
  const now = Date.now();
  for (const [k, d] of Object.entries(S.data.days)) if (fmtISO(now) === d.date) return k;
  return '1';
}
const fmtISO = ms => { const d = new Date(ms + 3600e3); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`; };

/* ------------------------------------------------------------------ chrome */
function setupChrome() {
  $$('#tabs button').forEach(b => b.onclick = () => show(b.dataset.v));
  const upd = () => { S.online = navigator.onLine; const b = $('#netBadge'); b.textContent = S.online ? 'En ligne' : 'Hors ligne'; b.className = 'badge' + (S.online ? '' : ' off'); };
  window.addEventListener('online', upd); window.addEventListener('offline', upd); upd();
  $('#themeBtn').onclick = () => { S.prefs.theme = S.prefs.theme === 'night' ? 'day' : 'night'; Prefs.save(); applyTheme(); if (S.view === 'tides') renderTides(); };
  $('#gpsBadge').onclick = () => show('nav');
}
function applyTheme() {
  document.documentElement.dataset.theme = S.prefs.theme === 'night' ? 'night' : 'day';
  $('#themeBtn').textContent = S.prefs.theme === 'night' ? 'Jour' : 'Nuit';
}
function show(v) {
  if (!S.data) return;
  S.view = v; S.prefs.view = v; Prefs.save();
  $$('.view').forEach(e => e.classList.add('hidden'));
  $(`#v-${v}`).classList.remove('hidden');
  $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.v === v));
  ({ trip: renderTrip, day: renderDay, charts: renderCharts, tides: renderTides, weather: renderWeather, nav: renderNav, ports: renderPorts, info: renderInfo })[v]();
  window.scrollTo(0, 0);
}

/* ------------------------------------------------------------------ geodesy */
const R_E = 6371008.8, RM = 6378137;
const rad = d => d * Math.PI / 180, deg = r => r * 180 / Math.PI;
function distNM(la1, lo1, la2, lo2) {
  const p1 = rad(la1), p2 = rad(la2), dp = p2 - p1, dl = rad(lo2 - lo1);
  const a = Math.sin(dp / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dl / 2) ** 2;
  return 2 * R_E * Math.asin(Math.sqrt(a)) / 1852;
}
function bearing(la1, lo1, la2, lo2) {
  const p1 = rad(la1), p2 = rad(la2), dl = rad(lo2 - lo1);
  return (deg(Math.atan2(Math.sin(dl) * Math.cos(p2), Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl))) + 360) % 360;
}
const merc = (lat, lon) => [RM * rad(lon), RM * Math.log(Math.tan(Math.PI / 4 + rad(lat) / 2))];
function fmtPos(lat, lon) {
  const f = (v, h, w) => { const a = Math.abs(v), d = Math.floor(a), m = (a - d) * 60; return `${String(d).padStart(w, '0')}°${m.toFixed(2).padStart(5, '0').replace('.', ',')}'${h}`; };
  return `${f(lat, lat >= 0 ? 'N' : 'S', 2)} ${f(lon, lon >= 0 ? 'E' : 'W', 3)}`;
}

/* ------------------------------------------------------------------ tides */
function tideH(port, t) {
  const s = S.data.tides[port]; const x = (t - s.t0) / s.step; const i = Math.floor(x);
  if (i < 0 || i >= s.h.length - 1) return { h: NaN, src: '?' };
  const f = x - i;
  return { h: s.h[i] * (1 - f) + s.h[i + 1] * f, src: s.src[Math.round(x)] };
}
function trend(port, t) {
  const a = tideH(port, t - 900e3).h, b = tideH(port, t + 900e3).h;
  return b > a + 0.01 ? 'montante' : b < a - 0.01 ? 'descendante' : 'étale';
}
function access(code, t) {
  const p = S.data.ports[code], B = S.data.boat;
  const { h, src } = tideH(p.tide, t);
  const water = p.depth + h, req = B.draft + B.margin - p.depth;
  return { h, src, water, ukc: water - B.draft, req, ok: h >= req, trend: trend(p.tide, t) };
}

/* ------------------------------------------------------------------ currents (SHOM atlas) */
let A = null;
function initAtlas() {
  const m = S.data.atlas; const [nc, nt, ny, nx] = m.shape;
  A = { ...m, nc, nt, ny, nx, n: nc * nt * ny * nx, hw: S.data.concarneauHW };
}
function phaseMin(t) {
  const hw = A.hw;
  for (let i = 0; i < hw.length - 1; i++) {
    const a = hw[i].t, b = hw[i + 1].t;
    if (t >= a && t < b) { const f = (t - a) / (b - a); return f < 0.5 ? f * 720 : (f - 1) * 720; }
  }
  return null;
}
function coefAt(t) {
  const hw = A.hw;
  if (t <= hw[0].t) return hw[0].coef;
  for (let i = 0; i < hw.length - 1; i++) if (t < hw[i + 1].t) { const f = (t - hw[i].t) / (hw[i + 1].t - hw[i].t); return hw[i].coef * (1 - f) + hw[i + 1].coef * f; }
  return hw[hw.length - 1].coef;
}
const aIdx = (comp, c, k, j, i) => comp * A.n + ((c * A.nt + k) * A.ny + j) * A.nx + i;
function searchsorted(arr, v) { let lo = 0, hi = arr.length; while (lo < hi) { const m = (lo + hi) >> 1; if (arr[m] < v) lo = m + 1; else hi = m; } return lo; }
function current(lat, lon, t) {
  const ph = phaseMin(t); if (ph == null) return null;
  const c = coefAt(t);
  const j = searchsorted(A.lat, lat) - 1, i = searchsorted(A.lon, lon) - 1;
  if (j < 0 || i < 0 || j >= A.ny - 1 || i >= A.nx - 1) return null;
  const fy = (lat - A.lat[j]) / (A.lat[j + 1] - A.lat[j]), fx = (lon - A.lon[i]) / (A.lon[i + 1] - A.lon[i]);
  const W = [[j, i, (1 - fy) * (1 - fx)], [j, i + 1, (1 - fy) * fx], [j + 1, i, fy * (1 - fx)], [j + 1, i + 1, fy * fx]];
  const k = Math.min(Math.max(searchsorted(A.minutes, ph) - 1, 0), A.nt - 2);
  const ft = (ph - A.minutes[k]) / (A.minutes[k + 1] - A.minutes[k]);
  const val = (comp, cc) => {
    let s = 0, w = 0;
    for (const [jj, ii, ww] of W) {
      const a0 = A.data[aIdx(comp, cc, k, jj, ii)], a1 = A.data[aIdx(comp, cc, k + 1, jj, ii)];
      if (a0 === A.nodata || a1 === A.nodata) continue;
      s += ww * ((a0 * (1 - ft) + a1 * ft) * A.scale); w += ww;
    }
    return w > 0 ? s / w : null;
  };
  const u45 = val(0, 0), u95 = val(0, 1), v45 = val(1, 0), v95 = val(1, 1);
  if (u45 == null || u95 == null || v45 == null || v95 == null) return null;
  const a = (c - A.coeffs[0]) / (A.coeffs[1] - A.coeffs[0]);
  const ue = (u45 + a * (u95 - u45)) * KN, vn = (v45 + a * (v95 - v45)) * KN;
  return { ue, vn, rate: Math.hypot(ue, vn), set: (deg(Math.atan2(ue, vn)) + 360) % 360, coef: c, phase: ph };
}
function initAtlasData() { if (!A.data) A.data = S.atlas; }

/* ------------------------------------------------------------------ passage simulation */
const trackCache = {};
function track(key) {
  if (trackCache[key]) return trackCache[key];
  const L = S.data.legs[key], P = S.data.waypoints, out = [];
  for (const s of L.segments) {
    const a = P[s.from], b = P[s.to];
    const n = Math.max(1, Math.ceil(s.nm / 0.4));
    for (let q = 0; q < n; q++) {
      const f0 = q / n, f1 = (q + 1) / n;
      const la0 = a.lat + (b.lat - a.lat) * f0, lo0 = a.lon + (b.lon - a.lon) * f0;
      const la1 = a.lat + (b.lat - a.lat) * f1, lo1 = a.lon + (b.lon - a.lon) * f1;
      out.push({ lat: (la0 + la1) / 2, lon: (lo0 + lo1) / 2, course: bearing(la0, lo0, la1, lo1), nm: distNM(la0, lo0, la1, lo1), from: s.from, to: s.to });
    }
  }
  return (trackCache[key] = out);
}
function simulate(key, dep, stw) {
  initAtlasData();
  let t = dep; const log = [];
  for (const x of track(key)) {
    let tm = t, along = 0, cross = 0, sog = stw, cur = null, dt = 0;
    for (let it = 0; it < 2; it++) {
      cur = current(x.lat, x.lon, tm);
      const ue = cur ? cur.ue : 0, vn = cur ? cur.vn : 0, r = rad(x.course);
      along = ue * Math.sin(r) + vn * Math.cos(r); cross = ue * Math.cos(r) - vn * Math.sin(r);
      sog = Math.sqrt(Math.max(stw * stw - cross * cross, 0.01)) + along;
      dt = x.nm / Math.max(sog, 0.5) * 3600e3; tm = t + dt / 2;
    }
    log.push({ t, ...x, set: cur ? cur.set : null, rate: cur ? cur.rate : null, along, cross, sog, coef: cur ? cur.coef : null });
    t += dt;
  }
  return { arr: t, log };
}
function legInfo(key) {
  const L = S.data.legs[key]; return { from: L.wps[0], to: L.wps[L.wps.length - 1], nm: L.segments.reduce((a, s) => a + s.nm, 0) };
}
function evaluate(key, dep, stw) {
  const { arr, log } = simulate(key, dep, stw); const li = legInfo(key);
  const nocur = li.nm / stw * 60, durm = (arr - dep) / 60e3;
  const eta = {}; for (const x of log) if (!(x.from in eta)) eta[x.from] = x.t; eta[li.to] = arr;
  return { key, dep, arr, stw, nm: li.nm, dur: durm, gain: nocur - durm, log, eta,
           accDep: access(li.from, dep), accArr: access(li.to, arr), from: li.from, to: li.to };
}
function windowScan(key, date, stw) {
  const out = [];
  for (let m = 5 * 60; m <= 12 * 60 + 30; m += 5) {
    const dep = cetMs(date, Math.floor(m / 60), m % 60); const e = evaluate(key, dep, stw);
    out.push({ dep, ok: e.accDep.ok && e.accArr.ok && e.arr <= cetMs(date, 16, 0) });
  }
  const segs = []; let cur = null;
  for (const o of out) { if (o.ok && !cur) cur = [o.dep, o.dep]; else if (o.ok) cur[1] = o.dep; else if (cur) { segs.push(cur); cur = null; } }
  if (cur) segs.push(cur);
  return segs.map(([a, b]) => fmtT(a) === '05:00' ? `≤ ${fmtT(b)}` : fmtT(b) === '12:30' ? `≥ ${fmtT(a)}` : `${fmtT(a)}–${fmtT(b)}`);
}
function periods(log, thr = 0.1) {
  const out = [];
  for (const x of log) {
    const k = x.along > thr ? 'fav' : x.along < -thr ? 'adv' : 'neutre';
    const last = out[out.length - 1];
    if (last && last.k === k) { last.t1 = x.t; last.max = Math.max(last.max, Math.abs(x.along)); }
    else out.push({ k, t0: x.t, t1: x.t, max: Math.abs(x.along) });
  }
  return out.filter(p => p.t1 - p.t0 >= 20 * 60e3 || out.length === 1);
}

/* ------------------------------------------------------------------ day / plan-B selection */
function allKeys() { return [...Object.keys(S.data.days), ...Object.keys(S.data.planB)]; }
function keyInfo(k) {
  if (S.data.days[k]) return { ...S.data.days[k], label: `J${k}`, main: true };
  const b = S.data.planB[k]; return { ...b, label: k, main: false };
}
function depFor(k) { return S.prefs.deps[k] || keyInfo(k).dep; }
function buildDayChips() {
  const el = $('#dayChips'); el.innerHTML = '';
  for (const k of allKeys()) {
    const ki = keyInfo(k); const P = S.data.ports;
    const b = document.createElement('button'); b.className = 'chip' + (k === S.prefs.day ? ' on' : '');
    b.innerHTML = ki.main ? `${ki.label} ${fmtD(cetMs(ki.date, 12, 0))}<small>${esc(P[ki.from].short)} → ${esc(P[ki.to].short)}</small>`
                          : `Plan ${k}<small>${esc(P[ki.from].short)} → ${esc(P[ki.to].short)}</small>`;
    b.onclick = () => { S.prefs.day = k; Prefs.save(); buildDayChips(); renderDay(); };
    el.appendChild(b);
  }
  const ki = keyInfo(S.prefs.day); $('#hdrDay').textContent = ki.main ? `· J${S.prefs.day}` : `· plan ${S.prefs.day}`;
}
function buildSpeedSeg() {
  const el = $('#speedSeg'); el.innerHTML = '';
  for (const v of [4.5, 5, 5.5, 6, 6.5]) {
    const b = document.createElement('button'); b.textContent = num(v, 1);
    b.className = Math.abs(v - S.prefs.speed) < 1e-6 ? 'on' : '';
    b.onclick = () => { S.prefs.speed = v; Prefs.save(); buildSpeedSeg(); renderDay(); };
    el.appendChild(b);
  }
}

/* ------------------------------------------------------------------ weather (Open-Meteo) */
function wxBlocks() { return S.wx ? { atm: S.wx.atm, sea: S.wx.sea, pts: S.wx.points } : null; }
function wxSeries(block, v, model) {
  const h = block.hourly; if (!h) return null;
  const key = model ? `${v}_${model}` : v; const a = h[key];
  if (!a || !a.some(x => x != null)) return null;
  if (!block._t) block._t = h.time.map(x => Date.parse(x + 'Z'));
  return { t: block._t, v: a };
}
function wxNearest(la, lo, blocks, v, model) {
  const pts = S.wx.points; const c = Math.cos(rad(la));
  const order = pts.map((p, i) => [(p[0] - la) ** 2 + ((p[1] - lo) * c) ** 2, i]).sort((a, b) => a[0] - b[0]).slice(0, 6);
  for (const [, i] of order) { const s = wxSeries(blocks[i], v, model); if (s) return s; }
  return null;
}
function wxValue(la, lo, t, v, model, sea) {
  if (!S.wx) return null;
  const s = wxNearest(la, lo, sea ? S.wx.sea : S.wx.atm, v, model); if (!s) return null;
  const i = searchsorted(s.t, t); if (i <= 0 || i >= s.t.length) return null;
  const a = s.v[i - 1], b = s.v[i]; if (a == null || b == null) return null;
  const f = (t - s.t[i - 1]) / (s.t[i] - s.t[i - 1]);
  if (v.endsWith('direction')) { const x = rad(a), y = rad(b); return (deg(Math.atan2((1 - f) * Math.sin(x) + f * Math.sin(y), (1 - f) * Math.cos(x) + f * Math.cos(y))) + 360) % 360; }
  return a * (1 - f) + b * f;
}
function wind(la, lo, t) {
  for (const m of S.data.weatherModels) {
    const sp = wxValue(la, lo, t, 'wind_speed_10m', m);
    if (sp != null) return { sp, dir: wxValue(la, lo, t, 'wind_direction_10m', m), gust: wxValue(la, lo, t, 'wind_gusts_10m', m), model: m };
  }
  return null;
}
function seaState(la, lo, t) {
  const hs = wxValue(la, lo, t, 'wave_height', null, true); if (hs == null) return null;
  return { hs, dir: wxValue(la, lo, t, 'wave_direction', null, true), tp: wxValue(la, lo, t, 'wave_period', null, true),
           swell: wxValue(la, lo, t, 'swell_wave_height', null, true), swellDir: wxValue(la, lo, t, 'swell_wave_direction', null, true) };
}
const allure = twa => { const a = Math.abs(twa); return a < 45 ? 'près serré' : a < 70 ? 'près' : a < 110 ? 'travers' : a < 150 ? 'largue' : 'vent arrière'; };
const inSector = (d, a, b) => a <= b ? d >= a && d <= b : d >= a || d <= b;
function wxAnalyse(e) {
  if (!S.wx) return null;
  const TH = S.data.thresholds; const rows = [];
  for (const x of e.log) {
    const w = wind(x.lat, x.lon, x.t); if (!w) continue;
    const twa = ((w.dir - x.course + 540) % 360) - 180;
    const wac = x.set != null && x.rate >= TH.wac_current && w.sp >= TH.wac_wind && Math.abs(((((w.dir + 180) % 360) - x.set + 540) % 360) - 180) > 135;
    rows.push({ ...w, nm: x.nm, twa, wac, t: x.t });
  }
  if (!rows.length) return { available: false };
  const nm = rows.reduce((a, r) => a + r.nm, 0);
  const res = { available: true, min: Math.min(...rows.map(r => r.sp)), max: Math.max(...rows.map(r => r.sp)),
                gust: Math.max(...rows.map(r => r.gust ?? r.sp)),
                dir: (deg(Math.atan2(rows.reduce((a, r) => a + Math.sin(rad(r.dir)) * r.nm, 0), rows.reduce((a, r) => a + Math.cos(rad(r.dir)) * r.nm, 0))) + 360) % 360,
                models: [...new Set(rows.map(r => r.model))], allures: {}, flags: [] };
  for (const r of rows) res.allures[allure(r.twa)] = (res.allures[allure(r.twa)] || 0) + r.nm / nm;
  const wac = rows.filter(r => r.wac);
  const P = S.data.ports, WP = S.data.waypoints;
  res.at = {};
  for (const [lab, t, code] of [['dep', e.dep, e.from], ['arr', e.arr, e.to]]) {
    const p = WP[P[code].entrance]; res.at[lab] = { wind: wind(p.lat, p.lon, t), sea: seaState(p.lat, p.lon, t), code };
  }
  if (res.max >= TH.wind_nogo || res.gust >= TH.gust_nogo) res.flags.push(['nogo', `vent jusqu'à ${res.max.toFixed(0)} kn, rafales ${res.gust.toFixed(0)} kn : report / repli`]);
  else if (res.max >= TH.wind_caution || res.gust >= TH.gust_caution) res.flags.push(['caution', `vent fort ${res.max.toFixed(0)} kn, rafales ${res.gust.toFixed(0)} kn`]);
  if ((res.allures['près serré'] || 0) >= 0.4) res.flags.push(['caution', `${Math.round(res.allures['près serré'] * 100)} % au près serré : moteur ou louvoyage`]);
  if (wac.length) res.flags.push(['caution', `vent contre courant ${fmtT(wac[0].t)}–${fmtT(wac[wac.length - 1].t)} : mer courte`]);
  for (const lab of ['dep', 'arr']) {
    const at = res.at[lab]; const [a, b, sw, wk, txt] = S.data.exposed[at.code];
    const s = at.sea, w = at.wind;
    if ((s && s.swell != null && s.swellDir != null && s.swell >= sw && inSector(s.swellDir, a, b)) || (w && w.sp >= wk && inSector(w.dir, a, b))) res.flags.push(['caution', txt]);
    if (s && s.hs >= TH.hs_nogo) res.flags.push(['nogo', `mer ${num(s.hs, 1)} m à l'approche de ${P[at.code].short}`]);
    else if (s && s.hs >= TH.hs_caution) res.flags.push(['caution', `mer ${num(s.hs, 1)} m à l'approche de ${P[at.code].short}`]);
  }
  return res;
}
async function updateWeather() {
  const btn = $('#wxUpdate'); btn.disabled = true; $('#wxStatus').textContent = 'Téléchargement…';
  try {
    const pts = S.data.weatherPoints; const lat = pts.map(p => p[0]).join(','), lon = pts.map(p => p[1]).join(',');
    const T = S.data.trip; const start = T.wxStart;
    const end = new Date(Math.min(Date.parse(T.wxEnd + 'T00:00:00Z'), Date.now() + 15 * 86400e3)).toISOString().slice(0, 10);
    if (end < start) throw new Error('prévision pas encore disponible (horizon 16 jours)');
    const q = (base, o) => base + '?' + new URLSearchParams(o).toString();
    const ra = await fetch(q('https://api.open-meteo.com/v1/forecast', { latitude: lat, longitude: lon,
      hourly: 'wind_speed_10m,wind_direction_10m,wind_gusts_10m', wind_speed_unit: 'kn', timezone: 'UTC', start_date: start, end_date: end,
      models: S.data.weatherModels.join(',') }));
    if (!ra.ok) throw new Error('Open-Meteo ' + ra.status + ' ' + (await ra.text()).slice(0, 120));
    let atm = await ra.json(); if (!Array.isArray(atm)) atm = [atm];
    let sea = [];
    try {
      const rs = await fetch(q('https://marine-api.open-meteo.com/v1/marine', { latitude: lat, longitude: lon, timezone: 'UTC', start_date: start, end_date: end,
        hourly: 'wave_height,wave_direction,wave_period,swell_wave_height,swell_wave_direction,swell_wave_period' }));
      if (rs.ok) { sea = await rs.json(); if (!Array.isArray(sea)) sea = [sea]; }
    } catch (e) { /* marine optional */ }
    S.wx = { run: Date.now(), points: pts, atm, sea };
    await DB.put('weather', S.wx);
    toast('Météo mise à jour et enregistrée.');
  } catch (e) {
    toast('Mise à jour météo impossible : ' + e.message, 6000);
  }
  btn.disabled = false; renderWeather();
}

/* ------------------------------------------------------------------ view: itinerary (= PDF pages 1-3 + annex) */
async function renderTrip() {
  const D = S.data, P = D.ports, sp = S.prefs.speed;
  const E = {}; for (const k of Object.keys(D.days)) E[k] = evaluate(k, depFor(k), sp);
  const tot = Object.values(E).reduce((a, e) => a + e.nm, 0);
  const custom = Object.keys(D.days).some(k => S.prefs.deps[k]);
  let h = `<h1>Itinéraire · ${esc(D.trip.title)}</h1>
    <p class="muted">${esc(D.trip.period)} · ${esc(D.boat.name)}, tirant d'eau ${num(D.boat.draft)} m · place : ${esc(D.boat.berth)} ·
    heures CET (UTC+1) · routes vraies (°V) · milles (M). Calculs à <b>${num(sp, 1)} kn</b>${custom ? ' avec vos heures de départ' : ' avec les heures conseillées'}
    (modifiables dans l'onglet Étape).</p>
    <button id="ovBtn" class="ghost" style="width:100%;padding:0;overflow:hidden"><img id="ovImg" alt="Carte de l'itinéraire" style="width:100%;display:block"></button>`;
  h += `<h2>Les 6 étapes</h2><div class="scroll"><table><tr><th>Jour</th><th>Trajet</th><th class="num">Départ</th><th class="num">Arrivée</th><th class="num">Distance</th><th class="num">Durée</th><th>Courant</th><th></th></tr>`;
  for (const [k, e] of Object.entries(E)) {
    const late = e.arr > cetMs(D.days[k].date, 16, 0);
    h += `<tr><td><b>J${k}</b> ${fmtD(e.dep)}</td><td>${esc(P[e.from].short)} → ${esc(P[e.to].short)}</td><td class="num"><b>${fmtT(e.dep)}</b></td>
      <td class="num ${late ? 'bad' : ''}"><b>${fmtT(e.arr)}</b></td><td class="num">${num(e.nm, 1)} M</td><td class="num">${dur(e.dur)}</td>
      <td>${e.gain >= 0 ? '+' : '−'}${Math.abs(e.gain).toFixed(0)} min</td><td><button class="ghost" data-day="${k}">Voir</button></td></tr>`;
  }
  h += `<tr><td></td><td><b>Total</b></td><td></td><td></td><td class="num"><b>${num(tot, 1)} M</b></td><td></td><td></td><td></td></tr></table></div>`;
  // timetable, tides, access (PDF p. 2)
  h += `<h2>Horaires, marées et accès</h2><div class="scroll"><table><tr><th>Jour</th><th>Fenêtre de départ*</th><th>Marée départ</th><th class="num">EsQ dép.</th><th>Marée arrivée</th><th class="num">EsQ arr.</th><th>Coef.</th><th>Soleil</th></tr>`;
  for (const [k, e] of Object.entries(E)) {
    const d = D.days[k], sun = D.sun[e.from][d.date];
    const tag = a => `<span class="tag ${a.src}">${a.src === 'S' ? 'Shom' : 'calcul'}</span>`;
    h += `<tr><td><b>J${k}</b></td><td>${windowScan(k, d.date, sp).join(' et ') || '<span class="bad">aucune</span>'}</td>
      <td>${num(e.accDep.h)} m ${e.accDep.trend} ${tag(e.accDep)}</td><td class="num ${e.accDep.ok ? 'ok' : 'bad'}">${num(e.accDep.ukc)}</td>
      <td>${num(e.accArr.h)} m ${e.accArr.trend} ${tag(e.accArr)}</td><td class="num ${e.accArr.ok ? 'ok' : 'bad'}">${num(e.accArr.ukc)}</td>
      <td>${d.coef.join(' / ')}</td><td>${fmtT(sun.sunrise)}–${fmtT(sun.sunset)}</td></tr>`;
  }
  h += `</table></div><p class="muted">* Départs (pas de 5 min, 05:00–12:30) avec assez d'eau au départ et à l'arrivée, et arrivée avant 16:00. EsQ = eau sous quille (m), accès accepté si ≥ ${num(D.boat.margin)} m.</p>`;
  h += `<h3>Pourquoi ces heures de départ</h3><ul class="plain">${Object.entries(D.days).map(([k, d]) => `<li><b>J${k} ${fmtD(d.dep)}</b> – ${esc(d.rationale)}</li>`).join('')}</ul>`;
  h += `<h3>Accès peu profonds : sondes retenues</h3><ul class="plain">${Object.values(P).map(p => `<li><b>${esc(p.short)}</b> : ${num(p.depth, 1)} m → marée mini ${num(D.boat.draft + D.boat.margin - p.depth)} m (${esc(p.where)}).</li>`).join('')}</ul>`;
  // tidal streams (PDF p. 3)
  h += `<h2>Courants de marée le long des routes</h2><div class="scroll"><table><tr><th>Jour</th><th>Coef.</th><th>Périodes favorables / défavorables</th><th>Max rencontré</th><th class="num">Effet</th></tr>`;
  for (const [k, e] of Object.entries(E)) {
    const per = periods(e.log).filter(p => p.k !== 'neutre');
    const mx = e.log.filter(x => x.rate != null).reduce((a, x) => (!a || x.rate > a.rate) ? x : a, null);
    h += `<tr><td><b>J${k}</b></td><td>${D.days[k].coef.join(' / ')}</td>
      <td>${per.map(p => `${fmtT(p.t0)}–${fmtT(p.t1)} <span class="${p.k}">${p.k === 'fav' ? 'fav.' : 'déf.'}</span> ≤ ${num(p.max, 1)} kn`).join(' · ') || 'faible'}</td>
      <td>${mx ? `${num(mx.rate, 1)} kn vers ${Math.round(mx.set).toString().padStart(3, '0')}° à ${fmtT(mx.t)}` : '–'}</td>
      <td class="num">${e.gain >= 0 ? '+' : '−'}${Math.abs(e.gain).toFixed(0)} min</td></tr>`;
  }
  h += `</table></div><p class="muted">Atlas Shom 565 reconstitué aux dates (PM de Concarneau, coefficients Shom). Effet + = gain de temps.</p>`;
  h += `<h2>Météo prévue</h2>${S.wx ? `<p class="muted">Prévision du ${fmtDT(S.wx.run)}.</p>` : ''}${wxTable()}`;
  // risks and plan B
  const EB = {}; for (const k of Object.keys(D.planB)) EB[k] = evaluate(k, depFor(k), sp);
  const fill = tpl => tpl.replace(/\{(\w+)\.(nm|dep|arr)\}/g, (m, k, f) => {
    const e = EB[k]; if (!e) return m;
    if (f === 'nm') return num(e.nm, 1);
    if (f === 'dep') return fmtT(e.dep);
    return e.arr > cetMs(D.planB[k].date, 16, 0) ? `<span class="bad">${fmtT(e.arr)}</span>` : fmtT(e.arr);
  });
  h += `<h2>Risques et plans B</h2><ul class="plain">${D.notes.risks.map(r => `<li>${r}</li>`).join('')}${D.notes.planB.map(r => `<li>${fill(r)}</li>`).join('')}</ul>
    <p class="muted">Les plans B sont détaillés (waypoints, marées, courants) dans l'onglet Étape.</p>`;
  h += `<h2>Passages délicats</h2><ul class="plain">${D.notes.passages.map(r => `<li>${r}</li>`).join('')}</ul>`;
  h += `<h2>Radio et sécurité</h2><ul class="plain">${D.radio.map(r => `<li>${esc(r)}</li>`).join('')}</ul>`;
  h += `<h2>Sources et limites</h2><ul class="plain">${Object.values(D.sources).map(s => `<li>${esc(s)}</li>`).join('')}${D.notes.limits.map(r => `<li>${r}</li>`).join('')}</ul>
    <p class="muted">Aide à la préparation : ne remplace ni les cartes officielles, ni la météo du jour, ni les avis aux navigateurs.</p>`;
  $('#tripBody').innerHTML = h;
  $$('#tripBody [data-day]').forEach(b => b.onclick = () => { S.prefs.day = b.dataset.day; Prefs.save(); buildDayChips(); show('day'); });
  $('#ovBtn').onclick = () => openChart('overview');
  try { $('#ovImg').src = await chartSrc(D.charts.find(c => c.id === 'overview')); } catch (e) { $('#ovImg').alt = 'Carte non disponible hors connexion (onglet Données → Préparer le mode hors connexion).'; }
}

/* ------------------------------------------------------------------ view: day */
function curEval() {
  const k = S.prefs.day; const ki = keyInfo(k); const dep = depFor(k);
  return { k, ki, e: evaluate(k, dep, S.prefs.speed) };
}
function accCard(title, a, code, t) {
  const p = S.data.ports[code];
  return `<div class="card ${a.ok ? 'okc' : 'badc'}">
    <div class="k">${title} – ${esc(p.short)} à ${fmtT(t)}</div>
    <div class="v">EsQ ${num(a.ukc)} m ${a.ok ? '' : '<span class="bad">!!</span>'}</div>
    <div class="s">marée ${num(a.h)} m (${a.trend}) <span class="tag ${a.src}">${a.src === 'S' ? 'Shom' : 'calcul'}</span><br>
    sonde retenue ${num(p.depth, 1)} m · mini requis ${num(a.req)} m</div></div>`;
}
function renderDay() {
  const { k, ki, e } = curEval(); const P = S.data.ports, WP = S.data.waypoints;
  const [hh, mm] = cetHM(e.dep); $('#depTime').value = `${pad(hh)}:${pad(mm)}`;
  $('#depTime').onchange = ev => { const [h, m] = ev.target.value.split(':').map(Number); if (isNaN(h)) return;
    S.prefs.deps[k] = cetMs(ki.date, h, m); Prefs.save(); renderDay(); };
  $('#depReset').onclick = () => { delete S.prefs.deps[k]; Prefs.save(); renderDay(); };
  const sun = S.data.sun[e.from][ki.date];
  const latest = cetMs(ki.date, 16, 0);
  const wins = windowScan(k, ki.date, S.prefs.speed);
  const per = periods(e.log).filter(p => p.k !== 'neutre');
  const wx = wxAnalyse(e);
  let h = `<h1>${ki.main ? `J${k} · ` : `Plan ${k} · `}${fmtD(e.dep)} · ${esc(P[e.from].short)} → ${esc(P[e.to].short)}</h1>`;
  if (!ki.main) h += `<p class="note">${esc(ki.label)}</p>`;
  h += `<div class="cards">
    <div class="card"><div class="k">Départ</div><div class="v">${fmtT(e.dep)}</div><div class="s">conseillé ${fmtT(ki.dep)}${e.dep < sun.dawn ? ' · <span class="warn">avant l\'aube civile</span>' : ''}</div></div>
    <div class="card ${e.arr > latest ? 'badc' : 'okc'}"><div class="k">Arrivée à ${num(S.prefs.speed, 1)} kn</div><div class="v">${fmtT(e.arr)}</div><div class="s">${dur(e.dur)} · ${num(e.nm, 1)} M · courant ${e.gain >= 0 ? '+' : '−'}${Math.abs(e.gain).toFixed(0)} min</div></div>
    ${accCard('Départ', e.accDep, e.from, e.dep)}${accCard('Arrivée', e.accArr, e.to, e.arr)}
  </div>`;
  h += `<p><b>Fenêtre de départ possible</b> (accès suffisant au départ et à l'arrivée, arrivée ≤ 16:00) : <b>${wins.join(' et ') || 'aucune'}</b>.
        Aube ${fmtT(sun.dawn)} · lever ${fmtT(sun.sunrise)} · coucher ${fmtT(sun.sunset)}.</p>`;
  if (ki.rationale) h += `<p class="muted">${esc(ki.rationale)}</p>`;
  h += `<p><b>Courant</b> : ${per.length ? per.map(p => `${fmtT(p.t0)}–${fmtT(p.t1)} <span class="${p.k}">${p.k === 'fav' ? 'favorable' : 'défavorable'}</span> ≤ ${num(p.max, 1)} kn`).join(' · ') : 'faible sur toute la route'}.</p>`;
  if (wx && wx.available) {
    h += `<p><b>Météo</b> (prévision du ${fmtDT(S.wx.run)}) : ${compass(wx.dir)} ${wx.min.toFixed(0)}–${wx.max.toFixed(0)} kn, rafales ${wx.gust.toFixed(0)} ;
          ${Object.entries(wx.allures).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([a, v]) => `${a} ${Math.round(v * 100)} %`).join(', ')}.
          ${wx.flags.map(f => `<br><span class="${f[0] === 'nogo' ? 'bad' : 'warn'}">${f[0] === 'nogo' ? '!! ' : '• '}${esc(f[1])}</span>`).join('')}</p>`;
  } else h += `<p class="muted">Pas de prévision météo enregistrée pour ce jour : onglet Météo → Mettre à jour (avec une connexion).</p>`;
  // waypoint table
  const L = S.data.legs[k]; let cum = 0;
  h += `<h2>Waypoints</h2><div class="scroll"><table><tr><th>N°</th><th>Waypoint</th><th>Position</th><th class="num">Route</th><th class="num">Dist.</th><th class="num">Cumul</th><th class="num">ETA</th><th>Courant</th><th>Vent</th><th>Repère</th></tr>`;
  L.wps.forEach((w, i) => {
    const seg = L.segments[i]; const p = WP[w]; const t = e.eta[w];
    const c = current(p.lat, p.lon, t);
    let cs = '–';
    if (c) { cs = `${Math.round(c.set).toString().padStart(3, '0')}° ${num(c.rate, 1)}`;
      if (seg) { const r = rad(seg.course); const al = c.ue * Math.sin(r) + c.vn * Math.cos(r); cs += ` <span class="${al >= 0 ? 'fav' : 'adv'}">(${al >= 0 ? '+' : '−'}${num(Math.abs(al), 1)})</span>`; } }
    const w_ = S.wx ? wind(p.lat, p.lon, t) : null;
    h += `<tr><td><b>${i === 0 ? 'D' : i === L.wps.length - 1 ? 'A' : i}</b></td><td><b>${esc(P[w] ? P[w].short : p.name)}</b></td><td>${fmtPos(p.lat, p.lon)}</td>
      <td class="num"><b>${seg ? Math.round(seg.course).toString().padStart(3, '0') + '°' : ''}</b></td><td class="num">${seg ? num(seg.nm, 2) : ''}</td><td class="num">${num(cum, 1)}</td>
      <td class="num"><b>${fmtT(t)}</b></td><td>${cs}</td><td>${w_ ? `${compass(w_.dir)} ${w_.sp.toFixed(0)} (${(w_.gust ?? w_.sp).toFixed(0)})` : '–'}</td><td class="muted">${esc(p.note || (P[w] ? 'port' : ''))}</td></tr>`;
    if (seg) cum += seg.nm;
  });
  h += `</table></div><p class="muted">Routes vraies (°V), distances en milles. Cap magnétique ≈ route vraie − 1°. Courant : vers, kn, (composante sur la route). Vent : kn (rafales).</p>`;
  h += `<div class="row wrap">${S.data.charts.filter(c => (c.day == k && c.kind !== 'leg') || c.id === `leg${k}`).map(c => `<button class="ghost" data-chart="${c.id}">${esc(c.title)}</button>`).join('')}
        <button class="ghost" data-port="${e.from}">Port de départ</button><button class="ghost" data-port="${e.to}">Port d'arrivée</button></div>`;
  $('#dayBody').innerHTML = h;
  $$('#dayBody [data-chart]').forEach(b => b.onclick = () => openChart(b.dataset.chart));
  $$('#dayBody [data-port]').forEach(b => b.onclick = () => { S.prefs.portFocus = b.dataset.port; show('ports'); });
}

/* ------------------------------------------------------------------ view: charts + viewer */
function renderCharts() {
  const C = S.data.charts, P = S.data.ports; let h = '<h1>Cartes</h1><p class="muted">Extraits © Shom RasterMarine, non officiels : à utiliser avec les cartes officielles. Pincer pour zoomer.</p>';
  const grid = list => `<div class="chartgrid">${list.map(c => `<button data-chart="${c.id}">${esc(c.title)}<span class="muted">${Math.round(c.bytes / 1024)} Ko</span></button>`).join('')}</div>`;
  h += '<h2>Vue d\'ensemble</h2>' + grid(C.filter(c => c.kind === 'overview'));
  for (const k of Object.keys(S.data.days)) {
    const d = S.data.days[k];
    h += `<h2>J${k} · ${esc(P[d.from].short)} → ${esc(P[d.to].short)}</h2>` + grid(C.filter(c => c.day == k));
  }
  h += '<h2>Ports (1:10 000 et approches)</h2>' + grid(C.filter(c => c.kind === 'port' || c.kind === 'approach'));
  $('#chartList').innerHTML = h;
  $$('#chartList [data-chart]').forEach(b => b.onclick = () => openChart(b.dataset.chart));
}
async function chartSrc(c) {
  if (S.chartURL[c.id]) return S.chartURL[c.id];
  const buf = await fetchFile(c.file);
  return (S.chartURL[c.id] = URL.createObjectURL(new Blob([buf], { type: 'image/jpeg' })));
}
const V = { c: null, z: 1, x: 0, y: 0, ptrs: new Map(), last: null };
async function openChart(id) {
  const c = S.data.charts.find(x => x.id === id); if (!c) return;
  $('#viewer').classList.remove('hidden'); $('#vTitle').textContent = c.title; $('#vInfo').textContent = 'Chargement…';
  V.c = c;
  try { $('#vImg').src = await chartSrc(c); }
  catch (e) { $('#vInfo').textContent = 'Carte indisponible hors connexion : préparez le mode hors connexion (onglet Données). ' + e.message; return; }
  $('#vImg').onload = () => { $('#vImg').style.width = c.w + 'px'; $('#vImg').style.height = c.h + 'px'; fitChart(); updateMark(); };
}
function fitChart() {
  const st = $('#vStage').getBoundingClientRect(); const c = V.c;
  V.z = Math.min(st.width / c.w, st.height / c.h); V.x = (st.width - c.w * V.z) / 2; V.y = (st.height - c.h * V.z) / 2; applyV();
}
function applyV() {
  $('#vLayer').style.transform = `translate(${V.x}px,${V.y}px) scale(${V.z})`;
  $('#vMark').style.transform = `scale(${1 / V.z})`;
}
function zoomAt(f, cx, cy) {
  const nz = Math.min(Math.max(V.z * f, 0.05), 6); const k = nz / V.z;
  V.x = cx - (cx - V.x) * k; V.y = cy - (cy - V.y) * k; V.z = nz; applyV();
}
function setupViewer() {
  const st = $('#vStage');
  st.addEventListener('pointerdown', ev => { st.setPointerCapture(ev.pointerId); V.ptrs.set(ev.pointerId, [ev.clientX, ev.clientY]); V.last = null; });
  st.addEventListener('pointermove', ev => {
    if (!V.ptrs.has(ev.pointerId)) return;
    const prev = V.ptrs.get(ev.pointerId); V.ptrs.set(ev.pointerId, [ev.clientX, ev.clientY]);
    const r = st.getBoundingClientRect();
    if (V.ptrs.size === 1) { V.x += ev.clientX - prev[0]; V.y += ev.clientY - prev[1]; applyV(); }
    else if (V.ptrs.size === 2) {
      const [a, b] = [...V.ptrs.values()]; const d = Math.hypot(a[0] - b[0], a[1] - b[1]); const cx = (a[0] + b[0]) / 2 - r.left, cy = (a[1] + b[1]) / 2 - r.top;
      if (V.last) { zoomAt(d / V.last.d, cx, cy); V.x += cx - V.last.cx; V.y += cy - V.last.cy; applyV(); }
      V.last = { d, cx, cy };
    }
  });
  const up = ev => { V.ptrs.delete(ev.pointerId); V.last = null; };
  st.addEventListener('pointerup', up); st.addEventListener('pointercancel', up);
  st.addEventListener('wheel', ev => { ev.preventDefault(); const r = st.getBoundingClientRect(); zoomAt(ev.deltaY < 0 ? 1.15 : 1 / 1.15, ev.clientX - r.left, ev.clientY - r.top); }, { passive: false });
  st.addEventListener('dblclick', ev => { const r = st.getBoundingClientRect(); zoomAt(2, ev.clientX - r.left, ev.clientY - r.top); });
  const ctr = () => { const r = st.getBoundingClientRect(); return [r.width / 2, r.height / 2]; };
  $('#vIn').onclick = () => zoomAt(1.5, ...ctr()); $('#vOut').onclick = () => zoomAt(1 / 1.5, ...ctr());
  $('#vFit').onclick = fitChart;
  $('#vClose').onclick = () => { $('#viewer').classList.add('hidden'); $('#vImg').removeAttribute('src'); };
  $('#vGps').onclick = () => { if (!S.gps) { startGPS(); toast('GPS en cours d\'activation…'); return; } const p = markPx(); if (!p) { toast('Position hors de cette carte.'); return; }
    const r = st.getBoundingClientRect(); V.x = r.width / 2 - p[0] * V.z; V.y = r.height / 2 - p[1] * V.z; applyV(); };
  window.addEventListener('resize', () => { if (V.c && !$('#viewer').classList.contains('hidden')) fitChart(); });
}
function markPx() {
  if (!S.gps || !V.c) return null;
  const [x, y] = merc(S.gps.lat, S.gps.lon); const [x0, y0, x1, y1] = V.c.bounds;
  if (x < x0 || x > x1 || y < y0 || y > y1) return null;
  return [(x - x0) / (x1 - x0) * V.c.w, (y1 - y) / (y1 - y0) * V.c.h];
}
function updateMark() {
  if (!V.c || $('#viewer').classList.contains('hidden')) return;
  const p = markPx(); const m = $('#vMark');
  if (!p) { m.classList.add('hidden'); $('#vInfo').textContent = S.gps ? 'Position GPS hors de cette carte.' : 'GPS inactif (bouton « Me situer »).'; return; }
  m.classList.remove('hidden'); m.style.left = p[0] + 'px'; m.style.top = p[1] + 'px';
  $('#vInfo').textContent = `Position ${fmtPos(S.gps.lat, S.gps.lon)} · ±${Math.round(S.gps.acc)} m` + (S.gps.sog != null ? ` · ${num(S.gps.sog, 1)} kn` : '') + (S.gps.cog != null ? ` · ${Math.round(S.gps.cog)}°` : '');
}
function bestChartFor(lat, lon) {
  const [x, y] = merc(lat, lon); const pri = { port: 0, approach: 1, sheet: 2, leg: 3, overview: 4 };
  return S.data.charts.filter(c => x >= c.bounds[0] && x <= c.bounds[2] && y >= c.bounds[1] && y <= c.bounds[3])
    .sort((a, b) => pri[a.kind] - pri[b.kind] || ((a.bounds[2] - a.bounds[0]) - (b.bounds[2] - b.bounds[0])))[0];
}

/* ------------------------------------------------------------------ view: tides */
function buildTideSelectors() {
  const sp = $('#tidePort'); sp.innerHTML = Object.entries(S.data.ports).map(([c, p]) => `<option value="${c}">${esc(p.short)}</option>`).join('');
  const sd = $('#tideDate'); sd.innerHTML = S.data.trip.dates.map(d => `<option value="${d}">${fmtD(cetMs(d, 12, 0))}</option>`).join('');
  sp.value = S.prefs.tidePort || keyInfo(S.prefs.day).from; sd.value = S.prefs.tideDate || keyInfo(S.prefs.day).date;
  sp.onchange = sd.onchange = () => { S.prefs.tidePort = sp.value; S.prefs.tideDate = sd.value; Prefs.save(); renderTides(); };
}
function renderTides() {
  const code = $('#tidePort').value, date = $('#tideDate').value; const p = S.data.ports[code]; const T = S.data.tides[p.tide];
  const t0 = cetMs(date, 0, 0), t1 = t0 + 86400e3;
  const cv = $('#tideCanvas'); const dpr = window.devicePixelRatio || 1; const W = cv.clientWidth, H = 360;
  cv.width = W * dpr; cv.height = H * dpr; const g = cv.getContext('2d'); g.scale(dpr, dpr);
  const css = getComputedStyle(document.documentElement); const ink = css.getPropertyValue('--ink'), line = css.getPropertyValue('--line'), acc = css.getPropertyValue('--accent'), ok = css.getPropertyValue('--ok'), bad = css.getPropertyValue('--bad');
  g.clearRect(0, 0, W, H); g.font = '16px ' + css.getPropertyValue('--font');
  const L = 52, Rr = 12, Tp = 14, B = 34; const pts = [];
  for (let t = t0; t <= t1; t += 300e3) pts.push([t, tideH(p.tide, t).h]);
  const hmax = Math.ceil(Math.max(...pts.map(q => q[1])) + 0.3), hmin = Math.min(0, Math.floor(Math.min(...pts.map(q => q[1])) - 0.3));
  const X = t => L + (t - t0) / 86400e3 * (W - L - Rr), Y = h => Tp + (hmax - h) / (hmax - hmin) * (H - Tp - B);
  g.strokeStyle = line; g.fillStyle = ink; g.lineWidth = 1;
  for (let hh = 0; hh <= 24; hh += 3) { const x = X(t0 + hh * 3600e3); g.beginPath(); g.moveTo(x, Tp); g.lineTo(x, H - B); g.stroke(); g.fillText(`${pad(hh)}h`, Math.min(x - 12, W - Rr - 30), H - 10); }
  for (let v = hmin; v <= hmax; v++) { const y = Y(v); g.beginPath(); g.moveTo(L, y); g.lineTo(W - Rr, y); g.stroke(); g.fillText(`${v} m`, 6, y + 5); }
  const req = S.data.boat.draft + S.data.boat.margin - p.depth;
  g.strokeStyle = bad; g.setLineDash([6, 4]); g.beginPath(); g.moveTo(L, Y(req)); g.lineTo(W - Rr, Y(req)); g.stroke(); g.setLineDash([]);
  g.fillStyle = bad; g.fillText(`accès : marée ≥ ${num(req)} m`, L + 6, Y(req) - 6);
  g.strokeStyle = acc; g.lineWidth = 3; g.beginPath(); pts.forEach(([t, h], i) => i ? g.lineTo(X(t), Y(h)) : g.moveTo(X(t), Y(h))); g.stroke();
  const now = Date.now(); if (now > t0 && now < t1) { g.strokeStyle = ok; g.lineWidth = 2; g.beginPath(); g.moveTo(X(now), Tp); g.lineTo(X(now), H - B); g.stroke(); }
  const ev = T.hl.filter(e => e.t >= t0 && e.t < t1);
  g.fillStyle = ink; g.font = 'bold 16px ' + css.getPropertyValue('--font');
  for (const e of ev) { const x = X(e.t), y = Y(e.h); g.beginPath(); g.arc(x, y, 4, 0, 7); g.fill(); g.fillText(`${e.type} ${fmtT(e.t)}`, Math.min(x - 30, W - 110), e.type === 'PM' ? y - 10 : y + 22); }
  const coefs = S.data.concarneauHW.filter(x => fmtISO(x.t) === date).map(x => x.coef);
  let h = `<div class="scroll"><table><tr><th></th><th>Heure</th><th class="num">Hauteur (m/ZH)</th><th>Source</th></tr>` +
    ev.map(e => `<tr><td><b>${e.type === 'PM' ? 'Pleine mer' : 'Basse mer'}</b></td><td><b>${fmtT(e.t)}</b></td><td class="num">${num(e.h)}</td><td><span class="tag ${e.src === 'SHOM' ? 'S' : 'c'}">${e.src === 'SHOM' ? 'Shom' : 'calcul'}</span></td></tr>`).join('') + '</table></div>';
  h += `<p>Coefficient(s) : <b>${coefs.join(' / ') || '–'}</b> · port de référence Shom : ${esc(S.data.tideNames[p.tide] || p.tide)}${code === 'BRG' ? ' (Bourgenay : marée des Sables, 6 M)' : ''}.</p>`;
  h += `<p class="muted">Ligne tiretée : hauteur de marée mini pour garder 0,50 m sous la quille avec la sonde retenue (${num(p.depth, 1)} m). Ligne verticale : maintenant.</p>`;
  $('#tideBody').innerHTML = h;
}

/* ------------------------------------------------------------------ view: weather */
function renderWeather() {
  const st = $('#wxStatus');
  st.innerHTML = S.wx ? `Prévision enregistrée du <b>${fmtDT(S.wx.run)}</b>` + (S.online ? '' : ' · hors ligne') : 'Aucune prévision enregistrée.';
  $('#wxUpdate').onclick = updateWeather; $('#wxUpdate').disabled = !S.online;
  if (!S.wx) { $('#wxBody').innerHTML = '<p>Avec une connexion (au port), touchez « Mettre à jour la météo » : la prévision est enregistrée sur l\'iPad pour la navigation.</p>' + wxLinks(); return; }
  $('#wxBody').innerHTML = wxTable() + wxLinks();
}
function wxTable() {
  if (!S.wx) return '<p class="muted">Aucune prévision enregistrée : onglet Météo → Mettre à jour (avec une connexion).</p>';
  let h = `<div class="scroll"><table><tr><th>Jour</th><th>Échéance</th><th>Vent sur la route</th><th>Allures</th><th>Mer départ / arrivée</th><th>Alertes</th></tr>`;
  for (const k of allKeys()) {
    const ki = keyInfo(k); const e = evaluate(k, depFor(k), S.prefs.speed); const w = wxAnalyse(e);
    const lead = Math.round((cetMs(ki.date, 12, 0) - S.wx.run) / 86400e3);
    if (!w || !w.available) { h += `<tr><td><b>${ki.main ? 'J' + k : k}</b></td><td>J−${lead}</td><td colspan="4" class="muted">hors horizon de la prévision</td></tr>`; continue; }
    const seas = ['dep', 'arr'].map(l => { const s = w.at[l].sea; return s ? `${num(s.hs, 1)} m` + (s.swell != null && s.swellDir != null ? ` (houle ${num(s.swell, 1)} m ${compass(s.swellDir)})` : '') : 'n/d'; });
    h += `<tr class="${ki.main ? '' : 'muted'}"><td><b>${ki.main ? 'J' + k : k}</b> ${fmtD(e.dep)}</td><td>J−${lead}${lead > 7 ? '<br><span class="warn">indicatif</span>' : ''}</td>
      <td><b>${compass(w.dir)} ${w.min.toFixed(0)}–${w.max.toFixed(0)} kn</b>, rafales ${w.gust.toFixed(0)}</td>
      <td>${Object.entries(w.allures).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([a, v]) => `${a} ${Math.round(v * 100)} %`).join(', ')}</td>
      <td>${seas.join(' / ')}</td><td>${w.flags.map(f => `<span class="${f[0] === 'nogo' ? 'bad' : 'warn'}">${f[0] === 'nogo' ? '!! ' : '• '}${esc(f[1])}</span>`).join('<br>') || '–'}</td></tr>`;
  }
  h += '</table></div><p class="muted">Calculé le long de la route simulée avec l\'heure de départ et la vitesse choisies. Modèles : ' +
    S.data.weatherModels.map(m => S.data.weatherModelNames[m]).join(', ') + ' (le premier disponible). Source Open-Meteo (CC BY 4.0). Au-delà de J−7 : tendance seulement.</p>';
  return h;
}
function wxLinks() {
  return `<h2>Bulletins officiels</h2><ul class="plain">${S.data.radio.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
    <p>En ligne : <a href="https://meteofrance.com/meteo-marine" target="_blank" rel="noopener">Météo-France marine</a> ·
    <a href="https://portail.ping-info-nautique.fr/" target="_blank" rel="noopener">Avis aux navigateurs (PING)</a> ·
    <a href="https://maree.shom.fr/" target="_blank" rel="noopener">Marées Shom</a></p>`;
}

/* ------------------------------------------------------------------ view: navigation (GPS) */
function startGPS() {
  if (!('geolocation' in navigator)) { toast('Géolocalisation indisponible sur cet appareil.'); return; }
  if (S.gpsWatch != null) return;
  $('#gpsBadge').textContent = 'GPS…';
  S.gpsWatch = navigator.geolocation.watchPosition(p => {
    const c = p.coords;
    S.gps = { lat: c.latitude, lon: c.longitude, acc: c.accuracy, t: p.timestamp,
              sog: c.speed != null && c.speed >= 0 ? c.speed * KN : null, cog: c.heading != null && !isNaN(c.heading) ? c.heading : null };
    const b = $('#gpsBadge'); b.textContent = `GPS ±${Math.round(c.accuracy)} m`; b.className = 'badge' + (c.accuracy > 100 ? ' off' : '');
    updateMark(); if (S.view === 'nav') renderNav();
  }, err => { const b = $('#gpsBadge'); b.textContent = 'GPS ✕'; b.className = 'badge bad'; toast('GPS : ' + err.message); S.gpsWatch = null; },
  { enableHighAccuracy: true, maximumAge: 2000, timeout: 30000 });
}
function navCompute() {
  if (!S.gps) return null;
  const k = S.prefs.day; const L = S.data.legs[k]; const WP = S.data.waypoints; const { lat, lon } = S.gps;
  const c = Math.cos(rad(lat)); let best = null;
  L.segments.forEach((s, i) => {
    const a = WP[s.from], b = WP[s.to];
    const ax = (a.lon - lon) * c * 60, ay = (a.lat - lat) * 60, bx = (b.lon - lon) * c * 60, by = (b.lat - lat) * 60;
    const dx = bx - ax, dy = by - ay; const L2 = dx * dx + dy * dy;
    let f = L2 ? -(ax * dx + ay * dy) / L2 : 0; f = Math.max(0, Math.min(1, f));
    const px = ax + f * dx, py = ay + f * dy; const d = Math.hypot(px, py);
    const xte = (dx * (-ay) - dy * (-ax)) / Math.sqrt(L2 || 1);   // >0 : bateau à droite de la route
    if (!best || d < best.d) best = { i, f, d, xte, s };
  });
  const s = best.s; const nxt = WP[s.to];
  const dNext = distNM(lat, lon, nxt.lat, nxt.lon), brg = bearing(lat, lon, nxt.lat, nxt.lon);
  let rest = dNext; for (let j = best.i + 1; j < L.segments.length; j++) rest += L.segments[j].nm;
  const v = S.gps.sog != null && S.gps.sog > 1 ? S.gps.sog : S.prefs.speed;
  return { seg: best, next: s.to, brg, dNext, rest, v, etaNext: Date.now() + dNext / v * 3600e3, etaArr: Date.now() + rest / v * 3600e3 };
}
function renderNav() {
  const k = S.prefs.day; const ki = keyInfo(k); const P = S.data.ports;
  $('#navLeg').textContent = `${ki.main ? 'J' + k : 'plan ' + k} ${P[ki.from].short} → ${P[ki.to].short}`;
  $('#gpsStart').onclick = startGPS;
  $('#gpsChart').onclick = () => { const c = S.gps ? bestChartFor(S.gps.lat, S.gps.lon) : null; if (c) openChart(c.id); else toast(S.gps ? 'Aucune carte ne couvre la position.' : 'Activez d\'abord le GPS.'); };
  if (!S.gps) { $('#navBody').innerHTML = `<p>Le GPS de l'iPad fonctionne sans réseau (modèles cellulaires ; un iPad Wi-Fi seul n'a pas de GPS). Touchez « Activer le GPS ».</p>
      <p class="muted">Les données affichées ici sont une aide : la navigation se fait avec les instruments du bord et les cartes officielles.</p>`; return; }
  const n = navCompute(); const WP = S.data.waypoints; const g = S.gps;
  const nm = WP[n.next]; const nname = P[n.next] ? P[n.next].short : n.next.replace(/_/g, ' ');
  const side = n.seg.xte > 0 ? 'à droite' : 'à gauche';
  let h = `<div class="navbig">
    <div class="card"><div class="k">Prochain waypoint</div><div class="v">${esc(nname)}</div><div class="s">${fmtPos(nm.lat, nm.lon)}</div></div>
    <div class="card"><div class="k">Relèvement (vrai)</div><div class="v">${Math.round(n.brg).toString().padStart(3, '0')}°</div><div class="s">magnétique ≈ ${Math.round((n.brg - 1 + 360) % 360).toString().padStart(3, '0')}°</div></div>
    <div class="card"><div class="k">Distance</div><div class="v">${num(n.dNext, 1)} M</div><div class="s">ETA ${fmtT(n.etaNext)} à ${num(n.v, 1)} kn</div></div>
    <div class="card"><div class="k">Écart de route</div><div class="v">${num(Math.abs(n.seg.xte), 2)} M</div><div class="s">${side} de la route ${Math.round(n.seg.s.course).toString().padStart(3, '0')}°</div></div>
    <div class="card"><div class="k">Vitesse / cap fond</div><div class="v">${g.sog != null ? num(g.sog, 1) + ' kn' : '–'}</div><div class="s">${g.cog != null ? Math.round(g.cog) + '°' : 'cap fond indisponible à l\'arrêt'}</div></div>
    <div class="card"><div class="k">Arrivée ${esc(P[ki.to].short)}</div><div class="v">${fmtT(n.etaArr)}</div><div class="s">reste ${num(n.rest, 1)} M</div></div>
  </div>`;
  const c = current(g.lat, g.lon, Date.now());
  h += `<p>Position <b>${fmtPos(g.lat, g.lon)}</b> (±${Math.round(g.acc)} m, ${fmtT(g.t)}).` + (c ? ` Courant de marée calculé ici : <b>${Math.round(c.set).toString().padStart(3, '0')}° ${num(c.rate, 1)} kn</b>.` : '') + '</p>';
  const tA = access(ki.to, n.etaArr);
  h += isFinite(tA.h) ? `<p>À l'arrivée estimée (${fmtT(n.etaArr)}) : marée ${num(tA.h)} m, EsQ ${num(tA.ukc)} m ${tA.ok ? '<span class="ok">accès OK</span>' : '<span class="bad">!! accès insuffisant</span>'}.</p>`
                      : `<p class="muted">Marée à l'arrivée estimée (${fmtDT(n.etaArr)}) : hors de la période couverte (${esc(S.data.trip.coverage)}).</p>`;
  $('#navBody').innerHTML = h;
}

/* ------------------------------------------------------------------ view: ports */
function renderPorts() {
  const P = S.data.ports; const focus = S.prefs.portFocus; delete S.prefs.portFocus;
  let h = `<div class="chips">${Object.entries(P).map(([c, p]) => `<button class="chip" data-go="${c}">${esc(p.short)}</button>`).join('')}</div>`;
  for (const [c, p] of Object.entries(P)) {
    const tel = (p.contact.match(/(\d{2}[ .]?){5}/) || [''])[0].replace(/\s/g, '');
    h += `<section class="card" id="port-${c}" style="margin:14px 0"><h2>${esc(p.title)}</h2>
      <p class="big"><b>${esc(p.contact)}</b></p>${tel ? `<p><a href="tel:${tel}">Appeler le ${esc(tel.replace(/(\d{2})(?=\d)/g, '$1 '))}</a></p>` : ''}
      <p>${esc(p.hours)}</p>
      <p>Sonde retenue <b>${num(p.depth, 1)} m</b> → marée mini <b>${num(S.data.boat.draft + S.data.boat.margin - p.depth)} m</b> (${esc(p.where)}).</p>
      <h3>Accès</h3><ul class="plain">${p.access.map(x => `<li>${esc(x)}</li>`).join('')}</ul>
      <h3>${esc(p.visitors_title || 'Accueil visiteurs')}</h3><ul class="plain">${p.visitors.map(x => `<li>${esc(x)}</li>`).join('')}</ul>
      ${p.attention && p.attention.length ? `<h3 class="bad">Attention</h3><ul class="plain">${p.attention.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
      <div class="row wrap">${S.data.charts.filter(x => x.port === c).map(x => `<button class="ghost" data-chart="${x.id}">${esc(x.title.split('–').pop().trim())}</button>`).join('')}
      <button class="ghost" data-tide="${c}">Marées</button></div></section>`;
  }
  $('#portsBody').innerHTML = h;
  $$('#portsBody [data-chart]').forEach(b => b.onclick = () => openChart(b.dataset.chart));
  $$('#portsBody [data-go]').forEach(b => b.onclick = () => $('#port-' + b.dataset.go).scrollIntoView({ behavior: 'smooth' }));
  $$('#portsBody [data-tide]').forEach(b => b.onclick = () => { S.prefs.tidePort = b.dataset.tide; $('#tidePort').value = b.dataset.tide; show('tides'); });
  if (focus) setTimeout(() => $('#port-' + focus).scrollIntoView(), 50);
}

/* ------------------------------------------------------------------ view: data / offline */
async function renderInfo() {
  const F = S.files; const D = S.data;
  const nS = Object.values(D.tides).reduce((a, t) => a + [...t.src].filter(c => c === 'S').length, 0), nAll = Object.values(D.tides).reduce((a, t) => a + t.src.length, 0);
  const offi = Object.values(D.tides).flatMap(t => t.hl.filter(e => e.src === 'SHOM').map(e => e.t)); const lastOff = offi.length ? Math.max(...offi) : null;
  let est = ''; try { const e = await navigator.storage.estimate(); est = `${(e.usage / 1048576).toFixed(0)} Mo utilisés`; } catch (e) { /* */ }
  let persisted = ''; try { persisted = (await navigator.storage.persisted()) ? ' · stockage persistant' : ' · stockage non persistant'; } catch (e) { /* */ }
  const cached = await countCached();
  let h = `<h1>Données et hors connexion</h1>
    <div class="cards">
      <div class="card"><div class="k">Données du roadbook</div><div class="v">${esc(F.version)}</div><div class="s">générées le ${esc(D.generated.slice(0, 16).replace('T', ' '))}</div></div>
      <div class="card"><div class="k">Marées</div><div class="v">${Math.round(nS / nAll * 100)} % Shom</div><div class="s">${lastOff ? 'officielles jusqu\'au ' + fmtD(lastOff) + ', ensuite calcul' : 'calcul harmonique'}</div></div>
      <div class="card"><div class="k">Météo</div><div class="v">${S.wx ? fmtT(S.wx.run) : '–'}</div><div class="s">${S.wx ? 'prévision du ' + fmtD(S.wx.run) : 'aucune'}</div></div>
      <div class="card"><div class="k">Hors connexion</div><div class="v">${cached.n}/${cached.total}</div><div class="s">fichiers en cache · ${est}${persisted}</div></div>
    </div>
    <h2>Avant de partir (avec une connexion)</h2>
    <div class="row wrap">
      <button id="btnOffline" class="primary">Préparer le mode hors connexion</button>
      <button id="btnData" class="ghost">Chercher une mise à jour des données</button>
      <button id="btnWx" class="ghost">Mettre à jour la météo</button>
    </div>
    <div class="progress hidden" id="prog"><div></div></div><p id="progMsg" class="muted"></p>
    <ul class="plain">
      <li>Ouvrez l'application depuis l'écran d'accueil (Partager → « Sur l'écran d'accueil »), puis « Préparer le mode hors connexion » : toutes les cartes (${(F.total / 1048576).toFixed(0)} Mo) sont enregistrées sur l'iPad.</li>
      <li><b>Marées, courants, plan</b> : calculés sur l'iPad à partir des données embarquées ; « Chercher une mise à jour » récupère la dernière version publiée (marées Shom officielles, corrections).</li>
      <li><b>Météo</b> : à mettre à jour au port chaque soir ou matin ; elle reste enregistrée pour la navigation.</li>
    </ul>
    <h2>Sources</h2><ul class="plain">${Object.values(D.sources).map(s => `<li>${esc(s)}</li>`).join('')}</ul>
    <p class="muted">Aide à la préparation : ne remplace ni les cartes officielles, ni la météo du jour, ni les avis aux navigateurs.</p>
    <p><button id="btnReset" class="ghost">Réinitialiser les réglages (heures de départ, vitesse)</button></p>`;
  $('#infoBody').innerHTML = h;
  $('#btnOffline').onclick = prepareOffline; $('#btnData').onclick = checkDataUpdate; $('#btnWx').onclick = () => { show('weather'); updateWeather(); };
  $('#btnReset').onclick = () => { S.prefs.deps = {}; S.prefs.speed = 5; Prefs.save(); toast('Réglages réinitialisés.'); };
  ['btnOffline', 'btnData', 'btnWx'].forEach(id => $('#' + id).disabled = !S.online);
}
async function countCached() {
  const list = Object.keys(S.files.files); let n = 0;
  try { const c = await caches.open('rb-data'); for (const p of list) if (await c.match(fileURL(p))) n++; } catch (e) { /* */ }
  return { n, total: list.length };
}
async function prepareOffline() {
  const list = Object.keys(S.files.files); const prog = $('#prog'); prog.classList.remove('hidden'); let done = 0, fail = 0;
  for (const p of list) {
    try { const r = await fetch(fileURL(p)); if (!r.ok) throw 0; await r.arrayBuffer(); } catch (e) { fail++; }
    done++; prog.firstElementChild.style.width = (done / list.length * 100) + '%'; $('#progMsg').textContent = `${done} / ${list.length} fichiers`;
  }
  try { await navigator.storage.persist(); } catch (e) { /* */ }
  $('#progMsg').textContent = fail ? `${fail} fichier(s) non téléchargé(s) : recommencez avec une meilleure connexion.` : 'Prêt : l\'application fonctionne sans réseau.';
  if (!fail && !S.wx) toast('Pensez aussi à mettre à jour la météo.');
  renderInfo();
}
async function checkDataUpdate() {
  $('#progMsg').textContent = 'Recherche…';
  try {
    const f = await loadFilesManifest(true);
    if (f.version === S.files.version) { $('#progMsg').textContent = `Données à jour (version ${f.version}).`; return; }
    const old = S.files;
    if (f.encrypted) {                       // same key? (salt + passphrase unchanged) – test it on the new check block
      let same = !!old.kdf && f.kdf.salt === old.kdf.salt && f.kdf.iter === old.kdf.iter;
      if (same) { try { const u = b64(f.kdf.check); await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, S.key, u.slice(12)); }
                  catch (e) { same = false; } }
      if (!same) { await DB.del('key'); delete S.prefs.pass; Prefs.save(); await DB.put('files', f); await DB.del('data'); location.reload(); return; }
    }
    S.files = f;
    const d = JSON.parse(new TextDecoder().decode(await fetchFile('data.json'))); const a = new Int16Array(await fetchFile('atlas.bin'));
    S.data = d; S.atlas = a; await DB.put('data', { version: f.version, data: d, atlas: a }); await DB.put('files', f);
    Object.values(S.chartURL).forEach(u => URL.revokeObjectURL(u)); S.chartURL = {};
    for (const k in trackCache) delete trackCache[k];
    initAtlas();
    try { const c = await caches.open('rb-data'); for (const p of Object.keys(old.files)) { if (!f.files[p] || f.files[p].hash !== old.files[p].hash) await c.delete(`${old.files[p].url}?h=${old.files[p].hash}`); } } catch (e) { /* */ }
    $('#progMsg').textContent = `Données mises à jour : version ${f.version}. Relancez « Préparer le mode hors connexion » pour les cartes modifiées.`;
    buildDayChips(); buildTideSelectors();
  } catch (e) { $('#progMsg').textContent = 'Mise à jour impossible : ' + e.message; }
}

/* ------------------------------------------------------------------ start */
document.addEventListener('DOMContentLoaded', () => { setupViewer(); boot(); });
