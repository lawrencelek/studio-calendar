/* Encrypted calendar — static app. Data is AES-256-GCM encrypted (PBKDF2-SHA256 key),
   decrypted in the browser, and saved back to GitHub through the Contents API.
   Same format as tools/cal.py. No external scripts, no tracking.
   Every label, event type, colour rule and name comes from the encrypted data ("settings"). */
'use strict';

const CFG = { dataPath: 'data/calendar.enc.json', iterations: 600000, commitMessage: 'Update calendar' };
const TRIPWIRE_STATUSES = ['Open', 'On track', 'At risk', 'Met', 'Missed'];
const PREMORTEM_STATUSES = ['Open', 'Guard in place', 'Watching', 'Happened', 'Closed'];
const DAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const FORMAT = 'encrypted-calendar';
const GENERIC = { brand: '◷', title: 'Calendar' };
const VIEWS = [
  ['overview', 'Overview'], ['weeks', 'Weeks'], ['events', 'Events'], ['months', 'Months'],
  ['tripwires', 'Tripwires'], ['premortem', 'Premortem'], ['priorities', 'Priorities'], ['backcast', 'Backcast'], ['focus', 'Focus flow'],
];

const S = {
  data: null, pw: null, key: null, salt: null, iterations: CFG.iterations,
  sha: null, baseline: null, dirty: false, view: 'overview',
  showPast: false, evType: 'All', evQuery: '', evPast: false,
};
const $ = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ settings (from the encrypted data) */
const ST = () => (S.data && S.data.settings) || {};
function eventTypes() { const t = ST().eventTypes; return Array.isArray(t) && t.length ? t.map((x) => x.name) : ['Event']; }
function toneOf(type) { const t = (ST().eventTypes || []).find((x) => x.name === type); return (t && t.tone) || 'slate'; }
function dayHeaders() { const n = ST().dayNames; return Array.isArray(n) && n.length === 7 ? n : DAY_NAMES; }
function defaultWeek() { const w = ST().defaultWeek; return Array.isArray(w) && w.length === 7 ? [...w] : Array(7).fill(''); }
const gateType = () => ST().gateType || 'Gate';
const countdownShort = () => ST().countdownShort || 'target';
let catSrc = null, catCache = [];
function dayCats() {
  const src = ST().dayCategories || [];
  if (src !== catSrc) {
    catSrc = src;
    const esc = (m) => String(m).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    catCache = src.map((c) => ({ ...c, re: new RegExp((c.match || []).map(esc).join('|') || '(?!)', 'i') }));
  }
  return catCache;
}
function setBrand(on) {
  const st = on ? ST() : {};
  $('brand-mark').textContent = st.brand || GENERIC.brand;
  $('brand-title').textContent = st.title || (on && S.data.title) || GENERIC.title;
  document.title = (on && S.data.title) || GENERIC.title;
}

/* ------------------------------------------------------------------ crypto */
const TE = new TextEncoder(), TD = new TextDecoder();
function b64(bytes) { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000)); return btoa(s); }
function unb64(s) { const bin = atob(s.replace(/\s/g, '')); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
async function deriveKey(pw, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', TE.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const keyCache = new Map();
async function keyFor(env) {
  const id = env.salt + ':' + env.iterations;
  if (!keyCache.has(id)) keyCache.set(id, await deriveKey(S.pw, unb64(env.salt), env.iterations));
  return keyCache.get(id);
}
async function decryptEnv(env, key) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, key, unb64(env.ct));
  return JSON.parse(TD.decode(pt));
}
async function encryptData(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.key, TE.encode(JSON.stringify(obj, null, 1))));
  return { format: FORMAT, v: 1, kdf: 'PBKDF2-SHA256', iterations: S.iterations, cipher: 'AES-256-GCM', salt: b64(S.salt), iv: b64(iv), ct: b64(ct) };
}

/* ------------------------------------------------------------------ GitHub */
function ghCfg() {
  let c = {}; try { c = JSON.parse(localStorage.getItem('mc-gh') || '{}'); } catch (e) { /* ignore */ }
  if (!c.owner && location.hostname.endsWith('.github.io')) {
    c.owner = location.hostname.split('.')[0];
    const seg = location.pathname.split('/').filter(Boolean)[0];
    c.repo = c.repo || (seg && !seg.includes('.') ? seg : `${c.owner}.github.io`);
  }
  return { owner: '', repo: '', branch: 'main', path: CFG.dataPath, token: '', editor: '', ...c };
}
function saveGhCfg(c) { try { localStorage.setItem('mc-gh', JSON.stringify(c)); } catch (e) { toast('Could not store settings in this browser.'); } }
function canSave() { const c = ghCfg(); return !!(c.owner && c.repo && c.token); }
async function ghFetch(method, body) {
  const c = ghCfg();
  const url = `https://api.github.com/repos/${encodeURIComponent(c.owner)}/${encodeURIComponent(c.repo)}/contents/${c.path.split('/').map(encodeURIComponent).join('/')}` + (method === 'GET' ? `?ref=${encodeURIComponent(c.branch)}&t=${Date.now()}` : '');
  const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
  if (c.token) headers.Authorization = `Bearer ${c.token}`;
  if (body) headers['Content-Type'] = 'application/json';
  const r = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store' });
  if (!r.ok) {
    let msg = `${r.status}`; try { msg += ' ' + (await r.json()).message; } catch (e) { /* ignore */ }
    throw new Error(`GitHub: ${msg}`);
  }
  return r.json();
}
async function ghGet() { const f = await ghFetch('GET'); return { sha: f.sha, text: TD.decode(unb64(f.content)) }; }
async function ghPut(text, sha) {
  const c = ghCfg();
  const r = await ghFetch('PUT', { message: CFG.commitMessage, content: b64(TE.encode(text)), sha, branch: c.branch });
  return r.content.sha;
}
async function fetchEnvelope() {
  if (canSave()) {
    try { const f = await ghGet(); S.sha = f.sha; return JSON.parse(f.text); } catch (e) { console.warn('API load failed, using site copy', e); }
  }
  S.sha = null;
  const r = await fetch(`${CFG.dataPath}?t=${Date.now()}`, { cache: 'no-store' });
  if (!r.ok) throw new Error(`Could not load the calendar file (${r.status}).`);
  return r.json();
}

/* ------------------------------------------------------------------ dates */
function parseISO(s) { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s || ''); if (!m) return null; const d = new Date(+m[1], +m[2] - 1, +m[3]); return isNaN(d) ? null : d; }
function toISO(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; }
function today() { const n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate()); }
function addDays(d, n) { const x = new Date(d); x.setDate(x.getDate() + n); return x; }
function daysBetween(a, b) { return Math.round((b - a) / 86400000); }
function mondayOf(d) { return addDays(d, -((d.getDay() + 6) % 7)); }
const fmt = (d, o) => d.toLocaleDateString('en-GB', o);
const fmtDay = (d) => fmt(d, { day: 'numeric', month: 'short' });
const fmtFull = (d) => fmt(d, { day: 'numeric', month: 'short', year: 'numeric' });
const fmtMonth = (d) => fmt(d, { month: 'long', year: 'numeric' });
function fmtSpan(e) { const d = parseISO(e.date), u = parseISO(e.until); if (!d) return e.date; return u && toISO(u) !== e.date ? `${fmtDay(d)} – ${fmtDay(u)}` : fmt(d, { weekday: 'short', day: 'numeric', month: 'short' }); }

/* ------------------------------------------------------------------ derived */
function evEnd(e) { return parseISO(e.until) || parseISO(e.date); }
function eventsInWeek(start) {
  const end = addDays(start, 7);
  return S.data.events.filter((e) => { const d = parseISO(e.date); return d && d < end && evEnd(e) >= start; });
}
function openingDate() {
  const n = (S.data.settings && S.data.settings.openingTripwire) || 8;
  const t = S.data.tripwires.find((x) => x.n === n); return t ? parseISO(t.by) : null;
}
function weeksTo(start) { const o = openingDate(); if (!o) return ''; const d = daysBetween(start, o); return d >= 0 ? Math.floor(d / 7) : ''; }
function daysLeft(by) { const d = parseISO(by); return d ? daysBetween(today(), d) : null; }
function dayBg(text) {
  const t = (text || '').trim(); if (!t) return '';
  const cats = dayCats();
  for (const c of cats) if (c.exclusive && c.re.test(t)) return c.color;
  const hits = cats.filter((c) => !c.exclusive && c.re.test(t)).map((c) => c.color);
  if (!hits.length) return '';
  if (hits.length === 1) return hits[0];
  const step = 100 / hits.length;
  return `linear-gradient(90deg, ${hits.map((c, i) => `${c} ${i * step}%, ${c} ${(i + 1) * step}%`).join(', ')})`;
}
function score(p) { return Number.isInteger(p.likelihood) && Number.isInteger(p.impact) ? p.likelihood * p.impact : null; }
function scoreStyle(s) { if (s == null) return {}; if (s >= 15) return { background: '#FBE3E1', color: '#9B2C2C', fontWeight: 700 }; if (s >= 8) return { background: '#FFF1D6', color: '#8A5A00', fontWeight: 600 }; return { background: '#E3F4EA', color: '#22663F' }; }
const uid = (p) => `${p}-${Math.random().toString(16).slice(2, 10)}`;

/* ------------------------------------------------------------------ DOM helpers */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') Object.assign(el.style, v);
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) { if (c == null || c === false) continue; el.append(c instanceof Node ? c : document.createTextNode(String(c))); }
  return el;
}
const PLAINTEXT_OK = (() => { try { const d = document.createElement('div'); d.contentEditable = 'plaintext-only'; return d.contentEditable === 'plaintext-only'; } catch (e) { return false; } })();
function ed(obj, key, opts = {}) {
  const el = h('div', { class: `ed ${opts.cls || ''}`, contenteditable: PLAINTEXT_OK ? 'plaintext-only' : 'true', spellcheck: 'true', 'data-ph': opts.ph || '' });
  el.textContent = obj[key] == null ? '' : String(obj[key]);
  if (opts.bg) el.style.background = dayBg(el.textContent);
  el.addEventListener('input', () => {
    obj[key] = el.innerText.replace(/ /g, ' ').replace(/\n+$/, '');
    if (opts.bg) el.style.background = dayBg(obj[key]);
    changed(); if (opts.onInput) opts.onInput(obj[key], el);
  });
  el.addEventListener('paste', (e) => { if (PLAINTEXT_OK) return; e.preventDefault(); document.execCommand('insertText', false, e.clipboardData.getData('text/plain')); });
  el.addEventListener('keydown', (e) => { if (e.key === 'Escape') el.blur(); });
  return el;
}
function sel(obj, key, options, opts = {}) {
  const s = h('select', { class: opts.cls || '', 'aria-label': opts.label || key },
    options.map((o) => { const [v, l] = Array.isArray(o) ? o : [o, o]; return h('option', { value: String(v), selected: String(obj[key] ?? '') === String(v) ? true : null }, l); }));
  s.addEventListener('change', () => { obj[key] = opts.num ? (s.value === '' ? null : Number(s.value)) : s.value; changed(); if (opts.onChange) opts.onChange(obj[key], s); });
  return s;
}
function dateInput(obj, key, opts = {}) {
  const i = h('input', { type: 'date', value: obj[key] || '', 'aria-label': opts.label || key });
  i.addEventListener('change', () => { obj[key] = i.value; changed(); if (opts.onChange) opts.onChange(i.value, i); });
  return i;
}
const pill = (cls, text) => h('span', { class: `pill ${cls}` }, text);
const typePill = (type) => pill(`tone-${toneOf(type)}`, type);
const statusPill = (s) => pill(`s-${String(s).replace(/\s+/g, '-')}`, s);
function delBtn(list, row, label) {
  return h('button', { class: 'icon-btn', title: `Delete ${label}`, 'aria-label': `Delete ${label}`, onclick: () => {
    if (!confirm(`Delete this ${label}?`)) return;
    const i = list.indexOf(row); if (i >= 0) list.splice(i, 1); changed(); render();
  } }, '×');
}
function viewHead(title, note) { return [h('h2', { text: title }), note ? h('p', { class: 'sub', text: note }) : null]; }
function sheetMeta(k) { return (S.data.sheets && S.data.sheets[k]) || {}; }

/* ------------------------------------------------------------------ state changes */
let draftTimer = null;
function changed() { S.dirty = true; updateStatus(); clearTimeout(draftTimer); draftTimer = setTimeout(saveDraft, 900); }
function updateStatus() {
  const st = $('status');
  if (S.dirty) { st.textContent = 'Unsaved changes'; st.className = 'status dirty'; }
  else {
    const u = S.data && S.data.updatedAt ? new Date(S.data.updatedAt) : null;
    st.textContent = u ? `Saved ${fmt(u, { day: 'numeric', month: 'short' })} ${u.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}${S.data.updatedBy ? ' · ' + S.data.updatedBy : ''}` : '';
    st.className = 'status';
  }
  $('save').disabled = !S.dirty;
}
async function saveDraft() {
  if (!S.dirty || !S.key) return;
  try { localStorage.setItem('mc-draft', JSON.stringify({ savedAt: new Date().toISOString(), env: await encryptData(S.data) })); } catch (e) { console.warn('Draft not stored', e); }
}
function clearDraft() { try { localStorage.removeItem('mc-draft'); } catch (e) { /* ignore */ } }
async function checkDraft() {
  let d; try { d = JSON.parse(localStorage.getItem('mc-draft') || 'null'); } catch (e) { d = null; }
  if (!d) return;
  let draft; try { draft = await decryptEnv(d.env, await keyFor(d.env)); } catch (e) { clearDraft(); return; }
  if (JSON.stringify(draft) === S.baseline) { clearDraft(); return; }
  const when = new Date(d.savedAt);
  showBanner([
    h('span', null, `You have unsaved edits from ${fmt(when, { day: 'numeric', month: 'short' })} ${when.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })} on this device.`),
    h('button', { class: 'btn small', onclick: () => { S.data = draft; S.dirty = true; hideBanner(); updateStatus(); render(); toast('Edits restored. Save to keep them.'); } }, 'Restore them'),
    h('button', { class: 'btn small danger', onclick: () => { clearDraft(); hideBanner(); } }, 'Discard'),
  ]);
}
function showBanner(kids) { const b = $('banner'); b.replaceChildren(...kids); b.hidden = false; }
function hideBanner() { $('banner').hidden = true; }
let toastTimer = null;
function toast(msg, ms = 3500) { const t = $('toast'); t.textContent = msg; t.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, ms); }

/* ------------------------------------------------------------------ unlock / lock / save */
async function unlock(pw) {
  const env = await fetchEnvelope();
  S.pw = pw;
  const key = await keyFor(env);
  let data;
  try { data = await decryptEnv(env, key); } catch (e) { S.pw = null; keyCache.clear(); throw new Error('Wrong password.'); }
  S.key = key; S.salt = unb64(env.salt); S.iterations = env.iterations;
  S.data = data; S.baseline = JSON.stringify(data); S.dirty = false;
  $('login').hidden = true; $('app').hidden = false;
  setBrand(true); buildTabs(); updateStatus(); render();
  if (!canSave()) showBanner([h('span', null, 'Read-only on this device: add your GitHub token in Settings to save changes. Edits you make are kept on this device until then.'),
    h('button', { class: 'btn small', onclick: openSettings }, 'Open Settings')]);
  await checkDraft();
}
function lock() {
  if (S.dirty && !confirm('You have unsaved changes. They are kept as a draft on this device. Lock anyway?')) return;
  Object.assign(S, { data: null, pw: null, key: null, salt: null, sha: null, baseline: null, dirty: false });
  keyCache.clear(); $('view').replaceChildren(); hideBanner(); setBrand(false);
  $('app').hidden = true; $('login').hidden = false; $('pw').value = ''; $('pw').focus();
}
async function save(force = false) {
  if (!canSave()) { openSettings('Add your GitHub token to save.'); return; }
  const btn = $('save'); btn.disabled = true; btn.textContent = 'Saving…';
  try {
    const remote = await ghGet();
    if (!force && remote.sha !== S.sha) {
      let same = false;
      try { const env = JSON.parse(remote.text); same = JSON.stringify(await decryptEnv(env, await keyFor(env))) === S.baseline; } catch (e) { same = false; }
      if (!same) { conflict(); return; }
    }
    S.data.updatedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    S.data.updatedBy = ghCfg().editor || 'Web app';
    const text = JSON.stringify(await encryptData(S.data), null, 1);
    S.sha = await ghPut(text, remote.sha);
    S.baseline = JSON.stringify(S.data); S.dirty = false; clearDraft(); hideBanner();
    toast('Saved to GitHub. The public site catches up in about a minute.');
  } catch (e) {
    console.error(e); toast(`Not saved: ${e.message}`, 6000);
  } finally {
    btn.textContent = 'Save'; updateStatus();
  }
}
function conflict() {
  openModal([
    h('h3', { text: 'The calendar changed on GitHub' }),
    h('p', null, 'Someone (probably Claude, or you on another device) saved a newer version since you opened this one.'),
    h('p', { class: 'note' }, 'Reload to see their version (your edits here are lost, but you can download them first), or overwrite theirs with yours.'),
    h('div', { class: 'modal-actions' },
      h('button', { class: 'btn', onclick: () => download(`calendar-my-edits-${toISO(today())}.json`, JSON.stringify(S.data, null, 1)) }, 'Download my edits'),
      h('button', { class: 'btn', onclick: async () => { closeModal(); S.dirty = false; clearDraft(); try { await unlock(S.pw); toast('Reloaded the latest version.'); } catch (e) { toast(e.message); } } }, 'Reload theirs'),
      h('button', { class: 'btn primary', onclick: () => { closeModal(); save(true); } }, 'Overwrite with mine')),
  ]);
}

/* ------------------------------------------------------------------ modal + settings */
function openModal(kids) { $('modal-body').replaceChildren(...kids.flat()); $('modal').hidden = false; }
function closeModal() { $('modal').hidden = true; }
function download(name, text, type = 'application/json') {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name }); document.body.append(a); a.click(); a.remove();
}
function openSettings(msg) {
  const c = ghCfg();
  const f = (k, label, type = 'text', ph = '') => {
    const i = h('input', { type, value: c[k] || '', placeholder: ph, autocomplete: 'off', spellcheck: 'false' });
    i.addEventListener('input', () => { c[k] = i.value.trim(); });
    return h('div', { class: 'form-row' }, h('label', { text: label }), i);
  };
  const result = h('p', { class: 'note' });
  const pw1 = h('input', { type: 'password', placeholder: 'New password', autocomplete: 'new-password' });
  const pw2 = h('input', { type: 'password', placeholder: 'Repeat', autocomplete: 'new-password' });
  openModal([
    h('h3', { text: 'Settings' }),
    typeof msg === 'string' ? h('p', { class: 'error', text: msg }) : null,
    h('h4', { text: 'Saving to GitHub (this device only)' }),
    h('p', { class: 'note' }, 'Use a fine-grained token limited to this one repository, with “Contents: Read and write” and nothing else. It is stored in this browser only.'),
    f('owner', 'Owner', 'text', 'GitHub user'), f('repo', 'Repository', 'text', 'repository name'), f('branch', 'Branch', 'text', 'main'),
    f('path', 'Data file', 'text', CFG.dataPath), f('token', 'Token', 'password', 'github_pat_…'), f('editor', 'Your name', 'text', 'Shown as “saved by”'),
    result,
    h('div', { class: 'modal-actions' },
      h('button', { class: 'btn', onclick: async () => { saveGhCfg(c); result.textContent = 'Testing…'; try { const r = await ghGet(); result.textContent = `Connected. File found (${r.text.length.toLocaleString()} bytes).`; } catch (e) { result.textContent = e.message; } } }, 'Test connection'),
      h('button', { class: 'btn primary', onclick: () => { saveGhCfg(c); closeModal(); hideBanner(); updateStatus(); toast('Settings saved on this device.'); } }, 'Save settings')),
    h('h4', { text: 'Change the calendar password' }),
    h('div', { class: 'form-row' }, h('label', { text: 'New' }), pw1),
    h('div', { class: 'form-row' }, h('label', { text: 'Repeat' }), pw2),
    h('p', { class: 'note' }, 'Re-encrypts the calendar. Tell anyone else who uses it. Older versions in the repository history keep the old password.'),
    h('div', { class: 'modal-actions' }, h('button', { class: 'btn', onclick: async () => {
      if (pw1.value.length < 12) { toast('Use at least 12 characters.'); return; }
      if (pw1.value !== pw2.value) { toast('The two passwords differ.'); return; }
      S.pw = pw1.value; S.salt = crypto.getRandomValues(new Uint8Array(16)); S.iterations = CFG.iterations;
      S.key = await deriveKey(S.pw, S.salt, S.iterations); keyCache.clear(); keyCache.set(`${b64(S.salt)}:${S.iterations}`, S.key);
      changed(); closeModal(); toast('Password changed here. Press Save to apply it.', 5000);
    } }, 'Change password')),
    h('h4', { text: 'Export' }),
    h('div', { class: 'modal-actions', style: { justifyContent: 'flex-start' } },
      h('button', { class: 'btn', onclick: () => download(`events-${toISO(today())}.csv`, eventsCsv(), 'text/csv') }, 'Events as CSV'),
      h('button', { class: 'btn', onclick: async () => download(`calendar-encrypted-${toISO(today())}.json`, JSON.stringify(await encryptData(S.data), null, 1)) }, 'Encrypted backup'),
      h('button', { class: 'btn danger', onclick: () => { if (confirm('This file is NOT encrypted. Keep it private. Download?')) download(`calendar-PLAINTEXT-${toISO(today())}.json`, JSON.stringify(S.data, null, 1)); } }, 'Plain JSON')),
    h('p', { class: 'note' }, 'For an Excel copy, ask Claude: “export the master calendar to xlsx”.'),
    h('div', { class: 'modal-actions' }, h('button', { class: 'btn', onclick: closeModal }, 'Close')),
  ]);
}
function eventsCsv() {
  const q = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  return ['Date,Until,Item,Type,Source', ...[...S.data.events].sort((a, b) => a.date.localeCompare(b.date))
    .map((e) => [e.date, e.until || e.date, e.item, e.type, e.source].map(q).join(','))].join('\n');
}

/* ------------------------------------------------------------------ views */
function buildTabs() {
  $('tabs').replaceChildren(...VIEWS.map(([k, label]) => h('button', { class: `tab${S.view === k ? ' on' : ''}`, 'data-view': k, onclick: () => { S.view = k; buildTabs(); render(); window.scrollTo(0, 0); } }, label)));
}
function render() {
  const v = $('view'); const fn = { overview, weeks, events, months, tripwires, premortem, priorities, backcast, focus }[S.view];
  v.replaceChildren(...[fn()].flat(Infinity).filter((x) => x != null && x !== false));
  if (S.view === 'weeks') { const cur = v.querySelector('tr.current'); if (cur) cur.scrollIntoView({ block: 'center' }); }
}

function overview() {
  const t = today(), wk = mondayOf(t), week = S.data.weeks.find((w) => w.start === toISO(wk));
  const o = openingDate(); const toOpen = o ? daysBetween(t, o) : null;
  const upcoming = S.data.events.filter((e) => evEnd(e) >= t && parseISO(e.date) <= addDays(t, 30)).sort((a, b) => a.date.localeCompare(b.date));
  const tw = S.data.tripwires;
  const risky = S.data.premortem.map((p) => [p, score(p)]).filter(([, s]) => s != null).sort((a, b) => b[1] - a[1]);
  const unscored = S.data.premortem.filter((p) => score(p) == null).length;
  return [
    ...viewHead(fmt(t, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }), null),
    h('div', { class: 'cards' },
      h('div', { class: 'card wide' }, h('h3', { text: `This week · from ${fmtDay(wk)}` }),
        week ? h('div', { class: 'week-strip' }, week.days.map((d, i) => h('div', { class: `day-tile${i === (t.getDay() + 6) % 7 ? ' today' : ''}`, style: { background: dayBg(d) || '#F4F5F7' } },
          h('div', { class: 'dname', text: `${DAY_NAMES[i]} ${addDays(wk, i).getDate()}` }), d || '—')))
          : h('p', { class: 'muted' }, 'This week is not in Weeks yet. Add it from the Weeks tab.'),
        week && week.notes ? h('p', { class: 'note', style: { marginTop: '10px' } }, week.notes) : null),
      h('div', { class: 'card' }, h('h3', { text: 'Countdown' }),
        h('div', { class: 'kpis' },
          h('div', { class: 'kpi' }, h('div', { class: 'big', text: toOpen != null ? String(toOpen) : '—' }), h('div', { class: 'lbl', text: o ? `days to ${ST().countdownLabel || 'the target date'} (${fmtFull(o)})` : 'target date not set' })),
          h('div', { class: 'kpi' }, h('div', { class: 'big', text: String(weeksTo(wk)) }), h('div', { class: 'lbl', text: 'weeks from this Monday' })))),
      h('div', { class: 'card' }, h('h3', { text: 'Tripwires' }),
        h('ul', { class: 'list' }, tw.map((x) => { const dl = daysLeft(x.by); return h('li', { style: { gridTemplateColumns: '28px 1fr auto' } },
          h('span', { class: 'when', text: `#${x.n}` }), h('span', null, x.checkpoint, h('br'), h('span', { class: `note${dl != null && dl < 0 && !['Met'].includes(x.status) ? ' overdue' : ''}` }, dl != null ? (dl >= 0 ? `${dl} days left · ${fmtFull(parseISO(x.by))}` : `${-dl} days overdue`) : x.by)),
          statusPill(x.status)); }))),
      h('div', { class: 'card' }, h('h3', { text: 'Premortem watch' }),
        risky.length ? h('ul', { class: 'list' }, risky.slice(0, 5).map(([p, s]) => h('li', { style: { gridTemplateColumns: '40px 1fr auto' } }, h('span', { class: 'pill', style: scoreStyle(s), text: String(s) }), h('span', { text: p.how }), statusPill(p.status)))) : null,
        unscored ? h('p', { class: 'note' }, `${unscored} of ${S.data.premortem.length} risks not scored yet. `, h('a', { href: '#', onclick: (ev) => { ev.preventDefault(); S.view = 'premortem'; buildTabs(); render(); } }, 'Score them')) : null),
      h('div', { class: 'card wide' }, h('h3', { text: 'Next 30 days' }),
        upcoming.length ? h('ul', { class: 'list' }, upcoming.map((e) => h('li', null, h('span', { class: 'when', text: fmtSpan(e) }), h('span', { class: 'pill-cell' }, typePill(e.type)), h('span', { text: e.item }))))
          : h('p', { class: 'muted' }, 'Nothing dated in the next 30 days.')),
    ),
  ];
}

function weeks() {
  const t = today(), cur = toISO(mondayOf(t));
  const meta = sheetMeta('weeks');
  const rows = S.data.weeks.filter((w) => S.showPast || parseISO(w.start) >= addDays(mondayOf(t), -7));
  let lastMonth = '';
  const body = [];
  for (const w of rows) {
    const start = parseISO(w.start); const m = fmtMonth(start);
    if (m !== lastMonth) { lastMonth = m; body.push(h('tr', { class: 'month-row' }, h('td', { colspan: 12, text: m }))); }
    const evs = eventsInWeek(start); const gate = evs.some((e) => e.type === gateType());
    body.push(h('tr', { class: `${w.start === cur ? 'current' : ''}${start < mondayOf(t) ? ' past' : ''}` },
      h('td', { class: 'ro sticky-col w-s' }, h('b', { text: fmtDay(start) })),
      w.days.map((d, i) => h('td', { class: 'day' }, ed(w.days, i, { bg: true, ph: '—' }))),
      h('td', { class: 'ro w-l' }, evs.map((e) => h('div', { style: { margin: '1px 0' } }, typePill(e.type), ' ', e.item))),
      h('td', { class: 'ro w-xs' }, gate ? pill('gate', gateType()) : ''),
      h('td', { class: 'ro num w-xs', text: String(weeksTo(start)) }),
      h('td', { class: 'w-m' }, ed(w, 'notes', { ph: 'Notes' })),
      h('td', { class: 'w-xs' }, delBtn(S.data.weeks, w, 'week'))));
  }
  return [
    ...viewHead(meta.title || 'Weeks', `Day cells and notes are yours to change. “Fixed this week” and “${gateType()}” read from Events.`),
    h('div', { class: 'legend' }, dayCats().map((c) => h('span', { style: { background: c.color }, text: c.label }))),
    h('div', { class: 'toolbar' },
      h('label', { class: 'toggle' }, h('input', { type: 'checkbox', checked: S.showPast ? true : null, onchange: (e) => { S.showPast = e.target.checked; render(); } }), 'Show past weeks'),
      h('button', { class: 'btn small', onclick: () => { const cur = document.querySelector('tr.current'); if (cur) cur.scrollIntoView({ block: 'center', behavior: 'smooth' }); } }, 'This week'),
      h('button', { class: 'btn small', onclick: addWeek }, '+ Add next week')),
    h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
      h('thead', null, h('tr', null, h('th', { class: 'sticky-col', text: 'Week of' }), dayHeaders().map((d) => h('th', { text: d })),
        h('th', { text: 'Fixed this week' }), h('th', { text: gateType() }), h('th', { text: `Wks to ${countdownShort()}` }), h('th', { text: 'Notes' }), h('th', null))),
      h('tbody', null, body))),
  ];
}
function addWeek() {
  const last = S.data.weeks.map((w) => w.start).sort().pop();
  const start = last ? addDays(parseISO(last), 7) : mondayOf(today());
  S.data.weeks.push({ start: toISO(start), days: defaultWeek(), notes: '' });
  S.data.weeks.sort((a, b) => a.start.localeCompare(b.start)); changed(); render();
  toast(`Added the week of ${fmtFull(start)} with the default week.`);
}

function events() {
  const t = today(), q = S.evQuery.toLowerCase();
  const meta = sheetMeta('events');
  const list = [...S.data.events].sort((a, b) => (a.date || '').localeCompare(b.date || ''))
    .filter((e) => (S.evType === 'All' || e.type === S.evType) && (S.evPast || !evEnd(e) || evEnd(e) >= t) && (!q || `${e.item} ${e.source}`.toLowerCase().includes(q)));
  let lastMonth = '';
  const body = [];
  for (const e of list) {
    const d = parseISO(e.date); const m = d ? fmtMonth(d) : 'No date';
    if (m !== lastMonth) { lastMonth = m; body.push(h('tr', { class: 'month-row' }, h('td', { colspan: 6, text: m }))); }
    body.push(h('tr', { class: evEnd(e) && evEnd(e) < t ? 'past' : '' },
      h('td', { class: 'w-s' }, dateInput(e, 'date', { label: 'Date' })),
      h('td', { class: 'w-s' }, dateInput(e, 'until', { label: 'Until' })),
      h('td', { class: 'w-xl' }, ed(e, 'item', { ph: 'What' })),
      h('td', { class: 'w-s' }, sel(e, 'type', eventTypes(), { label: 'Type' })),
      h('td', { class: 'w-m' }, ed(e, 'source', { ph: 'Source' })),
      h('td', { class: 'w-xs' }, delBtn(S.data.events, e, 'event'))));
  }
  const search = h('input', { type: 'search', placeholder: 'Search events', value: S.evQuery });
  search.addEventListener('input', () => { S.evQuery = search.value; const pos = search.selectionStart; render(); const s = document.querySelector('.toolbar input[type=search]'); s.focus(); s.setSelectionRange(pos, pos); });
  return [
    ...viewHead(meta.title || 'Events', 'Every dated commitment. Add one here and it appears in Weeks. Month-only items sit on the 1st.'),
    h('div', { class: 'toolbar' },
      h('button', { class: 'btn primary', onclick: addEvent }, '+ Add event'),
      ['All', ...eventTypes()].map((ty) => h('button', { class: `chip${S.evType === ty ? ' on' : ''}`, onclick: () => { S.evType = ty; render(); } }, ty)),
      search,
      h('label', { class: 'toggle' }, h('input', { type: 'checkbox', checked: S.evPast ? true : null, onchange: (ev) => { S.evPast = ev.target.checked; render(); } }), 'Show past')),
    h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
      h('thead', null, h('tr', null, ['Date', 'Until', 'Item', 'Type', 'Source', ''].map((x) => h('th', { text: x })))),
      h('tbody', null, body.length ? body : h('tr', null, h('td', { class: 'ro muted', colspan: 6, text: 'No events match.' }))))),
  ];
}
function addEvent() {
  const e = { id: uid('ev'), date: toISO(today()), until: '', item: '', type: ST().defaultEventType || eventTypes()[0], source: ghCfg().editor || ST().defaultSource || '' };
  S.data.events.push(e); S.evType = 'All'; S.evQuery = ''; changed(); render();
  const row = [...document.querySelectorAll('.grid tbody tr')].find((tr) => tr.querySelector('.ed') && tr.querySelector('.ed').textContent === '' && tr.querySelector('input[type=date]').value === e.date);
  if (row) { row.scrollIntoView({ block: 'center' }); row.querySelector('.ed').focus(); }
}

function simpleTable(listKey, cols, opts = {}) {
  const list = S.data[listKey];
  return h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
    h('thead', null, h('tr', null, cols.map((c) => h('th', { text: c.label })), h('th', null))),
    h('tbody', null, list.map((row) => h('tr', null, cols.map((c) => h('td', { class: c.ro ? `ro ${c.w || ''}` : (c.w || '') }, c.render ? c.render(row) : ed(row, c.key, { ph: c.ph || '' }))),
      h('td', { class: 'w-xs' }, delBtn(list, row, opts.noun || 'row')))))));
}
function addRowBtn(listKey, make, label) {
  return h('button', { class: 'btn small', onclick: () => { S.data[listKey].push(make()); changed(); render(); } }, label);
}

function months() {
  const meta = sheetMeta('months'); const widths = ['w-s', 'w-m', 'w-l', 'w-l', 'w-m', 'w-m', 'w-l', 'w-m'];
  return [...viewHead(meta.title || 'Months', meta.note),
    h('div', { class: 'toolbar' }, addRowBtn('months', () => ({ id: uid('mo'), ...Object.fromEntries(S.data.monthColumns.map((c) => [c.key, ''])) }), '+ Add month')),
    simpleTable('months', S.data.monthColumns.map((c, i) => ({ key: c.key, label: c.label, w: widths[i] })), { noun: 'month' })];
}

function tripwires() {
  const meta = sheetMeta('tripwires');
  const cols = [
    { key: 'n', label: '#', ro: true, w: 'w-xs', render: (r) => `#${r.n}` },
    { key: 'checkpoint', label: 'Checkpoint', w: 'w-l' },
    { key: 'by', label: 'By (YYYY-MM-DD or words)', w: 'w-s', render: (r) => ed(r, 'by', { ph: 'YYYY-MM-DD', onInput: () => { const c = document.querySelector(`[data-dl="${r.id}"]`); if (c) fillDaysLeft(c, r); } }) },
    { key: 'byNote', label: 'Where the date comes from', w: 'w-l' },
    { key: 'ifMissed', label: "If it's missed", w: 'w-l' },
    { key: 'dl', label: 'Days left', ro: true, w: 'w-s', render: (r) => { const c = h('span', { 'data-dl': r.id }); fillDaysLeft(c, r); return c; } },
    { key: 'status', label: 'Status', w: 'w-s', render: (r) => sel(r, 'status', TRIPWIRE_STATUSES, { label: 'Status', onChange: () => { const c = document.querySelector(`[data-dl="${r.id}"]`); if (c) fillDaysLeft(c, r); } }) },
  ];
  return [...viewHead(meta.title || 'Tripwires', meta.note),
    h('div', { class: 'toolbar' }, addRowBtn('tripwires', () => ({ id: uid('tw'), n: Math.max(0, ...S.data.tripwires.map((x) => x.n || 0)) + 1, checkpoint: '', by: '', byNote: '', ifMissed: '', status: 'Open' }), '+ Add tripwire')),
    simpleTable('tripwires', cols, { noun: 'tripwire' })];
}
function fillDaysLeft(el, r) {
  const dl = daysLeft(r.by);
  el.textContent = dl == null ? '' : dl < 0 ? `${-dl} overdue` : String(dl);
  el.className = dl != null && dl < 0 && r.status !== 'Met' ? 'overdue' : '';
}

function premortem() {
  const meta = sheetMeta('premortem'); const lvl = [['', '–'], 1, 2, 3, 4, 5];
  const refresh = (r) => { const c = document.querySelector(`[data-score="${r.id}"]`); if (c) { const s = score(r); c.textContent = s == null ? '' : String(s); c.removeAttribute('style'); Object.assign(c.style, scoreStyle(s)); } };
  const cols = [
    { key: 'n', label: '#', ro: true, w: 'w-xs', render: (r) => String(r.n) },
    { key: 'how', label: 'How it failed', w: 'w-m' }, { key: 'why', label: "Why it's plausible", w: 'w-l' },
    { key: 'luck', label: 'Luck or decision', w: 'w-s' }, { key: 'guard', label: 'Guard to put in place now', w: 'w-l' },
    { key: 'source', label: 'Source', w: 'w-m' },
    { key: 'likelihood', label: 'Likelihood', w: 'w-s', render: (r) => sel(r, 'likelihood', lvl, { num: true, label: 'Likelihood', onChange: () => refresh(r) }) },
    { key: 'impact', label: 'Impact', w: 'w-s', render: (r) => sel(r, 'impact', lvl, { num: true, label: 'Impact', onChange: () => refresh(r) }) },
    { key: 'score', label: 'Score', ro: true, w: 'w-xs', render: (r) => { const s = score(r); return h('span', { class: 'pill', 'data-score': r.id, style: scoreStyle(s), text: s == null ? '' : String(s) }); } },
    { key: 'owner', label: 'Owner', w: 'w-s' },
    { key: 'status', label: 'Status', w: 'w-s', render: (r) => sel(r, 'status', PREMORTEM_STATUSES, { label: 'Status' }) },
    { key: 'notes', label: 'Notes', w: 'w-m' },
  ];
  return [...viewHead(meta.title || 'Premortem', meta.note),
    h('div', { class: 'toolbar' }, addRowBtn('premortem', () => ({ id: uid('pm'), n: Math.max(0, ...S.data.premortem.map((x) => x.n || 0)) + 1, how: '', why: '', luck: '', guard: '', source: '', likelihood: null, impact: null, owner: '', status: 'Open', notes: '' }), '+ Add risk')),
    simpleTable('premortem', cols, { noun: 'risk' })];
}

function priorities() {
  const meta = sheetMeta('priorities');
  return [...viewHead(meta.title || 'Priorities', meta.note),
    h('div', { class: 'toolbar' }, addRowBtn('priorities', () => ({ id: uid('pr'), rank: S.data.priorities.length + 1, work: '', form: '', condition: '', funder: '', due: '' }), '+ Add priority')),
    simpleTable('priorities', [{ key: 'rank', label: 'Rank', w: 'w-xs' }, { key: 'work', label: 'Work', w: 'w-m' }, { key: 'form', label: 'Form', w: 'w-l' },
      { key: 'condition', label: 'Condition or cap', w: 'w-l' }, { key: 'funder', label: 'Funder', w: 'w-m' }, { key: 'due', label: 'Due', w: 'w-s' }], { noun: 'priority' })];
}

function backcast() {
  const meta = sheetMeta('backcast');
  return [...viewHead(meta.title || 'Backcast', meta.note),
    h('div', { class: 'toolbar' }, addRowBtn('backcast', () => ({ id: uid('bc'), when: '', what: '', tripwire: '' }), '+ Add line')),
    simpleTable('backcast', [{ key: 'when', label: 'When', w: 'w-s' }, { key: 'what', label: 'What happened', w: 'w-xl' }, { key: 'tripwire', label: 'Tripwire #', w: 'w-xs' }], { noun: 'line' })];
}

function focus() {
  const meta = sheetMeta('focus');
  return [...viewHead(meta.title || 'Focus flow', meta.note),
    S.data.focus.map((sec) => h('div', { class: 'focus-sec' },
      ed(sec, 'title', { cls: 'title' }),
      h('ol', null, sec.steps.map((_, i) => h('li', null, h('div', { class: 'row' }, ed(sec.steps, i), h('button', { class: 'icon-btn', title: 'Delete step', onclick: () => { if (confirm('Delete this step?')) { sec.steps.splice(i, 1); changed(); render(); } } }, '×'))))),
      h('button', { class: 'btn small', style: { marginTop: '8px' }, onclick: () => { sec.steps.push(''); changed(); render(); } }, '+ Add step'))),
    h('button', { class: 'btn small', onclick: () => { S.data.focus.push({ id: uid('fs'), title: 'New section', steps: [''] }); changed(); render(); } }, '+ Add section')];
}

/* ------------------------------------------------------------------ first-run setup */
async function boot() {
  let exists = true;
  try {
    const r = await fetch(`${CFG.dataPath}?t=${Date.now()}`, { method: 'HEAD', cache: 'no-store' });
    if (r.status === 404) {
      exists = false;
      if (canSave()) { try { await ghGet(); exists = true; } catch (e) { exists = !/GitHub: 404/.test(e.message); } }
    }
  } catch (e) { /* offline or blocked: fall back to the password screen */ }
  if (!exists) { $('login').hidden = true; $('setup').hidden = false; }
}
async function setupCalendar() {
  const file = $('su-file').files[0];
  const code = $('su-code').value, p1 = $('su-pw1').value, p2 = $('su-pw2').value, token = $('su-token').value.trim();
  if (!file) throw new Error('Choose the setup file.');
  if (p1.length < 12) throw new Error('Use at least 12 characters for your password.');
  if (p1 !== p2) throw new Error('The two new passwords differ.');
  if (p1 === code) throw new Error('Choose a password that is different from the setup code.');
  let env; try { env = JSON.parse(await file.text()); } catch (e) { env = null; }
  if (!env || !env.ct || !env.salt || !env.iv) throw new Error('That is not a setup file.');
  let data;
  try { data = await decryptEnv(env, await deriveKey(code, unb64(env.salt), env.iterations)); } catch (e) { throw new Error('The setup code does not open that file.'); }
  const c = ghCfg(); c.token = token;
  if ($('su-name').value.trim()) c.editor = $('su-name').value.trim();
  if (!c.owner || !c.repo) throw new Error('Open this page from its GitHub Pages address so the repository can be found.');
  saveGhCfg(c);
  S.pw = p1; S.salt = crypto.getRandomValues(new Uint8Array(16)); S.iterations = CFG.iterations;
  S.key = await deriveKey(p1, S.salt, S.iterations); keyCache.clear(); keyCache.set(`${b64(S.salt)}:${S.iterations}`, S.key);
  data.updatedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z'); data.updatedBy = c.editor || 'Setup';
  const text = JSON.stringify(await encryptData(data), null, 1);
  try { S.sha = await ghPut(text, undefined); } catch (e) {
    if (/GitHub: 422/.test(e.message)) throw new Error('A calendar already exists here. Reload the page and unlock it instead.');
    throw e;
  }
  S.data = data; S.baseline = JSON.stringify(data); S.dirty = false;
  ['su-code', 'su-pw1', 'su-pw2', 'su-token'].forEach((id) => { $(id).value = ''; });
  $('setup').hidden = true; $('app').hidden = false;
  setBrand(true); buildTabs(); updateStatus(); render();
  toast('Calendar created and locked with your password. The site shows it to other devices in about a minute.', 7000);
}

/* ------------------------------------------------------------------ boot */
document.addEventListener('DOMContentLoaded', () => {
  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('unlock'), err = $('login-error');
    btn.disabled = true; btn.textContent = 'Unlocking…'; err.textContent = '';
    try { await unlock($('pw').value); } catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; btn.textContent = 'Unlock'; }
  });
  $('setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('su-go'), err = $('setup-error');
    btn.disabled = true; btn.textContent = 'Creating…'; err.textContent = '';
    try { await setupCalendar(); } catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; btn.textContent = 'Create calendar'; }
  });
  $('save').addEventListener('click', () => save(false));
  $('lock').addEventListener('click', lock);
  $('settings-btn').addEventListener('click', () => openSettings());
  $('modal').addEventListener('click', (e) => { if (e.target === $('modal')) closeModal(); });
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's' && S.data) { e.preventDefault(); if (S.dirty) save(false); }
    if (e.key === 'Escape' && !$('modal').hidden) closeModal();
  });
  window.addEventListener('beforeunload', (e) => { if (S.dirty) { e.preventDefault(); e.returnValue = ''; } });
  if (!window.crypto || !crypto.subtle) $('login-error').textContent = 'This page needs HTTPS (or localhost) to decrypt the calendar.';
  boot();
});
