'use strict';

const $ = (s, el = document) => el.querySelector(s);
const enc = new TextEncoder();
const strictUTF8 = new TextDecoder('utf-8', { fatal: true });

// The token arrives in the URL fragment once; keep it for reloads but out of the address bar.
let token = new URLSearchParams(location.hash.slice(1)).get('token');
if (token) {
  sessionStorage.setItem('mucha-token', token);
  history.replaceState(null, '', location.pathname);
} else token = sessionStorage.getItem('mucha-token') || '';

const SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const KEY = /^[-._a-zA-Z0-9]+$/;
const PRESETS = {
  'kubernetes.io/tls': ['tls.crt', 'tls.key'],
  'kubernetes.io/dockerconfigjson': ['.dockerconfigjson'],
  'kubernetes.io/basic-auth': ['username', 'password'],
  'kubernetes.io/ssh-auth': ['ssh-privatekey'],
};
const REQUIRED = { 'kubernetes.io/tls': PRESETS['kubernetes.io/tls'], 'kubernetes.io/dockerconfigjson': PRESETS['kubernetes.io/dockerconfigjson'], 'kubernetes.io/ssh-auth': PRESETS['kubernetes.io/ssh-auth'] };

const state = { cert: null, certError: '', certLoading: false, namespaces: [], labels: null, annotations: null, sealedSnapshot: '', sealError: '', original: null, history: null, historyError: '' };
const rows = [];

async function api(path, body, method) {
  const res = await fetch(path, {
    method: method || (body ? 'POST' : 'GET'),
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: body && JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) throw new Error('This tab lost its session. Open the link mucha printed in your terminal.');
  if (!res.ok || data.error) throw new Error(sentence(data.error || `Request failed with status ${res.status}.`));
  return data;
}

const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

// Runs a discrete UI change as a view transition, so panels glide between layouts. Resolves once the DOM is updated.
const canAnimate = () => document.startViewTransition && !document.hidden && !reducedMotion();
async function animate(update) {
  if (!canAnimate()) return update();
  const t = document.startViewTransition(update);
  t.ready.catch(() => {}); // a newer transition skipped this one; the DOM update still happens
  t.finished.catch(() => {});
  return t.updateCallbackDone;
}

const sentence = (s) => { s = s.trim(); return s.charAt(0).toUpperCase() + s.slice(1) + (/[.!?]$/.test(s) ? '' : '.'); };

function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(b) {
  const s = atob(b), out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
function asText(bytes) { try { return strictUTF8.decode(bytes); } catch { return null; } }

// Returns the decoded text when a value already looks base64 encoded, so we can warn about double encoding.
function looksBase64(v) {
  const s = v.trim();
  if (s.length < 8 || s.length % 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  try {
    const t = asText(fromB64(s));
    return t && /^[^\x00-\x08\x0E-\x1F\x7F]+$/.test(t) ? t : null;
  } catch { return null; }
}

/* ---------- certificate ---------- */

const ctxSelect = $('#context');
const sourceName = () => state.cert?.source || '';

function drawCert() {
  const box = $('#cert');
  box.className = 'medallion';
  if (state.certLoading) {
    box.classList.add('loading');
    box.innerHTML = '<span class="sk w60"></span><span class="sk w80"></span><span class="sk w40"></span>';
    return;
  }
  if (state.certError) {
    box.classList.add('bad');
    box.replaceChildren(el('p', 'error', state.certError), el('p', 'muted', 'Check the context and the controller location, or load the certificate from a file.'));
    return;
  }
  if (!state.cert) { box.replaceChildren(el('p', 'muted', 'No certificate yet. Values are sealed with the public key of one specific cluster.')); return; }
  const { info, source } = state.cert;
  const days = Math.floor((new Date(info.notAfter) - Date.now()) / 864e5);
  const until = new Date(info.notAfter).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' });
  const fp = info.fingerprint.slice(0, 24).match(/.{4}/g).join(' ');
  box.classList.add(days < 0 ? 'bad' : days < 30 ? 'warn' : 'ok');
  const dl = document.createElement('dl');
  // The controller's own certificate has an empty subject, so the row only appears when there is something to show.
  for (const [k, v] of [['For', source], ...(info.subject ? [['Subject', info.subject]] : []), ['Valid until', `${until} (${days < 0 ? 'expired' : days + ' days left'})`], ['Fingerprint', fp + ' …']]) {
    dl.append(el('dt', '', k), el('dd', k === 'Fingerprint' ? 'mono' : '', v));
  }
  box.replaceChildren(icon('seal-check'), dl);
}

// The box has a fixed height, so long content scrolls inside it and must be reachable by keyboard.
function renderCert() {
  drawCert();
  const box = $('#cert');
  if (box.scrollHeight > box.clientHeight) box.tabIndex = 0;
  else box.removeAttribute('tabindex');
}

async function loadCert(body, source, onPageLoad = false) {
  state.cert = null; state.certError = ''; state.certLoading = true;
  renderCert(); refresh();
  try {
    const c = await api('/api/cert', { ...body, source });
    if (source === sourceFor()) state.cert = c;
    // Redrawing during page load could insert a row and push the others down. It catches up on the next action.
    if (!onPageLoad) loadHistory(c.historyError);
  } catch (e) {
    if (source === sourceFor()) state.certError = e.message;
  }
  state.certLoading = false;
  renderCert(); refresh();
}

// Which certificate source the UI currently points at; late responses for another source are dropped.
let pastedSource = '';
const sourceFor = () => ($('#tab-file').ariaSelected === 'true' ? pastedSource : ctxSelect.value || 'current context');

function fetchFromCluster(onPageLoad = false) {
  loadCert({ context: ctxSelect.value, controllerNamespace: $('#ctrl-ns').value.trim(), controllerName: $('#ctrl-name').value.trim() }, sourceFor(), onPageLoad);
  state.namespaces = [];
  $('#ns-list').replaceChildren();
  const ctx = ctxSelect.value;
  api('/api/namespaces?context=' + encodeURIComponent(ctx)).then(({ namespaces }) => {
    if (ctx !== ctxSelect.value) return;
    state.namespaces = namespaces;
    $('#ns-list').replaceChildren(...namespaces.map((n) => Object.assign(document.createElement('option'), { value: n })));
    refresh();
  }).catch(() => {}); // suggestions only; RBAC may forbid listing namespaces
}

async function initContexts() {
  try {
    const { contexts, current } = await api('/api/contexts');
    if (!contexts.length) throw new Error('No contexts in your kubeconfig.');
    ctxSelect.replaceChildren(...contexts.map((c) => Object.assign(document.createElement('option'), { value: c, textContent: c + (c === current ? '  (current)' : '') })));
    ctxSelect.value = current || contexts[0];
    if ($('#tab-cluster').ariaSelected === 'true') fetchFromCluster(true); // a certificate picked meanwhile must not be overwritten
  } catch {
    ctxSelect.replaceChildren(Object.assign(document.createElement('option'), { value: '', textContent: 'No kubeconfig contexts found' }));
    ctxSelect.disabled = true;
    $('#fetch').disabled = true;
    selectTab('file');
  }
}

function selectTab(name) {
  for (const t of ['cluster', 'file']) {
    const on = t === name;
    $('#tab-' + t).ariaSelected = String(on);
    $('#tab-' + t).tabIndex = on ? 0 : -1;
    $('#pane-' + t).hidden = !on;
  }
}

$('#tab-cluster').onclick = () => animate(() => selectTab('cluster'));
$('#tab-file').onclick = () => animate(() => selectTab('file'));
$('.tabs').onkeydown = (e) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  const next = $('#tab-cluster').ariaSelected === 'true' ? 'file' : 'cluster';
  animate(() => { selectTab(next); $('#tab-' + next).focus(); });
};
ctxSelect.onchange = () => fetchFromCluster();
$('#fetch').onclick = () => fetchFromCluster();
$('#pem-pick').onclick = () => $('#pem-file').click();
$('#pem-file').onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $('#pem').value = await f.text();
  pastedSource = f.name;
  e.target.value = '';
  loadCert({ pem: $('#pem').value }, pastedSource);
};
$('#use-pem').onclick = () => { pastedSource = 'pasted certificate'; loadCert({ pem: $('#pem').value }, pastedSource); };

/* ---------- key rows ---------- */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'i');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `icons.svg#i-${name}`);
  svg.append(use);
  return svg;
}

function addRow({ key = '', text = '', bytes = null, sealed = null } = {}, focus = false) {
  const li = $('#key-row').content.firstElementChild.cloneNode(true);
  const row = { key, text, bytes, sealed, li, valueIssues: [] };
  const k = $('.k', li), v = $('.v', li);
  k.value = key; v.value = text;
  k.oninput = () => { row.key = k.value; renderRow(row); refresh(); };
  v.oninput = () => { row.text = v.value; checkValue(row); refresh(); };
  $('.reveal', li).onclick = (e) => {
    const shown = v.classList.toggle('masked') === false;
    e.currentTarget.ariaPressed = String(shown);
    e.currentTarget.title = e.currentTarget.ariaLabel = shown ? 'Hide value' : 'Show value';
    $('use', e.currentTarget).setAttribute('href', `icons.svg#i-${shown ? 'eye-slash' : 'eye'}`);
  };
  $('.pick', li).onclick = () => $('.file', li).click();
  $('.file', li).onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const b = new Uint8Array(await f.arrayBuffer());
    const t = asText(b);
    if (!row.key) row.key = k.value = f.name.replace(/[^-._a-zA-Z0-9]/g, '_');
    row.text = t ?? ''; row.bytes = t === null ? b : null;
    e.target.value = '';
    renderRow(row); checkValue(row); refresh();
  };
  $('.replace', li).onclick = () => animate(() => { row.sealed = null; renderRow(row); checkValue(row); refresh(); v.focus(); });
  $('.remove', li).onclick = () => animate(() => { rows.splice(rows.indexOf(row), 1); li.remove(); refresh(); $('#add-key').focus(); });
  $('.d-build', li).onclick = () => {
    const reg = $('.d-reg', li).value.trim(), user = $('.d-user', li).value, pass = $('.d-pass', li).value;
    const auth = toB64(enc.encode(`${user}:${pass}`));
    setText(row, JSON.stringify({ auths: { [reg]: { username: user, password: pass, auth } } }));
    $('.d-pass', li).value = '';
  };
  rows.push(row);
  $('#keys').append(li);
  renderRow(row); checkValue(row);
  if (focus) k.focus();
  return row;
}

function setText(row, text) {
  row.text = text; row.bytes = null;
  $('.v', row.li).value = text;
  renderRow(row); checkValue(row); refresh();
}

function renderRow(row) {
  const { li } = row;
  const sealed = !!row.sealed;
  $('.sealed-tag', li).hidden = !sealed;
  $('.replace', li).hidden = !sealed;
  $('.reveal', li).hidden = $('.pick', li).hidden = sealed || !!row.bytes;
  $('.v', li).hidden = sealed || !!row.bytes;
  $('.docker', li).hidden = sealed || row.key !== '.dockerconfigjson';
  li.classList.toggle('is-sealed', sealed);
}

const issue = (level, text, action, fn) => ({ level, text, action, fn });

function checkValue(row) {
  const out = [];
  if (row.sealed) { /* ciphertext is opaque */ }
  else if (row.bytes) out.push(issue('info', `Binary file, ${row.bytes.length.toLocaleString()} bytes.`, 'Clear', () => setText(row, '')));
  else {
    const v = row.text;
    if (!v) out.push(issue('error', 'Value is empty. Add one or remove this key.'));
    else {
      if (/[\r\n]$/.test(v)) out.push(issue('warn', 'Ends with a line break, often left by echo or a copied file.', 'Remove it', () => setText(row, v.replace(/[\r\n]+$/, ''))));
      else if (/^\s|\s$/.test(v)) out.push(issue('warn', 'Starts or ends with spaces.', 'Trim', () => setText(row, v.trim())));
      const decoded = looksBase64(v);
      if (decoded !== null) out.push(issue('warn', 'Looks base64 encoded already. Values are encoded for you, so this would end up encoded twice.', 'Decode it', () => setText(row, decoded)));
      if (row.key === '.dockerconfigjson') { try { JSON.parse(v); } catch { out.push(issue('error', 'Not valid JSON. Build it from a registry login below.')); } }
      if (row.key === 'tls.crt' && !v.includes('-----BEGIN CERTIFICATE-----')) out.push(issue('warn', 'Does not look like a PEM certificate.'));
      if (row.key === 'tls.key' && !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(v)) out.push(issue('warn', 'Does not look like a PEM private key.'));
    }
  }
  row.valueIssues = out;
}

function keyIssues(row) {
  if (!row.key) return [issue('error', 'Give this key a name.')];
  if (row.key.length > 253 || !KEY.test(row.key)) return [issue('error', 'Keys may only use letters, digits, dashes, underscores and dots.')];
  if (rows.some((r) => r !== row && r.key === row.key)) return [issue('error', 'This key appears twice. Only one value would survive.')];
  return [];
}

function renderHints(row, list) {
  const ul = $('.hints', row.li);
  ul.replaceChildren(...list.map((i) => {
    const li = el('li', i.level, i.text);
    if (i.fn) {
      const b = el('button', 'link', i.action);
      b.type = 'button'; b.onclick = i.fn;
      li.append(' ', b);
    }
    return li;
  }));
  row.li.classList.toggle('has-error', list.some((i) => i.level === 'error'));
}

/* ---------- form state ---------- */

const scope = () => document.querySelector('input[name=scope]:checked').value;
const nameIn = $('#name'), nsIn = $('#namespace'), typeIn = $('#type');

function refresh() {
  const name = nameIn.value, ns = nsIn.value, sc = scope(), type = typeIn.value;
  const todo = [], warns = [];

  for (const [input, hint, ok, msg] of [
    [nameIn, '#name-hint', name.length <= 253 && SUBDOMAIN.test(name), 'Lowercase letters, digits, dashes and dots. Start and end with a letter or digit.'],
    [nsIn, '#namespace-hint', ns.length <= 63 && LABEL.test(ns), 'Lowercase letters, digits and dashes, at most 63 characters.'],
  ]) {
    const bad = input.value !== '' && !ok;
    $(hint).textContent = bad ? msg : '';
    input.ariaInvalid = String(bad);
  }

  // Always exactly one line, so the certificate finishing during page load cannot move what is below it.
  const certTodo = state.certLoading ? 'Waiting for the certificate.' : !state.cert ? 'Load a certificate in step 1.'
    : new Date(state.cert.info.notAfter) < Date.now() ? 'The certificate has expired. Fetch the current one.' : '';
  if (!name) todo.push('Name the secret.');
  else if ($('#name-hint').textContent) todo.push('Fix the secret name.');
  if (!ns && sc !== 'cluster-wide') todo.push('Choose a namespace, or use cluster wide scope.');
  else if ($('#namespace-hint').textContent) todo.push('Fix the namespace.');
  else if (ns && state.namespaces.length && !state.namespaces.includes(ns)) warns.push(`Namespace ${ns} does not exist in ${sourceName()} yet.`);

  if (!rows.length) todo.push('Add at least one key.');
  for (const k of REQUIRED[type] || []) if (!rows.some((r) => r.key === k)) todo.push(`Type ${type} needs a ${k} key.`);
  let size = 0;
  for (const row of rows) {
    if (!row.key && !row.text && !row.bytes && !row.sealed) { // untouched row: guide, do not scold
      renderHints(row, []);
      todo.push(rows.length === 1 ? 'Add a key and its value.' : 'Fill in the empty key or remove it.');
      continue;
    }
    const list = [...keyIssues(row), ...row.valueIssues];
    renderHints(row, list);
    const label = row.key || 'An unnamed key';
    for (const i of list) {
      if (i.level === 'error') todo.push(`${label}: ${i.text}`);
      else if (i.level === 'warn') warns.push(`${label}: ${i.text}`);
    }
    if (!row.sealed) size += row.bytes ? row.bytes.length : enc.encode(row.text).length;
  }
  if (size > 1 << 20) todo.push('Values add up to more than 1 MiB, the Kubernetes secret limit.');

  // Sealed values are bound to the scope label they were encrypted with; changing it would make them undecryptable.
  const sealedCount = rows.filter((r) => r.sealed).length;
  nameIn.readOnly = sealedCount > 0 && sc === 'strict';
  nsIn.readOnly = sealedCount > 0 && sc !== 'cluster-wide';
  for (const r of document.querySelectorAll('input[name=scope]')) r.disabled = sealedCount > 0 && !r.checked;
  const lock = $('#lock');
  lock.hidden = !sealedCount;
  if (sealedCount) {
    const bound = sc === 'strict' ? `${ns}/${name}` : sc === 'namespace-wide' ? `namespace ${ns}` : 'the whole cluster';
    lock.textContent = `${sealedCount} sealed ${sealedCount === 1 ? 'value is' : 'values are'} bound to ${bound}, so these fields are locked. Replace or remove the values to edit them. They only decrypt on the cluster they were sealed for, so step 1 must point at it.`;
  }

  $('[data-label=strict]').textContent = `${ns || 'namespace'}/${name || 'name'}`;
  $('[data-label=namespace-wide]').textContent = ns || 'the namespace';

  const ul = $('#issues');
  ul.replaceChildren(el('li', `${certTodo ? 'todo' : 'ok'} one-line`, certTodo || `Certificate: ${sourceName()}`), ...(state.sealError ? [el('li', 'error', state.sealError)] : []), ...todo.map((t) => el('li', 'todo', t)), ...warns.map((t) => el('li', 'warn', t)));
  const btn = $('#seal');
  btn.disabled = !!certTodo || todo.length > 0;
  btn.textContent = state.cert ? `Seal for ${sourceName()}` : 'Seal';

  const stale = !!state.sealedSnapshot && state.sealedSnapshot !== snapshot();
  $('#stale').hidden = !stale;
  $('#output').classList.toggle('stale', stale);
  $('#copy').disabled = $('#download').disabled = stale;
}

// Identity of everything that ends up in the sealed output; byte buffers compare by reference.
const bufIds = new WeakMap();
let bufSeq = 0;
function snapshot() {
  const bytesId = (b) => { if (!b) return null; if (!bufIds.has(b)) bufIds.set(b, ++bufSeq); return bufIds.get(b); };
  return JSON.stringify([nameIn.value, nsIn.value, scope(), typeIn.value, state.cert?.info.fingerprint,
    rows.map((r) => [r.key, r.sealed, r.text, bytesId(r.bytes)])]);
}

function formPayload() {
  const data = {}, sealed = {};
  for (const r of rows) {
    if (r.sealed) sealed[r.key] = r.sealed;
    else data[r.key] = toB64(r.bytes ?? enc.encode(r.text));
  }
  return { name: nameIn.value, namespace: nsIn.value, scope: scope(), type: typeIn.value, labels: state.labels, annotations: state.annotations, data, sealed };
}

let lastYAML = '';
async function doSeal() {
  const btn = $('#seal');
  if (btn.disabled) return;
  btn.disabled = true; btn.classList.add('busy');
  try {
    const form = formPayload();
    const sealedState = snapshot(); // taken before the request, so an edit made meanwhile still reads as stale
    const { yaml, historyError } = await api('/api/seal', { cert: state.cert.pem, source: sourceName(), form });
    loadHistory(historyError);
    await animate(() => {
      lastYAML = yaml;
      $('#yaml').textContent = yaml;
      const n = Object.keys(form.data).length + Object.keys(form.sealed).length;
      $('#out-meta').textContent = `${form.namespace ? form.namespace + '/' : ''}${form.name} · ${form.scope} · ${n} ${n === 1 ? 'key' : 'keys'} · ${sourceName()}`;
      const out = $('#output');
      out.hidden = false;
      out.classList.remove('stale', 'stamp');
      void out.offsetWidth; // restart the stamp animation
      out.classList.add('stamp');
      state.sealedSnapshot = sealedState;
      state.sealError = '';
      renderOriginal();
      refresh();
      scrollToEl(out);
    });
  } catch (e) {
    state.sealError = e.message;
  } finally {
    btn.classList.remove('busy');
    refresh();
  }
}

/* ---------- import ---------- */

function renderOriginal() {
  const o = state.original;
  $('#original').hidden = $('#orig-pane').hidden = !o;
  $('#sealed-panel').classList.toggle('wide', !!o && !$('#output').hidden);
  if (!o) return;
  document.querySelectorAll('.orig-yaml').forEach((pre) => (pre.textContent = o.revealed ? o.raw : o.masked));
  for (const btn of document.querySelectorAll('.orig-reveal')) {
    btn.hidden = o.raw === o.masked; // a SealedSecret has nothing to hide
    btn.ariaPressed = String(o.revealed);
    btn.title = btn.ariaLabel = o.revealed ? 'Hide original values' : 'Show original values';
    $('use', btn).setAttribute('href', `icons.svg#i-${o.revealed ? 'eye-slash' : 'eye'}`);
  }
}
document.querySelectorAll('.orig-reveal').forEach((btn) => (btn.onclick = () => animate(() => { state.original.revealed = !state.original.revealed; renderOriginal(); })));

function applyImport(f, kind, raw, masked) {
  // Output sealed from an earlier form would sit next to an original it did not come from.
  state.original = { raw, masked, revealed: false };
  state.sealedSnapshot = ''; lastYAML = '';
  $('#output').hidden = true;
  renderOriginal();
  rows.splice(0).forEach((r) => r.li.remove());
  nameIn.value = f.name || ''; nsIn.value = f.namespace || '';
  document.querySelector(`input[name=scope][value="${f.scope}"]`).checked = true;
  if (![...typeIn.options].some((o) => o.value === f.type)) typeIn.append(Object.assign(document.createElement('option'), { value: f.type, textContent: f.type }));
  typeIn.value = f.type || 'Opaque';
  state.labels = f.labels || null; state.annotations = f.annotations || null;
  for (const k of Object.keys(f.data || {}).sort()) {
    const bytes = fromB64(f.data[k]), text = asText(bytes);
    addRow({ key: k, text: text ?? '', bytes: text === null ? bytes : null });
  }
  for (const k of Object.keys(f.sealed || {}).sort()) addRow({ key: k, sealed: f.sealed[k] });
  const sealedN = Object.keys(f.sealed || {}).length, plainN = Object.keys(f.data || {}).length;
  const kept = [f.labels && Object.keys(f.labels).length && 'labels', f.annotations && Object.keys(f.annotations).length && 'annotations'].filter(Boolean);
  const note = $('#imported');
  note.textContent = kind === 'SealedSecret'
    ? `SealedSecret ${f.name}: ${sealedN} sealed ${sealedN === 1 ? 'key' : 'keys'}. Add keys or replace values, then seal again.`
    : `Secret ${f.name}: ${plainN} ${plainN === 1 ? 'value' : 'values'}. Delete the plaintext file once it is sealed.`;
  if (kept.length) note.textContent += ` ${kept.join(' and ').replace(/^./, (c) => c.toUpperCase())} carried over.`;
  note.hidden = false;
  refresh();
}

const dialog = $('#import-dialog');
$('#open-import').onclick = () => { $('#import-error').textContent = ''; dialog.showModal(); $('#import-text').focus(); };
$('#import-pick').onclick = () => $('#import-file').click();
$('#import-file').onchange = async (e) => { const f = e.target.files[0]; if (f) $('#import-text').value = await f.text(); e.target.value = ''; };
$('#do-import').onclick = async () => {
  try {
    const raw = $('#import-text').value;
    const { form, kind, masked } = await api('/api/import', { text: raw });
    dialog.close();
    await animate(() => applyImport(form, kind, raw, masked));
  } catch (e) {
    $('#import-error').textContent = e.message;
  }
};
dialog.addEventListener('close', () => { $('#import-text').value = ''; });

/* ---------- wiring ---------- */

nameIn.oninput = nsIn.oninput = refresh;
document.querySelectorAll('input[name=scope]').forEach((r) => (r.onchange = refresh));
typeIn.onchange = () => {
  const keys = PRESETS[typeIn.value] || [];
  const blank = rows.length === 1 && !rows[0].key && !rows[0].text && !rows[0].bytes ? rows[0] : null;
  for (const k of keys) {
    if (rows.some((r) => r.key === k)) continue;
    if (blank && !blank.key) { blank.key = $('.k', blank.li).value = k; renderRow(blank); checkValue(blank); }
    else addRow({ key: k });
  }
  refresh();
};
$('#add-key').onclick = () => animate(() => { addRow({}, true); refresh(); });
$('#seal').onclick = doSeal;
document.addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && !dialog.open) { e.preventDefault(); doSeal(); } });

$('#copy').onclick = async () => {
  await navigator.clipboard.writeText(lastYAML);
  const label = $('#copy span');
  label.textContent = 'Copied';
  setTimeout(() => (label.textContent = 'Copy'), 1600);
};
function downloadYAML(name, yaml) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([yaml], { type: 'application/yaml' })), download: `${name || 'secret'}.sealed.yaml` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
$('#download').onclick = () => downloadYAML(nameIn.value, lastYAML);
$('#clear').onclick = () => {
  for (const r of rows) if (!r.sealed) { r.text = ''; r.bytes = null; $('.v', r.li).value = ''; renderRow(r); checkValue(r); }
  for (const p of document.querySelectorAll('.d-pass')) p.value = '';
  if (state.original) { state.original.raw = state.original.masked; state.original.revealed = false; renderOriginal(); }
  const fresh = state.sealedSnapshot && !$('#output').classList.contains('stale');
  if (fresh) state.sealedSnapshot = snapshot(); // wiping plaintext does not make the sealed output stale
  refresh();
};
$('main').addEventListener('input', () => { state.sealError = ''; }, true);

/* ---------- history ---------- */

const when = (t) => new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
// Inside a view transition the jump itself is what glides, so only browsers without one need smooth scrolling.
function scrollToEl(n) { n.scrollIntoView({ block: 'start', behavior: document.startViewTransition || reducedMotion() ? 'instant' : 'smooth' }); }

async function loadHistory(writeError = '', render = renderHistory) {
  try {
    state.history = await api('/api/history');
    state.historyError = writeError || '';
  } catch (e) {
    state.history = null;
    state.historyError = e.message;
  }
  await render();
}

function histButton(label, fn) {
  const b = el('button', 'btn ghost sm', label);
  b.type = 'button';
  b.onclick = fn;
  return b;
}

function histDelete(label, question, path) {
  const b = el('button', 'icon');
  b.type = 'button';
  b.title = b.ariaLabel = label;
  b.append(icon('trash'));
  b.onclick = async () => {
    if (!confirm(question)) return;
    try {
      await api(path, null, 'DELETE');
      await loadHistory('', () => animate(renderHistory));
    } catch (e) {
      state.historyError = e.message;
      renderHistory();
    }
    $('#h-history').focus(); // the clicked button is gone after the list redraws
  };
  return b;
}

function histItem(title, meta, actions) {
  const li = el('li', 'hist-item'), main = el('div', 'hist-main'), acts = el('div', 'hist-actions');
  const metaEl = el('div', 'hist-meta');
  metaEl.append(...meta);
  main.append(el('div', 'hist-title', title), metaEl);
  acts.append(...actions);
  li.append(main, acts);
  return li;
}

function useCert(c) {
  selectTab('file');
  $('#pem').value = c.pem;
  pastedSource = c.source;
  return loadCert({ pem: c.pem }, c.source);
}

async function openSealed(rec) {
  const plaintext = rows.some((r) => !r.sealed && (r.text || r.bytes));
  if (plaintext && !confirm('Replace the current form? Its values have not been saved anywhere.')) return;
  try {
    const { form, kind, masked } = await api('/api/import', { text: rec.yaml });
    await animate(() => {
      applyImport(form, kind, rec.yaml, masked);
      const cert = state.history?.certs.find((c) => c.fingerprint === rec.fingerprint);
      if (cert) useCert(cert); // new values should go to the cluster the existing ones were sealed for
      scrollToEl($('#secret'));
    });
  } catch (e) {
    state.historyError = e.message;
    renderHistory();
  }
}

function renderHistory() {
  const h = state.history, error = $('#history-error');
  error.textContent = state.historyError;
  $('#hist-path').textContent = h ? `Kept in ${h.path}. Sealed output and public certificates only, never plaintext. Keeps the newest 100 seals and 50 certificates.` : '';
  const empty = (text) => el('li', 'muted', text);
  $('#hist-sealed').replaceChildren(...(h?.sealed.length ? h.sealed.map((r) => {
    const n = r.keys.length;
    const copy = histButton('Copy', async () => {
      await navigator.clipboard.writeText(r.yaml);
      copy.textContent = 'Copied';
      setTimeout(() => (copy.textContent = 'Copy'), 1600);
    });
    return histItem(`${r.namespace ? r.namespace + '/' : ''}${r.name}`,
      [`${r.scope.replace('-', ' ')} · ${n} ${n === 1 ? 'key' : 'keys'}: ${r.keys.join(', ')}`, el('br'), `For ${r.source || 'unknown certificate'} · ${when(r.at)}`],
      [histButton('Open', () => openSealed(r)), copy, histButton('Download', () => downloadYAML(r.name, r.yaml)),
        histDelete(`Delete ${r.name} from history`, `Delete this entry for ${r.name} from history? The copy in history cannot be recovered.`, `/api/history/sealed/${r.id}`)]);
  }) : [empty(h ? 'Nothing sealed yet. Each seal is saved here as ciphertext.' : 'History is unavailable.')]));
  $('#hist-certs').replaceChildren(...(h?.certs.length ? h.certs.map((c) => {
    const expired = new Date(c.notAfter) < Date.now();
    const validity = el('span', expired ? 'expired' : '', `${expired ? 'Expired' : 'Valid until'} ${new Date(c.notAfter).toLocaleDateString(undefined, { dateStyle: 'medium' })}`);
    const use = histButton('Use', () => animate(() => { useCert(c); scrollToEl($('#cert-panel')); }));
    use.disabled = expired;
    return histItem(c.source, [`${c.fingerprint.slice(0, 24).match(/.{4}/g).join(' ')} …`, el('br'), validity, ` · Last loaded ${when(c.lastLoaded)}`],
      [use, histDelete(`Delete certificate ${c.source} from history`, `Delete the certificate for ${c.source} from history?`, `/api/history/certs/${c.fingerprint}`)]);
  }) : [empty(h ? 'No certificates yet. Each one you load is saved here.' : 'History is unavailable.')]));
}

const root = document.documentElement, systemDark = matchMedia('(prefers-color-scheme: dark)');
const isDark = () => (root.dataset.theme ?? (systemDark.matches ? 'dark' : 'light')) === 'dark';
function renderTheme() {
  const btn = $('#theme');
  btn.title = btn.ariaLabel = isDark() ? 'Switch to light mode' : 'Switch to dark mode';
  $('use', btn).setAttribute('href', `icons.svg#i-${isDark() ? 'sun' : 'moon'}`);
}
new Image().src = 'bloom.svg'; // fetched now, so the first bloom's mask is ready the moment it starts
function switchTheme() {
  root.dataset.theme = isDark() ? 'light' : 'dark';
  document.cookie = `mucha-theme=${root.dataset.theme}; path=/; max-age=31536000; samesite=strict`;
  renderTheme();
}
$('#theme').onclick = async () => {
  if (root.classList.contains('theme-bloom')) return; // a bloom is already running
  if (!canAnimate()) return switchTheme();
  const r = $('#theme').getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2;
  root.style.setProperty('--bloom-x', `${x}px`);
  root.style.setProperty('--bloom-y', `${y}px`);
  // 285 is the radius, in bloom.svg units, that every petal valley reaches, so the page ends up fully covered.
  root.style.setProperty('--bloom-end', Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y)) / 285);
  root.classList.add('theme-bloom');
  const t = document.startViewTransition(switchTheme);
  t.ready.catch(() => {});
  await t.finished.catch(() => {});
  root.classList.remove('theme-bloom');
};
systemDark.addEventListener('change', renderTheme);
renderTheme();

// Scroll is restored by hand: the browser's own attempt runs before the page has reached its full height.
history.scrollRestoration = 'manual';
addEventListener('pagehide', () => sessionStorage.setItem('mucha-scroll', scrollY));

addRow({});
renderCert();
refresh();
Promise.all([loadHistory(), initContexts(), document.fonts.load('20px Federant').catch(() => {})]).then(() => {
  scrollTo(0, Number(sessionStorage.getItem('mucha-scroll')));
  root.classList.remove('booting');
});
