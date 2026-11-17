(() => {
'use strict';

const $ = id => document.getElementById(id);
const LS_REC = 'ubic.registros.v1';
const LS_LOC = 'ubic.loc.v1';

// ---------- Estado ----------
let records = load(LS_REC, []);
let loc = load(LS_LOC, { pasillo: '', rack: '01', nivel: '01' });
const db = new Map();        // EAN sin ceros a la izquierda -> {ean, art, desc}
let dbReady = false;

function load(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } }
function save() {
  try { localStorage.setItem(LS_REC, JSON.stringify(records)); localStorage.setItem(LS_LOC, JSON.stringify(loc)); } catch (e) { toast('No se pudo guardar: almacenamiento lleno'); }
}
const pad2 = v => String(v).replace(/\D/g, '').slice(0, 2).padStart(2, '0');
const key = ean => ean.replace(/^0+/, '');
const fmtDate = t => { const m = String(t || '').match(/^(\d{4})-(\d{2})-(\d{2})/); return m ? m[3] + '/' + m[2] + '/' + m[1] : ''; };
const lnFmt = a => /^\d+$/.test(String(a)) ? String(a).padStart(8, '0') : String(a || '—');   // código LN siempre a 8 dígitos

// ---------- Acceso y datos cifrados ----------
// Los datos del repositorio están cifrados (AES-GCM, clave derivada del código de acceso con PBKDF2). Sin el código no se pueden leer.
const KEYSTORE = 'ubic.k';
let dataKey = null, dataInfo = null;   // dataInfo: { actualizado, files: nombre -> archivo cifrado }
const b64 = u8 => btoa(String.fromCharCode(...u8)), unb64 = t => Uint8Array.from(atob(t), c => c.charCodeAt(0));
const normCode = c => String(c).toUpperCase().replace(/[^A-Z0-9]/g, '');
async function importKey(raw) { return crypto.subtle.importKey('raw', raw, 'AES-GCM', true, ['decrypt']); }
async function deriveKey(code, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(normCode(code)), 'PBKDF2', false, ['deriveBits']);
  return importKey(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 256)));
}
async function fetchEnc(name, fresh) {
  const r = await fetch('data/' + name + (name.endsWith('.enc') ? '' : '.enc'), fresh ? { cache: 'no-cache' } : undefined);
  if (!r.ok) throw new Error('http ' + r.status);
  return new Uint8Array(await r.arrayBuffer());
}
async function decryptFile(buf, key) {
  const iv = buf.subarray(20, 32), plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode('UBE1') }, key, buf.subarray(32));
  const ds = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Response(ds).arrayBuffer();
}
class Locked extends Error { }
// tiendas: cada una tiene su archivo de ubicaciones; la BBDD de artículos y EAN es común
const stores = () => (dataInfo && dataInfo.stores) || [];
let storeId = ''; try { storeId = localStorage.getItem('ubic.store') || ''; } catch { }
const curStore = () => stores().find(x => x.id === storeId) || stores()[0] || null;
function fillStores() {
  const sel = $('storeSel'), cs = curStore();
  sel.innerHTML = stores().map(x => '<option value="' + esc(x.id) + '">' + esc(x.nombre || x.id) + '</option>').join('');
  if (cs) { sel.value = cs.id; storeId = cs.id; }
  setStoreTitle();
}
function setStoreTitle() { const cs = curStore(); document.body.dataset.store = cs ? (cs.nombre || cs.id) : ''; }
$('storeSel').addEventListener('change', async () => {
  storeId = $('storeSel').value; try { localStorage.setItem('ubic.store', storeId); } catch { }
  setStoreTitle(); clearInfo(); $('locCard').hidden = true; $('locInput').value = '';
  await loadUbic();
});
async function getText(name) {
  if (!dataKey) throw new Locked();
  const file = name === 'ubicaciones' ? (curStore() || {}).file : dataInfo && dataInfo.files && dataInfo.files[name];
  if (!file) throw new Error('sin archivo ' + name);
  const buf = await fetchEnc(file);
  try { return new TextDecoder().decode(await decryptFile(buf, dataKey)); }
  catch (e) { if (e instanceof DOMException) { lockApp('El código de acceso ha cambiado. Introduce el nuevo.'); throw new Locked(); } throw e; }
}
function lockApp(msg) {
  dataKey = null; try { localStorage.removeItem(KEYSTORE); } catch { }
  $('lock').hidden = false; $('lockErr').textContent = msg || ''; $('lockCode').value = '';
}
/** Prueba el código: la sal va en la cabecera de cualquier archivo, y se comprueba descifrando el pequeño de fecha. */
async function tryCode(code) {
  const buf = await fetchEnc('ubicaciones-info', true);
  const key = await deriveKey(code, buf.subarray(4, 20));
  dataInfo = JSON.parse(new TextDecoder().decode(await decryptFile(buf, key)));   // lanza error si el código no es el bueno
  return key;
}
async function startData() {
  fillStores();
  await loadDB();
  loadUbic();
}
async function boot() {
  let saved = null; try { saved = localStorage.getItem(KEYSTORE); } catch { }
  if (saved) {
    try {
      dataKey = await importKey(unb64(saved));
      dataInfo = JSON.parse(new TextDecoder().decode(await decryptFile(await fetchEnc('ubicaciones-info', true), dataKey)));
      await startData(); return;
    } catch (e) { if (!(e instanceof DOMException)) { try { await startData(); return; } catch { } } }
  }
  lockApp('');
}
$('lockForm').addEventListener('submit', async e => {
  e.preventDefault();
  const code = $('lockCode').value, btn = $('lockBtn');
  if (normCode(code).length < 6) { $('lockErr').textContent = 'Introduce el código de acceso.'; return; }
  btn.disabled = true; $('lockErr').textContent = 'Comprobando…';
  try {
    const key = await tryCode(code);
    dataKey = key;
    try { localStorage.setItem(KEYSTORE, b64(new Uint8Array(await crypto.subtle.exportKey('raw', key)))); } catch { }
    $('lock').hidden = true; $('lockErr').textContent = '';
    startData();
  } catch (err) {
    $('lockErr').textContent = err instanceof DOMException ? 'Código incorrecto.' : 'No se pudo comprobar (¿sin conexión?).';
  } finally { btn.disabled = false; }
});
$('lockNow').addEventListener('click', () => lockApp(''));

// ---------- Base de datos ----------
const eansByArt = new Map(); // código LN (sin ceros) -> todos sus EAN
const artMap = new Map();    // código LN (sin ceros) -> {ean, art, desc}  (artículos con EAN)
let extraText = '', extraIdx = null;   // artículos sin EAN: "art\tdesc\n" ordenado por art
async function loadDB() {
  const st = $('dbstate');
  try {
    const text = await getText('bbdd');
    let i = 0;
    const n = text.length;
    while (i < n) {
      let j = text.indexOf('\n', i);
      if (j < 0) j = n;
      const line = text.slice(i, j);
      i = j + 1;
      const a = line.indexOf('\t');
      if (a < 0) continue;
      const b = line.indexOf('\t', a + 1);
      const ean = line.slice(0, a);
      const e = { ean, art: line.slice(a + 1, b), desc: line.slice(b + 1) };
      db.set(key(ean), e);
      if (e.art && !artMap.has(e.art)) artMap.set(e.art, e);
      if (e.art) { const l = eansByArt.get(e.art); if (l) l.push(ean); else eansByArt.set(e.art, [ean]); }
    }
    dbReady = true;
    st.textContent = 'Última actualización EAN: ' + (fmtDate(dataInfo && dataInfo.ean) || 'fecha no indicada');
    st.className = 'dbline dbstate ok';
  } catch (e) {
    st.textContent = 'BBDD no disponible (sin conexión)';
    st.className = 'dbline dbstate err';
    return;
  }
  try {                                   // códigos LN que no tienen EAN
    extraText = await getText('articulos');
    const idx = [0];
    for (let p = extraText.indexOf('\n'); p >= 0 && p < extraText.length - 1; p = extraText.indexOf('\n', p + 1)) idx.push(p + 1);
    extraIdx = Int32Array.from(idx);
  } catch (e) { st.textContent += ' (LN parcial)'; }
}
function findExtra(k) {
  if (!extraIdx) return null;
  let lo = 0, hi = extraIdx.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1, s0 = extraIdx[mid], t = extraText.indexOf('\t', s0), kk = extraText.slice(s0, t);
    if (kk === k) { let e = extraText.indexOf('\n', t); if (e < 0) e = extraText.length; return { ean: '', art: k, desc: extraText.slice(t + 1, e) }; }
    if (kk < k) lo = mid + 1; else hi = mid - 1;
  }
  return null;
}
function findArt(clean) {
  const k = clean.replace(/^0+/, '');
  if (!k) return null;
  return artMap.get(k) || findExtra(k);
}
/** Interpreta el texto como EAN y, si no está, como código LN. */
function resolve(raw, onlyEan) {
  const clean = String(raw).trim().toUpperCase().replace(/\s+/g, '');
  if (onlyEan) { const d = clean.replace(/\D/g, ''); return { clean: d, hit: d ? db.get(key(d)) || null : null }; }
  if (!clean) return { clean, hit: null };
  const num = /^\d+$/.test(clean);
  // hasta 8 caracteres: código LN primero; más largo: EAN primero
  const hit = (num && clean.length > 8) ? (db.get(key(clean)) || findArt(clean)) : (findArt(clean) || (num ? db.get(key(clean)) : null));
  return { clean, hit: hit || null };
}
const codeOf = r => r.ean || r.art || '';
function sameProd(r, hit, clean) {
  if (hit) return !!((hit.ean && r.ean && key(hit.ean) === key(r.ean)) || (hit.art && r.art && hit.art === r.art));
  return !!clean && key(clean) === key(codeOf(r));
}

// ---------- Ubicación ----------
function locCode() { return loc.pasillo.length === 2 ? loc.pasillo + pad2(loc.rack) + pad2(loc.nivel) : ''; }
function nextPos(code) {
  let m = 0;
  for (const r of records) if (r.ubic === code && r.pos > m) m = r.pos;
  return m + 1;
}
function refreshLoc() {
  const code = locCode();
  $('locCode').textContent = code || '—';
  $('nextPos').textContent = code ? pad2(nextPos(code)) : '01';
}
function readLoc() {
  loc.pasillo = $('pasillo').value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 2);
  loc.rack = pad2($('rack').value || 0);
  loc.nivel = pad2($('nivel').value || 0);
  scU.reset();   // mismo producto en otro nivel: no lo ignora la cámara
  save(); render();
}
function writeLoc() {
  $('pasillo').value = loc.pasillo; $('rack').value = loc.rack; $('nivel').value = loc.nivel; refreshLoc();
}
$('pasillo').addEventListener('input', () => { $('pasillo').value = $('pasillo').value.toUpperCase().replace(/[^A-Z0-9]/g, ''); readLoc(); });
['rack', 'nivel'].forEach(id => {
  $(id).addEventListener('focus', e => e.target.select());
  $(id).addEventListener('change', () => { $(id).value = pad2($(id).value || 0); readLoc(); });
});
document.querySelectorAll('.stepper button').forEach(b => b.addEventListener('click', () => {
  const f = b.dataset.step, d = +b.dataset.d;
  let v = (parseInt($(f).value, 10) || 0) + d;
  v = Math.max(0, Math.min(99, v));
  $(f).value = pad2(v); readLoc();
}));

// ---------- Registro ----------
function validLoc() {
  if (loc.pasillo.length !== 2) { toast('Escribe el pasillo (2 letras)'); $('pasillo').focus(); return false; }
  return true;
}
/** @returns {{status:'ok'|'nf'|'dup'|'full', rec?:object}} */
function addCode(raw, onlyEan) {
  const { clean, hit } = resolve(raw, onlyEan);
  if (!clean) return { status: 'nf' };
  const ubic = locCode();
  const dup = records.find(r => r.ubic === ubic && sameProd(r, hit, clean));
  if (dup) return { status: 'dup', rec: dup };
  const pos = nextPos(ubic);
  if (pos > 99) return { status: 'full' };
  const rec = {
    id: Date.now() + Math.random(),
    ubic, pasillo: loc.pasillo, rack: pad2(loc.rack), nivel: pad2(loc.nivel), pos,
    ean: hit ? hit.ean : clean,
    art: hit ? hit.art : '',
    desc: hit ? hit.desc : '',
    found: !!hit, manual: false,
    ts: localTs()
  };
  records.push(rec);
  save(); render();
  return { status: hit ? 'ok' : 'nf', rec };
}
let view = 'recent';
function sortedAt(ubic) { return records.filter(r => r.ubic === ubic).sort((x, y) => x.pos - y.pos); }
function titleOf(r) { return r.found ? (r.desc || '(sin descripción)') : r.manual ? r.desc + ' (manual)' : 'NO ENCONTRADO EN BBDD'; }
function render() {
  const ul = $('records');
  ul.innerHTML = '';
  const cur = locCode();
  const byLoc = view === 'loc';
  $('locTools').hidden = !byLoc;
  document.querySelectorAll('.seg button').forEach(b => b.classList.toggle('on', b.dataset.view === view));
  let rows;
  if (byLoc) rows = cur ? sortedAt(cur) : [];
  else rows = records.slice().reverse().slice(0, 200);
  rows.forEach((r, i) => {
    const li = document.createElement('li');
    if (!r.found && !r.manual) li.className = 'nf';
    li.innerHTML = '<div class="pos">' + esc(r.ubic) + '<small>pos ' + pad2(r.pos) + '</small></div>' +
      '<div><div class="d">' + esc(titleOf(r)) + '</div>' +
      '<div class="m">' + esc([r.ean, r.art ? 'LN ' + r.art : ''].filter(Boolean).join(' · ')) + '</div></div>' +
      (byLoc
        ? '<div class="acts col"><button type="button" class="mv up" aria-label="Subir"' + (i === 0 ? ' disabled' : '') + '>▲</button><button type="button" class="mv dn" aria-label="Bajar"' + (i === rows.length - 1 ? ' disabled' : '') + '>▼</button></div>'
        : '<div class="acts"><button type="button" class="x" aria-label="Borrar">×</button></div>');
    li.onclick = () => openEdit(r.id);
    const stop = (sel, fn) => { const el = li.querySelector(sel); if (el) el.onclick = e => { e.stopPropagation(); fn(); }; };
    stop('.up', () => movePos(r.id, -1));
    stop('.dn', () => movePos(r.id, 1));
    stop('.x', () => { records = records.filter(x => x.id !== r.id); save(); render(); });
    ul.appendChild(li);
  });
  $('count').textContent = records.length;
  $('empty').hidden = rows.length > 0;
  $('empty').textContent = byLoc ? (cur ? 'No hay registros en ' + cur + '.' : 'Escribe el pasillo para ver su ubicación.') : 'Aún no hay registros. Elige pasillo, rack y nivel y escanea un EAN.';
  $('undoBtn').disabled = !records.length;
  $('exportBtn').disabled = !records.length;
  $('resetBtn').disabled = !records.length;
  refreshLoc();
}
document.querySelectorAll('.seg button').forEach(b => b.onclick = () => { view = b.dataset.view; render(); });

// ---- subir / bajar / renumerar ----
function movePos(id, dir) {
  const r = records.find(x => x.id === id); if (!r) return;
  const list = sortedAt(r.ubic), i = list.findIndex(x => x.id === id), o = list[i + dir];
  if (!o) return;
  [r.pos, o.pos] = [o.pos, r.pos];
  save(); render();
}
$('renumBtn').onclick = () => {
  const cur = locCode(); if (!cur) return;
  sortedAt(cur).forEach((r, i) => r.pos = i + 1);
  save(); render(); toast('Posiciones renumeradas en ' + cur);
};

// ---- edición ----
let editId = null;
function openEdit(id) {
  const r = records.find(x => x.id === id); if (!r) return;
  editId = id;
  $('ePasillo').value = r.pasillo; $('eRack').value = r.rack; $('eNivel').value = r.nivel;
  $('ePos').value = pad2(r.pos); $('eEan').value = codeOf(r); $('eDesc').value = r.desc || '';
  $('eNote').textContent = '';
  $('editDlg').showModal();
}
['ePasillo'].forEach(i => $(i).addEventListener('input', () => $(i).value = $(i).value.toUpperCase().replace(/[^A-Z0-9]/g, '')));
$('eCancel').onclick = () => $('editDlg').close();
$('eDel').onclick = () => {
  const r = records.find(x => x.id === editId); if (!r) return;
  records = records.filter(x => x.id !== editId); save(); render(); $('editDlg').close(); toast('Registro borrado');
};
$('editForm').addEventListener('submit', e => {
  e.preventDefault();
  const r = records.find(x => x.id === editId); if (!r) return;
  const pasillo = $('ePasillo').value.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const note = t => { $('eNote').textContent = t; };
  if (pasillo.length !== 2) return note('El pasillo debe tener 2 caracteres.');
  const rack = pad2($('eRack').value || 0), nivel = pad2($('eNivel').value || 0);
  let pos = parseInt($('ePos').value, 10);
  if (!(pos >= 1 && pos <= 99)) return note('La posición debe estar entre 01 y 99.');
  const raw = $('eEan').value.trim();
  if (!raw) return note('Escribe el EAN o el código LN.');
  const ubic = pasillo + rack + nivel;
  const codeChanged = key(raw.toUpperCase().replace(/\s+/g, '')) !== key(codeOf(r));
  const typed = $('eDesc').value.trim(), descChanged = typed !== (r.desc || '');
  const res = codeChanged ? resolve(raw) : { clean: codeOf(r), hit: r.found ? { ean: r.ean, art: r.art, desc: r.desc } : null };
  const hit = res.hit;
  const dupRec = records.find(x => x.id !== r.id && x.ubic === ubic && sameProd(x, hit, res.clean));
  if (dupRec) return note('Ese producto ya está en este nivel (' + ubic + ', pos ' + pad2(dupRec.pos) + ').');
  // producto
  if (hit && codeChanged) { r.ean = hit.ean; r.art = hit.art; r.desc = hit.desc; r.found = true; r.manual = false; }
  else if (hit) { r.desc = typed || hit.desc; }
  else { r.ean = res.clean; r.art = ''; r.found = false; r.desc = (descChanged || !codeChanged) ? typed : ''; r.manual = !!r.desc; }
  const eanChanged = codeChanged;
  // ubicación y posición
  let msg = '';
  if (ubic === r.ubic) {
    const occ = records.find(x => x.id !== r.id && x.ubic === ubic && x.pos === pos);
    if (occ) { occ.pos = r.pos; msg = 'Intercambiada con la posición ' + pad2(r.pos); }
  } else {
    if (records.some(x => x.id !== r.id && x.ubic === ubic && x.pos === pos)) {
      pos = Math.max(0, ...records.filter(x => x.id !== r.id && x.ubic === ubic).map(x => x.pos)) + 1;
      msg = 'Posición ocupada: asignada la ' + pad2(pos);
    }
    if (pos > 99) return note('Esa ubicación está llena.');
  }
  Object.assign(r, { pasillo, rack, nivel, ubic, pos });
  save(); render(); $('editDlg').close();
  toast(msg || ('Guardado · ' + ubic + pad2(pos) + (eanChanged ? ' · ' + titleOf(r) : '')));
});

function localTs() { const d = new Date(), p = n => String(n).padStart(2, '0'); return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()); }
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

$('manualForm').addEventListener('submit', e => {
  e.preventDefault();
  if (!validLoc()) return;
  const v = $('eanInput').value.trim();
  if (!v) return;
  const r = addCode(v);
  feedback(r.status);
  if (r.status === 'dup') toast('Ya está en este nivel (' + locCode() + ', pos ' + pad2(r.rec.pos) + ')');
  else if (r.status === 'full') toast('Ubicación llena (99 posiciones)');
  else { toast(r.status === 'ok' ? '✓ ' + r.rec.desc : '⚠ Código no encontrado, registrado igualmente'); $('eanInput').value = ''; }
});
$('undoBtn').onclick = () => { if (records.length) { const r = records.pop(); save(); render(); toast('Eliminado ' + r.ubic + ' pos ' + pad2(r.pos)); } };

// ---------- Exportar / reiniciar ----------
function buildXlsx() {
  const rows = records.slice().sort((a, b) => a.ubic.localeCompare(b.ubic) || a.pos - b.pos);
  const aoa = [['CODIGO', 'DESCRIPCION', 'UBICACION']];
  for (const r of rows) aoa.push([r.art || r.ean, r.found || r.manual ? r.desc : 'NO ENCONTRADO EN BBDD', r.ubic + pad2(r.pos)]);
  const ws = XLSX.utils.aoa_to_sheet(aoa);
  ws['!cols'] = [{ wch: 15 }, { wch: 56 }, { wch: 13 }];
  ws['!autofilter'] = { ref: 'A1:C' + aoa.length };
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Ubicaciones');
  const d = new Date(), p = n => String(n).padStart(2, '0');
  const name = 'Ubicaciones_' + d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '_' + p(d.getHours()) + p(d.getMinutes()) + '.xlsx';
  const data = XLSX.write(wb, { type: 'array', bookType: 'xlsx' });
  const type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  return { name, count: rows.length, blob: new Blob([data], { type }), type };
}
function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob), a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}
$('exportBtn').onclick = () => {
  if (!records.length) return;
  const x = buildXlsx();
  downloadBlob(x.blob, x.name);
  toast('Exportado ' + x.count + ' registros');
};
$('resetBtn').onclick = () => {
  if (!records.length) return;
  if (confirm('¿Borrar los ' + records.length + ' registros y empezar de cero?\n\nSi no has exportado, se perderán.')) {
    records = []; save(); render(); toast('Archivo reiniciado');
  }
};

// ---------- Avisos ----------
let toastT;
function toast(msg) {
  const t = $('toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toastT); toastT = setTimeout(() => t.hidden = true, 2800);
}
function makeWav(parts) {
  const sr = 22050, data = [];
  for (const [f, ms, sq] of parts) {
    const n = Math.round(sr * ms / 1000);
    for (let i = 0; i < n; i++) {
      let v = f ? Math.sin(2 * Math.PI * f * i / sr) : 0;
      if (sq) v = v >= 0 ? 0.6 : -0.6;
      const env = Math.min(1, i / 120, (n - i) / 400);   // evita chasquidos
      data.push(Math.round(v * env * 0.95 * 32767));
    }
  }
  const buf = new ArrayBuffer(44 + data.length * 2), dv = new DataView(buf);
  const w = (o, t) => [...t].forEach((c, i) => dv.setUint8(o + i, c.charCodeAt(0)));
  w(0, 'RIFF'); dv.setUint32(4, 36 + data.length * 2, true); w(8, 'WAVEfmt ');
  dv.setUint32(16, 16, true); dv.setUint16(20, 1, true); dv.setUint16(22, 1, true);
  dv.setUint32(24, sr, true); dv.setUint32(28, sr * 2, true); dv.setUint16(32, 2, true); dv.setUint16(34, 16, true);
  w(36, 'data'); dv.setUint32(40, data.length * 2, true);
  data.forEach((v, i) => dv.setInt16(44 + i * 2, v, true));
  return URL.createObjectURL(new Blob([buf], { type: 'audio/wav' }));
}
const sounds = {
  ok:  new Audio(makeWav([[988, 90], [1319, 160]])),            // pi-pip agudo
  nf:  new Audio(makeWav([[220, 280, 1], [165, 380, 1]])),      // grave largo
  dup: new Audio(makeWav([[660, 110], [0, 60], [660, 110]]))    // doble pitido
};
Object.values(sounds).forEach(a => { a.preload = 'auto'; a.volume = 1; });
let audioUnlocked = false;
function unlockAudio() {          // llamar dentro de un toque del usuario
  if (audioUnlocked) return;
  audioUnlocked = true;
  for (const a of Object.values(sounds)) {
    a.volume = 0;
    a.play().then(() => { a.pause(); a.currentTime = 0; a.volume = 1; }).catch(() => { a.volume = 1; audioUnlocked = false; });
  }
}
function feedback(s) {
  const key = s === 'ok' ? 'ok' : s === 'nf' ? 'nf' : 'dup';
  const a = sounds[key];
  try { a.currentTime = 0; a.play().catch(() => { }); } catch { }
  navigator.vibrate?.(s === 'ok' ? 40 : [80, 60, 80]);
}
document.addEventListener('pointerdown', unlockAudio, { once: false, passive: true });

// ---------- Escáner (reutilizable en Ubicar e Info) ----------
/** Dígito de control GS1 (EAN-8/12/13/14). */
function gs1ok(s) {
  if (!/^\d+$/.test(s) || ![8, 12, 13, 14].includes(s.length)) return false;
  const d = [...s].map(Number), chk = d.pop();
  let tot = 0;
  d.reverse().forEach((v, i) => tot += v * (i % 2 === 0 ? 3 : 1));
  return (10 - tot % 10) % 10 === chk;
}
/** Un código leído es "plausible" si, siendo numérico de longitud EAN, su dígito de control es correcto. */
function plausible(code) {
  if (!code || code.length < 4 || code.length > 30) return false;
  if (/^\d+$/.test(code) && [8, 12, 13, 14].includes(code.length)) return gs1ok(code);
  return true;
}
/** Busca en el texto leído (OCR) un EAN válido y presente en la BBDD o, si no, un LN de 8 cifras con ceros. */
function ocrMatch(text) {
  const raw = String(text), toks = raw.match(/\d{6,14}/g) || [];
  // a mano se escribe con espacios o guiones entre cifras: también se prueba cada línea sin separadores
  for (const ln of raw.split(/\n/)) { const j = ln.replace(/(?<=\d)[ .\-](?=\d)/g, ''); for (const t of j.match(/\d{6,14}/g) || []) toks.push(t); }
  for (const t of toks) if (gs1ok(t) && db.get(key(t))) return { code: t, strong: true };
  for (const t of toks) if (t.length === 8 && t[0] === '0' && findArt(t)) return { code: t, strong: false };
  for (const t of toks) if (t.length >= 6 && t.length <= 8 && t[0] !== '0' && findArt(t)) return { code: t, strong: false };   // LN escrito a mano sin ceros
  return null;
}
/** Blanco y negro con umbral automático (Otsu): ayuda a leer cifras escritas a mano con bolígrafo. */
function binarize(ctx, w, h) {
  const img = ctx.getImageData(0, 0, w, h), d = img.data, n = w * h, g = new Uint8Array(n), hist = new Array(256).fill(0);
  for (let i = 0; i < n; i++) { const v = (d[i * 4] * 77 + d[i * 4 + 1] * 150 + d[i * 4 + 2] * 29) >> 8; g[i] = v; hist[v]++; }
  let sum = 0; for (let t = 0; t < 256; t++) sum += t * hist[t];
  let wB = 0, sB = 0, best = 0, th = 128;
  for (let t = 0; t < 256; t++) { wB += hist[t]; if (!wB) continue; const wF = n - wB; if (!wF) break; sB += t * hist[t]; const mB = sB / wB, mF = (sum - sB) / wF, v = wB * wF * (mB - mF) * (mB - mF); if (v > best) { best = v; th = t; } }
  let dark = 0; for (let i = 0; i < n; i++) if (g[i] <= th) dark++;
  const inv = dark > n / 2;      // el texto debe quedar negro sobre blanco
  for (let i = 0; i < n; i++) { const black = inv ? g[i] > th : g[i] <= th, v = black ? 0 : 255; d[i * 4] = d[i * 4 + 1] = d[i * 4 + 2] = v; }
  ctx.putImageData(img, 0, 0);
}
let handLoading = null;
/** Lector de cifras escritas a mano (ocr/hand.js + ocr/hand.bin); si falla, la lectura de texto sigue funcionando sin él. */
function loadHand() {
  if (window.HandOCR && handLoading) return handLoading;
  handLoading = (async () => {
    try {
      if (!window.HandOCR) await new Promise((ok, ko) => { const el = document.createElement('script'); el.src = 'ocr/hand.js'; el.onload = ok; el.onerror = ko; document.head.appendChild(el); });
      const r = await fetch('ocr/hand.bin'); HandOCR.load(await r.arrayBuffer());
    } catch { handLoading = null; }
  })();
  return handLoading;
}
let tessLoading = null;
function loadTesseract() {
  if (window.Tesseract) return Promise.resolve();
  return tessLoading || (tessLoading = new Promise((res, rej) => {
    const sc = document.createElement('script'); sc.src = 'ocr/tesseract.min.js';
    sc.onload = res; sc.onerror = () => { tessLoading = null; rej(new Error('script')); };
    document.head.appendChild(sc);
  }));
}
const abs = p => new URL(p, location.href).href;

function makeScanner(c) {
  const video = $(c.video), view = $(c.view);
  let stream, on = false, detector, zxReader, canvas, ctx2d, track, lastCode = '', lastTime = 0, wakeLock, timer, torchOn = false, tick = 0;
  // estabilidad: un código debe verse varias veces seguidas y durante un rato antes de aceptarlo
  let cand = '', candCount = 0, candSince = 0, candSeen = 0;
  // texto (OCR)
  let ocrOn = localStorage.getItem('ubic.ocr') === '1', ocrWorker = null, ocrBusy = false, ocrTimer, ocrAngle = 0, weak = '', weakN = 0, weakAt = 0, ocrCv, ocrCtx;
  // combinaciones (giro, modo de página): texto suelto sin girar, y una línea de texto girada a un lado u otro
  const COMBOS = [[0, '11', 0], [270, '7', 0], [90, '7', 0], [0, '7', 1], [0, '6', 1]];   // [giro, modo de página, 1 = realzar contraste]
  let curPsm = '11';
  function setResult(html, cls) { const r = $(c.result); r.hidden = false; r.innerHTML = html; r.className = 'scanresult ' + cls; }

  /** Zonas del vídeo (en píxeles del vídeo): recuadro de lectura y área visible. */
  function regions() {
    const vw = video.videoWidth, vh = video.videoHeight, cw = video.clientWidth || 1, ch = video.clientHeight || 1;
    const sc = Math.max(cw / vw, ch / vh), ox = (cw - vw * sc) / 2, oy = (ch - vh * sc) / 2;
    const m = (x0, y0, x1, y1) => { const X0 = Math.max(0, (x0 - ox) / sc), Y0 = Math.max(0, (y0 - oy) / sc), X1 = Math.min(vw, (x1 - ox) / sc), Y1 = Math.min(vh, (y1 - oy) / sc); return { x: X0, y: Y0, w: X1 - X0, h: Y1 - Y0 }; };
    return { ret: m(cw * 0.08, ch * 0.15, cw * 0.92, ch * 0.85), vis: m(0, 0, cw, ch), vw, vh };
  }

  async function start() {
    if (on) return;
    if (c.canStart && !c.canStart()) return;
    if (!navigator.mediaDevices?.getUserMedia) { toast('Este navegador no permite cámara (¿HTTPS?)'); return; }
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: 'environment' }, width: { ideal: 1920 }, height: { ideal: 1080 } } });
    } catch (e) {
      toast('No se pudo abrir la cámara. Revisa el permiso del navegador.'); return;
    }
    video.srcObject = stream;
    await video.play().catch(() => { });
    track = stream.getVideoTracks()[0];
    try { await track.applyConstraints({ advanced: [{ focusMode: 'continuous' }] }); } catch { }
    const caps = track.getCapabilities?.() || {};
    $(c.torch).hidden = !caps.torch;
    view.hidden = false;
    $(c.btn).classList.add('on'); $(c.label).textContent = 'Detener cámara';
    setResult('Apunta al código de barras o a los números', '');
    view.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    try { wakeLock = await navigator.wakeLock?.request('screen'); } catch { }

    if ('BarcodeDetector' in window) {
      try { detector = new BarcodeDetector(); } catch { detector = null; }   // todos los formatos que admita el móvil
    }
    if (!detector) {
      const Z = ZXing;
      const hints = new Map();
      hints.set(Z.DecodeHintType.POSSIBLE_FORMATS, [Z.BarcodeFormat.EAN_13, Z.BarcodeFormat.EAN_8, Z.BarcodeFormat.UPC_A, Z.BarcodeFormat.UPC_E, Z.BarcodeFormat.CODE_128, Z.BarcodeFormat.CODE_39, Z.BarcodeFormat.CODE_93, Z.BarcodeFormat.CODABAR, Z.BarcodeFormat.ITF]);
      hints.set(Z.DecodeHintType.TRY_HARDER, true);
      zxReader = new Z.MultiFormatReader(); zxReader.setHints(hints);
      canvas = document.createElement('canvas'); ctx2d = canvas.getContext('2d', { willReadFrequently: true });
    }
    on = true;
    applyOcr();
    loop();
  }

  // ---- lectura de códigos de barras ----
  function loop() {
    if (!on) return;
    timer = setTimeout(async () => {
      try {
        let code = null;
        if (video.readyState >= 2 && video.videoWidth) {
          const R = regions();
          if (detector) {
            const rs = await detector.detect(video);
            // solo cuenta lo que está dentro del recuadro de lectura (la zona central)
            const inside = rs.filter(r => { const b = r.boundingBox, cx = b.x + b.width / 2, cy = b.y + b.height / 2; return cx >= R.ret.x && cx <= R.ret.x + R.ret.w && cy >= R.ret.y && cy <= R.ret.y + R.ret.h; });
            const mid = { x: R.ret.x + R.ret.w / 2, y: R.ret.y + R.ret.h / 2 };
            inside.sort((p, q) => Math.hypot(p.boundingBox.x + p.boundingBox.width / 2 - mid.x, p.boundingBox.y + p.boundingBox.height / 2 - mid.y) - Math.hypot(q.boundingBox.x + q.boundingBox.width / 2 - mid.x, q.boundingBox.y + q.boundingBox.height / 2 - mid.y));
            if (inside.length) code = inside[0].rawValue;
          } else code = zxDecode(R, (tick++ % 2) * 90);
        }
        if (code && plausible(code)) offer(code); else if (cand && Date.now() - candSeen > 700) { cand = ''; candCount = 0; }
      } catch { }
      loop();
    }, detector ? 90 : 120);
  }
  function zxDecode(R, angle) {
    const Z = ZXing, r = R.ret;
    if (r.w < 20 || r.h < 20) return null;
    const sw = Math.round(r.w), sh = Math.round(r.h);
    if (angle === 0) { canvas.width = sw; canvas.height = sh; ctx2d.drawImage(video, r.x, r.y, r.w, r.h, 0, 0, sw, sh); }
    else { canvas.width = sh; canvas.height = sw; ctx2d.save(); ctx2d.translate(sh, 0); ctx2d.rotate(Math.PI / 2); ctx2d.drawImage(video, r.x, r.y, r.w, r.h, 0, 0, sw, sh); ctx2d.restore(); }
    const src = new Z.HTMLCanvasElementLuminanceSource(canvas);
    const bmp = new Z.BinaryBitmap(new Z.HybridBinarizer(src));
    try { return zxReader.decodeWithState(bmp).getText(); } catch { return null; }
  }
  /** Acepta un código solo si se mantiene estable: 2 lecturas iguales seguidas (mín. 0,15 s). */
  function offer(code) {
    const now = Date.now();
    candSeen = now;
    if (code !== cand) { cand = code; candCount = 1; candSince = now; setResult('Leyendo… mantén el código enfocado', ''); return; }
    candCount++;
    if (candCount >= 2 && now - candSince >= 150) { cand = ''; candCount = 0; handle(code); }
  }
  function handle(code) {
    const now = Date.now();
    if (code === lastCode && now - lastTime < 2500) return;
    if (now - lastTime < 600) return;
    lastCode = code; lastTime = now;
    c.onCode(code, setResult);
  }

  // ---- lectura de texto impreso (EAN / LN) ----
  async function applyOcr() {
    $(c.ocr).classList.toggle('on', ocrOn);
    $(c.ocr).textContent = ocrOn ? 'Texto: sí' : 'Texto: no';
    view.classList.toggle('big', ocrOn);
    if (!ocrOn) { clearTimeout(ocrTimer); clearTimeout(handTimer); await killOcr(); return; }
    if (!on) return;
    if (!ocrWorker) {
      setResult('Cargando lector de texto…', '');
      try {
        await loadTesseract();
        await loadHand();
        ocrWorker = await Tesseract.createWorker('eng', 1, { workerPath: abs('ocr/worker.min.js'), corePath: abs('ocr/core/'), langPath: abs('ocr/lang'), gzip: true, cacheMethod: 'none', workerBlobURL: false, logger: () => { } });
        await ocrWorker.setParameters({ tessedit_char_whitelist: '0123456789', tessedit_pageseg_mode: '11' }); curPsm = '11';
      } catch (e) {
        ocrWorker = null; ocrOn = false; localStorage.setItem('ubic.ocr', '0');
        toast('No se pudo cargar el lector de texto (¿sin conexión?)'); applyOcr(); return;
      }
      if (!on || !ocrOn) { killOcr(); return; }
      setResult('Encuadra los números de la etiqueta (EAN o LN)', '');
    }
    ocrLoop(); handLoop();
  }
  async function killOcr() { const w = ocrWorker; ocrWorker = null; ocrBusy = false; try { await w?.terminate(); } catch { } }
  function ocrLoop() {
    clearTimeout(ocrTimer);
    if (!on || !ocrOn || !ocrWorker) return;
    ocrTimer = setTimeout(async () => {
      if (!ocrBusy && video.readyState >= 2 && video.videoWidth) {
        ocrBusy = true;
        try { await ocrOnce(); } catch { }
        ocrBusy = false;
      }
      ocrLoop();
    }, 200);
  }
  let handTimer;
  function handLoop() {
    clearTimeout(handTimer);
    if (!on || !ocrOn || !ocrWorker) return;
    handTimer = setTimeout(() => {
      if (video.readyState >= 2 && video.videoWidth) { try { handPass(); } catch { } }
      handLoop();
    }, 350);
  }
  let handCv, handWeak = '', handN = 0, handAt = 0;
  /** Cifras a mano: separa y clasifica cada cifra. Un EAN válido se acepta al momento; un LN solo si se lee igual 3 veces seguidas. */
  function handPass() {
    if (!window.HandOCR || !HandOCR.read) return false;
    const R = regions().vis, sc = Math.min(1, 640 / Math.max(R.w, R.h)), sw = Math.round(R.w * sc), sh = Math.round(R.h * sc);
    if (sw < 40 || sh < 40) return false;
    handCv = handCv || document.createElement('canvas'); handCv.width = sw; handCv.height = sh;
    const cx = handCv.getContext('2d', { willReadFrequently: true });
    cx.drawImage(video, R.x, R.y, R.w, R.h, 0, 0, sw, sh);
    const d = cx.getImageData(0, 0, sw, sh).data, g = new Uint8Array(sw * sh);
    for (let i = 0; i < g.length; i++) g[i] = (d[i * 4] * 77 + d[i * 4 + 1] * 150 + d[i * 4 + 2] * 29) >> 8;
    const rs = HandOCR.read(g, sw, sh), now = Date.now();
    for (const r of rs) {
      if (r.conf < 0.88 || r.alts.some(a => a[1] < 0.6)) continue;
      const t = r.text;
      if (t.length >= 8 && gs1ok(t) && db.get(key(t))) { handWeak = ''; handN = 0; handle(t); return true; }
      if (t.length >= 6 && t.length <= 8 && findArt(t)) {
        if (t === handWeak && now - handAt < 10000) handN++; else { handWeak = t; handN = 1; }
        handAt = now;
        if (handN >= 3) { handWeak = ''; handN = 0; handle(t); return true; }
        return false;
      }
    }
    return false;
  }
  async function ocrOnce() {
    const w = ocrWorker; if (!w) return;
    const R = regions().vis, [angle, psm, prep] = COMBOS[ocrAngle++ % COMBOS.length];
    const scale = Math.min(1, 800 / Math.max(R.w, R.h));
    const sw = Math.max(8, Math.round(R.w * scale)), sh = Math.max(8, Math.round(R.h * scale));
    ocrCv = ocrCv || document.createElement('canvas'); ocrCtx = ocrCtx || ocrCv.getContext('2d', { willReadFrequently: true });
    if (angle === 0) { ocrCv.width = sw; ocrCv.height = sh; ocrCtx.drawImage(video, R.x, R.y, R.w, R.h, 0, 0, sw, sh); }
    else {
      ocrCv.width = sh; ocrCv.height = sw; ocrCtx.save();
      if (angle === 90) { ocrCtx.translate(sh, 0); ocrCtx.rotate(Math.PI / 2); } else { ocrCtx.translate(0, sw); ocrCtx.rotate(-Math.PI / 2); }
      ocrCtx.drawImage(video, R.x, R.y, R.w, R.h, 0, 0, sw, sh); ocrCtx.restore();
    }
    if (prep) binarize(ocrCtx, ocrCv.width, ocrCv.height);
    if (psm !== curPsm) { await w.setParameters({ tessedit_pageseg_mode: psm }); curPsm = psm; }
    const { data } = await w.recognize(ocrCv);
    if (!on || !ocrOn) return;
    if (window.__ocrDbg) window.__ocrDbg(angle + '/psm' + psm, data.text, Math.round(R.w) + 'x' + Math.round(R.h));
    const m = ocrMatch(data.text), now = Date.now();
    if (!m) return;
    if (m.strong) { weak = ''; weakN = 0; handle(m.code); return; }     // EAN con dígito de control correcto y presente en la BBDD
    // un LN (más fácil de confundir) solo se acepta si se lee dos veces en pocos segundos
    if (m.code === weak && now - weakAt < 8000) weakN++; else { weak = m.code; weakN = 1; }
    weakAt = now;
    if (weakN >= 2) { weak = ''; weakN = 0; handle(m.code); }
  }
  $(c.ocr).onclick = () => { ocrOn = !ocrOn; localStorage.setItem('ubic.ocr', ocrOn ? '1' : '0'); applyOcr(); };

  function stop() {
    if (!on && !stream) return;
    on = false; clearTimeout(timer); clearTimeout(ocrTimer); clearTimeout(handTimer); killOcr();
    stream?.getTracks().forEach(t => t.stop()); stream = null; video.srcObject = null;
    wakeLock?.release?.().catch(() => { }); wakeLock = null;
    view.hidden = true; $(c.result).hidden = true; detector = null; torchOn = false; cand = ''; candCount = 0;
    $(c.btn).classList.remove('on'); $(c.label).textContent = 'Activar cámara';
    c.onStop?.();
  }
  $(c.torch).onclick = async () => {
    torchOn = !torchOn;
    try { await track.applyConstraints({ advanced: [{ torch: torchOn }] }); } catch { toast('Linterna no disponible'); }
  };
  $(c.btn).onclick = () => on ? stop() : start();
  applyOcr();
  return { start, stop, isOn: () => on, reset() { lastCode = ''; lastTime = 0; cand = ''; candCount = 0; } };
}

// ---- Ubicar: lo que lee la cámara se registra ----
const scU = makeScanner({
  video: 'video', view: 'camView', result: 'scanResult', btn: 'scanBtn', label: 'scanLabel', torch: 'torchBtn', ocr: 'ocrBtn',
  canStart: validLoc,
  onStop: render,
  onCode(code, setResult) {
    const r = addCode(code, false);
    feedback(r.status);
    if (r.status === 'ok') setResult(esc(r.rec.desc || '(sin descripción)') + '<small>' + esc(r.rec.ubic) + pad2(r.rec.pos) + ' · ' + esc(r.rec.ean) + '</small>', 'ok');
    else if (r.status === 'nf') setResult('NO ENCONTRADO<small>' + esc(code) + ' registrado en ' + esc(r.rec.ubic) + pad2(r.rec.pos) + '</small>', 'nf');
    else if (r.status === 'dup') setResult('YA ESTÁ EN ESTE NIVEL<small>' + esc(r.rec.desc || code) + ' · ' + esc(r.rec.ubic) + pad2(r.rec.pos) + '</small>', 'dup');
    else setResult('Ubicación llena (99 posiciones)', 'nf');
  }
});

// ---------- Info artículo ----------
let ubicIdx = null;            // LN (sin ceros) -> [ubicaciones]
async function loadUbic() {
  try {
    const text = await getText('ubicaciones');
    const idx = new Map();
    for (const line of text.split(/\r?\n/)) {
      const cols = line.split(/\t|;/);
      const ln = (cols[0] || '').trim().toUpperCase().replace(/^0+/, ''), ub = (cols[1] || '').trim().toUpperCase(), sel = (cols[2] || '').trim().toUpperCase();
      if (!ln || !ub) continue;
      const arr = idx.get(ln) || []; if (!arr.some(x => x.u === ub)) arr.push({ u: ub, s: sel }); idx.set(ln, arr);
    }
    ubicIdx = idx; descIdx = null; locRows = null;
  } catch { ubicIdx = null; }
  const n = $('infoNote');
  n.hidden = !!ubicIdx;
  n.textContent = 'Todavía no se ha cargado el archivo de ubicaciones: de momento solo se muestran el código LN y la descripción.';
  // fecha de la última actualización de ubicaciones (data/ubicaciones-info.json)
  const st = $('ubicState');
  if (!ubicIdx) { st.textContent = 'Ubicaciones: pendiente de cargar'; return; }
  st.textContent = 'Última actualización ubicaciones: ' + (fmtDate(curStore() && curStore().actualizado) || 'fecha no indicada');
}
// ---- búsqueda por descripción ----
let descIdx = null;     // [{ ln, hit, txt }] artículos con ubicación
const norm = t => String(t).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
function buildDescIdx() {
  descIdx = [];
  if (!ubicIdx) return;
  for (const [ln] of ubicIdx) { const hit = findArt(ln); if (hit) descIdx.push({ ln, hit, txt: norm(hit.desc || '') }); }
}
/** Todas las palabras escritas deben aparecer en la descripción (en cualquier orden); gana la que las trae más pronto y más corta. */
function descSearch(q) {
  if (!descIdx) buildDescIdx();
  const words = norm(q).split(/[^a-z0-9ñ.,/+]+/).filter(Boolean);
  if (!words.length) return [];
  const out = [];
  for (const e of descIdx) {
    let ok = true, pos = 0;
    for (const w of words) { const i = e.txt.indexOf(w); if (i < 0) { ok = false; break; } pos += i; }
    if (ok) out.push({ e, score: pos + e.txt.length * 0.15 });
  }
  out.sort((a, b) => a.score - b.score);
  return out.map(x => x.e);
}
const MAXRES = 60;
function renderSearch(q) {
  const res = descSearch(q), card = $('srchCard'), ul = $('srchList');
  ul.innerHTML = '';
  $('infoCard').hidden = true;
  card.hidden = false;
  $('srchTitle').textContent = res.length ? res.length + (res.length === 1 ? ' resultado' : ' resultados') + (res.length > MAXRES ? ' (se muestran ' + MAXRES + '; añade palabras para afinar)' : '') : 'Sin resultados';
  res.slice(0, MAXRES).forEach(e => {
    const ubs = ubicIdx.get(e.ln) || [];
    const li = document.createElement('li');
    li.innerHTML = '<div class="pos">' + esc(lnFmt(e.hit.art || e.ln)) + '<small>LN</small></div><div><div class="d">' + esc(e.hit.desc || '') + '</div><div class="m">' + esc(ubs.map(x => x.u + (x.s ? ' (' + x.s + ')' : '')).join(' · ')) + '</div></div><div></div>';
    li.onclick = () => { const o = { clean: e.hit.art, hit: e.hit, ubs, ean: e.hit.ean }; renderInfo(o); card.hidden = true; window.scrollTo({ top: 0, behavior: 'smooth' }); };
    ul.appendChild(li);
  });
}
const looksLikeText = v => /\s/.test(v) || /[A-Za-zÁÉÍÓÚÑáéíóúñ]{3,}/.test(v) && !/\d/.test(v);
const infoHist = [];
function renderInfo(o) {
  const card = $('infoCard');
  card.hidden = false;
  card.className = 'card result' + (o.hit ? '' : ' nf');
  if (!o.hit) {
    card.innerHTML = '<div class="ln"><small>Código leído</small><b>' + esc(o.clean) + '</b></div><div class="ubs"><p class="none" style="margin-top:14px">No encontrado en la BBDD</p></div>';
    return;
  }
  const h = o.hit;
  let ubs;
  if (o.ubs.length) ubs = o.ubs.map(x => '<span class="chip">' + esc(x.u) + '</span>').join('');
  else ubs = '<p class="none">' + (ubicIdx ? 'Sin ubicación en el archivo' : 'Archivo de ubicaciones sin cargar') + '</p>';
  const ean = o.ean || h.ean;
  const sels = [...new Set(o.ubs.map(x => x.s).filter(Boolean))];
  card.innerHTML = '<div class="ln"><div><small>Código LN</small><b>' + esc(lnFmt(h.art)) + '</b></div>' + (sels.length ? '<div class="sel">' + esc(sels.join(' · ')) + '</div>' : '') + '</div>' +
    '<div class="desc">' + esc(h.desc || '(sin descripción)') + '</div>' +
    (() => { const all = (eansByArt.get(h.art) || []).filter(x => key(x) !== key(ean || '')); const list = (ean ? [ean] : []).concat(all); return list.length ? '<div class="ean">EAN ' + list.map(esc).join(' · ') + '</div>' : '<div class="ean"></div>'; })() +
    '<div class="ubs"><h3>' + (o.ubs.length > 1 ? 'Ubicaciones' : 'Ubicación') + '</h3>' + ubs + '</div>';
}
function renderHist() {
  const ul = $('infoHist'); ul.innerHTML = '';
  infoHist.forEach(o => {
    const li = document.createElement('li');
    li.className = o.hit ? '' : 'nf';
    li.innerHTML = '<div class="pos">' + esc(o.hit ? lnFmt(o.hit.art) : '?') + '<small>LN</small></div><div><div class="d">' + esc(o.hit ? (o.hit.desc || '(sin descripción)') : 'NO ENCONTRADO') + '</div><div class="m">' + esc(o.hit ? (o.ubs.map(x => x.u + (x.s ? ' (' + x.s + ')' : '')).join(' · ') || 'sin ubicación') : o.clean) + '</div></div><div></div>';
    li.onclick = () => { renderInfo(o); window.scrollTo({ top: 0, behavior: 'smooth' }); };
    ul.appendChild(li);
  });
  $('histCard').hidden = !infoHist.length;
}
/** Busca por EAN (cámara) o EAN/LN (manual) y muestra LN, descripción y ubicación. */
function infoLookup(raw, onlyEan) {
  const { clean, hit } = resolve(raw, onlyEan);
  if (!clean) return null;
  const ubs = hit && hit.art && ubicIdx ? (ubicIdx.get(hit.art) || []) : [];
  const o = { clean, hit, ubs, ean: hit && onlyEan ? clean : '' };
  if (o.ean && hit && key(hit.ean) === key(clean)) o.ean = hit.ean;
  renderInfo(o);
  infoHist.unshift(o); if (infoHist.length > 10) infoHist.pop();
  renderHist();
  const status = !hit ? 'nf' : ubs.length ? 'ok' : 'dup';
  feedback(status);
  return { status, o };
}
const scI = makeScanner({
  video: 'videoI', view: 'camViewI', result: 'scanResultI', btn: 'scanBtnI', label: 'scanLabelI', torch: 'torchBtnI', ocr: 'ocrBtnI',
  onCode(code, setResult) {
    const r = infoLookup(code, false);
    if (!r) return;
    const { status, o } = r;
    if (status === 'ok') setResult('LN ' + esc(lnFmt(o.hit.art)) + '<small>' + esc(o.ubs.map(x => x.u + (x.s ? ' (' + x.s + ')' : '')).join(' · ')) + '</small>', 'ok');
    else if (status === 'dup') setResult('LN ' + esc(lnFmt(o.hit.art)) + '<small>Sin ubicación en el archivo</small>', 'dup');
    else setResult('NO ENCONTRADO<small>' + esc(code) + '</small>', 'nf');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
});
$('infoForm').addEventListener('submit', e => {
  e.preventDefault();
  const v = $('infoInput').value.trim();
  if (!v) return;
  $('srchCard').hidden = true;
  if (looksLikeText(v) && ubicIdx) { renderSearch(v); return; }
  const r = infoLookup(v, false);
  if (r && r.status === 'nf' && /[A-Za-z]{3,}/.test(v) && ubicIdx) { infoHist.shift(); renderHist(); renderSearch(v); return; }
  $('infoInput').value = '';
});
// al escribir palabras se van mostrando los artículos que coinciden
let srchT;
$('infoInput').addEventListener('input', () => {
  clearTimeout(srchT);
  srchT = setTimeout(() => {
    const v = $('infoInput').value.trim();
    if (v.length >= 3 && looksLikeText(v) && ubicIdx) renderSearch(v); else $('srchCard').hidden = true;
  }, 250);
});


// ---------- Ubicaciones: buscar por EAN, LN, descripción o ubicación ----------
let locRows = null;     // [{ u, s, ln }] todas las ubicaciones del archivo
function buildLocRows() {
  locRows = [];
  if (!ubicIdx) return;
  for (const [ln, arr] of ubicIdx) for (const x of arr) locRows.push({ u: x.u, s: x.s, ln });
  locRows.sort((a, b) => a.u < b.u ? -1 : a.u > b.u ? 1 : 0);
}
const LOCPAGE = 100;
let locRes = [], locShown = 0;
const locTxt = ubs => ubs.map(x => x.u + (x.s ? ' (' + x.s + ')' : '')).join(' · ') || 'sin ubicación';
function locEntry(ln, ubs) { return { ln, hit: findArt(ln), ubs: ubs || ubicIdx.get(ln) || [] }; }
/** Devuelve { res, title }: por código (EAN/LN), por ubicación (prefijo: GG01, GG0102…) o por descripción. */
function locSearch(raw) {
  const v = raw.trim(), compact = v.toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (!v || !ubicIdx) return { res: [], title: '' };
  if (!/\s/.test(v) && /^\d+$/.test(compact)) {          // número: EAN o LN
    const { hit } = resolve(compact, false);
    const res = hit ? [locEntry(hit.art, hit.art && ubicIdx.get(hit.art))] : [];
    return { res, title: res.length ? 'Artículo encontrado' : 'No encontrado', code: true };
  }
  if (!/\s/.test(v) && compact.length >= 2 && /^[A-Z]/.test(compact)) {      // ubicación: se busca por el principio del código
    if (!locRows) buildLocRows();
    const by = new Map();
    for (const r of locRows) if (r.u.startsWith(compact)) { const e = by.get(r.ln) || { ln: r.ln, hit: null, ubs: [] }; e.ubs.push({ u: r.u, s: r.s }); by.set(r.ln, e); }
    if (by.size) {
      const res = [...by.values()]; res.forEach(e => e.hit = findArt(e.ln));
      return { res, title: res.length + (res.length === 1 ? ' artículo en ' : ' artículos en ') + compact };
    }
  }
  const res = descSearch(v).map(e => locEntry(e.ln));     // descripción
  return { res, title: res.length ? res.length + (res.length === 1 ? ' resultado' : ' resultados') : 'Sin resultados' };
}
function drawLoc(first) {
  const ul = $('locList'); if (first) ul.innerHTML = '';
  locRes.slice(first ? 0 : locShown, locShown = Math.min(locRes.length, (first ? 0 : locShown) + LOCPAGE)).forEach(e => {
    const li = document.createElement('li');
    li.innerHTML = '<div class="pos">' + esc(lnFmt(e.ln)) + '</div><div><div class="d">' + esc((e.hit && e.hit.desc) || '(sin descripción)') + '</div><div class="m">' + esc(locTxt(e.ubs)) + '</div></div><div></div>';
    ul.appendChild(li);
  });
  $('locMore').hidden = locShown >= locRes.length;
  $('locMore').textContent = 'Mostrar más (' + (locRes.length - locShown) + ')';
}
function showLoc(raw) {
  const { res, title } = locSearch(raw);
  locRes = res; locShown = 0;
  $('locCard').hidden = !title;
  $('locTitle').textContent = title;
  drawLoc(true);
  return res;
}
$('locMore').onclick = () => drawLoc(false);
$('locForm').addEventListener('submit', e => { e.preventDefault(); showLoc($('locInput').value); $('locInput').blur(); });
let locT;
$('locInput').addEventListener('input', () => { clearTimeout(locT); locT = setTimeout(() => { const v = $('locInput').value.trim(); if (v.length >= 2) showLoc(v); else $('locCard').hidden = true; }, 250); });
const scL = makeScanner({
  video: 'videoL', view: 'camViewL', result: 'scanResultL', btn: 'scanBtnL', label: 'scanLabelL', torch: 'torchBtnL', ocr: 'ocrBtnL',
  onCode(code, setResult) {
    const res = showLoc(code), e = res[0];
    if (!e) { feedback('nf'); setResult('NO ENCONTRADO<small>' + esc(code) + '</small>', 'nf'); return; }
    feedback(e.ubs.length ? 'ok' : 'dup');
    setResult('LN ' + esc(lnFmt(e.ln)) + '<small>' + esc(locTxt(e.ubs)) + '</small>', e.ubs.length ? 'ok' : 'dup');
  }
});

// ---------- Navegación ----------
// altura de la cabecera para que la zona fija (cámara/buscador) quede justo debajo
const setTopH = () => document.documentElement.style.setProperty('--topH', (document.querySelector('.top')?.offsetHeight || 64) + 'px');
setTopH(); addEventListener('resize', setTopH); addEventListener('orientationchange', setTopH);
const TITLES = { home: 'Control de ubicaciones', ubics: 'Ubicaciones', ubicar: 'Editar ubicación', info: 'Artículo', loc: 'Consulta ubicaciones' };
/** Al salir de Artículo se vacía todo (ficha, búsqueda, historial y campo) para que se entre siempre en blanco. */
function clearInfo() {
  infoHist.length = 0; renderHist();
  for (const id of ['infoCard', 'srchCard', 'histCard', 'scanResultI']) $(id).hidden = true;
  $('srchList').innerHTML = ''; $('infoInput').value = '';
}
let curScreen = 'home';
function show(name, push) {
  scU.stop(); scI.stop(); scL.stop();
  if (curScreen === 'info' && name !== 'info') clearInfo();
  curScreen = name;
  $('screenUbics').hidden = name !== 'ubics';
  $('screenLoc').hidden = name !== 'loc';
  $('home').hidden = name !== 'home';
  $('screenUbicar').hidden = name !== 'ubicar';
  $('screenInfo').hidden = name !== 'info';
  $('backBtn').hidden = name === 'home';
  setTimeout(setTopH, 0);
  $('title').textContent = TITLES[name];
  document.body.className = 'on-' + name;
  if (push) history.pushState({ s: name }, '', '#' + name);
  if (name === 'ubicar') render();
  window.scrollTo(0, 0);
}
$('goUbicar').onclick = () => show('ubicar', true);
$('goInfo').onclick = () => show('info', true);
$('goUbics').onclick = () => show('ubics', true);
$('goLoc').onclick = () => show('loc', true);
$('backBtn').onclick = () => { if (history.state && history.state.s && history.state.s !== 'home') history.back(); else show('home', false); };
window.addEventListener('popstate', e => show((e.state && e.state.s) || 'home', false));
document.addEventListener('visibilitychange', () => { if (document.hidden) { scU.stop(); scI.stop(); scL.stop(); } });

// ---------- Arranque ----------
history.replaceState({ s: 'home' }, '', location.pathname);
writeLoc();
render();
show('home', false);
boot();
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => { });
})();
