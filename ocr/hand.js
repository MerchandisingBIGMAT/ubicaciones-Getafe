/* Lectura de cifras escritas a mano (sin librerías): separa las cifras de la imagen y las clasifica con una red pequeña entrenada con MNIST. */
(function (root) {
  let NET = null;
  function load(buf) {
    const f = new Float32Array(buf); let o = 0; const L = [[784, 256], [256, 128], [128, 10]];
    NET = L.map(([i, n]) => { const W = f.subarray(o, o += i * n), b = f.subarray(o, o += n); return { W, b, i, n }; });
  }
  function fwd(x) {
    let a = x;
    NET.forEach((l, k) => {
      const out = new Float32Array(l.n); out.set(l.b);
      for (let i = 0; i < l.i; i++) { const v = a[i]; if (v === 0) continue; const row = i * l.n; for (let j = 0; j < l.n; j++) out[j] += v * l.W[row + j]; }
      if (k < NET.length - 1) for (let j = 0; j < l.n; j++) if (out[j] < 0) out[j] = 0;
      a = out;
    });
    let mx = Math.max(...a), s = 0; const p = Array.from(a, v => { const e = Math.exp(v - mx); s += e; return e; });
    return p.map(v => v / s);
  }
  /** Tinta = más oscura que su entorno (umbral local con imagen integral): funciona con degradados de luz. */
  function ink(g, w, h) {
    const I = new Float64Array((w + 1) * (h + 1));
    for (let y = 0; y < h; y++) { let r = 0; for (let x = 0; x < w; x++) { r += g[y * w + x]; I[(y + 1) * (w + 1) + x + 1] = I[y * (w + 1) + x + 1] + r; } }
    const k = Math.max(7, Math.round(Math.min(w, h) / 7)), m = new Uint8Array(w * h);
    for (let y = 0; y < h; y++) {
      const y0 = Math.max(0, y - k), y1 = Math.min(h, y + k + 1);
      for (let x = 0; x < w; x++) {
        const x0 = Math.max(0, x - k), x1 = Math.min(w, x + k + 1);
        const s = I[y1 * (w + 1) + x1] - I[y0 * (w + 1) + x1] - I[y1 * (w + 1) + x0] + I[y0 * (w + 1) + x0];
        const mean = s / ((x1 - x0) * (y1 - y0));
        m[y * w + x] = g[y * w + x] < mean - 14 ? 1 : 0;
      }
    }
    return m;
  }
  function comps(m, w, h) {
    const lab = new Int32Array(w * h), out = []; const st = [];
    for (let s = 0; s < w * h; s++) {
      if (!m[s] || lab[s]) continue;
      const id = out.length + 1; let x0 = w, y0 = h, x1 = 0, y1 = 0; const px = [];
      st.push(s); lab[s] = id;
      while (st.length) {
        const p = st.pop(), x = p % w, y = (p - x) / w; px.push(p);
        if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y;
        for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
          const nx = x + dx, ny = y + dy; if (nx < 0 || ny < 0 || nx >= w || ny >= h) continue;
          const q = ny * w + nx; if (m[q] && !lab[q]) { lab[q] = id; st.push(q); }
        }
      }
      out.push({ x0, y0, x1, y1, px });
    }
    return out;
  }
  /** Convierte un grupo de píxeles (ya girado) en una imagen 28x28 estilo MNIST. */
  function glyph(px, w, rot, bb) {
    const bw = bb.x1 - bb.x0 + 1, bh = bb.y1 - bb.y0 + 1, sc = 20 / Math.max(bw, bh);
    const tw = Math.max(1, Math.round(bw * sc)), th = Math.max(1, Math.round(bh * sc));
    const acc = new Float32Array(28 * 28), cnt = new Float32Array(28 * 28);
    const g = new Uint8Array(bw * bh);
    for (const [x, y] of px) g[(y - bb.y0) * bw + (x - bb.x0)] = 1;
    // reducir con promedio (área) a tw x th
    const small = new Float32Array(tw * th);
    for (let y = 0; y < th; y++) for (let x = 0; x < tw; x++) {
      const sx0 = Math.floor(x / sc), sx1 = Math.max(sx0 + 1, Math.floor((x + 1) / sc)), sy0 = Math.floor(y / sc), sy1 = Math.max(sy0 + 1, Math.floor((y + 1) / sc));
      let s = 0, n = 0; for (let yy = sy0; yy < Math.min(sy1, bh); yy++) for (let xx = sx0; xx < Math.min(sx1, bw); xx++) { s += g[yy * bw + xx]; n++; }
      small[y * tw + x] = n ? Math.min(1, (s / n) * 1.6) : 0;
    }
    let mx = 0, my = 0, mm = 0;
    for (let y = 0; y < th; y++) for (let x = 0; x < tw; x++) { const v = small[y * tw + x]; mx += v * x; my += v * y; mm += v; }
    mx = mm ? mx / mm : tw / 2; my = mm ? my / mm : th / 2;
    const ox = Math.round(14 - mx), oy = Math.round(14 - my), img = new Float32Array(784);
    for (let y = 0; y < th; y++) for (let x = 0; x < tw; x++) { const X = x + ox, Y = y + oy; if (X >= 0 && X < 28 && Y >= 0 && Y < 28) img[Y * 28 + X] = small[y * tw + x]; }
    return img;
  }
  function rotPt(x, y, w, h, r) { return r === 0 ? [x, y] : r === 1 ? [h - 1 - y, x] : r === 2 ? [w - 1 - x, h - 1 - y] : [y, w - 1 - x]; }
  /** Lee la imagen en gris y devuelve candidatos [{text, conf, alt}] para las 4 orientaciones, mejores primero. */
  function read(g, w, h) {
    if (!NET) return [];
    const m = ink(g, w, h);
    // quitar manchas macizas (bordes, sombras): un trazo de bolígrafo es fino y no sobrevive a una erosión
    const r0 = Math.round(0.007 * Math.max(w, h)) + 1, S = new Int32Array((w + 1) * (h + 1));
    for (let y = 0; y < h; y++) { let rr = 0; for (let x = 0; x < w; x++) { rr += m[y * w + x]; S[(y + 1) * (w + 1) + x + 1] = S[y * (w + 1) + x + 1] + rr; } }
    const full = (x, y) => { const x0 = x - r0, x1 = x + r0 + 1, y0 = y - r0, y1 = y + r0 + 1; if (x0 < 0 || y0 < 0 || x1 > w || y1 > h) return false; return S[y1 * (w + 1) + x1] - S[y0 * (w + 1) + x1] - S[y1 * (w + 1) + x0] + S[y0 * (w + 1) + x0] === (2 * r0 + 1) * (2 * r0 + 1); };
    let cs = comps(m, w, h).filter(c => { let n = 0; for (const p of c.px) { const x = p % w; if (full(x, (p - x) / w)) n++; } return n < 0.02 * c.px.length; }).filter(c => c.px.length >= 12 && Math.max(c.x1 - c.x0, c.y1 - c.y0) >= Math.min(w, h) * 0.04 && Math.max(c.x1 - c.x0, c.y1 - c.y0) < Math.max(w, h) * 0.4 && (() => { const f = c.px.length / ((c.x1 - c.x0 + 1) * (c.y1 - c.y0 + 1)); return f > 0.06 && f < 0.4; })());
    if (cs.length < 3 || cs.length > 60) return [];
    const res = [];
    for (let r = 0; r < 4; r++) {
      const W = r % 2 ? h : w, H = r % 2 ? w : h;
      let gs = cs.map(c => { const px = c.px.map(p => { const x = p % w; return rotPt(x, (p - x) / w, w, h, r); }); let x0 = W, y0 = H, x1 = 0, y1 = 0; for (const [x, y] of px) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; } return { px, x0, y0, x1, y1 }; });
      // quedarse con la línea de cifras: piezas de altura parecida y alineadas en una misma franja
      const hs = gs.map(c => c.y1 - c.y0 + 1).sort((a, b) => a - b), med = hs[Math.floor(hs.length * 0.75)];
      gs = gs.filter(c => { const hh = c.y1 - c.y0 + 1; return hh > med * 0.45 && hh < med * 1.7 || (c.x1 - c.x0 + 1) > med * 0.45 && hh < med * 1.7; });
      let best = [];
      for (const s0 of gs) { const cy = (s0.y0 + s0.y1) / 2, set = gs.filter(c => Math.abs((c.y0 + c.y1) / 2 - cy) < med * 0.7); if (set.length > best.length) best = set; }
      gs = best;
      gs.sort((a, b) => a.x0 - b.x0);
      // separar cifras pegadas: una pieza más ancha de lo normal se parte en k trozos por las columnas con menos tinta
      const split = [];
      for (const c of gs) {
        const cw = c.x1 - c.x0 + 1, k = cw > 0.95 * med ? Math.round(cw / (0.65 * med)) : 1;
        if (k >= 2) {
          const col = new Array(cw).fill(0); for (const [x] of c.px) col[x - c.x0]++;
          const mk = P => { let x0 = W, y0 = H, x1 = 0, y1 = 0; for (const [x, y] of P) { if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y; } return { px: P, x0, y0, x1, y1 }; };
          const conf = P => { if (P.length < 8) return 0; const g = mk(P), p = fwd(glyph(g.px, W, r, g)); return Math.max(...p); };
          const cuts = [0];
          for (let j = 1; j < k; j++) {
            const t = Math.round(cw * j / k), lo = Math.max(cuts[cuts.length - 1] + 3, t - Math.round(cw * 0.22)), hi = Math.min(cw - 3, t + Math.round(cw * 0.22));
            let bi = t, bv = -1;
            for (let i = lo; i <= hi; i += 2) {      // se elige el corte en que la red reconoce mejor las dos mitades
              const A = c.px.filter(p => p[0] - c.x0 >= cuts[cuts.length - 1] && p[0] - c.x0 < i), B = c.px.filter(p => p[0] - c.x0 >= i);
              const sc = conf(A) + (k === 2 ? conf(B) : 0) - 0.002 * col[i];
              if (sc > bv) { bv = sc; bi = i; }
            }
            cuts.push(bi);
          }
          cuts.push(cw);
          for (let j = 0; j < k; j++) { const P = c.px.filter(p => p[0] - c.x0 >= cuts[j] && p[0] - c.x0 < cuts[j + 1]); if (P.length >= 8) split.push(mk(P)); }
        } else split.push(c);
      }
      gs = split.filter(c => (c.x1 - c.x0 + 1) > 0.12 * med || (c.y1 - c.y0 + 1) > 0.8 * med);
      // unir trazos sueltos (raya del 7, punto, trozo de una cifra partida) con su vecino
      const mg = [];
      for (const c of gs) {
        const l = mg[mg.length - 1], cw = c.x1 - c.x0 + 1, lw = l ? l.x1 - l.x0 + 1 : 0, gap = l ? c.x0 - l.x1 : 0;
        const narrow = !!l && Math.min(cw, lw) < 0.3 * med, tall = (narrow ? (cw < lw ? c : l) : c);
        const lone1 = narrow && (tall.y1 - tall.y0 + 1) > 0.8 * med && gap > 0.1 * med;     // un 1 suelto
        if (l && narrow && !lone1 && gap < 0.2 * med) { l.px = l.px.concat(c.px); l.x1 = Math.max(l.x1, c.x1); l.x0 = Math.min(l.x0, c.x0); l.y0 = Math.min(l.y0, c.y0); l.y1 = Math.max(l.y1, c.y1); } else mg.push({ ...c });
      }
      { // varios grupos separados por huecos grandes: se queda el más numeroso
        const grp = [[mg[0]]]; for (let i = 1; i < mg.length; i++) { if (mg[i].x0 - mg[i - 1].x1 > 1.6 * med) grp.push([]); grp[grp.length - 1].push(mg[i]); }
        if (grp.length > 1) { grp.sort((a, b) => b.length - a.length); mg.length = 0; mg.push(...grp[0]); }
      }
      if (mg.length < 3 || mg.length > 14) continue;
      let text = '', conf = 0; const alts = [];
      for (const c of mg) {
        const p = fwd(glyph(c.px, W, r, c)); let b = 0, b2 = -1;
        for (let i = 1; i < 10; i++) if (p[i] > p[b]) { b2 = b; b = i; } else if (b2 < 0 || p[i] > p[b2]) b2 = i;
        text += b; conf += p[b]; alts.push([b, p[b], b2, p[b2]]);
      }
      res.push({ text, conf: conf / mg.length, alts, rot: r, boxes: mg.map(c => [c.x0, c.y0, c.x1, c.y1]), W, H });
    }
    return res.sort((a, b) => b.conf - a.conf);
  }
  root.HandOCR = { load, read, ink };
})(typeof window !== 'undefined' ? window : globalThis);
