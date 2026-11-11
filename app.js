/* Masa arayüzü.
 *
 * Güvenlik (Masa Protokolü 6.4):
 *  G2  Projelerden gelen hiçbir metin HTML olarak yorumlanmaz: yalnız textContent ve createElement.
 *      Bu dosyada innerHTML, outerHTML, insertAdjacentHTML ve document.write kullanılmaz.
 *  G3  CSP index.html'de: yalnız bu dosyalar çalışır, bağlantı yalnız api.github.com'a.
 *  G4  Dış kaynak yok.
 *  G5  Cihaz anahtarı PIN ile şifreli saklanır (PBKDF2-SHA256 → AES-GCM). PIN saklanmaz.
 *  G6  Anahtar yalnız masa deposuna erişir; bu kod yalnız masa deposuna istek atar.
 */
'use strict';

(() => {
  // ================================================================ yardımcılar (G2)
  const $ = (s) => document.querySelector(s);
  const NS = 'http://www.w3.org/2000/svg';
  const GUVENLI_OZ = /^(class|id|type|title|role|aria-[a-z-]+|x|y|x1|x2|y1|y2|cx|cy|r|width|height|d|points|transform|viewBox|preserveAspectRatio|text-anchor|marker-end|data-[a-z-]+|disabled|target|rel)$/;

  function oz(e, attrs) {
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (!GUVENLI_OZ.test(k)) throw new Error(`İzinsiz öznitelik: ${k}`);
      e.setAttribute(k, v === true ? '' : String(v));
    }
    return e;
  }
  function ekle(e, cocuklar) {
    for (const c of cocuklar.flat()) {
      if (c === null || c === undefined || c === false) continue;
      e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
    }
    return e;
  }
  const h = (tag, attrs, ...c) => ekle(oz(document.createElement(tag), attrs), c);
  const s = (tag, attrs, ...c) => ekle(oz(document.createElementNS(NS, tag), attrs), c);
  const temizle = (e) => { while (e.firstChild) e.removeChild(e.firstChild); return e; };

  /** Yalnız github.com'a giden, depo ve yol parçaları kodlanmış bağlantı. */
  function ghBag(konum) {
    if (!konum || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(konum.repo || '')) return null;
    const yol = String(konum.yol || '').split('/').map(encodeURIComponent).join('/');
    const sha = durumSha(konum.repo);
    const href = `https://github.com/${konum.repo}/blob/${encodeURIComponent(sha || 'HEAD')}/${yol}` +
      (Number.isInteger(konum.satir) ? `#L${konum.satir}` : '');
    const a = h('a', { target: '_blank', rel: 'noopener noreferrer' }, `${konum.repo}/${konum.yol}${konum.satir ? ':' + konum.satir : ''}`);
    a.href = href; // DOM özelliği; şema ve alan adı yukarıda sabit
    return a;
  }

  const kisalt = (m, n) => { m = String(m ?? ''); return m.length > n ? m.slice(0, n - 1) + '…' : m; };
  const tarih = (iso) => { try { return new Date(iso).toLocaleString('tr-TR', { dateStyle: 'short', timeStyle: 'short', timeZone: 'Europe/Istanbul' }); } catch { return String(iso); } };

  const EVRE = ['İhtiyaç', 'Gereksinim', 'Tasarım', 'Geliştirme', 'Doğrulama', 'Yayın', 'İşletim', 'Bakım'];
  const DURUM = { bekliyor: 'Bekliyor', suruyor: 'Sürüyor', engelli: 'Engelli', bitti: 'Bitti', vazgecildi: 'Vazgeçildi' };
  const SEVIYE = { kritik: 'Kritik', yuksek: 'Yüksek', orta: 'Orta', dusuk: 'Düşük', bilgi: 'Bilgi' };
  const SEVIYE_SIRA = ['kritik', 'yuksek', 'orta', 'dusuk', 'bilgi'];
  const BDURUM = { acik: 'Açık', kararda: 'Kararda', risk_kabulu: 'Risk kabulü', kapandi: 'Kapandı', gecersiz: 'Geçersiz' };
  const ACIK_BULGU = new Set(['acik', 'kararda', 'risk_kabulu']);
  const TUR = { proje: 'PROJE', asama: 'AŞAMA', alan: 'İŞ ALANI', bilesen: 'BİLEŞEN', ip: 'İŞ PAKETİ', dosya: 'DOSYA' };

  // ================================================================ kasa (G5)
  const KASA = 'masa.kasa.v1';
  const b64 = (u8) => btoa(String.fromCharCode(...u8));
  const b64c = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  const yaz = (t) => new TextEncoder().encode(t);

  async function anahtar(pin, tuz) {
    const temel = await crypto.subtle.importKey('raw', yaz(pin), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: tuz, iterations: 600000, hash: 'SHA-256' },
      temel, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function kasaKaydet(repo, token, pin) {
    const tuz = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await anahtar(pin, tuz), yaz(token)));
    localStorage.setItem(KASA, JSON.stringify({ v: 1, repo, tuz: b64(tuz), iv: b64(iv), ct: b64(ct) }));
  }
  function kasaOku() {
    try { const k = JSON.parse(localStorage.getItem(KASA) || 'null'); return k && k.v === 1 ? k : null; } catch { return null; }
  }
  async function kasaAc(k, pin) {
    const acik = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64c(k.iv) }, await anahtar(pin, b64c(k.tuz)), b64c(k.ct));
    return new TextDecoder().decode(acik);
  }
  function kasaSil() { try { localStorage.removeItem(KASA); } catch { /* yok say */ } }

  // ================================================================ GitHub (yalnız masa deposu)
  const API = 'https://api.github.com';
  let oturum = null; // { repo, token } yalnız bellekte

  async function gh(yol, { yontem = 'GET', govde, ham = false } = {}) {
    const r = await fetch(API + yol, {
      method: yontem,
      headers: {
        Authorization: `Bearer ${oturum.token}`,
        Accept: ham ? 'application/vnd.github.raw+json' : 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(govde ? { 'Content-Type': 'application/json' } : {}),
      },
      body: govde ? JSON.stringify(govde) : undefined,
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
    });
    if (r.status === 401) throw new Error('Anahtar geçersiz ya da süresi dolmuş (401).');
    if (r.status === 403) throw new Error('Anahtarın bu işe izni yok (403).');
    if (r.status === 404) throw new Error('Bulunamadı (404): depo adı ya da anahtarın depo erişimi.');
    if (!r.ok) throw new Error(`GitHub ${r.status}`);
    if (r.status === 204) return null;
    return ham ? r.text() : r.json();
  }
  const depo = () => `/repos/${oturum.repo.split('/').map(encodeURIComponent).join('/')}`;

  async function durumlariGetir() {
    let liste;
    try { liste = await gh(`${depo()}/contents/durum`); } catch (e) {
      if (String(e.message).includes('404')) return [];
      throw e;
    }
    const dosyalar = (Array.isArray(liste) ? liste : []).filter((f) => f.type === 'file' && /^[a-z0-9-]+\.json$/.test(f.name));
    const out = [];
    for (const f of dosyalar) {
      const m = JSON.parse(await gh(`${depo()}/contents/durum/${encodeURIComponent(f.name)}`, { ham: true }));
      if (m && m.model === '1' && m.proje && Array.isArray(m.dugumler)) out.push(m);
    }
    return out.sort((a, b) => a.proje.ad.localeCompare(b.proje.ad, 'tr'));
  }

  async function toplamaBaslat(bilgi) {
    const bas = Date.now();
    await gh(`${depo()}/actions/workflows/topla.yml/dispatches`, { yontem: 'POST', govde: { ref: 'main' } });
    bilgi('Toplama başlatıldı…');
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 5000));
      const v = await gh(`${depo()}/actions/workflows/topla.yml/runs?per_page=1&event=workflow_dispatch`);
      const run = v && v.workflow_runs && v.workflow_runs[0];
      if (!run || Date.parse(run.created_at) < bas - 15000) { bilgi('Toplama sırada…'); continue; }
      if (run.status !== 'completed') { bilgi('Toplanıyor…'); continue; }
      if (run.conclusion !== 'success') throw new Error(`Toplama başarısız (${run.conclusion}).`);
      return;
    }
    throw new Error('Toplama 3 dakikada bitmedi; sonra yeniden yükleyin.');
  }

  // ================================================================ kapı
  function kapiGoster(kip, hata = '') {
    $('#masa').hidden = true;
    $('#kapi').hidden = false;
    $('#kurulum').hidden = kip !== 'kurulum';
    $('#kilit').hidden = kip !== 'kilit';
    $('#kapi-baslik').textContent = kip === 'kurulum' ? 'Kurulum' : 'Kilitli';
    $('#kapi-aciklama').textContent = kip === 'kurulum'
      ? 'Anahtar bu cihazda PIN ile şifrelenip saklanır. PIN hiçbir yerde tutulmaz; unutulursa anahtar yeniden girilir.'
      : `Masa deposu: ${(kasaOku() || {}).repo || '—'}`;
    $('#kapi-hata').textContent = hata;
    (kip === 'kurulum' ? $('#k-repo') : $('#l-pin')).focus();
  }

  let hataliDeneme = 0;
  async function kurulumGonder(e) {
    e.preventDefault();
    const repo = $('#k-repo').value.trim(), token = $('#k-token').value.trim();
    const pin = $('#k-pin').value, pin2 = $('#k-pin2').value;
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) return void ($('#kapi-hata').textContent = 'Depo "sahip/depo" biçiminde olmalı.');
    if (pin.length < 6) return void ($('#kapi-hata').textContent = 'PIN en az 6 hane olmalı.');
    if (pin !== pin2) return void ($('#kapi-hata').textContent = "PIN'ler aynı değil.");
    oturum = { repo, token };
    try {
      await gh(depo()); // anahtar ve depo doğru mu
      await kasaKaydet(repo, token, pin);
    } catch (h2) { oturum = null; return void ($('#kapi-hata').textContent = h2.message); }
    $('#kurulum').reset();
    masayiAc();
  }
  async function kilitGonder(e) {
    e.preventDefault();
    const k = kasaOku();
    if (!k) return kapiGoster('kurulum');
    try {
      oturum = { repo: k.repo, token: await kasaAc(k, $('#l-pin').value) };
      hataliDeneme = 0;
      $('#kilit').reset();
      masayiAc();
    } catch {
      hataliDeneme++;
      $('#kapi-hata').textContent = 'PIN yanlış.';
      const btn = $('#kilit button[type=submit]');
      btn.disabled = true;
      setTimeout(() => { btn.disabled = false; }, Math.min(30000, 1000 * 2 ** hataliDeneme));
    }
  }
  function kilitle() { oturum = null; projeler = []; temizle($('#dunya')); kapiGoster(kasaOku() ? 'kilit' : 'kurulum'); }

  // ================================================================ durum
  let projeler = [], etkin = 0, gorunumler = {}, secili = null;
  let yer = null; // yerleşim: { dugumler: Map, kutu }
  const katman = { ilerleme: true, denetim: true, uyari: true };
  const p = () => projeler[etkin];
  function durumSha(repo) { const k = p() && p().kaynaklar.find((x) => x.repo === repo); return k && k.sha; }

  async function masayiAc() {
    $('#kapi').hidden = true;
    $('#masa').hidden = false;
    await yenidenYukle();
  }
  async function yenidenYukle() {
    const satir = $('#durum-satiri');
    satir.textContent = 'Yükleniyor…';
    try {
      projeler = await durumlariGetir();
      satir.textContent = projeler.length ? '' : 'Henüz durum dosyası yok. GÜNCELLE ile toplamayı başlatın.';
    } catch (e) { satir.textContent = e.message; projeler = []; }
    etkin = Math.min(etkin, Math.max(0, projeler.length - 1));
    ciz(true);
  }

  // ================================================================ yerleşim
  // Akış yerleşimi: aşamalar soldan sağa sütun, iş alanları alttaki ayrı bant.
  // Sütun içinde bileşen → iş paketi → dosya girintili alt alta.
  const OLCU = { proje: [400, 150], asama: [380, 122], alan: [380, 122], bilesen: [356, 110], ip: [330, 82], dosya: [306, 28] };
  const GIRINTI = { bilesen: 24, ip: 26, dosya: 24 };
  const ARA = { bilesen: 40, ip: 14, dosya: 6 };
  const KOLON = 380, KOLON_ARA = 150, BANT_ARA = 260, BAS_Y = 120;
  const DERINLIK = { proje: 0, asama: 1, alan: 1, bilesen: 2, ip: 3, dosya: 4 };
  const ESIK = [0, 0, 0.3, 0.6, 1.05];

  // L: görünen en derin düzey (1–4). Daha derindeki düğümler yer kaplamaz; yakınlaştıkça sütunlar açılır.
  const seviye = (k) => Math.max(1, ESIK.filter((e) => k >= e).length - 1);
  function yerlesim(m, L) {
    const dug = new Map(m.dugumler.map((d) => [d.id, { ...d, cocuk: [] }]));
    for (const d of dug.values()) if (d.ust && dug.has(d.ust)) dug.get(d.ust).cocuk.push(d);
    for (const [ip, liste] of Object.entries(m.katmanlar.dosyalar || {})) {
      const ust = dug.get(ip);
      if (!ust) continue;
      const tek = new Map();
      for (const f of liste) { const k = tek.get(f.yol) || { ...f, ekle: 0, sil: 0 }; k.ekle += f.ekle; k.sil += f.sil; tek.set(f.yol, k); }
      [...tek.values()].slice(0, 8).forEach((f, i) => {
        const id = `dosya:${ip}:${i}`;
        const d = { id, tur: 'dosya', ust: ip, ad: f.yol, dosya: f, cocuk: [] };
        dug.set(id, d); ust.cocuk.push(d);
      });
    }
    const kok = [...dug.values()].find((d) => d.tur === 'proje');
    if (!kok) return null;
    for (const d of dug.values()) [d.w, d.h] = OLCU[d.tur];
    // sütun içi yığın: düğüm, altında girintili çocukları; dönen değer yığının alt sınırı
    const gizle = (c, u) => { c.x = u.x; c.y = u.y; c.derinlik = DERINLIK[c.tur] ?? u.derinlik + 1; c.cocuk.forEach((x) => gizle(x, c)); };
    const yig = (d, x, y, der) => {
      d.x = x; d.y = y; d.derinlik = DERINLIK[d.tur] ?? der;
      let alt = y + d.h;
      for (const c of d.cocuk) {
        if ((DERINLIK[c.tur] ?? d.derinlik + 1) > L) { gizle(c, d); continue; }
        alt = yig(c, x + (GIRINTI[c.tur] || 24), alt + (ARA[c.tur] || 14), d.derinlik + 1);
      }
      return alt;
    };
    kok.derinlik = 0;
    kok.x = 0; kok.y = BAS_Y - (OLCU.proje[1] - OLCU.asama[1]) / 2;
    const asamalar = kok.cocuk.filter((c) => c.tur === 'asama');
    const alanlar = kok.cocuk.filter((c) => c.tur === 'alan');
    const ortak = kok.cocuk.filter((c) => c.tur !== 'asama' && c.tur !== 'alan');
    const x0 = kok.w + KOLON_ARA;
    const sx = (i) => x0 + i * (KOLON + KOLON_ARA);
    let ust = 0;
    asamalar.forEach((a, i) => { ust = Math.max(ust, yig(a, sx(i), BAS_Y, 1)); });
    // ortak bileşenler (aşamaya bağlı olmayan) aşama dizisinin sonunda ayrı sütun
    let oy = BAS_Y + OLCU.asama[1] + 40;
    const ortakX = sx(asamalar.length);
    for (const c of ortak) {
      if ((DERINLIK[c.tur] ?? 2) > L) { gizle(c, kok); continue; }
      ust = Math.max(ust, oy = yig(c, ortakX + GIRINTI.bilesen, oy, 2)); oy += ARA.bilesen;
    }
    const bantY = ust + BANT_ARA;
    let alt = bantY;
    alanlar.forEach((a, i) => { alt = Math.max(alt, yig(a, sx(i), bantY + BAS_Y, 1)); });
    const xs = [...dug.values()];
    const sag = Math.max(...xs.map((d) => d.x + d.w));
    const bantlar = [{ ad: 'AŞAMALAR · akış soldan sağa', y: 0, x: x0 }];
    if (ortak.length) bantlar.push({ ad: 'ORTAK', y: 0, x: ortakX, kucuk: true });
    if (alanlar.length) bantlar.push({ ad: 'İŞ ALANLARI · aşamalara paralel sürer', y: bantY, x: x0, cizgi: true });
    const kutu = { x: -80, y: -160, w: sag + 160, h: (alanlar.length ? alt : ust) + 240 };
    return { dug, kok, kutu, bantlar, asamalar, alanlar, ortak, bantY, sag, L };
  }

  // düğüme bağlı bulgular ve uyarılar (alt düğümler dahil toplam)
  function bagla(m, dug) {
    const dogrudan = new Map(), uyari = new Map();
    for (const b of m.katmanlar.denetim.bulgular) for (const n of b.bagli) { if (!dogrudan.has(n)) dogrudan.set(n, []); dogrudan.get(n).push(b); }
    for (const u of m.katmanlar.uyarilar) if (u.dugum) { if (!uyari.has(u.dugum)) uyari.set(u.dugum, []); uyari.get(u.dugum).push(u); }
    const toplam = new Map();
    const topla = (d) => {
      const set = new Map((dogrudan.get(d.id) || []).filter((b) => ACIK_BULGU.has(b.durum)).map((b) => [b.no, b]));
      for (const c of d.cocuk) for (const [k, v] of topla(c)) set.set(k, v);
      toplam.set(d.id, set); return set;
    };
    topla(dug.kok);
    return { dogrudan, toplam, uyari };
  }

  // ================================================================ çizim
  function ciz(sigdir = false) {
    sekmeleriCiz();
    const dunya = temizle($('#dunya'));
    const m = p();
    panelKapat();
    if (!m) { yer = null; hudCiz(); miniCiz(); return; }
    const v = gorunumler[m.proje.kimlik];
    yer = yerlesim(m, v && !sigdir ? seviye(v.k) : 1);
    if (!yer) { $('#durum-satiri').textContent = 'Durum dosyasında proje düğümü yok.'; return; }
    dunyaCiz(m);
    hudCiz();
    if (v && !sigdir) Object.assign(gorunum, v); else Object.assign(gorunum, baslangic());
    uygula();
  }

  function dunyaCiz(m) {
    const dunya = temizle($('#dunya'));
    yer.bag = bagla(m, yer);
    const ilerleme = m.katmanlar.ilerleme;

    const dallar = s('g'), devler = s('g'), kartlar = s('g');
    for (const d of yer.dug.values()) {
      // sütun içi bağ: üst kartın sol kenarından aşağı inen ray, çocuğa kısa yatay giriş
      if (d.ust && yer.dug.has(d.ust) && d.ust !== yer.kok.id) {
        const u = yer.dug.get(d.ust);
        const rx = u.x + 10, y1 = u.y + u.h, y2 = d.y + Math.min(d.h / 2, 30), x2 = d.x - 3;
        const surer = ilerleme.paketler[d.id] && ilerleme.paketler[d.id].durum === 'suruyor';
        dallar.appendChild(s('g', { class: d.derinlik >= 2 ? `k${d.derinlik}` : null },
          s('path', { class: `dal ray${surer ? ' surer' : ''}${d.tur === 'dosya' ? ' d4' : ''}`, d: `M${rx} ${y1} V${y2} H${x2}`, 'marker-end': `url(#${surer ? 'ok-surer' : 'ok'})` })));
      }
      if (d.tur === 'asama' || d.tur === 'alan') {
        const o = ilerleme.ozet[d.id];
        devler.appendChild(s('g', { class: 'dev' }, s('text', { x: d.x, y: d.y - 34 },
          kisalt(d.tur === 'asama' ? d.id.slice(6) : d.id.slice(5), 8), s('tspan', { class: 'dev-ek' }, o ? `  ${o.paket_sayisi} paket` : ''))));
      }
      kartlar.appendChild(kart(d, m));
    }
    const akis = s('g');
    const zincir = [yer.kok, ...yer.asamalar];
    for (let i = 1; i < zincir.length; i++) {
      const a = zincir[i - 1], b = zincir[i], y = b.y + b.h / 2;
      akis.appendChild(s('path', { class: 'akis-ok', d: `M${a.x + a.w} ${y} H${b.x - 4}`, 'marker-end': 'url(#ok)' }));
    }
    for (const b of yer.bantlar) {
      if (b.cizgi) akis.appendChild(s('path', { class: 'bant-cizgi', d: `M-40 ${b.y - 120} H${yer.sag + 40}` }));
      akis.appendChild(s('text', { class: `bant-ad${b.kucuk ? ' kucuk' : ''}`, x: b.x, y: b.y - 50 }, b.ad));
    }
    ekle(dunya, [akis, dallar, devler, kartlar]);
    katmanSiniflari();
    miniCiz();
    if (secili) { const g = document.querySelector(`.dugum[data-id="${CSS.escape(secili)}"]`); if (g) g.classList.add('secili'); }
  }

  // Düzey değişince yeniden yerleştir; çapa düğüm ekrandaki yerinde kalır.
  function yenidenYerlestir(L, capaId, odakNokta) {
    const m = p(); if (!m || !yer) return;
    const k = gorunum.k, o = odakNokta || { x: W() / 2, y: H() / 2 };
    let capa = capaId ? yer.dug.get(capaId) : null;
    if (!capa) {
      let en = Infinity;
      for (const d of yer.dug.values()) {
        if (d.derinlik > yer.L) continue;
        const dx = (d.x + d.w / 2) * k + gorunum.x - o.x, dy = (d.y + d.h / 2) * k + gorunum.y - o.y, u = dx * dx + dy * dy;
        if (u < en) { en = u; capa = d; }
      }
    }
    const once = capa ? { x: capa.x, y: capa.y } : null, id = capa && capa.id;
    yer = yerlesim(m, L);
    if (!yer) return;
    dunyaCiz(m);
    const sonra = id && yer.dug.get(id);
    if (once && sonra) { gorunum.x += (once.x - sonra.x) * k; gorunum.y += (once.y - sonra.y) * k; }
  }

  function kart(d, m) {
    const g = s('g', { class: `dugum t-${d.tur}`, 'data-id': d.id, transform: `translate(${d.x},${d.y})`, role: 'button' });
    if (d.derinlik >= 2) g.classList.add(`k${d.derinlik}`);
    const { w, hh = d.h } = { w: d.w, hh: d.h };
    if (d.tur === 'dosya') {
      ekle(g, [s('rect', { class: 'cerceve', width: w, height: hh }),
        s('text', { class: 'd-yol', x: 10, y: 18 }, kisalt(d.ad.length > 28 ? '…' + d.ad.slice(-27) : d.ad, 29)),
        s('text', { class: 'd-sil', x: w - 8, y: 18, 'text-anchor': 'end' }, `−${d.dosya.sil}`),
        s('text', { class: 'd-ekle', x: w - 48, y: 18, 'text-anchor': 'end' }, `+${d.dosya.ekle}`)]);
      g.classList.add('dosya');
      return g;
    }
    const c = 16;
    ekle(g, [s('path', { class: 'cerceve', d: `M0 0 H${w - c} L${w} ${c} V${hh} H0 Z` }),
      s('path', { class: 'cerceve2', d: `M5 5 H${w - c - 2} L${w - 5} ${c + 2} V${hh - 5} H5 Z` })]);
    const kay = m.katmanlar.ilerleme.paketler[d.id];
    const oz2 = m.katmanlar.ilerleme.ozet[d.id];
    let ust = TUR[d.tur];
    if (d.tur === 'proje') ust += ` · ${m.proje.kimlik}`;
    if (d.tur === 'asama') { ust += ` · ${d.id.slice(6)}`; g.classList.add(d.asama_durumu || 'bekliyor'); if (d.asama_durumu === 'aktif') ust += ' · AKTİF'; }
    if (d.tur === 'bilesen') ust += ` · ${d.id.slice(8)}`;
    if (d.tur === 'alan') ust += ` · ${d.id.slice(5)}`;
    if (d.tur === 'ip') {
      ust += ` · ${d.id.slice(3)}`;
      if (kay) { g.classList.add(`d-${kay.durum}`); ust += ` · ${DURUM[kay.durum].toUpperCase()}`; } else { g.classList.add('d-kayitsiz'); ust += ' · KAYIT YOK'; }
      if (d.onay === 'onay_bekliyor') ust += ' · ONAY BEKLİYOR';
    }
    const adY = d.tur === 'proje' ? 58 : d.tur === 'asama' ? 54 : d.tur === 'ip' ? 40 : 48;
    const adN = d.tur === 'proje' ? 24 : d.tur === 'asama' ? 28 : d.tur === 'ip' ? 32 : 32;
    ekle(g, [s('text', { class: 'd-ust', x: 16, y: 22 }, kisalt(ust, Math.floor(w / 7))),
      s('text', { class: 'd-ad', x: 16, y: adY }, kisalt(d.ad, adN))]);
    if (d.tur === 'bilesen') {
      const yer2 = d.repo ? `${d.repo.split('/')[1]}${d.klasor ? ' · ' + d.klasor : ''}` : 'kod deposu yok';
      g.appendChild(s('text', { class: 'd-alt d-yer', x: 16, y: 68 }, kisalt(yer2, 40)));
    }

    if (d.tur === 'ip') {
      const dg = s('g', { class: 'dilimler' });
      const gen = (w - 32 - 7 * 3) / 8;
      for (let i = 0; i < 8; i++) dg.appendChild(s('rect', { class: `dilim${kay && i <= kay.evre ? ' dolu' : ''}`, x: 16 + i * (gen + 3), y: hh - 18, width: gen, height: 5 }));
      ekle(g, [dg, s('text', { class: 'd-alt d-yakin', x: 16, y: hh - 25 }, kay ? `Evre ${kay.evre} · ${EVRE[kay.evre]}` : 'İlerleme kaydı yok')]);
    } else if (oz2) {
      const cg = s('g', { class: 'cubuklar' });
      const enb = Math.max(1, ...oz2.evre_dagilimi);
      const bx = w - 16 - 8 * 9, by = hh - 14;
      oz2.evre_dagilimi.forEach((n, i) => {
        cg.appendChild(s('rect', { class: 'cubuk-zemin', x: bx + i * 9, y: by - 26, width: 6, height: 26 }));
        if (n) cg.appendChild(s('rect', { class: 'cubuk', x: bx + i * 9, y: by - 26 * n / enb, width: 6, height: 26 * n / enb }));
      });
      const dd = Object.entries(oz2.durum_dagilimi).map(([k, n]) => `${n} ${DURUM[k].toLowerCase()}`).join(', ');
      ekle(g, [cg, s('text', { class: 'd-alt', x: 16, y: hh - 14 }, kisalt(`${oz2.paket_sayisi} paket${dd ? ' · ' + dd : ''}`, Math.floor((w - 100) / 6.3)))]);
    }
    // bulgu rozeti (alt düğümler dahil açık bulgular)
    const bul = yer.bag.toplam.get(d.id);
    if (bul && bul.size) {
      const en = SEVIYE_SIRA.find((sv) => [...bul.values()].some((b) => b.seviye === sv)) || 'bilgi';
      g.appendChild(s('g', { class: 'rozet', transform: `translate(${w - 34},${hh})` },
        s('circle', { class: `s-${en}`, r: 12 }), s('text', { y: 4 }, String(bul.size))));
    }
    const uy = (yer.bag.uyari.get(d.id) || []).filter((u) => u.kod !== 'ilerleme_kaydi_yok');
    if (uy.length) {
      g.appendChild(s('g', { class: 'ucgen-g', transform: `translate(${w - 64},${hh})` },
        s('path', { class: 'ucgen', d: 'M0 -12 L11 8 L-11 8 Z' }), s('text', { class: 'ucgen-t', y: 6 }, '!')));
    }
    return g;
  }

  function katmanSiniflari() {
    const sahne = $('#sahne');
    sahne.classList.toggle('gizle-ilerleme', !katman.ilerleme);
    sahne.classList.toggle('gizle-denetim', !katman.denetim);
    sahne.classList.toggle('gizle-uyari', !katman.uyari);
  }

  // ================================================================ HUD
  function sekmeleriCiz() {
    const nav = temizle($('#sekmeler'));
    projeler.forEach((m, i) => {
      const o = m.katmanlar.ilerleme.ozet[m.aktif_asama] || m.katmanlar.ilerleme.ozet[`proje:${m.proje.kimlik}`];
      const engelli = o && o.durum_dagilimi.engelli;
      const b = h('button', { class: `sekme${i === etkin ? ' etkin' : ''}`, type: 'button', title: m.proje.ad },
        h('span', { class: 'nokta' }), h('span', { class: 'ad' }, m.proje.ad),
        h('span', { class: 'ek' }, o ? `${o.paket_sayisi} paket${engelli ? ` · ${engelli} engelli` : ''}` : ''));
      if (engelli) b.querySelector('.nokta').style.background = 'var(--engel)';
      else if (o && o.durum_dagilimi.suruyor) b.querySelector('.nokta').style.background = 'var(--surer)';
      b.addEventListener('click', () => sekmeSec(i));
      nav.appendChild(b);
    });
  }
  function sekmeSec(i) {
    if (i === etkin) return;
    if (p()) gorunumler[p().proje.kimlik] = { ...gorunum };
    etkin = i; ciz();
  }

  function hudCiz() {
    const m = p();
    $('#m-kicker').textContent = m ? `${m.proje.kimlik.toUpperCase()} · MASA` : 'MASA';
    $('#m-baslik').textContent = m ? m.proje.ad : 'Proje yok';
    const genel = m ? m.katmanlar.uyarilar.filter((u) => !u.dugum) : [];
    $('#m-alt').textContent = m ? (genel.length ? `${genel.length} genel uyarı: ${kisalt(genel[0].mesaj, 80)}` :
      `Kaynaklar: ${m.kaynaklar.map((k) => `${k.repo.split('/')[1]}@${(k.sha || '?').slice(0, 7)}`).join(' · ')}`) : '';
    const asama = m && m.aktif_asama && m.dugumler.find((d) => d.id === m.aktif_asama);
    $('#a-proje').textContent = m ? m.proje.kimlik : '—';
    $('#a-asama').textContent = asama ? `${asama.id.slice(6)} · ${kisalt(asama.ad, 28)}` : '—';
    $('#a-zaman').textContent = m ? tarih(m.uretim.zaman) : '—';

    const der = temizle($('#derinlik'));
    der.appendChild(h('div', { class: 'kutu-baslik' }, 'DERİNLİK'));
    ['Proje', 'Aşama · iş alanı', 'Bileşen', 'İş paketi', 'Dosya'].forEach((ad, i) => {
      const b = h('button', { class: 'satir-dugme', type: 'button', 'data-l': i }, h('i'), ad);
      b.addEventListener('click', () => duzeyeGit(i));
      der.appendChild(b);
    });
    const kat = temizle($('#katmanlar'));
    kat.appendChild(h('div', { class: 'kutu-baslik' }, 'KATMANLAR'));
    [['ilerleme', 'İlerleme'], ['denetim', 'Denetim bulguları'], ['uyari', 'Uyarılar']].forEach(([k, ad]) => {
      const b = h('button', { class: `satir-dugme${katman[k] ? ' acik' : ''}`, type: 'button', 'aria-pressed': String(katman[k]) }, h('i'), ad);
      b.addEventListener('click', () => { katman[k] = !katman[k]; katmanSiniflari(); hudCiz(); });
      kat.appendChild(b);
    });
    derinlikIsaretle();
  }
  function derinlikIsaretle() {
    const l = ESIK.filter((e) => gorunum.k >= e).length - 1;
    document.querySelectorAll('#derinlik .satir-dugme').forEach((b, i) => b.classList.toggle('acik', i <= l));
  }

  // ================================================================ görünüm (pan / zoom / pinch)
  const tuval = $('#tuval'), dunya = $('#dunya'), sahne = $('#sahne');
  const gorunum = { x: 0, y: 0, k: 1 };
  const KMIN = 0.08, KMAX = 4;
  const sinir = (v, a, b) => Math.max(a, Math.min(b, v));
  const W = () => tuval.clientWidth, H = () => tuval.clientHeight;
  let anim = null;

  let animde = false, odak = null;
  function uygula() {
    if (yer && !animde && seviye(gorunum.k) !== yer.L) yenidenYerlestir(seviye(gorunum.k), null, odak);
    uygulaDonusum();
  }
  function uygulaDonusum() {
    const { x, y, k } = gorunum;
    dunya.setAttribute('transform', `translate(${x},${y}) scale(${k})`);
    tuval.style.setProperty('--kucuk', `${20 * k}px`);
    tuval.style.setProperty('--buyuk', `${100 * k}px`);
    tuval.style.setProperty('--ox', `${x}px`);
    tuval.style.setProperty('--oy', `${y}px`);
    tuval.style.setProperty('--ince', 20 * k < 7 ? '0' : '.07');
    for (const d of [2, 3, 4]) sahne.classList.toggle(`goster-${d}`, k >= ESIK[d]);
    sahne.classList.toggle('yakin', k >= 0.9);
    $('#z-oran').textContent = `${Math.round(k * 100)}%`;
    $('#a-olcek').textContent = `1:${(1 / k).toFixed(2)}`;
    derinlikIsaretle();
    miniGorus();
  }
  function zoomNokta(px, py, f) {
    const k2 = sinir(gorunum.k * f, KMIN, KMAX), r = k2 / gorunum.k;
    gorunum.x = px - (px - gorunum.x) * r; gorunum.y = py - (py - gorunum.y) * r; gorunum.k = k2;
    odak = { x: px, y: py }; uygula(); odak = null;
  }
  function git(h2, sure = 420) {
    cancelAnimationFrame(anim); animde = false;
    animde = true;
    const b = { ...gorunum }, t0 = performance.now();
    const ad = (n) => { const u = Math.min(1, (n - t0) / sure), e = 1 - (1 - u) ** 3;
      gorunum.x = b.x + (h2.x - b.x) * e; gorunum.y = b.y + (h2.y - b.y) * e; gorunum.k = b.k + (h2.k - b.k) * e; uygula();
      if (u < 1) anim = requestAnimationFrame(ad); else { animde = false; uygula(); } };
    anim = requestAnimationFrame(ad);
  }
  function sigdir(r, pay = 60, kmax = KMAX) {
    const ust = innerWidth > 860 ? 110 : 70;
    const k = sinir(Math.min((W() - pay * 2) / r.w, (H() - ust - pay) / r.h), KMIN, kmax);
    return { k, x: (W() - r.w * k) / 2 - r.x * k, y: ust + (H() - ust - r.h * k) / 2 - r.y * k };
  }
  function baslangic() {
    if (!yer) return { x: 0, y: 0, k: 1 };
    const g = [...yer.dug.values()].filter((d) => d.derinlik <= 1);
    const y0 = Math.min(...g.map((d) => d.y)), y1 = Math.max(...g.map((d) => d.y + d.h));
    // açılış: iki bant birlikte, bileşen düzeyinin hemen altında (yerleşim sıkı kalsın)
    return sigdir({ x: -40, y: y0 - 190, w: yer.sag + 80, h: y1 - y0 + 230 }, 40, ESIK[2] * 0.97);
  }
  function duzeyeGit(l) {
    const k = Math.max(ESIK[l] * 1.15, 0.2), cx = W() / 2, cy = H() / 2, r = k / gorunum.k;
    git({ k, x: cx - (cx - gorunum.x) * r, y: cy - (cy - gorunum.y) * r }, 380);
  }
  const yerel = (e) => { const r = tuval.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
  const dunyaya = (px, py) => ({ x: (px - gorunum.x) / gorunum.k, y: (py - gorunum.y) / gorunum.k });

  tuval.addEventListener('wheel', (e) => {
    e.preventDefault(); cancelAnimationFrame(anim); animde = false;
    if (e.shiftKey) { gorunum.x -= e.deltaY; uygula(); return; }
    const q = yerel(e); zoomNokta(q.x, q.y, Math.exp(-e.deltaY * (e.ctrlKey ? 0.012 : 0.0018)));
  }, { passive: false });

  const isaret = new Map(); let surukle = null, sikistir = null, hareket = 0;
  tuval.addEventListener('pointerdown', (e) => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    cancelAnimationFrame(anim); animde = false; tuval.setPointerCapture(e.pointerId); isaret.set(e.pointerId, yerel(e));
    if (isaret.size === 1) { surukle = { ...yerel(e), gx: gorunum.x, gy: gorunum.y }; hareket = 0; tuval.classList.add('surukle'); }
    if (isaret.size === 2) { const [a, b] = [...isaret.values()]; sikistir = { d: Math.hypot(a.x - b.x, a.y - b.y), mx: (a.x + b.x) / 2, my: (a.y + b.y) / 2, g: { ...gorunum } }; surukle = null; hareket = 99; }
  });
  tuval.addEventListener('pointermove', (e) => {
    const q = yerel(e), w = dunyaya(q.x, q.y);
    $('#koordinat').textContent = `X ${String(Math.round(w.x)).padStart(4, '0')} · Y ${String(Math.round(w.y)).padStart(4, '0')}`;
    if (!isaret.has(e.pointerId)) return;
    isaret.set(e.pointerId, q);
    if (sikistir && isaret.size >= 2) {
      const [a, b] = [...isaret.values()], d = Math.hypot(a.x - b.x, a.y - b.y), mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const k2 = sinir(sikistir.g.k * d / sikistir.d, KMIN, KMAX), r = k2 / sikistir.g.k;
      gorunum.k = k2; gorunum.x = mx - (sikistir.mx - sikistir.g.x) * r; gorunum.y = my - (sikistir.my - sikistir.g.y) * r; uygula();
    } else if (surukle) {
      const dx = q.x - surukle.x, dy = q.y - surukle.y; hareket = Math.max(hareket, Math.hypot(dx, dy));
      gorunum.x = surukle.gx + dx; gorunum.y = surukle.gy + dy; uygula();
    }
  });
  const birak = (e) => {
    const tik = surukle && hareket < 5 && isaret.size === 1;
    isaret.delete(e.pointerId); if (isaret.size < 2) sikistir = null;
    if (!isaret.size) { surukle = null; tuval.classList.remove('surukle'); }
    if (tik && e.type === 'pointerup') {
      const n = document.elementFromPoint(e.clientX, e.clientY);
      const g = n && n.closest('.dugum');
      if (g) panelAc(g.getAttribute('data-id')); else panelKapat();
    }
  };
  tuval.addEventListener('pointerup', birak); tuval.addEventListener('pointercancel', birak);
  tuval.addEventListener('dblclick', (e) => {
    // İşaretçi yakalandığı için olayın hedefi tuvaldir; düğüm, imlecin altındaki öğeden bulunur.
    const altta = document.elementFromPoint(e.clientX, e.clientY);
    const g = altta && altta.closest('.dugum');
    if (g && yer) {
      let d = yer.dug.get(g.getAttribute('data-id')); if (!d) return;
      const hedefL = Math.min(d.derinlik + 1, 4);
      if (hedefL > yer.L) { yenidenYerlestir(hedefL, d.id); d = yer.dug.get(d.id); uygulaDonusum(); }
      const alt = []; (function dolas(x) { alt.push(x); x.cocuk.forEach(dolas); })(d);
      const sinirDer = Math.min(d.derinlik + 1, 4), gor = alt.filter((x) => x.derinlik <= sinirDer);
      const x0 = Math.min(...gor.map((x) => x.x)), x1 = Math.max(...gor.map((x) => x.x + x.w));
      const y0 = Math.min(...gor.map((x) => x.y)), y1 = Math.max(...gor.map((x) => x.y + x.h));
      const t = sigdir({ x: x0 - 40, y: y0 - 40, w: x1 - x0 + 80, h: y1 - y0 + 80 }, 50, 2.2);
      t.k = Math.max(t.k, ESIK[sinirDer] * 1.1);
      const ust = innerWidth > 860 ? 110 : 70;
      t.x = W() / 2 - (x0 + x1) / 2 * t.k; t.y = ust + (H() - ust) / 2 - (y0 + y1) / 2 * t.k;
      git(t);
    } else { const q = yerel(e), k2 = sinir(gorunum.k * 1.8, KMIN, KMAX), r = k2 / gorunum.k; git({ k: k2, x: q.x - (q.x - gorunum.x) * r, y: q.y - (q.y - gorunum.y) * r }, 300); }
  });
  document.addEventListener('gesturestart', (e) => e.preventDefault());

  const merkezZoom = (f) => { const cx = W() / 2, cy = H() / 2, k2 = sinir(gorunum.k * f, KMIN, KMAX), r = k2 / gorunum.k; git({ k: k2, x: cx - (cx - gorunum.x) * r, y: cy - (cy - gorunum.y) * r }, 250); };
  $('#z-art').addEventListener('click', () => merkezZoom(1.4));
  $('#z-azal').addEventListener('click', () => merkezZoom(1 / 1.4));
  $('#z-oran').addEventListener('click', () => merkezZoom(1 / gorunum.k));
  const genel = () => { if (!yer) return; animde = true; if (yer.L !== 1) { yenidenYerlestir(1); uygulaDonusum(); } git(baslangic()); };
  $('#z-sigdir').addEventListener('click', genel);
  addEventListener('keydown', (e) => {
    if ($('#masa').hidden || e.target.closest('input')) return;
    if (e.key === '+' || e.key === '=') merkezZoom(1.3);
    else if (e.key === '-') merkezZoom(1 / 1.3);
    else if (e.key === '0') genel();
    else if (e.key === 'Escape') panelKapat();
  });
  addEventListener('resize', miniGorus);

  // ================================================================ mini harita
  const mini = $('#mini');
  function miniCiz() {
    temizle(mini);
    if (!yer) return;
    const k = yer.kutu;
    oz(mini, { viewBox: `${k.x} ${k.y} ${k.w} ${k.h}`, preserveAspectRatio: 'xMidYMid meet' });
    const m = p();
    for (const d of yer.dug.values()) {
      const kay = m.katmanlar.ilerleme.paketler[d.id];
      const r = s('rect', { x: d.x, y: d.y, width: d.w, height: d.h });
      r.style.fill = d.tur === 'dosya' ? 'rgba(156,195,240,.25)' : kay ? `var(--${{ bekliyor: 'bekler', suruyor: 'surer', engelli: 'engel', bitti: 'bitti', vazgecildi: 'vazgec' }[kay.durum]})` : d.tur === 'proje' ? 'var(--vurgu)' : 'rgba(156,195,240,.45)';
      mini.appendChild(r);
    }
    mini.appendChild(s('rect', { class: 'vp', id: 'mini-gorus' }));
    miniGorus();
  }
  function miniGorus() {
    const r = document.getElementById('mini-gorus'); if (!r) return;
    const a = dunyaya(0, 0), b = dunyaya(W(), H());
    oz(r, { x: a.x, y: a.y, width: b.x - a.x, height: b.y - a.y });
  }
  let miniSurukle = false;
  const miniGit = (e) => { const q = mini.createSVGPoint(); q.x = e.clientX; q.y = e.clientY; const w = q.matrixTransform(mini.getScreenCTM().inverse()); gorunum.x = W() / 2 - w.x * gorunum.k; gorunum.y = H() / 2 - w.y * gorunum.k; uygula(); };
  mini.addEventListener('pointerdown', (e) => { e.stopPropagation(); cancelAnimationFrame(anim); animde = false; miniSurukle = true; mini.setPointerCapture(e.pointerId); miniGit(e); });
  mini.addEventListener('pointermove', (e) => miniSurukle && miniGit(e));
  mini.addEventListener('pointerup', () => { miniSurukle = false; });

  // ================================================================ detay paneli
  const satir = (ad, ...deger) => h('div', { class: 'satir' }, h('span', {}, ad), h('span', {}, ...deger));
  function panelAc(id) {
    const m = p(); const d = yer && yer.dug.get(id); if (!d) return;
    secili = id;
    document.querySelectorAll('.dugum.secili').forEach((x) => x.classList.remove('secili'));
    const g = document.querySelector(`.dugum[data-id="${CSS.escape(id)}"]`); if (g) g.classList.add('secili');
    const panel = temizle($('#panel'));
    const kapat = h('button', { class: 'kapat', type: 'button', title: 'Kapat' }, '×');
    kapat.addEventListener('click', panelKapat);
    ekle(panel, [kapat, h('div', { class: 'kicker' }, TUR[d.tur]), h('h2', {}, d.ad)]);

    if (d.tur === 'dosya') {
      ekle(panel, [satir('Eklenen satır', `+${d.dosya.ekle}`), satir('Silinen satır', `−${d.dosya.sil}`),
        satir('Commit', d.dosya.commit.slice(0, 7)), satir('Zaman', tarih(d.dosya.zaman)),
        satir('Kaynak', ghBag({ repo: d.dosya.repo, yol: d.dosya.yol }) || d.dosya.yol)]);
    } else {
      const kay = m.katmanlar.ilerleme.paketler[id], oz2 = m.katmanlar.ilerleme.ozet[id];
      if (kay) {
        const serit = h('div', { class: 'evre-seridi' }); for (let i = 0; i < 8; i++) serit.appendChild(h('span', { class: i <= kay.evre ? 'dolu' : '' }));
        ekle(panel, [serit, satir('Evre', `${kay.evre} · ${EVRE[kay.evre]}`), satir('Durum', DURUM[kay.durum]),
          satir('Kayıt zamanı', tarih(kay.guncelleme))]);
        if (kay.engel) ekle(panel, [h('h3', {}, 'ENGEL'), h('p', {}, kay.engel)]);
        if (kay.not) ekle(panel, [h('h3', {}, 'NOT'), h('p', {}, kay.not)]);
        panel.appendChild(satir('Kayıt', ghBag(kay.kaynak) || '—'));
      } else if (d.tur === 'ip') {
        panel.appendChild(h('p', { class: 'soluk' }, 'Bu iş paketi için ilerleme kaydı yok.'));
      }
      if (oz2) {
        ekle(panel, [satir('İş paketi', String(oz2.paket_sayisi)),
          satir('Evre dağılımı', oz2.evre_dagilimi.map((n, i) => n ? `${EVRE[i]} ${n}` : null).filter(Boolean).join(', ') || '—'),
          satir('Durum', Object.entries(oz2.durum_dagilimi).map(([k, n]) => `${DURUM[k]} ${n}`).join(', ') || '—')]);
        if (oz2.en_geri_evre !== null) panel.appendChild(satir('En geri evre', `${oz2.en_geri_evre} · ${EVRE[oz2.en_geri_evre]}`));
      }
      if (d.dayanak && d.dayanak.length) panel.appendChild(satir('Dayanak', d.dayanak.join(', ')));
      if (d.tur === 'bilesen') panel.appendChild(satir('Yerleşim', d.repo ? `${d.repo}${d.klasor ? ' · ' + d.klasor : ''}` : 'Kod deposu yok (ilerleme karar deposunda)'));
      if (d.tur === 'asama') panel.appendChild(satir('Aşama durumu', { aktif: 'Aktif', bekliyor: 'Bekliyor', tamamlandi: 'Tamamlandı' }[d.asama_durumu] || '—'));
      if (d.onay === 'onay_bekliyor') panel.appendChild(satir('Onay', 'Bekliyor'));
      if (d.kaynak) panel.appendChild(satir('Tanım', ghBag(d.kaynak) || '—'));

      const dogrudan = (yer.bag.dogrudan.get(id) || []);
      const altta = [...(yer.bag.toplam.get(id) || new Map()).values()].filter((b) => !dogrudan.includes(b));
      const liste = (baslik, bl) => {
        if (!bl.length) return;
        panel.appendChild(h('h3', {}, baslik));
        const ul = h('ul');
        for (const b of [...bl].sort((x, y) => SEVIYE_SIRA.indexOf(x.seviye) - SEVIYE_SIRA.indexOf(y.seviye))) {
          ul.appendChild(h('li', {}, h('span', { class: `etiket e-${b.seviye}` }, SEVIYE[b.seviye]), `${b.no} · ${b.baslik}`,
            h('span', { class: 'soluk' }, ` — ${BDURUM[b.durum]}${b.kapi ? ' · kapı: ' + b.kapi : ''}`)));
        }
        panel.appendChild(ul);
      };
      liste('BULGULAR', dogrudan);
      liste('ALT DALLARDAKİ AÇIK BULGULAR', altta);
      const uy = yer.bag.uyari.get(id) || [];
      if (uy.length) { panel.appendChild(h('h3', {}, 'UYARILAR')); panel.appendChild(h('ul', {}, uy.map((u) => h('li', {}, u.mesaj)))); }
      if (d.tur === 'proje') {
        const genel = m.katmanlar.uyarilar.filter((u) => !u.dugum);
        if (genel.length) { panel.appendChild(h('h3', {}, 'GENEL UYARILAR')); panel.appendChild(h('ul', {}, genel.map((u) => h('li', {}, u.mesaj)))); }
        panel.appendChild(h('h3', {}, 'KAYNAKLAR'));
        panel.appendChild(h('ul', {}, m.kaynaklar.map((k) => h('li', {}, `${k.repo} · ${k.durum === 'okundu' ? (k.sha || '').slice(0, 7) : 'okunamadı: ' + (k.hata || '')}`))));
        const rap = m.katmanlar.denetim.son_raporlar || [];
        if (rap.length) { panel.appendChild(h('h3', {}, 'SON DENETİM RAPORLARI')); panel.appendChild(h('ul', {}, rap.map((r) => h('li', {}, `${r.tur} · ${r.tarih} · `, ghBag(r.kaynak) || '')))); }
      }
      const dosyalar = d.cocuk.filter((c) => c.tur === 'dosya');
      if (dosyalar.length) { panel.appendChild(h('h3', {}, 'DOSYALAR')); panel.appendChild(h('ul', {}, dosyalar.map((f) => h('li', {}, `${f.ad} +${f.dosya.ekle} −${f.dosya.sil}`)))); }
    }
    panel.classList.add('acik');
  }
  function panelKapat() {
    secili = null; $('#panel').classList.remove('acik');
    document.querySelectorAll('.dugum.secili').forEach((x) => x.classList.remove('secili'));
  }

  // ================================================================ düğmeler ve başlangıç
  $('#guncelle').addEventListener('click', async () => {
    const b = $('#guncelle'), satirE = $('#durum-satiri');
    if (b.disabled) return;
    b.disabled = true; b.classList.add('mesgul');
    try {
      await toplamaBaslat((t) => { satirE.textContent = t; });
      if (p()) gorunumler[p().proje.kimlik] = { ...gorunum };
      await yenidenYukle();
      satirE.textContent = `Güncellendi · ${tarih(new Date().toISOString())}`;
    } catch (e) { satirE.textContent = e.message; }
    b.disabled = false; b.classList.remove('mesgul');
  });
  $('#kilitle').addEventListener('click', kilitle);
  $('#kurulum').addEventListener('submit', kurulumGonder);
  $('#kilit').addEventListener('submit', kilitGonder);
  $('#anahtar-sil').addEventListener('click', () => { kasaSil(); oturum = null; kapiGoster('kurulum'); });

  if (!window.isSecureContext || !crypto.subtle) {
    kapiGoster('kurulum', 'Bu sayfa güvenli bağlantı (https) gerektirir.');
    $('#kurulum').hidden = true;
  } else {
    kapiGoster(kasaOku() ? 'kilit' : 'kurulum');
  }
})();
