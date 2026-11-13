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
  const GUVENLI_OZ = /^(class|id|type|title|role|aria-[a-z-]+|x|y|x1|x2|y1|y2|cx|cy|r|width|height|d|points|transform|viewBox|preserveAspectRatio|text-anchor|marker-end|data-[a-z-]+|disabled|target|rel|tabindex|rx|dx)$/;

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
  const TUR = { proje: 'PROJE', asama: 'AŞAMA', alan: 'İŞ ALANI', bilesen: 'BİLEŞEN', modul: 'MODÜL', ip: 'İŞ PAKETİ', dosya: 'DOSYA' };

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

  // ================================================================ yerleşim: örümcek ağı
  // Merkezde proje. Aşamalar saat yönünde 1a → 1b → …, ardından iş alanları. En kalabalık aşamanın
  // ortası doğuya bakar; dalları (bileşen, modül) dış halkada. İş paketi ve dosya tuvalde çizilmez,
  // liste kartında ve yan panelde görünür.
  const R1 = 270, R2 = 500;
  const SIRA = { bitti: 0, suruyor: 1, engelli: 2, bekliyor: 3, yok: 4, vazgecildi: 5 };
  const ISARET = { bitti: '✓', suruyor: '▶', engelli: '■', bekliyor: '○', yok: '·', vazgecildi: '–' };
  function paketDurumu(m, id) {
    const k = m.katmanlar.ilerleme.paketler[id];
    if (!k) return 'yok';
    return k.durum === 'bitti' || (k.evre >= 5 && k.durum !== 'vazgecildi') ? 'bitti' : k.durum;
  }
  const paketleri = (d) => { const o = []; (function gez(x) { for (const c of x.cocuk) { if (c.tur === 'ip') o.push(c); else if (c.tur !== 'dosya') gez(c); } })(d); return o; };
  function sayim(m, d) {
    const s = { bitti: 0, suruyor: 0, engelli: 0, bekliyor: 0, yok: 0 };
    for (const ip of paketleri(d)) { const du = paketDurumu(m, ip.id); if (du in s) s[du]++; }
    return s;
  }

  function yerlesim(m) {
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
    const dal = (d) => d.cocuk.filter((c) => c.tur === 'bilesen' || c.tur === 'modul');
    const asamalar = kok.cocuk.filter((c) => c.tur === 'asama');
    const alanlar = kok.cocuk.filter((c) => c.tur === 'alan');
    const ortak = kok.cocuk.filter((c) => c.tur === 'bilesen' || c.tur === 'modul');
    const dilim = [
      ...asamalar.map((a) => ({ d: a, w: dal(a).length ? Math.max(3, dal(a).length) : 3.6 })),
      ...(ortak.length ? [{ ortak, w: Math.max(2.2, ortak.length) }] : []),
      ...(alanlar.length ? [{ ayrac: true, w: 1 }] : []),
      ...alanlar.map((a) => ({ d: a, w: 2.4 })),
    ];
    const top = dilim.reduce((t, x) => t + x.w, 0) || 1;
    const nokta = (r, a) => [r * Math.cos(a), r * Math.sin(a)];
    const yerlestir = (d, r, a) => { [d.ax, d.ay] = nokta(r, a); d.aci = a; d.konumlu = true; };
    kok.ax = 0; kok.ay = 0; kok.konumlu = true;
    let aci = dilim.length ? -(dilim[0].w / top) * Math.PI : 0;
    let alanSira = 0;
    for (const s2 of dilim) {
      const a0 = aci, a1 = aci + (s2.w / top) * 2 * Math.PI, am = (a0 + a1) / 2; aci = a1;
      if (s2.ayrac) continue;
      const kollar = s2.ortak || dal(s2.d);
      // planlanmamış aşama kutusu biraz dışarıda; iş alanları sırayla iki halkada (etiketler çakışmasın)
      if (s2.d) yerlestir(s2.d, s2.d.tur === 'asama' && !kollar.length ? R1 + 70 : s2.d.tur === 'alan' ? R1 + (alanSira++ % 2) * 90 : R1, am);
      kollar.forEach((c, i) => yerlestir(c, R2, a0 + ((i + 0.5) / kollar.length) * (a1 - a0)));
    }
    const k = [...dug.values()].filter((d) => d.konumlu);
    const x0 = Math.min(...k.map((d) => d.ax)) - 380, x1 = Math.max(...k.map((d) => d.ax)) + 460;
    const y0 = Math.min(...k.map((d) => d.ay)) - 110, y1 = Math.max(...k.map((d) => d.ay)) + 110;
    return { dug, kok, asamalar, alanlar, ortak, dal, kutu: { x: x0, y: y0, w: x1 - x0, h: y1 - y0 } };
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
    temizle($('#dunya'));
    const m = p();
    panelKapat(); listeKapat();
    if (!m) { yer = null; hudCiz(); miniCiz(); return; }
    const v = gorunumler[m.proje.kimlik];
    yer = yerlesim(m);
    if (!yer) { $('#durum-satiri').textContent = 'Durum dosyasında proje düğümü yok.'; return; }
    dunyaCiz(m);
    hudCiz();
    if (v && !sigdir) Object.assign(gorunum, v); else Object.assign(gorunum, baslangic());
    uygula();
  }

  // sayım satırı: ✓ ▶ ■ ○ · ; sıfır olanlar (bitti hariç) yazılmaz
  function sayimYaz(m, d, attrs) {
    const sy = sayim(m, d), t = s('text', { class: 'sayim', ...attrs });
    let ilk = true;
    for (const k of ['bitti', 'suruyor', 'engelli', 'bekliyor', 'yok']) {
      if (!sy[k] && k !== 'bitti') continue;
      t.appendChild(s('tspan', { class: `s-${k}`, dx: ilk ? 0 : 12 }, `${ISARET[k]} ${sy[k]}`)); ilk = false;
    }
    return t;
  }
  // metnin genişliği DOM'a eklendikten sonra ölçülür
  const genislik = (el) => { try { return el.getComputedTextLength() + el.querySelectorAll('tspan').length * 13; } catch { return 0; } };

  function dunyaCiz(m) {
    const dunya = temizle($('#dunya'));
    yer.bag = bagla(m, yer);
    const dallar = s('g'), dugumler = s('g');
    ekle(dunya, [dallar, dugumler]);
    const kok = yer.kok;
    const cizgi = (u, d, egri) => {
      const yol = egri ? (() => { const r = (R1 + R2) / 2; const mx = r * Math.cos(d.aci), my = r * Math.sin(d.aci); return `M${u.ax} ${u.ay} Q${mx} ${my} ${d.ax} ${d.ay}`; })()
        : `M${u.ax} ${u.ay} L${d.ax} ${d.ay}`;
      dallar.appendChild(s('path', { class: `dal${egri ? ' ince' : ''}`, 'data-ust': u.id, 'data-alt': d.id, d: yol }));
    };
    for (const a of [...yer.asamalar, ...yer.alanlar]) cizgi(kok, a, false);
    for (const c of yer.ortak) cizgi(kok, c, false);
    for (const a of yer.asamalar) for (const c of yer.dal(a)) cizgi(a, c, true);

    // merkez
    const mg = s('g', { class: 'dugum t-proje', 'data-id': kok.id, role: 'button', tabindex: '0', 'aria-label': kok.ad });
    const mc = s('circle', { class: 'merkez', cx: 0, cy: 0, r: 96 });
    const mt = s('text', { class: 'merkez-ad', x: 0, y: -14, 'text-anchor': 'middle' }, kisalt(m.proje.kimlik.toUpperCase(), 14));
    const ms = sayimYaz(m, kok, { x: 0, y: 16, 'text-anchor': 'middle' });
    const mp = s('text', { class: 'kapsam-yazi', x: 0, y: 42, 'text-anchor': 'middle' }, `${paketleri(kok).length} paket`);
    ekle(mg, [mc, mt, ms, mp]); dugumler.appendChild(mg);
    mc.setAttribute('r', String(Math.max(96, genislik(ms) / 2 + 22)));
    rozetler(mg, kok, Math.max(96, genislik(ms) / 2 + 22) * 0.72, -70);

    for (const a of yer.asamalar) (yer.dal(a).length ? asamaLevhasi : planlanmamis)(m, a, dugumler);
    for (const c of [...yer.asamalar.flatMap((a) => yer.dal(a)), ...yer.ortak, ...yer.alanlar]) dalDugumu(m, c, dugumler);
    katmanSiniflari();
    miniCiz();
    if (secili) isaretle(secili);
  }

  function asamaLevhasi(m, d, ust) {
    const g = s('g', { class: `dugum t-asama levha ${d.asama_durumu || 'bekliyor'}`, 'data-id': d.id, role: 'button', tabindex: '0', 'aria-label': d.ad });
    const r = s('rect', { class: 'levha-cerceve', rx: 8, height: 62, y: d.ay - 31 });
    const t1 = s('text', { class: 'levha-ad', x: d.ax, y: d.ay - 6, 'text-anchor': 'middle' }, d.ad + (d.asama_durumu === 'aktif' ? ' · aktif' : ''));
    const t2 = sayimYaz(m, d, { x: d.ax, y: d.ay + 20, 'text-anchor': 'middle' });
    ekle(g, [r, t1, t2]); ust.appendChild(g);
    const w = Math.max(genislik(t1), genislik(t2)) + 32;
    oz(r, { x: d.ax - w / 2, width: w });
    rozetler(g, d, d.ax + w / 2 - 4, d.ay - 31);
  }

  // bileşeni olmayan aşama: ağdaki kendi yerinde kesikli kutu, içinde kapsamı
  function planlanmamis(m, d, ust) {
    const satirlar = sar(d.kapsam || '', 30, 2), w = 300, h = 58 + satirlar.length * 22;
    const bx = d.ax - w / 2 + Math.cos(d.aci) * w / 2, by = d.ay - h / 2 + Math.sin(d.aci) * h / 2;
    const g = s('g', { class: 'dugum t-asama planlanmamis', 'data-id': d.id, role: 'button', tabindex: '0', 'aria-label': `${d.ad}: henüz planlanmadı` });
    ekle(g, [s('rect', { class: 'bos-cerceve', x: bx, y: by, width: w, height: h, rx: 8 }),
      s('text', { class: 'levha-ad', x: bx + 16, y: by + 28 }, d.ad),
      s('text', { class: 'bos-yazi', x: bx + w - 16, y: by + 28, 'text-anchor': 'end' }, 'henüz planlanmadı'),
      ...satirlar.map((l, i) => s('text', { class: 'kapsam-yazi', x: bx + 16, y: by + 56 + i * 22 }, l))]);
    ust.appendChild(g);
  }

  // bileşen, modül, iş alanı: halkada nokta, yanında kod · kısa ad ve sayım
  function dalDugumu(m, d, ust) {
    const sagda = Math.cos(d.aci) >= -0.05, an = sagda ? 'start' : 'end', dx = sagda ? 22 : -22;
    const g = s('g', { class: `dugum t-${d.tur}`, 'data-id': d.id, role: 'button', tabindex: '0', 'aria-label': d.ad });
    const kod = d.id.split(':')[1];
    const t1 = s('text', { class: 'dal-ad', x: d.ax + dx, y: d.ay - 2, 'text-anchor': an }, `${kod} · ${kisalt(d.ad, 30)}`);
    const t2 = sayimYaz(m, d, { x: d.ax + dx, y: d.ay + 24, 'text-anchor': an });
    const bos = !paketleri(d).length;
    if (bos) { t2.textContent = ''; t2.appendChild(s('tspan', { class: 'bos-yazi' }, 'henüz planlanmadı')); }
    const alan = s('rect', { class: 'dokunma' });
    ekle(g, [alan, s('circle', { class: 'nokta', cx: d.ax, cy: d.ay, r: 13 }), t1, t2]); ust.appendChild(g);
    const w = Math.max(genislik(t1), genislik(t2)) + 40;
    oz(alan, { x: sagda ? d.ax - 20 : d.ax - w + 20, y: d.ay - 26, width: w, height: 60 });
    rozetler(g, d, sagda ? d.ax - 4 : d.ax + 4, d.ay - 30);
  }

  // bulgu rozeti ve tutarlılık uyarısı (kayıt yok uyarısı hariç; o, liste kartında gri satırdır)
  function rozetler(g, d, x, y) {
    const bul = yer.bag.toplam.get(d.id);
    if (bul && bul.size) {
      const en = SEVIYE_SIRA.find((sv) => [...bul.values()].some((b) => b.seviye === sv)) || 'bilgi';
      g.appendChild(s('g', { class: 'rozet', transform: `translate(${x},${y})` }, s('circle', { class: `s-${en}`, r: 13 }), s('text', { y: 5 }, String(bul.size))));
    }
    const uy = (yer.bag.uyari.get(d.id) || []).filter((u) => u.kod !== 'ilerleme_kaydi_yok');
    if (uy.length) {
      g.appendChild(s('g', { class: 'ucgen-g', transform: `translate(${x - 30},${y})` },
        s('path', { class: 'ucgen', d: 'M0 -12 L11 8 L-11 8 Z' }), s('text', { class: 'ucgen-t', y: 6 }, '!')));
    }
  }

  function sar(metin, n, en) {
    const out = [''];
    for (const k of String(metin).split(/\s+/)) {
      const aday = (out[out.length - 1] + ' ' + k).trim();
      if (aday.length <= n) { out[out.length - 1] = aday; continue; }
      if (out.length === en) { out[out.length - 1] = kisalt(aday, n); break; }
      out.push(k);
    }
    return out.filter(Boolean);
  }

  function isaretle(id) {
    document.querySelectorAll('.dugum.secili').forEach((x) => x.classList.remove('secili'));
    const g = document.querySelector(`.dugum[data-id="${CSS.escape(id)}"]`); if (g) g.classList.add('secili');
  }

  // ================================================================ liste kartı
  // Bileşen, modül ya da iş alanına dokununca açılır: her iş paketi bir satır, sabit sırayla.
  let listeId = null;
  function listeAc(id) {
    const m = p(), d = yer && yer.dug.get(id); if (!d) return;
    listeId = id; secili = id; isaretle(id);
    sahne.classList.add('odak');
    document.querySelectorAll('.dal').forEach((x) => x.classList.toggle('odakta', x.getAttribute('data-alt') === id));
    const kart = temizle($('#liste'));
    const kod = d.id.split(':')[1];
    const ust = `${TUR[d.tur]} · ${kod}${d.tur === 'modul' && d.bilesen ? ' · ' + d.bilesen.slice(8) : ''}`;
    const kapat = h('button', { class: 'kapat', type: 'button', title: 'Kapat', 'aria-label': 'Kartı kapat' }, '×');
    kapat.addEventListener('click', listeKapat);
    ekle(kart, [kapat, h('div', { class: 'liste-ust' }, h('span', {}, ust), h('span', {}, d.repo ? d.repo.split('/')[1] : '')),
      h('h2', {}, d.ad)]);
    if (d.kapsam) kart.appendChild(h('p', { class: 'liste-kapsam' }, d.kapsam));
    const ipler = paketleri(d).sort((a, b) => SIRA[paketDurumu(m, a.id)] - SIRA[paketDurumu(m, b.id)] || a.id.localeCompare(b.id, 'tr'));
    if (!ipler.length) kart.appendChild(h('p', { class: 'bos-yazi' }, 'henüz planlanmadı'));
    const ul = h('ul', { class: 'liste-satirlar' });
    for (const ip of ipler) {
      const du = paketDurumu(m, ip.id), k = m.katmanlar.ilerleme.paketler[ip.id];
      let sag = '';
      if (du === 'suruyor' || du === 'bekliyor') sag = k ? EVRE[k.evre] : '';
      if (du === 'engelli') sag = k && k.engel ? kisalt(k.engel, 34) : 'engel';
      if (du === 'yok') sag = 'kayıt yok';
      if (du === 'vazgecildi') sag = 'vazgeçildi';
      const b = h('button', { class: `liste-satir s-${du}`, type: 'button', title: ip.kapsam ? `${ip.ad}: ${ip.kapsam}` : ip.ad },
        h('span', { class: 'is' }, ISARET[du]), h('span', { class: 'no' }, ip.id.slice(3)), h('span', { class: 'ad' }, ip.ad), h('span', { class: 'sag' }, sag));
      b.addEventListener('click', () => panelAc(ip.id));
      ul.appendChild(h('li', {}, b));
    }
    kart.appendChild(ul);
    const ayr = h('button', { class: 'btn ayrinti', type: 'button' }, 'AYRINTI · bulgular ve uyarılar');
    ayr.addEventListener('click', () => panelAc(id));
    kart.appendChild(ayr);
    kart.hidden = false;
    listeKonumla();
  }
  function listeKonumla() {
    const kart = $('#liste'), d = listeId && yer && yer.dug.get(listeId);
    if (!d || kart.hidden) return;
    const px = d.ax * gorunum.k + gorunum.x, py = d.ay * gorunum.k + gorunum.y;
    const w = kart.offsetWidth, hh = kart.offsetHeight, ust = innerWidth > 860 ? 110 : 70;
    const sagda = Math.cos(d.aci || 0) >= -0.05;
    let x = sagda ? px - w - 40 : px + 40;
    if (x < 12) x = px + 40;
    if (x + w > W() - 12) x = Math.max(12, W() - w - 12);
    const y = sinir(py - hh / 2, ust, Math.max(ust, H() - hh - 12));
    kart.style.left = `${x}px`; kart.style.top = `${y}px`;
  }
  function listeKapat() {
    listeId = null; const kart = $('#liste'); kart.hidden = true; temizle(kart);
    sahne.classList.remove('odak');
    document.querySelectorAll('.dal.odakta').forEach((x) => x.classList.remove('odakta'));
    if (!$('#panel').classList.contains('acik')) { secili = null; document.querySelectorAll('.dugum.secili').forEach((x) => x.classList.remove('secili')); }
  }
  function dokun(id) {
    const d = yer && yer.dug.get(id); if (!d) return;
    if (d.tur === 'bilesen' || d.tur === 'modul' || d.tur === 'alan') { panelKapat(); listeAc(id); } else { listeKapat(); panelAc(id); }
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
    $('#a-asama').textContent = asama ? `${asama.id.slice(6)} · ${kisalt(asama.kapsam || asama.ad, 28)}` : '—';
    $('#a-zaman').textContent = m ? tarih(m.uretim.zaman) : '—';

    const kat = temizle($('#katmanlar'));
    kat.appendChild(h('div', { class: 'kutu-baslik' }, 'KATMANLAR'));
    [['ilerleme', 'İlerleme'], ['denetim', 'Denetim bulguları'], ['uyari', 'Uyarılar']].forEach(([k, ad]) => {
      const b = h('button', { class: `satir-dugme${katman[k] ? ' acik' : ''}`, type: 'button', 'aria-pressed': String(katman[k]) }, h('i'), ad);
      b.addEventListener('click', () => { katman[k] = !katman[k]; katmanSiniflari(); hudCiz(); });
      kat.appendChild(b);
    });
  }

  // ================================================================ görünüm (pan / zoom / pinch)
  const tuval = $('#tuval'), dunya = $('#dunya'), sahne = $('#sahne');
  const gorunum = { x: 0, y: 0, k: 1 };
  const KMIN = 0.08, KMAX = 4;
  const sinir = (v, a, b) => Math.max(a, Math.min(b, v));
  const W = () => tuval.clientWidth, H = () => tuval.clientHeight;
  let anim = null;

  function uygula() {
    const { x, y, k } = gorunum;
    dunya.setAttribute('transform', `translate(${x},${y}) scale(${k})`);
    tuval.style.setProperty('--kucuk', `${20 * k}px`);
    tuval.style.setProperty('--buyuk', `${100 * k}px`);
    tuval.style.setProperty('--ox', `${x}px`);
    tuval.style.setProperty('--oy', `${y}px`);
    tuval.style.setProperty('--ince', 20 * k < 7 ? '0' : '.07');
    $('#z-oran').textContent = `${Math.round(k * 100)}%`;
    $('#a-olcek').textContent = `1:${(1 / k).toFixed(2)}`;
    miniGorus();
    listeKonumla();
  }
  function zoomNokta(px, py, f) {
    const k2 = sinir(gorunum.k * f, KMIN, KMAX), r = k2 / gorunum.k;
    gorunum.x = px - (px - gorunum.x) * r; gorunum.y = py - (py - gorunum.y) * r; gorunum.k = k2; uygula();
  }
  function git(h2, sure = 420) {
    cancelAnimationFrame(anim);
    const b = { ...gorunum }, t0 = performance.now();
    const ad = (n) => { const u = Math.min(1, (n - t0) / sure), e = 1 - (1 - u) ** 3;
      gorunum.x = b.x + (h2.x - b.x) * e; gorunum.y = b.y + (h2.y - b.y) * e; gorunum.k = b.k + (h2.k - b.k) * e; uygula();
      if (u < 1) anim = requestAnimationFrame(ad); };
    anim = requestAnimationFrame(ad);
  }
  function sigdir(r, pay = 60, kmax = KMAX) {
    const ust = innerWidth > 860 ? 110 : 70;
    const k = sinir(Math.min((W() - pay * 2) / r.w, (H() - ust - pay) / r.h), KMIN, kmax);
    return { k, x: (W() - r.w * k) / 2 - r.x * k, y: ust + (H() - ust - r.h * k) / 2 - r.y * k };
  }
  // açılış: bütün ağ, kenarlardaki kutuların (katmanlar, yakınlaştırma, antet) arasına sığar
  function baslangic() {
    if (!yer) return { x: 0, y: 0, k: 1 };
    const k = yer.kutu, genis = innerWidth > 860;
    const sol = genis ? 170 : 12, sag = genis ? 100 : 12, ust = genis ? 110 : 70, alt = genis ? 90 : 12;
    const kk = sinir(Math.min((W() - sol - sag) / k.w, (H() - ust - alt) / k.h), KMIN, 1.2);
    return { k: kk, x: sol + (W() - sol - sag - k.w * kk) / 2 - k.x * kk, y: ust + (H() - ust - alt - k.h * kk) / 2 - k.y * kk };
  }
  const yerel = (e) => { const r = tuval.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };
  const dunyaya = (px, py) => ({ x: (px - gorunum.x) / gorunum.k, y: (py - gorunum.y) / gorunum.k });

  tuval.addEventListener('wheel', (e) => {
    e.preventDefault(); cancelAnimationFrame(anim);
    if (e.shiftKey) { gorunum.x -= e.deltaY; uygula(); return; }
    const q = yerel(e); zoomNokta(q.x, q.y, Math.exp(-e.deltaY * (e.ctrlKey ? 0.012 : 0.0018)));
  }, { passive: false });

  const isaret = new Map(); let surukle = null, sikistir = null, hareket = 0;
  tuval.addEventListener('pointerdown', (e) => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    cancelAnimationFrame(anim); tuval.setPointerCapture(e.pointerId); isaret.set(e.pointerId, yerel(e));
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
      if (g) dokun(g.getAttribute('data-id')); else { listeKapat(); panelKapat(); }
    }
  };
  tuval.addEventListener('pointerup', birak); tuval.addEventListener('pointercancel', birak);
  tuval.addEventListener('dblclick', (e) => {
    const q = yerel(e), k2 = sinir(gorunum.k * 1.8, KMIN, KMAX), r = k2 / gorunum.k;
    git({ k: k2, x: q.x - (q.x - gorunum.x) * r, y: q.y - (q.y - gorunum.y) * r }, 300);
  });
  // klavye: odaktaki düğüm Enter ya da boşlukla açılır
  $('#dunya').addEventListener('keydown', (e) => {
    const g = e.target.closest && e.target.closest('.dugum');
    if (g && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); dokun(g.getAttribute('data-id')); }
  });
  document.addEventListener('gesturestart', (e) => e.preventDefault());

  const merkezZoom = (f) => { const cx = W() / 2, cy = H() / 2, k2 = sinir(gorunum.k * f, KMIN, KMAX), r = k2 / gorunum.k; git({ k: k2, x: cx - (cx - gorunum.x) * r, y: cy - (cy - gorunum.y) * r }, 250); };
  $('#z-art').addEventListener('click', () => merkezZoom(1.4));
  $('#z-azal').addEventListener('click', () => merkezZoom(1 / 1.4));
  $('#z-oran').addEventListener('click', () => merkezZoom(1 / gorunum.k));
  const genel = () => { if (yer) git(baslangic()); };
  $('#z-sigdir').addEventListener('click', genel);
  addEventListener('keydown', (e) => {
    if ($('#masa').hidden || e.target.closest('input')) return;
    if (e.key === '+' || e.key === '=') merkezZoom(1.3);
    else if (e.key === '-') merkezZoom(1 / 1.3);
    else if (e.key === '0') genel();
    else if (e.key === 'Escape') { if ($('#panel').classList.contains('acik')) panelKapat(); else listeKapat(); }
  });
  addEventListener('resize', () => { miniGorus(); listeKonumla(); });

  // ================================================================ mini harita
  const mini = $('#mini');
  function miniCiz() {
    temizle(mini);
    if (!yer) return;
    const k = yer.kutu;
    oz(mini, { viewBox: `${k.x} ${k.y} ${k.w} ${k.h}`, preserveAspectRatio: 'xMidYMid meet' });
    const m = p();
    for (const d of yer.dug.values()) {
      if (!d.konumlu) continue;
      const sy = sayim(m, d);
      const renk = d.tur === 'proje' ? 'var(--vurgu)' : sy.engelli ? 'var(--engel)' : sy.suruyor ? 'var(--surer)' : d.tur === 'alan' ? '#b49cff' : 'rgba(156,195,240,.6)';
      const c = s('circle', { cx: d.ax, cy: d.ay, r: d.tur === 'proje' ? 60 : 26 });
      c.style.fill = renk; mini.appendChild(c);
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
  mini.addEventListener('pointerdown', (e) => { e.stopPropagation(); cancelAnimationFrame(anim); miniSurukle = true; mini.setPointerCapture(e.pointerId); miniGit(e); });
  mini.addEventListener('pointermove', (e) => miniSurukle && miniGit(e));
  mini.addEventListener('pointerup', () => { miniSurukle = false; });

  // ================================================================ detay paneli
  const satir = (ad, ...deger) => h('div', { class: 'satir' }, h('span', {}, ad), h('span', {}, ...deger));
  function panelAc(id) {
    const m = p(); const d = yer && yer.dug.get(id); if (!d) return;
    if (!listeId) { secili = id; isaretle(id); }
    const panel = temizle($('#panel'));
    const kapat = h('button', { class: 'kapat', type: 'button', title: 'Kapat' }, '×');
    kapat.addEventListener('click', panelKapat);
    ekle(panel, [kapat, h('div', { class: 'kicker' }, `${TUR[d.tur]}${d.tur === 'ip' ? ' · ' + d.id.slice(3) : ''}`), h('h2', {}, d.ad)]);
    if (d.kapsam) panel.appendChild(h('p', { class: 'liste-kapsam' }, d.kapsam));

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
      if (d.tur === 'modul' && d.bilesen) panel.appendChild(satir('Bileşeni', d.bilesen.slice(8)));
      if (d.tur === 'bilesen' || d.tur === 'modul') panel.appendChild(satir('Yerleşim', d.repo ? `${d.repo}${d.klasor ? ' · ' + d.klasor : ''}` : 'Kod deposu yok (ilerleme karar deposunda)'));
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
    $('#panel').classList.remove('acik');
    if (!listeId) { secili = null; document.querySelectorAll('.dugum.secili').forEach((x) => x.classList.remove('secili')); }
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
