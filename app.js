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
  function kilitle() { oturum = null; projeler = []; temizle($('#agac')); kapiGoster(kasaOku() ? 'kilit' : 'kurulum'); }

  // ================================================================ durum
  let projeler = [], etkin = 0, secili = null;
  let yer = null; // { dug: Map, kok, gruplar, bag }
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
    ciz();
  }

  const sinir = (v, a, b) => Math.max(a, Math.min(b, v));
  // ================================================================ yerleşim: yatay ağaç
  // Soldan sağa: proje → aşama → bileşen / modül; en altta iş alanları (protokol 0.10, Bölüm 7.2).
  // Bütün yazılar yataydır. Bir bileşene, modüle ya da iş alanına dokununca iş paketleri sağa dal
  // olarak açılır, ağın geri kalanı soluklaşır. Pakete dokununca yan panel açılır.
  const SIRA = { bitti: 0, suruyor: 1, engelli: 2, bekliyor: 3, yok: 4, vazgecildi: 5 };
  const ISARET = { bitti: '✓', suruyor: '▶', engelli: '■', bekliyor: '○', yok: '·', vazgecildi: '–' };
  function paketDurumu(m, id) {
    const k = m.katmanlar.ilerleme.paketler[id];
    if (!k) return 'yok';
    return k.durum === 'bitti' || (k.evre >= 5 && k.durum !== 'vazgecildi') ? 'bitti' : k.durum;
  }
  const paketleri = (d) => { const o = []; (function gez(x) { for (const c of x.cocuk) { if (c.tur === 'ip') o.push(c); else if (c.tur !== 'dosya') gez(c); } })(d); return o; };
  // Sayımlarda yalnız plana girmiş paketler; onay bekleyen paket dalda görünür ama sayılmaz (masa ADR-0004, özetle aynı).
  const sayilan = (d) => paketleri(d).filter((ip) => ip.onay !== 'onay_bekliyor');
  function sayim(m, d) {
    const s2 = { bitti: 0, suruyor: 0, engelli: 0, bekliyor: 0, yok: 0 };
    for (const ip of sayilan(d)) { const du = paketDurumu(m, ip.id); if (du in s2) s2[du]++; }
    return s2;
  }

  function yapi(m) {
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
    // bir aşamanın dalları: önce bileşen, ardından o bileşenin bu aşamadaki modülleri; sonra başka
    // aşamadaki bileşene bağlı modüller (ör. 1b'de B-CRM)
    const dallar = (ust) => {
      const c = ust.cocuk.filter((x) => x.tur === 'bilesen' || x.tur === 'modul');
      const out = [];
      for (const b of c.filter((x) => x.tur === 'bilesen')) {
        out.push(b);
        for (const md of c.filter((x) => x.tur === 'modul' && x.bilesen === b.id)) out.push(md);
      }
      for (const x of c) if (!out.includes(x)) out.push(x);
      return out;
    };
    const gruplar = kok.cocuk.filter((c) => c.tur === 'asama').map((a) => ({ d: a, ad: a.ad, dallar: dallar(a) }));
    const ortak = dallar(kok);
    if (ortak.length) gruplar.push({ d: null, ad: 'Ortak', dallar: ortak });
    const alanlar = kok.cocuk.filter((c) => c.tur === 'alan');
    if (alanlar.length) gruplar.push({ d: null, ad: 'İş alanları', dallar: alanlar });
    return { dug, kok, gruplar };
  }

  // düğüme bağlı bulgular ve uyarılar (alt düğümler dahil toplam)
  function bagla(m, y) {
    const dogrudan = new Map(), uyari = new Map();
    for (const b of m.katmanlar.denetim.bulgular) for (const n of b.bagli) { if (!dogrudan.has(n)) dogrudan.set(n, []); dogrudan.get(n).push(b); }
    for (const u of m.katmanlar.uyarilar) if (u.dugum) { if (!uyari.has(u.dugum)) uyari.set(u.dugum, []); uyari.get(u.dugum).push(u); }
    const toplam = new Map();
    const topla = (d) => {
      const set = new Map((dogrudan.get(d.id) || []).filter((b) => ACIK_BULGU.has(b.durum)).map((b) => [b.no, b]));
      for (const c of d.cocuk) for (const [k, v] of topla(c)) set.set(k, v);
      toplam.set(d.id, set); return set;
    };
    topla(y.kok);
    return { dogrudan, toplam, uyari };
  }

  // ================================================================ çizim
  let acik = null; // iş paketleri açık olan bileşen, modül ya da iş alanı
  const tuval = $('#tuval'), agac = $('#agac');
  const kod = (d) => d.id.split(':')[1];

  function ciz() {
    sekmeleriCiz();
    panelKapat();
    acik = null;
    const m = p();
    yer = m ? yapi(m) : null;
    if (m && !yer) $('#durum-satiri').textContent = 'Durum dosyasında proje düğümü yok.';
    if (yer) yer.bag = bagla(m, yer);
    hudCiz();
    agacCiz();
  }

  // sayım: ✓ ▶ ■ ○ · ; sıfır olanlar (bitti hariç) yazılmaz
  function sayimEl(m, d) {
    const sy = sayim(m, d), e = h('span', { class: 'sayim' });
    for (const k of ['bitti', 'suruyor', 'engelli', 'bekliyor', 'yok']) {
      if (!sy[k] && k !== 'bitti') continue;
      e.appendChild(h('b', { class: `s-${k}` }, `${ISARET[k]} ${sy[k]}`));
    }
    return e;
  }
  // bulgu rozeti ve tutarlılık uyarısı ("kayıt yok" uyarısı hariç; o, dalda gri yazıdır)
  function rozetler(d) {
    const out = [];
    const bul = yer.bag.toplam.get(d.id);
    if (bul && bul.size) {
      const en = SEVIYE_SIRA.find((sv) => [...bul.values()].some((b) => b.seviye === sv)) || 'bilgi';
      out.push(h('span', { class: `rozet r-${en}`, title: `${bul.size} açık bulgu` }, String(bul.size)));
    }
    const uy = (yer.bag.uyari.get(d.id) || []).filter((u) => u.kod !== 'ilerleme_kaydi_yok');
    if (uy.length) out.push(h('span', { class: 'uyari-isaret', title: uy.map((u) => u.mesaj).join('\n') }, `! ${uy.length}`));
    return out;
  }
  function sagMetin(m, ip, du) {
    const k = m.katmanlar.ilerleme.paketler[ip.id];
    if (du === 'yok') return 'kayıt yok';
    if (du === 'vazgecildi') return 'vazgeçildi';
    if (du === 'engelli') return k && k.engel ? k.engel.replace(/\s*\(.*$/, '') : 'engel';
    return k ? EVRE[k.evre] : '';
  }
  const konumla = (e, x, y2, w) => { e.style.left = `${x}px`; e.style.top = `${y2}px`; if (w) e.style.width = `${w}px`; return e; };

  function agacCiz() {
    temizle(agac);
    document.documentElement.style.setProperty('--ust', `${$('#ust').offsetHeight}px`);
    const m = p();
    if (!m || !yer) return;
    const genis = tuval.clientWidth, yuksek = tuval.clientHeight;
    const PAY = 12, GRUP_ARA = 10;
    const X = { proje: 16, asama: 150, dal: 320, yaprak: 736 }, DAL_W = 366;
    const satirSay = yer.gruplar.reduce((t, g) => t + Math.max(1, g.dallar.length), 0);
    const adim = sinir((yuksek - 2 * PAY - GRUP_ARA * (yer.gruplar.length - 1)) / satirSay, 36, 50);
    const kartH = adim - 4;

    // satırların dikey konumu
    let y0 = PAY;
    const satirlar = [];
    for (const g of yer.gruplar) {
      const n = Math.max(1, g.dallar.length), ys = [];
      for (let i = 0; i < n; i++) ys.push(y0 + i * adim + adim / 2);
      y0 += n * adim + GRUP_ARA;
      g.ys = ys; g.y = (ys[0] + ys[n - 1]) / 2;
      satirlar.push(...ys);
    }
    let icerikH = y0 - GRUP_ARA + PAY;

    // açık dalın paketleri
    const acikD = acik && yer.dug.get(acik);
    const yapraklar = acikD ? paketleri(acikD).sort((a, b) => SIRA[paketDurumu(m, a.id)] - SIRA[paketDurumu(m, b.id)] || a.id.localeCompare(b.id, 'tr')) : [];
    const yAdim = yapraklar.length ? sinir((Math.max(icerikH, yuksek) - 2 * PAY) / yapraklar.length, 34, 44) : 0;
    let acikY = 0;
    for (const g of yer.gruplar) g.dallar.forEach((c, i) => { if (c.id === acik) acikY = g.ys[i]; });
    const blokH = yapraklar.length * yAdim;
    const yBas = sinir(acikY - blokH / 2, PAY, Math.max(PAY, Math.max(icerikH, yuksek) - PAY - blokH));
    icerikH = Math.max(icerikH, yBas + blokH + PAY);
    // dar ekranda paketler, bileşen sütunuyla birlikte tek ekrana sığacak genişlikte açılır
    const icerikW = Math.max(genis, yapraklar.length ? Math.min(X.yaprak + 436, X.dal - 12 + genis) : X.dal + DAL_W + 16);
    agac.style.width = `${icerikW}px`; agac.style.height = `${Math.max(icerikH, yuksek)}px`;
    agac.classList.toggle('odak', !!acik);

    const svg = s('svg', { class: 'baglar', width: icerikW, height: Math.max(icerikH, yuksek), 'aria-hidden': 'true' });
    agac.appendChild(svg);
    const dugumler = [];
    const ekleDugum = (e) => { agac.appendChild(e); dugumler.push(e); return e; };
    const egri = (x1, y1, x2, y2, sinif) => {
      const mx = (x1 + x2) / 2;
      svg.appendChild(s('path', { class: `bag${sinif ? ' ' + sinif : ''}`, d: `M${x1} ${y1} C${mx} ${y1} ${mx} ${y2} ${x2} ${y2}` }));
    };

    // proje
    const kok = yer.kok;
    const pb = ekleDugum(konumla(h('button', { class: 'dugum proje', type: 'button', 'data-id': kok.id, title: m.proje.ad },
      h('span', { class: 'ad' }, m.proje.kimlik.toUpperCase()), h('span', { class: 'alt' }, `${sayilan(kok).length} paket`), ...rozetler(kok)), X.proje, (satirlar[0] + satirlar[satirlar.length - 1]) / 2));
    const projeY = (satirlar[0] + satirlar[satirlar.length - 1]) / 2;

    for (const g of yer.gruplar) {
      // aşama ya da grup adı
      const aktif = g.d && g.d.asama_durumu === 'aktif';
      const ab = h(g.d ? 'button' : 'div', { class: `dugum asama${aktif ? ' aktif' : ''}${g.d ? '' : ' grup'}`, 'data-id': g.d ? g.d.id : null, type: g.d ? 'button' : null },
        h('span', { class: 'ad' }, g.ad), aktif ? h('span', { class: 'etiket-aktif' }, 'aktif') : null, ...(g.d ? rozetler(g.d) : []));
      ekleDugum(konumla(ab, X.asama, g.y));
      g.el = ab;

      if (!g.dallar.length) {
        const bos = h('button', { class: 'dugum dal bos', type: 'button', 'data-id': g.d ? g.d.id : null, title: g.d && g.d.kapsam ? g.d.kapsam : '' },
          h('span', { class: 'bos-yazi' }, 'henüz planlanmadı'), g.d && g.d.kapsam ? h('span', { class: 'kapsam' }, `· ${g.d.kapsam}`) : null);
        bos.style.height = `${kartH}px`;
        ekleDugum(konumla(bos, X.dal, g.ys[0], DAL_W));
        continue;
      }
      g.dallar.forEach((c, i) => {
        const bosDal = !paketleri(c).length;
        const b = h('button', { class: `dugum dal t-${c.tur}${c.id === acik ? ' acik' : ''}`, type: 'button', 'data-id': c.id, 'aria-expanded': String(c.id === acik), title: c.kapsam ? `${c.ad}: ${c.kapsam}` : c.ad },
          h('span', { class: 'kod' }, kod(c)), h('span', { class: 'ad' }, c.ad),
          c.tur === 'modul' && c.bilesen && !g.dallar.some((x) => x.id === c.bilesen) ? h('span', { class: 'kod' }, `· ${c.bilesen.slice(8)}`) : null,
          h('span', { class: 'bosluk' }), ...rozetler(c),
          bosDal ? h('span', { class: 'bos-yazi' }, 'henüz planlanmadı') : sayimEl(m, c));
        b.style.height = `${kartH}px`;
        ekleDugum(konumla(b, X.dal, g.ys[i], DAL_W));
      });
    }

    // yapraklar
    yapraklar.forEach((ip, j) => {
      const du = paketDurumu(m, ip.id), yy = yBas + j * yAdim + yAdim / 2;
      const b = h('button', { class: `dugum yaprak y-${du}`, type: 'button', 'data-id': ip.id, title: ip.kapsam ? `${ip.ad}: ${ip.kapsam}` : ip.ad },
        h('span', { class: 'isaret' }, ISARET[du]), h('span', { class: 'no' }, ip.id.slice(3)), h('span', { class: 'ad' }, ip.ad),
        h('span', { class: 'sag' }, sagMetin(m, ip, du)), ...rozetler(ip));
      b.style.height = `${Math.min(yAdim - 4, 40)}px`;
      ekleDugum(konumla(b, X.yaprak, yy, icerikW - X.yaprak - 16));
    });

    // bağlar: düğümler yerleştikten sonra genişlikleri ölçülür. Aşama sütunu (yazı tipi, rozet)
    // bileşen sütununa yaklaşırsa bileşen ve paket sütunları sağa kaydırılır.
    const sag = (e) => e.offsetLeft + e.offsetWidth;
    const kayma = Math.max(0, Math.max(...yer.gruplar.map((g) => sag(g.el))) + 36 - X.dal);
    if (kayma) {
      // paket dalları sağa kayarken önce kendi genişliklerinden verir; içerik ancak 300 px'in altına inerse genişler
      const yaprakW = Math.max(300, icerikW - X.yaprak - 16 - kayma);
      for (const e of dugumler) {
        if (e.classList.contains('dal')) e.style.left = `${e.offsetLeft + kayma}px`;
        if (e.classList.contains('yaprak')) { e.style.left = `${e.offsetLeft + kayma}px`; e.style.width = `${yaprakW}px`; }
      }
      X.dal += kayma; X.yaprak += kayma;
      const w2 = Math.max(icerikW, yapraklar.length ? X.yaprak + yaprakW + 16 : X.dal + DAL_W + 16);
      agac.style.width = `${w2}px`; oz(svg, { width: w2 });
    }
    for (const g of yer.gruplar) {
      egri(sag(pb), projeY, X.asama, g.y);
      const ax = sag(g.el);
      (g.dallar.length ? g.ys : [g.ys[0]]).forEach((yy, i) => egri(ax, g.y, X.dal, yy, g.dallar[i] && g.dallar[i].id === acik ? 'acik' : ''));
    }
    yapraklar.forEach((ip, j) => egri(X.dal + DAL_W, acikY, X.yaprak - 4, yBas + j * yAdim + yAdim / 2, 'acik'));

    katmanSiniflari();
    if (secili) isaretle(secili);
  }

  function isaretle(id) {
    agac.querySelectorAll('.dugum.secili').forEach((x) => x.classList.remove('secili'));
    if (!id) return;
    const g = agac.querySelector(`.dugum[data-id="${CSS.escape(id)}"]`); if (g) g.classList.add('secili');
  }

  function dokun(id) {
    const d = yer && yer.dug.get(id); if (!d) return;
    if (d.tur === 'bilesen' || d.tur === 'modul' || d.tur === 'alan') {
      acik = acik === id ? null : id;
      panelKapat();
      agacCiz();
      const b = agac.querySelector(`.dugum[data-id="${CSS.escape(id)}"]`);
      if (b) b.focus({ preventScroll: true });
      // dar ekranda paketler sağda kalırsa oraya kaydır
      if (acik && agac.offsetWidth > tuval.clientWidth) tuval.scrollTo({ left: 308, behavior: 'smooth' });
      if (!acik) tuval.scrollTo({ left: 0, behavior: 'smooth' });
    } else {
      panelAc(id);
    }
  }
  function kapat() { if ($('#panel').classList.contains('acik')) panelKapat(); else if (acik) { acik = null; agacCiz(); } }

  agac.addEventListener('click', (e) => {
    const b = e.target.closest('.dugum[data-id]');
    if (b && b.tagName === 'BUTTON') dokun(b.getAttribute('data-id'));
    else if (!b) { panelKapat(); if (acik) { acik = null; agacCiz(); } }
  });
  addEventListener('keydown', (e) => {
    if ($('#masa').hidden || e.target.closest('input')) return;
    if (e.key === 'Escape') kapat();
  });
  let yenidenBoyut = 0;
  addEventListener('resize', () => { clearTimeout(yenidenBoyut); yenidenBoyut = setTimeout(agacCiz, 120); });

  function katmanSiniflari() {
    agac.classList.toggle('gizle-ilerleme', !katman.ilerleme);
    agac.classList.toggle('gizle-denetim', !katman.denetim);
    agac.classList.toggle('gizle-uyari', !katman.uyari);
  }

  // ================================================================ üst şerit
  function sekmeleriCiz() {
    const nav = temizle($('#sekmeler'));
    projeler.forEach((m, i) => {
      const o = m.katmanlar.ilerleme.ozet[m.aktif_asama] || m.katmanlar.ilerleme.ozet[`proje:${m.proje.kimlik}`];
      const engelli = o && o.durum_dagilimi.engelli;
      const b = h('button', { class: `sekme${i === etkin ? ' etkin' : ''}`, type: 'button', title: m.proje.ad },
        h('span', { class: `nokta${engelli ? ' engelli' : o && o.durum_dagilimi.suruyor ? ' suruyor' : ''}` }), h('span', { class: 'ad' }, m.proje.ad),
        h('span', { class: 'ek' }, o ? `${o.paket_sayisi} paket${engelli ? ` · ${engelli} engelli` : ''}` : ''));
      b.addEventListener('click', () => sekmeSec(i));
      nav.appendChild(b);
    });
  }
  function sekmeSec(i) { if (i !== etkin) { etkin = i; tuval.scrollTo(0, 0); ciz(); } }

  function hudCiz() {
    const m = p();
    $('#m-baslik').textContent = m ? m.proje.ad : 'Proje yok';
    const genel = m ? m.katmanlar.uyarilar.filter((u) => !u.dugum) : [];
    const asama = m && m.aktif_asama && m.dugumler.find((d) => d.id === m.aktif_asama);
    const parca = m ? [`${yer ? sayilan(yer.kok).length : 0} iş paketi`, asama ? `aktif ${asama.ad.toLocaleLowerCase('tr')}` : null, `son toplama ${tarih(m.uretim.zaman)}`] : [];
    if (genel.length) parca.push(`${genel.length} genel uyarı`);
    $('#m-alt').textContent = parca.filter(Boolean).join(' · ');
    const kat = temizle($('#katmanlar'));
    [['ilerleme', 'İlerleme'], ['denetim', 'Bulgular'], ['uyari', 'Uyarılar']].forEach(([k, ad]) => {
      const b = h('button', { class: `cip${katman[k] ? ' acik' : ''}`, type: 'button', 'aria-pressed': String(katman[k]) }, ad);
      b.addEventListener('click', () => { katman[k] = !katman[k]; katmanSiniflari(); hudCiz(); });
      kat.appendChild(b);
    });
  }

  // ================================================================ detay paneli
  const satir = (ad, ...deger) => h('div', { class: 'satir' }, h('span', {}, ad), h('span', {}, ...deger));
  function panelAc(id) {
    const m = p(); const d = yer && yer.dug.get(id); if (!d) return;
    secili = id; isaretle(id);
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
    secili = null; isaretle(null);
  }

  // ================================================================ düğmeler ve başlangıç
  $('#guncelle').addEventListener('click', async () => {
    const b = $('#guncelle'), satirE = $('#durum-satiri');
    if (b.disabled) return;
    b.disabled = true; b.classList.add('mesgul');
    try {
      await toplamaBaslat((t) => { satirE.textContent = t; });
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
