# Masa arayüzü

Masanın (proje panosu) arayüzü: proje sekmeleri, soldan sağa yatay ağaç (proje → aşama → bileşen / modül, iş alanları), dokununca açılan iş paketi dalları, yan panelde evre şeridi, denetim bulguları ve uyarılar (Masa Protokolü 7.2).

**Bu depoda veri yoktur.** Proje bilgisi, anahtar ya da masa deposunun adı koda yazılmaz. Arayüz veriyi, cihazda PIN ile şifreli saklanan anahtarla doğrudan masanın özel deposundan (`durum/*.json`) okur. Kurallar Masa Protokolü'nde (Bölüm 6.3, 6.4, 7).

## Dosyalar

| Dosya | İçerik |
| --- | --- |
| `index.html` | Sayfa; CSP, `noindex` |
| `app.js` | Uygulama. Bütün metin `textContent` ile basılır; HTML yorumlayan API yok |
| `styles.css` | Görünüm; sistem yazı tipleri, dış kaynak yok |
| `manifest.webmanifest`, `icon*` | Ana ekrana ekleme (PWA) |
| `kontrol/guvenlik.py` | Her PR'da güvenlik kontrolü (G1–G4, G8) |

## Güvenlik önlemleri

| # | Önlem | Nerede |
| --- | --- | --- |
| G1 | Depoda yalnız arayüz dosyaları; veri dosyası ve anahtar biçiminde metin yok | `kontrol/guvenlik.py` (CI) |
| G2 | Projelerden gelen metin düz metindir | `app.js` (`h`, `s` yardımcıları; izinli öznitelik listesi) + CI |
| G3 | CSP: `default-src 'none'`, betik yalnız `'self'`, bağlantı yalnız `https://api.github.com` | `index.html` + CI |
| G4 | Dış kaynak yok | CI |
| G5 | Anahtar PBKDF2-SHA256 (600.000 tur) ile türetilen anahtarla AES-GCM şifreli; PIN saklanmaz; yanlış PIN'de artan bekleme | `app.js` (kasa) |
| G6 | Anahtar yalnız masa deposuna erişir; kod yalnız o depoya istek atar | Anahtar ayarı + `app.js` |
| G7 | `main` korumalı, yalnız sahip birleştirir | Depo ayarı (sahip) |
| G8 | `noindex` | `index.html` |
| G9 | Lamba: arayüzde Claude anahtarı yok; düğme masa deposundaki lamba iş akışını başlatır (Claude Pro, Actions'ta); yanıt `lamba` dalından okunur, düz metin basılır | `app.js` (lamba) |

## Kurulum (sahip)

1. **GitHub Pages:** *Settings → Pages → Build and deployment → Source: Deploy from a branch*, *Branch: `main` / `(root)`*. Adres: `https://<sahip>.github.io/masa-arayuz/`.
2. **Dal koruması (G7):** *Settings → Branches → Add rule*. Kural `main` dalına uygulanır: PR zorunlu, `guvenlik` kontrolü zorunlu. Depo herkese açık olduğu için ücretsiz planda da uygulanır.
3. **Cihaz anahtarı** (fine-grained personal access token):
   - *Repository access:* yalnız masa deposu.
   - *Permissions:* Contents **Read-only**, Actions **Read and write**.
   - *Expiration:* 90 gün.
4. iPad'de adresi Safari'de aç ve ilk açılışta şunları gir:
   - Masa deposu, `sahip/masa` biçiminde.
   - Cihaz anahtarı.
   - Bir PIN.

   Sonra *Paylaş → Ana Ekrana Ekle*.

## Kullanım

| İşlem | Fare / klavye | iPad |
| --- | --- | --- |
| İş paketlerini aç / kapat | Bileşene, modüle ya da iş alanına tık | Dokun |
| Ayrıntı (yan panel) | Pakete, aşamaya ya da projeye tık | Dokun |
| Kapat | `Esc` ya da boş alana tık | Boş alana dokun |
| Kaydır (ekrana sığmazsa) | Tekerlek | Parmakla kaydır |

Üstteki **İlerleme**, **Bulgular**, **Uyarılar** düğmeleri katmanları açıp kapatır.

Diğer düğmeler:
- **GÜNCELLE:** masa deposunda toplama iş akışını başlatır, bitince veriyi yeniden okur.
- **DENETİM:** playbook hazır olunca etkinleşir.
- **KİLİTLE:** anahtarı bellekten siler. Masa yeniden açılırken PIN sorulur.

## Lamba (dijital danışman, masa ADR-0026)

Sağ alttaki lamba, proje yöneticisi asistanıdır. Dokununca sağdan kayan pencere ekranın yarısını kaplar; **»** ya da sağa kaydırma kapatır.
- **Ne durumdayız?:** projenin asıl eksiği, iki ya da üç seçenek (artısı, eksisi) ve dikkat edilecek risk; en çok 6 satır, kodsuz.
- **Sor:** aynı veri üzerine soru; cevap kısa, gerektiğinde ayrıntılı.

Lamba sahibin Claude Pro aboneliğiyle, masa deposundaki `lamba` iş akışında çalışır; cevap 1–2 dakika sürer. Arayüzde Claude anahtarı yoktur. Kurulum masa deposunun README'sinde (`CLAUDE_CODE_OAUTH_TOKEN`).
