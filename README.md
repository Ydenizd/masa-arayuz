# Masa arayüzü

Masanın (proje panosu) arayüzü: blueprint tuvali, proje sekmeleri, kademeli zoom (proje → aşama → bileşen → iş paketi → dosya), evre şeridi, denetim bulgusu rozetleri ve uyarılar.

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
| Kaydır | Sürükle | Tek parmakla sürükle |
| Yakınlaştır | Tekerlek (imlecin olduğu yere) | İki parmakla açıp kapat |
| Dalı odakla | Karta çift tık | Karta çift dokun |
| Ayrıntı | Karta tık | Karta dokun |
| Tümünü sığdır | `0` ya da ⤢ | ⤢ |

Diğer düğmeler:
- **GÜNCELLE:** masa deposunda toplama iş akışını başlatır, bitince veriyi yeniden okur.
- **DENETİM:** playbook hazır olunca etkinleşir.
- **KİLİTLE:** anahtarı bellekten siler. Masa yeniden açılırken PIN sorulur.

## Yerelde deneme

```bash
python3 -m http.server 8765   # http://localhost:8765 güvenli bağlam sayılır
python3 kontrol/guvenlik.py
```
