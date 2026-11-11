"""Arayüz deposu güvenlik kontrolü (Masa Protokolü 6.4). Her PR'da çalışır; hata varsa çıkış 1.

G1  Depoda yalnız arayüz dosyaları; veri dosyası ve anahtar biçiminde metin yok.
G2  app.js'de HTML yorumlayan API yok (innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, new Function).
G3  index.html'de CSP var; betik yalnız 'self', bağlantı yalnız api.github.com; satır içi betik ve stil yok.
G4  Kodda izinli adresler dışında dış adres yok.
G8  noindex etiketi var.
"""
import re
import subprocess
import sys
from pathlib import Path

KOK = Path(__file__).resolve().parent.parent
hatalar = []
hata = hatalar.append

IZINLI_UZANTI = {".html", ".css", ".js", ".svg", ".png", ".webmanifest", ".md", ".yml", ".py"}
IZINLI_AD = {".gitignore", ".nojekyll", "LICENSE"}
IZINLI_ADRES = {"https://api.github.com", "https://github.com/", "http://www.w3.org/2000/svg"}
ANAHTAR = re.compile(r"(github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
YASAK_API = re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function)\b")

dosyalar = subprocess.run(["git", "ls-files"], cwd=KOK, capture_output=True, text=True, check=True).stdout.split()
for ad in dosyalar:
    p = KOK / ad
    if p.name not in IZINLI_AD and p.suffix not in IZINLI_UZANTI:
        hata(f"G1: izinsiz dosya türü: {ad}")
    if p.suffix in {".png"}:
        continue
    metin = p.read_text(encoding="utf-8", errors="replace")
    if ANAHTAR.search(metin) and ad != "kontrol/guvenlik.py":
        hata(f"G1: anahtar biçiminde metin: {ad}")

js = (KOK / "app.js").read_text(encoding="utf-8")
kod = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
kod = re.sub(r"(?m)^\s*//.*$", "", kod)
for m in YASAK_API.finditer(kod):
    hata(f"G2: app.js yasak API: {m.group(0)}")

html = (KOK / "index.html").read_text(encoding="utf-8")
csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html)
if not csp:
    hata("G3: CSP yok")
else:
    c = {k.split()[0]: k.split()[1:] for k in [x.strip() for x in csp.group(1).split(";")] if k}
    if c.get("default-src") != ["'none'"]:
        hata("G3: default-src 'none' değil")
    if c.get("script-src") != ["'self'"]:
        hata("G3: script-src yalnız 'self' olmalı")
    if c.get("connect-src") != ["https://api.github.com"]:
        hata("G3: connect-src yalnız https://api.github.com olmalı")
    if "'unsafe-inline'" in csp.group(1) or "'unsafe-eval'" in csp.group(1):
        hata("G3: unsafe-inline / unsafe-eval var")
for m in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.S):
    if m.group(2).strip() or "src=" not in m.group(1):
        hata("G3: satır içi betik")
if re.search(r"\sstyle=", html):
    hata("G3: satır içi stil özniteliği")
if 'name="robots" content="noindex' not in html:
    hata("G8: noindex yok")

for ad in ("index.html", "app.js", "styles.css", "manifest.webmanifest"):
    for adres in re.findall(r"https?://[^\s\"'`)<>]+", (KOK / ad).read_text(encoding="utf-8")):
        if not any(adres.startswith(i) for i in IZINLI_ADRES):
            hata(f"G4: {ad} içinde izinsiz adres: {adres}")

if hatalar:
    print("\n".join(hatalar))
    sys.exit(1)
print(f"Güvenlik kontrolü temiz ({len(dosyalar)} dosya).")
