"""Dolandırıcılık & Oltalama: şüpheli SMS/link analizi ve IBAN doğrulama.

Güvenlik ilkesi: şüpheli bağlantılar varsayılan olarak AÇILMAZ. Oltalama SMS'lerindeki
linkler çoğu zaman kurbana özel bir kod taşır; bağlantıyı telefondan açmak dolandırıcıya
numaranın aktif olduğunu ve telefonun IP adresini bildirir. Pasif analiz yalnızca URL'nin
kendisine, DNS'e ve üçüncü taraf istihbarat kaynaklarına bakar. Yönlendirme takibi ayrı,
onaylı bir işlemdir.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote, urlsplit

from ..core import dns, validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Item, Level, Report

# ---------------------------------------------------------------- link analizi

URL_IN_TEXT = re.compile(
    r"(?i)\b((?:https?://|www\.)[^\s<>\"'()]+|(?:[a-z0-9-]+\.)+(?:com|net|org|info|xyz|top|click|icu|shop|online|"
    r"site|live|buzz|link|me|co|io|ly|gl|cc|tk|ml|ga|cf|gq|tr|com\.tr|net\.tr|org\.tr|app|vip|cfd|sbs|rest|"
    r"support|help|lol|monster|bond)(?:/[^\s<>\"'()]*)?)")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy",
              "t.ly", "shorturl.at", "rebrand.ly", "s.id", "v.gd", "tiny.cc", "bl.ink", "lnkd.in", "qr.ae",
              "urlkisalt.com", "kisa.link", "kısa.link", "gg.gg", "shorte.st", "adf.ly", "short.gy", "tr.ee"}
RISKY_TLDS = {"xyz", "top", "click", "icu", "shop", "online", "site", "live", "buzz", "link", "tk", "ml", "ga",
              "cf", "gq", "vip", "cfd", "sbs", "rest", "support", "help", "lol", "monster", "bond", "info"}
LURE_WORDS = ("iade", "odeme", "ödeme", "guncelle", "güncelle", "dogrula", "doğrula", "giris", "giriş", "kampanya",
              "hediye", "kargo", "takip", "ceza", "borc", "borç", "aidat", "fatura", "sifre", "şifre", "onay",
              "bloke", "askiya", "askıya", "puan", "odul", "ödül", "kazandiniz", "kazandınız", "login", "verify",
              "secure", "update", "account", "refund", "edevlet", "e-devlet", "hgs", "ogs", "vergi")
# Marka anahtar kelimesi → resmî (kayıtlı) domainler. Anahtar kelime host'ta geçip kayıtlı domain resmî
# listede değilse marka taklidi olarak işaretlenir.
BRANDS: dict[str, tuple[str, ...]] = {
    "edevlet": ("turkiye.gov.tr",), "e-devlet": ("turkiye.gov.tr",), "turkiye-gov": ("turkiye.gov.tr",),
    "ptt": ("ptt.gov.tr", "pttavm.com", "pttkargo.com.tr"), "garanti": ("garantibbva.com.tr",),
    "akbank": ("akbank.com",), "ziraat": ("ziraatbank.com.tr", "ziraatkatilim.com.tr"),
    "isbank": ("isbank.com.tr",), "yapikredi": ("yapikredi.com.tr",), "halkbank": ("halkbank.com.tr",),
    "vakifbank": ("vakifbank.com.tr",), "denizbank": ("denizbank.com",), "enpara": ("enpara.com",),
    "papara": ("papara.com",), "turkcell": ("turkcell.com.tr",), "vodafone": ("vodafone.com.tr",),
    "turktelekom": ("turktelekom.com.tr",), "yurtici": ("yurticikargo.com",), "araskargo": ("araskargo.com.tr",),
    "mngkargo": ("mngkargo.com.tr",), "trendyol": ("trendyol.com",), "hepsiburada": ("hepsiburada.com",),
    "sahibinden": ("sahibinden.com",), "getir": ("getir.com",), "netflix": ("netflix.com",),
    "paypal": ("paypal.com",), "apple": ("apple.com", "icloud.com"), "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com"), "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com", "whatsapp.net"), "facebook": ("facebook.com",), "google": ("google.com",),
    "amazon": ("amazon.com", "amazon.com.tr"), "binance": ("binance.com", "binance.tr"),
    "btcturk": ("btcturk.com",), "sgk": ("sgk.gov.tr",), "gib": ("gib.gov.tr",),
}


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    two_level = {"com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr", "biz.tr", "info.tr", "web.tr",
                 "co.uk", "com.au", "co.jp", "com.br"}
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in two_level else 2
    return ".".join(parts[-n:])


def extract_urls(text: str) -> list[str]:
    out: list[str] = []
    for m in URL_IN_TEXT.finditer(text):
        u = m.group(1).rstrip(".,;:!?)]")
        if m.start() > 0 and text[m.start() - 1] == "@":  # e-posta adresinin domain kısmı, link değil
            continue
        if "@" in u.split("/")[0] and "://" not in u:
            continue
        if not u.lower().startswith(("http://", "https://")):
            u = "http://" + u
        if u not in out:
            out.append(u)
    return out[:5]


def link_input(value: str) -> list[str]:
    urls = extract_urls(value)
    if not urls:
        raise ValueError("Metinde link bulunamadı (ör. https://ornek.com/… veya bit.ly/…)")
    return urls


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0])
    return out


def assess_url(url: str) -> dict:
    """Ağa çıkmadan yapılabilen kontroller: (bulgular, risk puanı, host)."""
    parts = urlsplit(url)
    raw_host = parts.hostname or ""
    findings: list[tuple[str, str, Level]] = []
    score = 0
    if parts.username or "@" in parts.netloc:
        findings.append(("@ hilesi", f"Adres '@' içeriyor; tarayıcı asıl olarak '{raw_host}' adresine gider",
                         Level.BAD))
        score += 3
    host = raw_host
    if any(lbl.startswith("xn--") for lbl in raw_host.split(".")):
        try:
            host = raw_host.encode().decode("idna")
        except UnicodeError:
            host = raw_host
        findings.append(("Punycode / IDN", f"Gerçek görünüm: {host}", Level.WARN))
        score += 2
    for lbl in host.split("."):
        sc = _scripts(lbl)
        if len(sc - {"DIGIT"}) > 1 and "LATIN" in sc:
            findings.append(("Karışık alfabe (homograf)", f"'{lbl}' farklı alfabelerden harfler içeriyor: "
                             + ", ".join(sorted(sc)), Level.BAD))
            score += 3
            break
    if validate.is_ip(host):
        findings.append(("IP adresi", "Domain yerine doğrudan IP adresine yönlendiriyor", Level.BAD))
        score += 3
    reg = registrable(host) if not validate.is_ip(host) else host
    if reg in SHORTENERS or host in SHORTENERS:
        findings.append(("Kısaltılmış link", "Gerçek hedef gizli; 'Bağlantıyı takip et' ile güvenli biçimde "
                         "çözebilirsiniz", Level.WARN))
        score += 1
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in RISKY_TLDS:
        findings.append(("Riskli uzantı", f".{tld} uzantısı oltalamada sık kullanılır", Level.WARN))
        score += 1
    flat = re.sub(r"[^a-z0-9-]", "", host.lower().replace(".", "-"))
    for kw, official in BRANDS.items():
        if kw in flat and reg not in official:
            findings.append(("Marka taklidi", f"'{kw}' geçiyor ama resmî domain değil (resmî: {', '.join(official)})",
                             Level.BAD))
            score += 4
            break
    lowered = unquote(url).lower()
    lures = [w for w in LURE_WORDS if w in lowered]
    if lures:
        findings.append(("Tuzak kelimeler", ", ".join(dict.fromkeys(lures))[:120], Level.WARN))
        score += 1
    if host.count(".") >= 4:
        findings.append(("Çok seviyeli alt alan adı", "Gerçek domaini gizlemek için kullanılabilir", Level.WARN))
        score += 1
    if parts.scheme == "http":
        findings.append(("Şifresiz bağlantı", "HTTPS değil", Level.INFO))
    return {"host": host, "raw_host": raw_host, "registrable": reg, "findings": findings, "score": score}


def _verdict(score: int) -> tuple[str, Level]:
    if score >= 4:
        return "YÜKSEK RİSK — açmayın, bilgi girmeyin", Level.BAD
    if score >= 2:
        return "ŞÜPHELİ — dikkatli olun", Level.WARN
    return "Belirgin bir risk işareti bulunamadı (bu, güvenli olduğu anlamına gelmez)", Level.INFO


def _intel(ctx: Context, rep: Report, sec, host: str, reg: str) -> int:
    """DNS, alan adı yaşı, OpenPhish ve urlscan; hedef siteye hiç bağlanmadan. Ek risk puanı döndürür."""
    extra = 0
    try:
        status, a = dns.query(ctx, reg if not validate.is_ip(host) else host, "A")
        if status == "NXDOMAIN":
            sec.add("DNS", "Domain artık yok (kapatılmış olabilir)", level=Level.MUTED)
        rep.source("DNS", True)
    except OsintError as e:
        rep.source("DNS", False, str(e)[:80])
    if not validate.is_ip(host):
        if reg.endswith(".tr"):
            sec.add("Domain yaşı", ".tr uzantıları kayıt tarihi bilgisi (RDAP) sunmaz", level=Level.MUTED)
        else:
            try:
                rd = ctx.http.json(f"https://rdap.org/domain/{reg}", ok=(200, 404))
                rep.source("RDAP", True)
                created = next((ev.get("eventDate", "") for ev in (rd or {}).get("events") or []
                                if ev.get("eventAction") == "registration"), "")
                if created:
                    from datetime import datetime, timezone
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
                    level = Level.BAD if age < 30 else Level.WARN if age < 180 else Level.OK
                    sec.add("Domain yaşı", f"{age} gün ({created[:10]} kaydı)", level=level)
                    extra += 3 if age < 30 else 1 if age < 180 else 0
            except (OsintError, ValueError) as e:
                rep.source("RDAP", False, str(e).split(": ", 1)[-1][:80])
    try:
        resp = ctx.http.get("https://openphish.com/feed.txt", timeout=max(20, ctx.settings.timeout))
        if resp.status_code == 200:
            rep.source("OpenPhish", True)
            if any((urlsplit(u).hostname or "").lower() in (host, reg) for u in resp.text.split()):
                sec.add("OpenPhish", "AKTİF OLTALAMA LİSTESİNDE", level=Level.BAD)
                extra += 5
    except OsintError as e:
        rep.source("OpenPhish", False, str(e).split(": ", 1)[-1][:80])
    try:
        data = ctx.http.json("https://urlscan.io/api/v1/search/", params={"q": f"domain:{reg}", "size": 20})
        results = [r for r in (data or {}).get("results") or [] if isinstance(r, dict)]
        rep.source("urlscan.io", True)
        mal = [r for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")]
        if mal:
            sec.add("urlscan.io", f"{len(mal)} taramada ZARARLI olarak işaretlenmiş", level=Level.BAD,
                    url=f"https://urlscan.io/search/#domain:{reg}")
            extra += 4
        elif results:
            sec.add("urlscan.io", f"{data.get('total', len(results))} geçmiş tarama, zararlı işareti yok",
                    url=f"https://urlscan.io/search/#domain:{reg}")
    except OsintError as e:
        rep.source("urlscan.io", False, str(e).split(": ", 1)[-1][:80])
    return extra


def _linkcheck(ctx: Context, rep: Report, v: dict) -> None:
    worst = 0
    for url in v["text"]:
        a = assess_url(url)
        sec = rep.section(f"Link: {url[:80]}")
        sec.add("Gerçek domain", a["registrable"] + (f" (görünen: {a['raw_host']})" if a["host"] != a["raw_host"]
                                                    else ""))
        for label, value, level in a["findings"]:
            sec.add(label, value, level=level)
        score = a["score"] + _intel(ctx, rep, sec, a["host"], a["registrable"])
        verdict, level = _verdict(score)
        sec.items.insert(0, Item("Değerlendirme", verdict, level=level))
        worst = max(worst, score)
        rep.changed()
    verdict, _ = _verdict(worst)
    rep.summary = verdict
    rep.notice("Linkler AÇILMADI: yalnızca adresin kendisi, DNS ve istihbarat kaynakları incelendi. Kısaltılmış "
               "linkin hedefini görmek için 'Bağlantıyı takip et' işlemini kullanın.")
    tips = rep.section("Ne yapmalı?")
    tips.add("Resmî kanaldan doğrulayın", "Bankanızı/kurumu bildiğiniz numaradan arayın; SMS'teki numarayı değil")
    tips.add("Bilgi girmeyin", "Kart, şifre, T.C. kimlik no veya SMS onay kodu istenmez")
    tips.add("Bildirin", "Oltalama SMS'lerini operatörünüze ve usom.gov.tr'ye bildirebilirsiniz",
             url="https://www.usom.gov.tr/bildirim")


def _expand(ctx: Context, rep: Report, v: dict) -> None:
    """Yönlendirme zincirini HEAD istekleriyle, çerezsiz ve gövde indirmeden takip eder."""
    import requests
    url = v["text"][0]
    chain = rep.section("Yönlendirme zinciri")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0", "Accept": "*/*"})
    for hop in range(10):
        ctx.check_cancelled()
        try:
            resp = session.head(url, allow_redirects=False, timeout=8)
            if resp.status_code in (405, 501):  # HEAD desteklenmiyorsa gövdeyi indirmeden GET
                resp = session.get(url, allow_redirects=False, timeout=8, stream=True)
                resp.close()
        except requests.RequestException as e:
            chain.add(f"{hop + 1}. hata", f"{url} — {type(e).__name__}", level=Level.MUTED)
            break
        finally:
            session.cookies.clear()
        loc = resp.headers.get("Location")
        chain.add(f"{hop + 1}. HTTP {resp.status_code}", url, level=Level.INFO)
        if resp.status_code in (301, 302, 303, 307, 308) and loc:
            from urllib.parse import urljoin
            url = urljoin(url, loc)
            continue
        break
    rep.changed()
    a = assess_url(url)
    sec = rep.section(f"Son hedef: {a['registrable']}")
    for label, value, level in a["findings"]:
        sec.add(label, value, level=level)
    score = a["score"] + _intel(ctx, rep, sec, a["host"], a["registrable"])
    verdict, level = _verdict(score)
    sec.items.insert(0, Item("Değerlendirme", verdict, level=level))
    rep.summary = verdict
    rep.notice("Yalnızca HEAD istekleri gönderildi (sayfa içeriği indirilmedi, çerez saklanmadı). Yine de "
               "bağlantının ilk sunucusu isteğin geldiğini görmüş olabilir.")


# ---------------------------------------------------------------- IBAN

IBAN_LENGTHS = {"TR": 26, "DE": 22, "GB": 22, "FR": 27, "NL": 18, "BE": 16, "AT": 20, "CH": 21, "IT": 27,
                "ES": 24, "PL": 28, "SE": 24, "NO": 15, "DK": 18, "FI": 18, "IE": 22, "PT": 25, "GR": 27,
                "AZ": 28, "GE": 22, "AE": 23, "SA": 24, "QA": 29, "CY": 28, "BG": 22, "RO": 24, "LU": 20}
# Yalnızca büyük ve kodundan emin olunan bankalar; tam liste için TCMB EFT katılımcı listesine bakılmalı.
TR_BANKS = {"00010": "T.C. Ziraat Bankası", "00012": "Türkiye Halk Bankası", "00015": "Türkiye Vakıflar Bankası",
            "00046": "Akbank", "00062": "Garanti BBVA", "00064": "Türkiye İş Bankası", "00067": "Yapı Kredi",
            "00111": "QNB Türkiye", "00032": "Türk Ekonomi Bankası (TEB)", "00134": "DenizBank",
            "00099": "ING Bank", "00123": "HSBC", "00205": "Kuveyt Türk", "00206": "Türkiye Finans",
            "00203": "Albaraka Türk", "00209": "Ziraat Katılım", "00210": "Vakıf Katılım",
            "00059": "Şekerbank", "00103": "Fibabanka", "00135": "Anadolubank", "00146": "Odeabank",
            "00125": "Burgan Bank", "00124": "Alternatif Bank"}


def iban_input(value: str) -> str:
    v = re.sub(r"[\s-]", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{8,30}", v):
        raise ValueError("Geçersiz IBAN biçimi (ör. TR33 0006 1005 1978 6457 8413 26)")
    return v


def iban_valid(iban: str) -> bool:
    moved = iban[4:] + iban[:4]
    digits = "".join(str(int(c, 36)) for c in moved)
    return int(digits) % 97 == 1


def _iban(ctx: Context, rep: Report, v: dict) -> None:
    iban = v["iban"]
    country = iban[:2]
    sec = rep.section("IBAN")
    sec.add("Biçimli", " ".join(iban[i:i + 4] for i in range(0, len(iban), 4)))
    expected = IBAN_LENGTHS.get(country)
    length_ok = expected is None or len(iban) == expected
    checksum_ok = iban_valid(iban)
    if checksum_ok and length_ok:
        sec.add("Doğrulama", "Geçerli (MOD-97 sağlama toplamı doğru)", level=Level.OK)
    else:
        sec.add("Doğrulama", "GEÇERSİZ — " + ("uzunluk hatalı" if not length_ok else "sağlama toplamı tutmuyor; "
                "bir rakam yanlış yazılmış olabilir"), level=Level.BAD)
    sec.add("Ülke", country + (f" · {expected} karakter olmalı" if expected else ""))
    if country == "TR" and len(iban) == 26:
        bank_code, reserve, account = iban[4:9], iban[9], iban[10:]
        name = TR_BANKS.get(bank_code)
        sec.add("Banka kodu", bank_code + (f" · {name}" if name else " · listede yok (TCMB listesinden kontrol edin)"),
                level=Level.OK if name else Level.MUTED)
        if reserve != "0":
            sec.add("Rezerv hane", f"'{reserve}' — Türk IBAN'larında 0 olmalı", level=Level.BAD)
        sec.add("Hesap numarası", account)
    rep.section("Kaynak").link("TCMB EFT katılımcı bankalar", "https://www.tcmb.gov.tr/wps/wcm/connect/TR/TCMB+TR/"
                                                               "Main+Menu/Temel+Faaliyetler/Odeme+Hizmetleri/EFT")
    rep.notice("IBAN geçerliliği hesap sahibini göstermez. Ödeme öncesi bankanızın uygulamasında alıcı adının "
               "(kısmen gizli) eşleştiğini kontrol edin. IBAN geçmişe kaydedilmedi.")


# ---------------------------------------------------------------- kayıt

LINK = Field("text", "Şüpheli link veya SMS metni", "Kargonuz bekliyor: bit.ly/…", "multiline", link_input,
             sensitive=True)

register(Tool("linkcheck", "Şüpheli Link / SMS", "Oltalama linki analizi; linki açmadan", "SMS_FAILED",
              "Dolandırıcılık & Oltalama", [
                  Action("analyze", "Analiz (açmadan)", (LINK,), _linkcheck),
                  Action("expand", "Bağlantıyı takip et", (LINK,), _expand,
                         consent="Kısaltılmış/şüpheli linkin yönlendirmeleri telefondan takip edilecek (yalnızca "
                                 "HEAD isteği, sayfa indirilmez, çerez saklanmaz). Link kişiye özel bir kod "
                                 "taşıyorsa dolandırıcı numaranızın aktif olduğunu ve IP adresinizi görebilir. "
                                 "Emin değilseniz önce 'Analiz (açmadan)' kullanın.")]))
register(Tool("iban", "IBAN Doğrulama", "Sağlama toplamı, banka kodu, ülke (çevrimdışı)", "ACCOUNT_BALANCE",
              "Dolandırıcılık & Oltalama", [
                  Action("check", "Doğrula", (Field("iban", "IBAN", "TR33 0006 1005 1978 6457 8413 26",
                                                    parse=iban_input, sensitive=True),), _iban)]))
