"""Tehdit istihbaratı: sızıntılar (HIBP), Shodan, VirusTotal."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from html import unescape
from urllib.parse import quote

from ..core import validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

# ---------------------------------------------------------------- HIBP


def _strip_html(s: str) -> str:
    return unescape(re.sub(r"<[^>]+>", "", s or ""))


def xon_breaches(ctx: Context, rep: Report, email: str) -> None:
    """Anahtarsız yedek: XposedOrNot sızıntı analizi."""
    data = ctx.http.json("https://api.xposedornot.com/v1/breach-analytics", params={"email": email},
                         ok=(200, 404), timeout=max(20, ctx.settings.timeout))
    details = (((data or {}).get("ExposedBreaches") or {}).get("breaches_details")) or []
    details = [d for d in details if isinstance(d, dict)]
    rep.source("XposedOrNot", True, f"{len(details)} sızıntı")
    if not details:
        rep.section("Sonuç").add("Durum", "Bilinen hiçbir sızıntıda bulunamadı", level=Level.OK)
        return
    summary = ((data or {}).get("BreachMetrics") or {})
    rep.summary = f"{len(details)} sızıntıda bulundu."
    risk = (summary.get("risk") or [{}])[0] if isinstance(summary.get("risk"), list) else {}
    if risk.get("risk_label"):
        rep.section("Risk değerlendirmesi").add(
            "Risk", f"{risk.get('risk_label')} ({risk.get('risk_score', '?')}/100)",
            level=Level.BAD if str(risk.get("risk_label")).lower() in ("high", "yüksek") else Level.WARN)
    pw_types = {"plaintext": "Düz metin (çok tehlikeli)", "easytocrack": "Kolay kırılan hash",
                "hardtocrack": "Güçlü hash", "unknown": "Bilinmiyor"}
    for d in sorted(details, key=lambda d: str(d.get("xposed_date", "")), reverse=True):
        sec = rep.section(f"{d.get('breach', '?')} — {d.get('xposed_date', '?')}")
        sec.add("Sızan veriler", str(d.get("xposed_data", "")).replace(";", ", "), level=Level.BAD)
        if d.get("xposed_records"):
            sec.add("Etkilenen hesap", f"{int(d['xposed_records']):,}".replace(",", "."))
        if d.get("password_risk"):
            sec.add("Şifre saklama", pw_types.get(d["password_risk"], d["password_risk"]),
                    level=Level.BAD if d["password_risk"] in ("plaintext", "easytocrack") else Level.INFO)
        if d.get("domain"):
            sec.add("Site", d["domain"])
        if d.get("industry"):
            sec.add("Sektör", d["industry"])
        if desc := _strip_html(str(d.get("details", ""))):
            sec.note = desc[:300] + ("…" if len(desc) > 300 else "")


def _hibp_email(ctx: Context, rep: Report, v: dict) -> None:
    if not ctx.settings.haveibeenpwned_api_key:
        rep.notice("HIBP anahtarı yok; sızıntı verileri ücretsiz XposedOrNot veritabanından alındı.")
        xon_breaches(ctx, rep, v["email"])
        return
    key = ctx.settings.haveibeenpwned_api_key
    resp = ctx.http.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(v['email'])}",
                        params={"truncateResponse": "false"},
                        headers={"hibp-api-key": key, "User-Agent": ctx.settings.user_agent})
    if resp.status_code == 404:
        rep.section("Sonuç").add("Durum", "Bilinen hiçbir sızıntıda bulunamadı", level=Level.OK)
        return
    if resp.status_code == 401:
        raise OsintError("HIBP: API anahtarı geçersiz")
    if resp.status_code == 429:
        raise OsintError("HIBP: istek limiti aşıldı, birkaç saniye sonra tekrar deneyin")
    if resp.status_code != 200:
        raise OsintError(f"HIBP: HTTP {resp.status_code}")
    from ..core.http import parse_json
    breaches = sorted((b for b in parse_json(resp, list) if isinstance(b, dict)),
                      key=lambda b: b.get("BreachDate", ""), reverse=True)
    if not breaches:
        rep.section("Sonuç").add("Durum", "Bilinen hiçbir sızıntıda bulunamadı", level=Level.OK)
        return
    rep.summary = f"{len(breaches)} sızıntıda bulundu."
    for b in breaches:
        sec = rep.section(f"{b.get('Title', b.get('Name'))} — {b.get('BreachDate', '?')}")
        sec.add("Sızan veriler", ", ".join(b.get("DataClasses", [])), level=Level.BAD)
        sec.add("Etkilenen hesap", f"{b.get('PwnCount', 0):,}".replace(",", "."))
        if b.get("Domain"):
            sec.add("Site", b["Domain"])
        if desc := _strip_html(b.get("Description", "")):
            sec.note = desc[:300] + ("…" if len(desc) > 300 else "")


def pwned_count(ctx: Context, password: str) -> int:
    """k-anonimlik: şifrenin SHA-1 özetinin yalnızca ilk 5 karakteri gönderilir."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    resp = ctx.http.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"})
    if resp.status_code != 200:
        raise OsintError(f"Pwned Passwords: HTTP {resp.status_code}")
    for line in resp.text.splitlines():
        h, _, count = line.partition(":")
        if h == suffix:
            return int(count)
    return 0


COMMON_PATTERNS = ("123", "qwe", "asd", "abc", "password", "sifre", "şifre", "parola", "admin", "1907",
                   "1905", "1903", "1967", "galatasaray", "fenerbahce", "besiktas", "trabzon")


def password_strength(pw: str) -> list[tuple[str, str, Level]]:
    import math
    classes = [("küçük harf", any(c.islower() for c in pw)), ("büyük harf", any(c.isupper() for c in pw)),
               ("rakam", any(c.isdigit() for c in pw)), ("sembol", any(not c.isalnum() for c in pw))]
    pool = sum(n for (_, has), n in zip(classes, (26, 26, 10, 32)) if has) or 1
    bits = len(pw) * math.log2(pool)
    found = [p for p in COMMON_PATTERNS if p in pw.lower()]
    if found:
        bits = min(bits, 28)
    verdict, level = ((("Çok zayıf", Level.BAD) if bits < 28 else ("Zayıf", Level.BAD) if bits < 40
                      else ("Orta", Level.WARN) if bits < 60 else ("Güçlü", Level.OK)))
    out = [("Değerlendirme", f"{verdict} (~{bits:.0f} bit)", level),
           ("Uzunluk", f"{len(pw)} karakter", Level.OK if len(pw) >= 12 else Level.WARN),
           ("Karakter çeşitleri", ", ".join(n for n, has in classes if has) or "—",
            Level.OK if sum(h for _, h in classes) >= 3 else Level.WARN)]
    if found:
        out.append(("Tahmin edilebilir kalıp", ", ".join(found), Level.BAD))
    return out


def _hibp_password(ctx: Context, rep: Report, v: dict) -> None:
    count = pwned_count(ctx, v["password"])
    sec = rep.section("Sonuç")
    if count:
        sec.add("Durum", f"Bu şifre {count:,} kez sızıntılarda görülmüş. KULLANMAYIN!".replace(",", "."),
                level=Level.BAD)
    else:
        sec.add("Durum", "Bilinen sızıntılarda bulunamadı", level=Level.OK)
    sec.note = ("Şifre cihazdan çıkmaz: yalnızca SHA-1 özetinin ilk 5 karakteri gönderilir "
                "(k-anonimlik).")
    strength = rep.section("Şifre gücü (cihazda hesaplandı)")
    for label, value, level in password_strength(v["password"]):
        strength.add(label, value, level=level)


# ---------------------------------------------------------------- Shodan

def internetdb(ctx: Context, rep: Report, ip: str) -> None:
    """Anahtarsız yedek: Shodan InternetDB (haftalık güncellenen port/CVE özeti)."""
    db = ctx.http.json(f"https://internetdb.shodan.io/{ip}", ok=(200, 404))
    rep.source("Shodan InternetDB", True)
    if not db or "ports" not in db:
        rep.section("Sonuç").add("Durum", "Bu IP Shodan taramalarında görünmüyor", level=Level.MUTED)
        return
    sec = rep.section("Host (InternetDB)")
    sec.add("Açık portlar", ", ".join(map(str, db.get("ports") or [])) or "—",
            level=Level.WARN if db.get("ports") else Level.OK)
    if db.get("hostnames"):
        sec.add("Hostname'ler", ", ".join(db["hostnames"][:15]))
    if db.get("tags"):
        sec.add("Etiketler", ", ".join(db["tags"]), level=Level.WARN if {"malware", "c2", "compromised"} & set(db["tags"]) else Level.INFO)
    cpes = db.get("cpes") or []
    if cpes:
        sw = rep.section(f"Tespit edilen yazılımlar ({len(cpes)})")
        for c in cpes[:30]:
            # CPE 2.2: cpe:/<tür>:<üretici>:<ürün>:<sürüm>
            parts = c.split(":")
            name = " ".join(p.replace("_", " ") for p in parts[2:4] if p) or c
            sw.add(name, parts[4] if len(parts) > 4 and parts[4] not in ("*", "-") else "")
    vulns = db.get("vulns") or []
    vs = rep.section(f"Zafiyetler ({len(vulns)})")
    if not vulns:
        vs.add("Bilinen CVE yok", level=Level.OK)
    for cve in vulns[:60]:
        vs.add(cve, "", url=f"https://nvd.nist.gov/vuln/detail/{cve}", level=Level.BAD)
    rep.section("Link").link("Shodan", f"https://www.shodan.io/host/{ip}")


def _shodan_host(ctx: Context, rep: Report, v: dict) -> None:
    if not ctx.settings.shodan_api_key:
        rep.notice("Shodan anahtarı yok; ücretsiz InternetDB verisi gösteriliyor (banner ve konum için anahtar ekleyin).")
        internetdb(ctx, rep, v["ip"])
        return
    key = ctx.settings.shodan_api_key
    data = ctx.http.json(f"https://api.shodan.io/shodan/host/{v['ip']}", params={"key": key}, ok=(200, 404))
    if not data or "error" in data:
        rep.section("Sonuç").add("Durum", "Bu IP Shodan'da kayıtlı değil", level=Level.MUTED)
        return
    sec = rep.section("Host")
    for label, key_ in (("Kurum", "org"), ("ISP", "isp"), ("ASN", "asn"), ("İşletim sistemi", "os")):
        if data.get(key_):
            sec.add(label, data[key_])
    sec.add("Konum", ", ".join(x for x in (data.get("city"), data.get("country_name")) if x) or "—")
    if data.get("hostnames"):
        sec.add("Hostname'ler", ", ".join(data["hostnames"]))
    sec.add("Son tarama", (data.get("last_update") or "")[:10])
    vulns = sorted(data.get("vulns") or [])
    if vulns:
        sec.add("Zafiyetler", ", ".join(vulns[:20]), level=Level.BAD)
    services = [s for s in data.get("data") or [] if isinstance(s, dict)]
    svc = rep.section(f"Servisler ({len(services)})")
    for s in sorted(services, key=lambda s: s.get("port", 0)):
        desc = " ".join(x for x in (s.get("product"), s.get("version")) if x) or s.get("_shodan", {}).get("module", "")
        svc.add(f"{s.get('port')}/{s.get('transport', 'tcp')}", desc or "—")
    rep.section("Link").link("Shodan", f"https://www.shodan.io/host/{v['ip']}")


def _shodan_search(ctx: Context, rep: Report, v: dict) -> None:
    key = ctx.require("shodan_api_key", "Shodan")
    data = ctx.http.json("https://api.shodan.io/shodan/host/search",
                         params={"key": key, "query": v["query"], "minify": "true"})
    rep.summary = f"Toplam {data.get('total', 0):,} sonuç (ilk 100 gösteriliyor).".replace(",", ".")
    sec = rep.section("Eşleşmeler")
    for m in [m for m in data.get("matches") or [] if isinstance(m, dict)][:100]:
        where = ", ".join(x for x in (m.get("org"), (m.get("location") or {}).get("country_name")) if x)
        sec.add(f"{m.get('ip_str')}:{m.get('port')}", where,
                url=f"https://www.shodan.io/host/{m.get('ip_str')}")


# ---------------------------------------------------------------- VirusTotal

def _vt(ctx: Context, path: str) -> dict | None:
    key = ctx.require("virustotal_api_key", "VirusTotal")
    data = ctx.http.json(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key},
                         ok=(200, 404))
    return (data or {}).get("data", {}).get("attributes") if data else None


def _vt_stats(rep: Report, attrs: dict) -> None:
    stats = attrs.get("last_analysis_stats", {})
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    sec = rep.section("Analiz sonucu")
    level = Level.BAD if mal else Level.WARN if sus else Level.OK
    sec.add("Tespit", f"{mal} zararlı, {sus} şüpheli / {total} motor", level=level)
    if "reputation" in attrs:
        r = attrs["reputation"]
        sec.add("Topluluk puanı", r, level=Level.BAD if r < 0 else Level.OK)
    if ts := attrs.get("last_analysis_date"):
        sec.add("Son analiz", datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d"))
    flagged = [(eng, r.get("result")) for eng, r in (attrs.get("last_analysis_results") or {}).items()
               if r.get("category") in ("malicious", "suspicious")]
    if flagged:
        f = rep.section("İşaretleyen motorlar")
        for eng, res in sorted(flagged):
            f.add(eng, res or "", level=Level.BAD)


def otx_report(ctx: Context, rep: Report, kind: str, value: str) -> None:
    """Anahtarsız yedek: AlienVault OTX topluluk tehdit istihbaratı."""
    base = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{value}"
    data = ctx.http.json(f"{base}/general", timeout=max(20, ctx.settings.timeout))
    rep.source("AlienVault OTX", True)
    pulses = [p for p in ((data.get("pulse_info") or {}).get("pulses") or []) if isinstance(p, dict)]
    count = (data.get("pulse_info") or {}).get("count", len(pulses))
    sec = rep.section("Tehdit istihbaratı (AlienVault OTX)")
    sec.add("Tehdit raporu (pulse)", f"{count} rapor" if count else "Hiçbir raporda geçmiyor",
            level=Level.BAD if count else Level.OK)
    validation = [x.get("name") or x.get("source") for x in data.get("validation") or [] if isinstance(x, dict)]
    if validation:
        sec.add("Beyaz liste", ", ".join(str(x) for x in validation[:5]), level=Level.OK)
    if data.get("reputation"):
        sec.add("İtibar puanı", data["reputation"], level=Level.BAD if data["reputation"] > 0 else Level.INFO)
    if data.get("country_name"):
        sec.add("Ülke", data["country_name"])
    if data.get("asn"):
        sec.add("ASN", data["asn"])
    if kind == "file" and data.get("type_title"):
        sec.add("Dosya türü", data["type_title"])
    tags = sorted({t for p in pulses for t in p.get("tags") or []})
    families = sorted({m.get("display_name") for p in pulses for m in p.get("malware_families") or []
                       if isinstance(m, dict) and m.get("display_name")})
    if families:
        sec.add("Zararlı aileleri", ", ".join(families[:10]), level=Level.BAD)
    if tags:
        sec.add("Etiketler", ", ".join(tags[:20]), level=Level.WARN)
    if pulses:
        ps = rep.section(f"Raporlar ({len(pulses)})")
        for p in pulses[:20]:
            ps.add(p.get("name", "?"), str(p.get("created", ""))[:10],
                   url=f"https://otx.alienvault.com/pulse/{p.get('id')}", level=Level.WARN)
    rep.section("Link").link("OTX", f"https://otx.alienvault.com/indicator/{kind}/{value}")


def _vt_or_otx(ctx: Context, rep: Report, kind: str, value: str) -> bool:
    if ctx.settings.virustotal_api_key:
        return False
    rep.notice("VirusTotal anahtarı yok; tehdit verileri ücretsiz AlienVault OTX'ten alındı.")
    otx_report(ctx, rep, kind, value)
    return True


def _vt_domain(ctx: Context, rep: Report, v: dict) -> None:
    if _vt_or_otx(ctx, rep, "domain", v["domain"]):
        return
    attrs = _vt(ctx, f"domains/{v['domain']}")
    if attrs is None:
        rep.section("Sonuç").add("Durum", "VirusTotal'de kayıt yok", level=Level.MUTED)
        return
    _vt_stats(rep, attrs)
    if cats := attrs.get("categories"):
        rep.section("Kategoriler").add("Sınıflandırma", ", ".join(sorted(set(cats.values()))))
    rep.section("Link").link("VirusTotal", f"https://www.virustotal.com/gui/domain/{v['domain']}")


def _vt_ip(ctx: Context, rep: Report, v: dict) -> None:
    if _vt_or_otx(ctx, rep, "IPv4" if ":" not in v["ip"] else "IPv6", v["ip"]):
        return
    attrs = _vt(ctx, f"ip_addresses/{v['ip']}")
    if attrs is None:
        rep.section("Sonuç").add("Durum", "VirusTotal'de kayıt yok", level=Level.MUTED)
        return
    _vt_stats(rep, attrs)
    sec = rep.section("Ağ")
    sec.add("ASN", f"AS{attrs.get('asn', '?')} {attrs.get('as_owner', '')}".strip())
    sec.add("Ülke", attrs.get("country", "—"))
    rep.section("Link").link("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{v['ip']}")


def file_hash(value: str) -> str:
    v = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", v):
        raise ValueError("MD5, SHA-1 veya SHA-256 özeti girin")
    return v


def _vt_file(ctx: Context, rep: Report, v: dict) -> None:
    if _vt_or_otx(ctx, rep, "file", v["hash"]):
        return
    attrs = _vt(ctx, f"files/{v['hash']}")
    if attrs is None:
        rep.section("Sonuç").add("Durum", "Bu dosya VirusTotal'de hiç taranmamış", level=Level.MUTED)
        return
    info = rep.section("Dosya")
    info.add("Ad", attrs.get("meaningful_name", "—"))
    info.add("Tür", attrs.get("type_description", "—"))
    info.add("Boyut", f"{attrs.get('size', 0):,} bayt".replace(",", "."))
    if label := (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"):
        info.add("Tehdit", label, level=Level.BAD)
    _vt_stats(rep, attrs)
    rep.section("Link").link("VirusTotal", f"https://www.virustotal.com/gui/file/{v['hash']}")


# ---------------------------------------------------------------- kayıt

IP = Field("ip", "IP adresi", "8.8.8.8", "number", validate.ip)
DOMAIN = Field("domain", "Domain", "ornek.com", "url", validate.domain)

register(Tool("hibp", "Sızıntı Kontrolü", "Have I Been Pwned: e-posta ve şifre", "GPP_MAYBE",
              "Tehdit İstihbaratı", [
                  Action("password", "Şifre", (Field("password", "Şifre", "Cihazdan çıkmaz", "password",
                                                     lambda s: s),), _hibp_password),
                  Action("email", "E-posta", (Field("email", "E-posta", "kisi@ornek.com", "email",
                                                    validate.email),), _hibp_email,
                         better_with="haveibeenpwned_api_key")]))
register(Tool("shodan", "Shodan", "Host detayı ve arama", "RADAR", "Tehdit İstihbaratı", [
    Action("host", "Host", (IP,), _shodan_host, better_with="shodan_api_key"),
    Action("search", "Arama", (Field("query", "Sorgu", "port:22 country:TR", parse=validate.text),),
           _shodan_search, needs_key="shodan_api_key")]))
register(Tool("virustotal", "VirusTotal", "Domain, IP ve dosya itibarı", "SHIELD", "Tehdit İstihbaratı", [
    Action("domain", "Domain", (DOMAIN,), _vt_domain, better_with="virustotal_api_key"),
    Action("ip", "IP", (IP,), _vt_ip, better_with="virustotal_api_key"),
    Action("file", "Dosya hash", (Field("hash", "MD5 / SHA-1 / SHA-256", "44d88612fea8a8f36de82e1278abb02f",
                                        parse=file_hash),), _vt_file, better_with="virustotal_api_key")]))


# ---------------------------------------------------------------- taklit domainler

from ..core import dns  # noqa: E402

TWO_LEVEL = {"com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "gen.tr", "biz.tr", "info.tr", "web.tr",
             "co.uk", "org.uk", "com.au", "co.jp", "com.br", "co.in", "com.de", "co.nz", "com.cn"}
ALT_TLDS = ["com", "net", "org", "com.tr", "net.tr", "info", "co", "io", "xyz", "online", "site", "shop",
            "app", "live", "top", "biz", "me", "tr", "store", "click", "support"]
KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
    "o": "ipl", "p": "o", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb",
    "j": "hukn", "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn",
    "n": "bhjm", "m": "njk",
}
HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l"], "e": ["3"],
              "a": ["4"], "s": ["5"], "m": ["rn"], "w": ["vv"], "d": ["cl"], "g": ["q"], "b": ["d"]}
AFFIXES = ["giris", "login", "destek", "guvenlik", "secure", "online", "hesap", "tr", "app", "my"]


def split_domain(domain: str) -> tuple[str, str]:
    parts = domain.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_LEVEL:
        return parts[-3], ".".join(parts[-2:])
    return parts[-2], parts[-1]


def typosquats(domain: str, limit: int = 400) -> dict[str, str]:
    """{aday domain: üretim yöntemi}"""
    name, tld = split_domain(domain)
    out: dict[str, str] = {}

    def add(label: str, kind: str, suffix: str = tld) -> None:
        label = label.strip("-")
        if label and (label != name or suffix != tld) and len(label) <= 63 and "--" not in label:
            cand = f"{label}.{suffix}"
            if cand != domain and cand not in out:
                out[cand] = kind

    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "harf eksiltme")
        add(name[:i] + name[i] + name[i:], "harf tekrarı")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "yer değiştirme")
        for ch in KEYBOARD.get(name[i], ""):
            add(name[:i] + ch + name[i + 1:], "komşu tuş")
        for g in HOMOGLYPHS.get(name[i], []):
            add(name[:i] + g + name[i + 1:], "benzer karakter")
        if 0 < i < len(name):
            add(name[:i] + "-" + name[i:], "tire ekleme")
    for a, b in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        if a in name:
            add(name.replace(a, b), "benzer karakter")
    for t in ALT_TLDS:
        if t != tld:
            add(name, "farklı uzantı", t)
    for affix in AFFIXES:
        add(f"{name}-{affix}", "oltalama eki")
        add(f"{affix}-{name}", "oltalama eki")
        add(f"{name}{affix}", "oltalama eki")
    return dict(list(out.items())[:limit])


def _typosquat(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    cands = typosquats(domain)

    def check(item):
        cand, kind = item
        try:
            status, a = dns.query(ctx, cand, "A")
            if status == "NXDOMAIN":
                return cand, kind, None, []
            mx = dns.resolve(ctx, cand, "MX") if a else []
            ns = [] if a else dns.resolve(ctx, cand, "NS")
            return cand, kind, (a or ns or ["kayıtlı"]), mx
        except OsintError:
            return cand, kind, None, []

    results = ctx.parallel(check, cands.items())
    live = [(c, k, a, mx) for c, k, a, mx in results if a]
    sec = rep.section(f"Kayıtlı benzer domainler ({len(live)})",
                      note="Kırmızı: e-posta alabiliyor (MX) — oltalama e-postası için kullanılabilir.")
    for cand, kind, addrs, mx in sorted(live, key=lambda x: (not x[3], x[0])):
        ip = next((x for x in addrs if validate.is_ip(x)), "")
        sec.add(cand, f"{kind}{' · ' + ip if ip else ''}{' · MX var' if mx else ''}",
                url=f"https://{cand}", level=Level.BAD if mx else Level.WARN)
    rep.summary = f"{len(cands)} varyasyon denendi, {len(live)} tanesi kayıtlı."
    rep.section("Dış araçlar").link("dnstwist.it", f"https://dnstwist.it/")


# ---------------------------------------------------------------- DNS kara listeleri

DNSBLS = {
    "zen.spamhaus.org": "Spamhaus ZEN",
    "bl.spamcop.net": "SpamCop",
    "b.barracudacentral.org": "Barracuda",
    "dnsbl.sorbs.net": "SORBS",
    "psbl.surriel.com": "PSBL",
    "dnsbl-1.uceprotect.net": "UCEPROTECT L1",
    "dnsbl.dronebl.org": "DroneBL",
    "all.s5h.net": "s5h",
    "bl.mailspike.net": "Mailspike",
    "spam.dnsbl.anonmails.de": "Anonmails",
}


def dnsbl_name(ip: str, zone: str) -> str:
    return ".".join(reversed(ip.split("."))) + "." + zone


def _blacklist(ctx: Context, rep: Report, v: dict) -> None:
    ip: str = v["ip"]
    if ":" in ip:
        raise OsintError("DNS kara listeleri şimdilik yalnızca IPv4 destekliyor")

    def check(zone):
        try:
            status, answers = dns.query(ctx, dnsbl_name(ip, zone), "A")
        except OsintError as e:
            return zone, "error", str(e)
        codes = [a for a in answers if a.startswith("127.")]
        if not codes:
            return zone, "clean", ""
        if any(c.startswith("127.255.255.") or c == "127.0.0.1" for c in codes):
            return zone, "blocked", "liste genel DNS sunucularından sorguyu reddetti"
        return zone, "listed", ", ".join(codes)

    results = ctx.parallel(check, DNSBLS)
    listed = [r for r in results if r[1] == "listed"]
    sec = rep.section("Kara liste kontrolü")
    for zone, state, detail in sorted(results, key=lambda r: ["listed", "clean", "blocked", "error"].index(r[1])):
        name = DNSBLS[zone]
        if state == "listed":
            sec.add(name, f"LİSTEDE ({detail})", level=Level.BAD)
        elif state == "clean":
            sec.add(name, "Temiz", level=Level.OK)
        else:
            rep.source(name, False, detail.split(": ", 1)[-1])
    rep.summary = (f"{len(listed)} kara listede bulundu — bu IP'den gelen e-postalar engellenebilir."
                   if listed else "Kontrol edilen listelerin hiçbirinde yok.")
    links = rep.section("Dış araçlar")
    links.link("MXToolbox", f"https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{ip}")
    links.link("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}")
    links.link("Spamhaus", f"https://check.spamhaus.org/results/?query={ip}")


# ---------------------------------------------------------------- OpenPhish

def _openphish(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    resp = ctx.http.get("https://openphish.com/feed.txt", timeout=max(30, ctx.settings.timeout))
    if resp.status_code != 200:
        raise OsintError(f"OpenPhish: HTTP {resp.status_code}")
    from urllib.parse import urlsplit
    hits = [u for u in resp.text.split()
            if (h := (urlsplit(u).hostname or "").lower()) == domain or h.endswith("." + domain)]
    sec = rep.section("OpenPhish (son 7 gün)")
    if hits:
        for u in hits[:50]:
            sec.add(u, level=Level.BAD)
        rep.summary = f"{len(hits)} aktif oltalama adresi bu domain altında!"
    else:
        sec.add("Durum", "Güncel oltalama listesinde yok", level=Level.OK)
    sec.note = "Ücretsiz akış, OpenPhish'in son tespitlerinin bir bölümünü içerir."
    links = rep.section("Dış araçlar")
    links.link("Google Safe Browsing", f"https://transparencyreport.google.com/safe-browsing/search?url={domain}")
    links.link("PhishTank", "https://phishtank.org/")
    links.link("URLhaus", f"https://urlhaus.abuse.ch/browse.php?search={domain}")


register(Tool("phishing", "Oltalama & Taklit", "Benzer kayıtlı domainler, OpenPhish", "PHISHING",
              "Tehdit İstihbaratı", [
                  Action("typosquat", "Taklit domainler", (DOMAIN,), _typosquat),
                  Action("openphish", "OpenPhish", (DOMAIN,), _openphish)]))
register(Tool("blacklist", "Kara Liste", "IP'nin 10 spam/DNSBL listesindeki durumu", "BLOCK",
              "Tehdit İstihbaratı", [Action("check", "Kontrol", (IP,), _blacklist)]))
