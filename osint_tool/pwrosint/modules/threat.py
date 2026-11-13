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


def _hibp_email(ctx: Context, rep: Report, v: dict) -> None:
    key = ctx.require("haveibeenpwned_api_key", "Have I Been Pwned")
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
    breaches = sorted(resp.json(), key=lambda b: b.get("BreachDate", ""), reverse=True)
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


# ---------------------------------------------------------------- Shodan

def _shodan_host(ctx: Context, rep: Report, v: dict) -> None:
    key = ctx.require("shodan_api_key", "Shodan")
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
    svc = rep.section(f"Servisler ({len(data.get('data', []))})")
    for s in sorted(data.get("data", []), key=lambda s: s.get("port", 0)):
        desc = " ".join(x for x in (s.get("product"), s.get("version")) if x) or s.get("_shodan", {}).get("module", "")
        svc.add(f"{s.get('port')}/{s.get('transport', 'tcp')}", desc or "—")
    rep.section("Link").link("Shodan", f"https://www.shodan.io/host/{v['ip']}")


def _shodan_search(ctx: Context, rep: Report, v: dict) -> None:
    key = ctx.require("shodan_api_key", "Shodan")
    data = ctx.http.json("https://api.shodan.io/shodan/host/search",
                         params={"key": key, "query": v["query"], "minify": "true"})
    rep.summary = f"Toplam {data.get('total', 0):,} sonuç (ilk 100 gösteriliyor).".replace(",", ".")
    sec = rep.section("Eşleşmeler")
    for m in data.get("matches", [])[:100]:
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


def _vt_domain(ctx: Context, rep: Report, v: dict) -> None:
    attrs = _vt(ctx, f"domains/{v['domain']}")
    if attrs is None:
        rep.section("Sonuç").add("Durum", "VirusTotal'de kayıt yok", level=Level.MUTED)
        return
    _vt_stats(rep, attrs)
    if cats := attrs.get("categories"):
        rep.section("Kategoriler").add("Sınıflandırma", ", ".join(sorted(set(cats.values()))))
    rep.section("Link").link("VirusTotal", f"https://www.virustotal.com/gui/domain/{v['domain']}")


def _vt_ip(ctx: Context, rep: Report, v: dict) -> None:
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
                         needs_key="haveibeenpwned_api_key")]))
register(Tool("shodan", "Shodan", "Host detayı ve arama", "RADAR", "Tehdit İstihbaratı", [
    Action("host", "Host", (IP,), _shodan_host, needs_key="shodan_api_key"),
    Action("search", "Arama", (Field("query", "Sorgu", "port:22 country:TR", parse=validate.text),),
           _shodan_search, needs_key="shodan_api_key")]))
register(Tool("virustotal", "VirusTotal", "Domain, IP ve dosya itibarı", "SHIELD", "Tehdit İstihbaratı", [
    Action("domain", "Domain", (DOMAIN,), _vt_domain, needs_key="virustotal_api_key"),
    Action("ip", "IP", (IP,), _vt_ip, needs_key="virustotal_api_key"),
    Action("file", "Dosya hash", (Field("hash", "MD5 / SHA-1 / SHA-256", "44d88612fea8a8f36de82e1278abb02f",
                                        parse=file_hash),), _vt_file, needs_key="virustotal_api_key")]))
