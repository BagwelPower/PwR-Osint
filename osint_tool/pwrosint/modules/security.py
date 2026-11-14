"""Güvenlik analizi: e-posta başlığı adli incelemesi ve CVE araştırması."""

from __future__ import annotations

import email
import email.policy
import ipaddress
import re
from datetime import timezone
from email.utils import parseaddr, parsedate_to_datetime

from ..core.context import Context
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

# ---------------------------------------------------------------- e-posta başlığı

_IP_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})\]?")


def parse_headers(value: str) -> email.message.Message:
    text = value.replace("\r\n", "\n").strip()
    if ":" not in text.split("\n", 1)[0]:
        raise ValueError("E-posta başlıklarını yapıştırın (Gmail: ⋮ → Orijinali göster; Outlook: Mesaj kaynağı)")
    msg = email.message_from_string(text + "\n\n", policy=email.policy.compat32)
    if not msg.get_all("Received") and not msg.get("From"):
        raise ValueError("Received veya From başlığı bulunamadı; tam başlık metnini yapıştırın")
    return msg


def _public_ips(text: str) -> list[str]:
    out = []
    for m in _IP_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_global and str(ip) not in out:
            out.append(str(ip))
    return out


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in addr else ""


def _org_domain(domain: str) -> str:
    """Kaba kayıtlı-alan adı (son iki etiket; com.tr gibi iki seviyeli uzantılarda üç)."""
    parts = domain.split(".")
    two_level = {"com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "co.uk", "com.au", "co.jp", "com.br"}
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in two_level else 2
    return ".".join(parts[-n:])


def parse_received(header: str) -> dict:
    h = " ".join(header.split())
    frm = re.search(r"\bfrom\s+(\S+)", h, re.I)
    by = re.search(r"\bby\s+(\S+)", h, re.I)
    with_ = re.search(r"\bwith\s+(\S+)", h, re.I)
    when = None
    if ";" in h:
        try:
            when = parsedate_to_datetime(h.rsplit(";", 1)[1].strip())
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, IndexError):
            when = None
    before_by = h.split(" by ", 1)[0] if " by " in h else h
    return {"from": frm.group(1) if frm else "", "by": by.group(1) if by else "",
            "with": with_.group(1) if with_ else "", "time": when, "ips": _public_ips(before_by)}


def _auth_results(msg: email.message.Message) -> dict[str, str]:
    """Yalnızca en üstteki Authentication-Results: onu alıcı sunucu ekler. Alttakiler sahtelenebilir."""
    ar = msg.get_all("Authentication-Results") or msg.get_all("ARC-Authentication-Results") or []
    if not ar:
        return {}
    top = " ".join(ar[0].split())
    out = {}
    for mech in ("spf", "dkim", "dmarc", "arc"):
        m = re.search(rf"\b{mech}=(\w+)", top, re.I)
        if m:
            out[mech] = m.group(1).lower()
    m = re.search(r"header\.from=([\w.-]+)", top, re.I)
    if m:
        out["header.from"] = m.group(1).lower()
    m = re.search(r"header\.d=([\w.-]+)|header\.i=@?([\w.-]+)", top, re.I)
    if m:
        out["dkim.domain"] = (m.group(1) or m.group(2)).lower()
    m = re.search(r"smtp\.mailfrom=(?:[^@\s;]*@)?([\w.-]+)", top, re.I)
    if m:
        out["spf.domain"] = m.group(1).lower()
    return out


def _email_header(ctx: Context, rep: Report, v: dict) -> None:
    msg: email.message.Message = v["headers"]
    from_name, from_addr = parseaddr(msg.get("From", ""))
    from_dom = _domain(from_addr)
    reply_dom = _domain(parseaddr(msg.get("Reply-To", ""))[1])
    return_dom = _domain(parseaddr(msg.get("Return-Path", ""))[1])
    msgid_dom = _domain(msg.get("Message-ID", "").strip("<>"))

    head = rep.section("Mesaj")
    for label, key in (("Konu", "Subject"), ("Kimden", "From"), ("Kime", "To"), ("Tarih", "Date"),
                       ("Yanıt adresi (Reply-To)", "Reply-To"), ("Dönüş yolu (Return-Path)", "Return-Path"),
                       ("Message-ID", "Message-ID"), ("Gönderen yazılım", "X-Mailer"),
                       ("Gönderen yazılım", "User-Agent")):
        if msg.get(key):
            head.add(label, " ".join(str(msg.get(key)).split())[:300])

    # --- kimlik doğrulama
    auth = _auth_results(msg)
    sec = rep.section("Kimlik doğrulama (alıcı sunucunun kararı)")
    if not auth:
        sec.add("Authentication-Results", "Yok — alıcı sunucu sonuç eklememiş; SPF/DKIM/DMARC değerlendirilemedi",
                level=Level.WARN)
    good = {"pass"}
    for mech, label in (("spf", "SPF"), ("dkim", "DKIM"), ("dmarc", "DMARC")):
        if mech in auth:
            val = auth[mech]
            level = Level.OK if val in good else Level.MUTED if val in ("none", "neutral") else Level.BAD
            sec.add(label, val.upper(), level=level)
    if auth.get("dkim.domain") and from_dom and _org_domain(auth["dkim.domain"]) != _org_domain(from_dom):
        sec.add("DKIM imzalayan", f"{auth['dkim.domain']} — From domaini ({from_dom}) ile uyuşmuyor", level=Level.WARN)
    if auth:
        sec.note = "Yalnızca en üstteki Authentication-Results dikkate alındı; alttakiler sahtelenebilir."

    # --- tutarlılık
    flags = rep.section("Sahtecilik göstergeleri")
    if reply_dom and from_dom and _org_domain(reply_dom) != _org_domain(from_dom):
        flags.add("Reply-To farklı domain", f"Yanıtlar {reply_dom} adresine gider (From: {from_dom})", level=Level.BAD)
    if return_dom and from_dom and _org_domain(return_dom) != _org_domain(from_dom):
        flags.add("Return-Path farklı domain", f"{return_dom} (From: {from_dom}) — toplu gönderim servislerinde "
                  "normal olabilir", level=Level.WARN)
    if msgid_dom and from_dom and _org_domain(msgid_dom) != _org_domain(from_dom):
        flags.add("Message-ID farklı domain", f"{msgid_dom} (From: {from_dom})", level=Level.WARN)
    if from_name and "@" in from_name and _domain(from_name) and _domain(from_name) != from_dom:
        flags.add("Görünen ad başka adres içeriyor", f'"{from_name}" — gerçek adres {from_addr}', level=Level.BAD)
    brands = ("paypal", "apple", "microsoft", "google", "amazon", "netflix", "garanti", "akbank", "ziraat",
              "isbank", "yapikredi", "turkcell", "vodafone", "e-devlet", "edevlet", "ptt", "hepsiburada", "trendyol")
    lname = (from_name or "").lower().replace(" ", "")
    for b in brands:
        if b in lname and b not in from_dom.replace("-", ""):
            flags.add("Marka taklidi", f"Görünen ad '{from_name}' ama gönderen domain {from_dom}", level=Level.BAD)
            break
    if not flags.items:
        flags.add("Belirgin tutarsızlık yok", level=Level.OK)

    # --- teslim yolu
    received = msg.get_all("Received") or []
    hops = [parse_received(r) for r in received]
    origin_ip = next((ip for hop in reversed(hops) for ip in hop["ips"]), None)
    path = rep.section(f"Teslim yolu ({len(hops)} sunucu, ilkinden sonuncusuna)")
    prev_time = None
    total_delay = 0.0
    for i, hop in enumerate(reversed(hops), 1):
        when = hop["time"]
        delay = ""
        if when and prev_time:
            d = (when - prev_time).total_seconds()
            total_delay += max(d, 0)
            delay = f" · +{d:.0f} sn" if d >= 0 else f" · saat tutarsız ({d:.0f} sn)"
        prev_time = when or prev_time
        desc = f"{hop['from'] or '?'} → {hop['by'] or '?'}"
        extra = " · ".join(x for x in (hop["with"], when.strftime("%Y-%m-%d %H:%M:%S %Z") if when else "") if x)
        path.add(f"{i}. {desc}"[:120], f"{extra}{delay}" + (f" · IP {', '.join(hop['ips'])}" if hop["ips"] else ""),
                 level=Level.WARN if delay.startswith(" · +") and float(delay[4:-3]) > 3600 else Level.INFO)
    if hops:
        path.note = f"Toplam teslim süresi ≈ {total_delay:.0f} sn."

    src = rep.section("Kaynak")
    x_orig = msg.get("X-Originating-IP") or msg.get("X-Sender-IP")
    if x_orig:
        ips = _public_ips(x_orig)
        if ips:
            src.add("Gönderenin IP'si (X-Originating-IP)", ips[0], level=Level.WARN)
            origin_ip = origin_ip or ips[0]
    if origin_ip:
        src.add("İlk public IP (Received zinciri)", origin_ip, level=Level.WARN)
        src.note = "Bu IP'yi 'IP & Domain' veya 'Kara Liste' araçlarıyla inceleyin (yanındaki 🔍 ile)."
    else:
        src.add("Public IP bulunamadı", level=Level.MUTED)
    if from_dom:
        src.add("Gönderen domain", from_dom)
    rep.notice("Başlıklar yalnızca cihazda incelendi; geçmişe kaydedilmedi. Bu bir karar desteğidir: "
               "SPF/DKIM/DMARC geçen bir e-posta da oltalama olabilir.")


# ---------------------------------------------------------------- kayıt

register(Tool("emailheader", "E-posta Başlık Analizi", "Oltalama incelemesi: SPF/DKIM/DMARC, yol, kaynak IP",
              "MARK_EMAIL_UNREAD", "Güvenlik Analizi", [
                  Action("analyze", "İncele", (Field("headers", "E-posta başlıkları",
                                                     "Received: from … (Gmail: ⋮ → Orijinali göster)", "multiline",
                                                     parse_headers, sensitive=True),), _email_header)]))



# ---------------------------------------------------------------- CVE

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = 24 * 3600
NVD_RETRY_DELAY = 6  # sn; anahtarsız NVD limiti (testlerde 0)


def cve_id(value: str) -> str:
    v = value.strip().upper().replace("_", "-")
    if not CVE_RE.match(v):
        raise ValueError("Format: CVE-2021-44228")
    return v


def _keyword(value: str) -> str:
    v = " ".join(value.split())
    if len(v) < 3:
        raise ValueError("En az 3 karakter (ör. 'fortinet ssl vpn', 'apache struts')")
    return v


def load_kev(ctx: Context) -> dict[str, dict]:
    """CISA 'aktif olarak istismar edilen zafiyetler' kataloğu; günde bir yenilenir, önbellekte tutulur."""
    import json as _json
    import os
    import time as _time

    from ..core.config import config_path
    from ..core.errors import OsintError

    cache = config_path().with_name("cisa-kev.json")
    data = None
    try:
        if cache.exists() and _time.time() - cache.stat().st_mtime < KEV_MAX_AGE:
            data = _json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if data is None:
        try:
            data = ctx.http.json(KEV_URL, timeout=max(30, ctx.settings.timeout))
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                tmp = cache.with_suffix(".tmp")
                tmp.write_text(_json.dumps(data), encoding="utf-8")
                os.replace(tmp, cache)
            except OSError:
                pass
        except OsintError:
            if cache.exists():
                data = _json.loads(cache.read_text(encoding="utf-8"))
            else:
                raise
    return {str(v.get("cveID", "")).upper(): v for v in (data or {}).get("vulnerabilities") or [] if isinstance(v, dict)}


def _cvss(metrics: dict) -> tuple[float | None, str, str, str]:
    """(puan, önem, vektör, sürüm) — en yeni CVSS sürümünü tercih eder."""
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                     ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData") or {}
            sev = data.get("baseSeverity") or primary.get("baseSeverity") or ""
            return data.get("baseScore"), str(sev), data.get("vectorString", ""), ver
    return None, "", "", ""


SEVERITY_TR = {"CRITICAL": "Kritik", "HIGH": "Yüksek", "MEDIUM": "Orta", "LOW": "Düşük", "NONE": "Yok"}


def _sev_level(score: float | None) -> Level:
    if score is None:
        return Level.INFO
    return Level.BAD if score >= 7 else Level.WARN if score >= 4 else Level.INFO


def _nvd(ctx: Context, params: dict) -> dict:
    from ..core.errors import OsintError
    for attempt in range(2):  # anahtarsız NVD: 30 sn'de 5 istek; 403/429'da bir kez bekleyip dene
        try:
            return ctx.http.json(NVD, params=params, timeout=max(30, ctx.settings.timeout))
        except OsintError as e:
            if attempt == 0 and any(c in str(e) for c in ("403", "429", "503")):
                ctx.cancel_event.wait(NVD_RETRY_DELAY)
                continue
            raise
    return {}


def _cve_circl(ctx: Context, cid: str) -> dict:
    """Yedek kaynak: CIRCL Vulnerability-Lookup (CVE JSON 5 biçimi)."""
    data = ctx.http.json(f"https://cve.circl.lu/api/cve/{cid}", timeout=max(20, ctx.settings.timeout))
    cna = ((data or {}).get("containers") or {}).get("cna") or {}
    desc = next((d.get("value", "") for d in cna.get("descriptions") or [] if d.get("lang", "").startswith("en")), "")
    score = sev = vector = ver = ""
    for m in cna.get("metrics") or []:
        for key, v in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0")):
            if key in m:
                score, sev, vector, ver = (m[key].get("baseScore"), m[key].get("baseSeverity", ""),
                                           m[key].get("vectorString", ""), v)
                break
        if score:
            break
    meta = (data or {}).get("cveMetadata") or {}
    return {"id": cid, "published": meta.get("datePublished", ""), "status": meta.get("state", ""),
            "description": desc, "score": score or None, "severity": sev, "vector": vector, "version": ver,
            "cwes": [d.get("cweId") for pt in cna.get("problemTypes") or [] for d in pt.get("descriptions") or []
                     if d.get("cweId")],
            "products": [f"{a.get('vendor', '')} {a.get('product', '')}".strip() for a in cna.get("affected") or []],
            "references": [r.get("url") for r in cna.get("references") or [] if r.get("url")]}


def _cve_nvd(ctx: Context, cid: str) -> dict | None:
    data = _nvd(ctx, {"cveId": cid})
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    c = vulns[0].get("cve") or {}
    score, sev, vector, ver = _cvss(c.get("metrics") or {})
    desc = next((d.get("value", "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
    products = []
    for conf in c.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable"):
                    parts = str(m.get("criteria", "")).split(":")
                    if len(parts) > 5:
                        rng = " ".join(x for x in (
                            f"≥{m['versionStartIncluding']}" if m.get("versionStartIncluding") else "",
                            f">{m['versionStartExcluding']}" if m.get("versionStartExcluding") else "",
                            f"<{m['versionEndExcluding']}" if m.get("versionEndExcluding") else "",
                            f"≤{m['versionEndIncluding']}" if m.get("versionEndIncluding") else "") if x)
                        ver_txt = parts[5] if parts[5] not in ("*", "-") else ""
                        products.append(f"{parts[3]} {parts[4]} {ver_txt} {rng}".replace("_", " ").strip())
    return {"id": c.get("id", cid), "published": c.get("published", ""), "status": c.get("vulnStatus", ""),
            "description": desc, "score": score, "severity": sev, "vector": vector, "version": ver,
            "cwes": [d.get("value") for w in c.get("weaknesses") or [] for d in w.get("description") or []
                     if str(d.get("value", "")).startswith("CWE-")],
            "products": list(dict.fromkeys(products)),
            "references": [r.get("url") for r in c.get("references") or [] if r.get("url")]}


def _cve(ctx: Context, rep: Report, v: dict) -> None:
    from ..core.errors import OsintError
    cid = v["cve"]
    info = None
    try:
        info = _cve_nvd(ctx, cid)
        rep.source("NVD", True)
    except OsintError as e:
        rep.source("NVD", False, str(e).split(": ", 1)[-1])
    if info is None:
        try:
            info = _cve_circl(ctx, cid)
            rep.source("CIRCL", True)
            if not info.get("description"):
                info = None
        except OsintError as e:
            rep.source("CIRCL", False, str(e).split(": ", 1)[-1])
    if info is None:
        if any(ok for _, ok, _ in rep.sources):
            rep.section("Sonuç").add("Durum", f"{cid} kayıtlı değil (rezerve edilmiş ya da hatalı numara)",
                                     level=Level.MUTED)
            return
        raise OsintError("Zafiyet veritabanlarına ulaşılamadı (NVD, CIRCL)")

    sec = rep.section(f"{info['id']}")
    score = info["score"]
    sev_tr = SEVERITY_TR.get(str(info["severity"]).upper(), info["severity"])
    sec.add("CVSS", f"{score} · {sev_tr} (CVSS {info['version']})" if score is not None else "Henüz puanlanmadı",
            level=_sev_level(score))
    if info["vector"]:
        sec.add("Vektör", info["vector"])
        if "AV:N" in info["vector"]:
            sec.add("Saldırı yolu", "Ağ üzerinden (uzaktan istismar edilebilir)", level=Level.WARN)
        if "PR:N" in info["vector"] and "UI:N" in info["vector"]:
            sec.add("Ön koşul", "Kimlik doğrulama ve kullanıcı etkileşimi gerekmiyor", level=Level.WARN)
    if info["cwes"]:
        sec.add("Zafiyet türü (CWE)", ", ".join(dict.fromkeys(info["cwes"])))
    sec.add("Yayın tarihi", str(info["published"])[:10])
    if info["status"]:
        sec.add("Durum", info["status"])
    if info["description"]:
        sec.note = info["description"][:900]
    rep.changed()

    exp = rep.section("İstismar durumu")
    try:
        kev = load_kev(ctx).get(cid)
        rep.source("CISA KEV", True)
        if kev:
            exp.add("CISA KEV", f"AKTİF OLARAK İSTİSMAR EDİLİYOR (listeye eklenme: {kev.get('dateAdded', '?')})",
                    level=Level.BAD)
            if str(kev.get("knownRansomwareCampaignUse", "")).lower() == "known":
                exp.add("Fidye yazılımı", "Fidye yazılımı kampanyalarında kullanıldığı biliniyor", level=Level.BAD)
            if kev.get("requiredAction"):
                exp.add("Gerekli aksiyon", kev["requiredAction"])
        else:
            exp.add("CISA KEV", "Aktif istismar listesinde değil", level=Level.OK)
    except OsintError as e:
        rep.source("CISA KEV", False, str(e).split(": ", 1)[-1])
    try:
        ep = ctx.http.json("https://api.first.org/data/v1/epss", params={"cve": cid})
        rows = [r for r in (ep or {}).get("data") or [] if isinstance(r, dict)]
        rep.source("FIRST EPSS", True)
        if rows:
            p, pct = float(rows[0].get("epss", 0)), float(rows[0].get("percentile", 0))
            exp.add("EPSS (30 gün içinde istismar olasılığı)", f"%{p * 100:.2f} · tüm CVE'lerin %{pct * 100:.0f}'inden yüksek",
                    level=Level.BAD if p >= 0.1 else Level.WARN if p >= 0.01 else Level.INFO)
    except OsintError as e:
        rep.source("FIRST EPSS", False, str(e).split(": ", 1)[-1])

    if info["products"]:
        prod = rep.section(f"Etkilenen ürünler ({len(info['products'])})")
        for p in info["products"][:40]:
            prod.add(p)
    refs = rep.section("Referanslar ve PoC araması")
    for url in info["references"][:15]:
        refs.add(url.split("/")[2] if "://" in url else url, url, url=url)
    refs.link("Exploit-DB", f"https://www.exploit-db.com/search?cve={cid.split('-', 1)[1]}")
    refs.link("GitHub PoC araması", f"https://github.com/search?q={cid}&type=repositories")
    refs.link("NVD", f"https://nvd.nist.gov/vuln/detail/{cid}")


def _cve_search(ctx: Context, rep: Report, v: dict) -> None:
    data = _nvd(ctx, {"keywordSearch": v["query"], "resultsPerPage": 30})
    vulns = [x.get("cve") or {} for x in (data or {}).get("vulnerabilities") or []]
    total = (data or {}).get("totalResults", len(vulns))
    rep.source("NVD", True)
    try:
        kev = load_kev(ctx)
    except Exception:  # KEV yoksa da arama sonucu gösterilsin
        kev = {}
    rows = []
    for c in vulns:
        score, sev, _, _ = _cvss(c.get("metrics") or {})
        rows.append((score or 0, c))
    rows.sort(key=lambda r: (str(r[1].get("published", ""))), reverse=True)
    sec = rep.section(f"Sonuçlar (en yeni {len(rows)} / {total})")
    for score, c in rows:
        cid = c.get("id", "")
        desc = next((d.get("value", "") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
        flag = " · KEV: aktif istismar" if cid in kev else ""
        sec.add(f"{cid} · {score or '—'}", f"{str(c.get('published', ''))[:10]}{flag} · {desc[:160]}",
                url=f"https://nvd.nist.gov/vuln/detail/{cid}",
                level=Level.BAD if cid in kev else _sev_level(score or None))
    if not rows:
        sec.add("Eşleşen CVE yok", level=Level.MUTED)
    rep.summary = (f"{total} CVE bulundu; {sum(1 for _, c in rows if c.get('id') in kev)} tanesi aktif olarak "
                   "istismar ediliyor (CISA KEV).")


register(Tool("cve", "CVE Sorgusu", "CVSS, aktif istismar (CISA KEV), EPSS, etkilenen ürünler", "BUG_REPORT",
              "Güvenlik Analizi", [
                  Action("lookup", "CVE numarası", (Field("cve", "CVE", "CVE-2021-44228", parse=cve_id),), _cve),
                  Action("search", "Ürün / anahtar kelime",
                         (Field("query", "Ürün veya anahtar kelime", "fortinet ssl vpn", parse=_keyword),),
                         _cve_search)]))
