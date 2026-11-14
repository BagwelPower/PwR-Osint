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

