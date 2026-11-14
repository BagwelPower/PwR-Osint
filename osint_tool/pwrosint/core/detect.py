"""Akıllı arama: serbest girdinin türünü tahmin edip uygun araçları önerir."""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import validate


@dataclass(frozen=True)
class Suggestion:
    tool: str
    action: str
    field: str
    value: str
    reason: str


def suggest(raw: str) -> list[Suggestion]:
    text = raw.strip()
    if not text:
        return []
    out: list[Suggestion] = []

    def add(tool, action, field, value, reason):
        out.append(Suggestion(tool, action, field, value, reason))

    # --- bilişimci girdileri (kullanıcı adı / domain kurallarından önce)
    if re.search(r"(?mi)^(received|authentication-results|return-path|message-id|dkim-signature):", text) or \
            (text.count("\n") >= 2 and re.search(r"(?mi)^from:", text)):
        add("emailheader", "analyze", "headers", text, "E-posta başlıkları")
        return out
    if re.fullmatch(r"(?i)cve[-_ ]?\d{4}[-_ ]\d{4,7}", text):
        cid = re.sub(r"[_ ]", "-", text.upper())
        if not cid.startswith("CVE-"):
            cid = "CVE-" + cid[3:].lstrip("-")
        add("cve", "lookup", "cve", cid, "CVE numarası")
        return out
    token = text[7:].strip() if text.lower().startswith("bearer ") else text
    if re.fullmatch(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", token):
        add("decoder", "jwt", "token", token, "JWT token")
        return out
    if re.fullmatch(r"[\d.]+/\d{1,2}|[\d.]+ \d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+/\d{1,3}", text):
        add("subnet", "calc", "net", text, "Ağ / CIDR")
        return out
    if re.fullmatch(r"\$(2[abxy]?|argon2(id|i|d)|[156y]|P|H)\$.+", text):
        add("hash", "identify", "hash", text, "Parola hash'i")
        return out

    try:
        email = validate.email(text)
        add("email", "analyze", "email", email, "E-posta")
        add("hibp", "email", "email", email, "E-posta sızıntısı")
        add("username", "scan", "username", email.split("@")[0], "E-postadaki kullanıcı adı")
        add("fediverse", "profile", "handle", email, "Mastodon hesabı olabilir")
        return out
    except ValueError:
        pass

    if validate.is_ip(text):
        add("host", "profile", "target", text, "IP adresi")
        add("shodan", "host", "ip", text, "Shodan")
        add("blacklist", "check", "ip", text, "Spam kara listeleri")
        add("asn", "lookup", "target", text, "Ağ sahibi (ASN)")
        add("reverseip", "lookup", "target", text, "Aynı sunucudaki siteler")
        add("virustotal", "ip", "ip", text, "VirusTotal")
        return out

    # Şüpheli link/SMS: önce ve her zaman PASİF analiz (link açılmaz). Linki açan araçlar sonra gelir.
    if " " in text and re.search(r"(?i)https?://|www\.|\b[a-z0-9-]+\.(?:com|xyz|top|click|link|ly|info|net|org)\b",
                                 text):
        add("linkcheck", "analyze", "text", text, "Mesajdaki linkleri açmadan incele")
        return out
    if re.match(r"https?://", text, re.I):
        add("linkcheck", "analyze", "text", text, "Linki açmadan incele (önerilen)")
        from ..modules.web import parse_url
        try:
            url = parse_url(text)
        except ValueError:
            url = None
        if url:
            path = url.split("?")[0].lower()
            if path.endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".tif", ".tiff")):
                add("image", "analyze", "url", url, "Görsel adresi")
            add("site", "analyze", "url", url, "Web sayfası")
            host = url.split("/")[2]
            if not validate.is_ip(host):
                add("host", "profile", "target", host, "Domain")
            return out

    from ..modules.crypto import btc_address, eth_address
    for parse, action, reason in ((btc_address, "btc", "Bitcoin adresi"), (eth_address, "eth", "Ethereum adresi")):
        try:
            add("crypto", action, "address", parse(text), reason)
            return out
        except ValueError:
            pass

    if re.fullmatch(r"(?i)AS\s?\d{1,10}", text):
        add("asn", "lookup", "target", text.upper().replace(" ", ""), "ASN")
        return out

    digits = re.sub(r"[\s()+.-]", "", text)
    if digits.isdigit() and 7 <= len(digits) <= 15:
        add("phone", "analyze", "phone", text, "Telefon numarası")
        return out

    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", text):
        add("hash", "identify", "hash", text, "Hash türünü tanı")
        add("virustotal", "file", "hash", text.lower(), "Dosya hash'i (tehdit itibarı)")
        return out

    try:
        validate.mac(text)
        if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", text):
            add("geo", "bssid", "mac", text, "MAC / BSSID")
            return out
    except ValueError:
        pass

    try:
        validate.coordinates(text)
        if re.search(r"\d+\.\d+", text):
            add("geo", "coords", "coords", text, "Koordinat")
            return out
    except ValueError:
        pass

    compact = re.sub(r"[\s-]", "", text.upper())
    if len(compact) == 17 and re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", compact) and re.search(r"\d", compact):
        add("vehicle", "vin", "vin", compact, "VIN / şasi no")
        return out
    if re.fullmatch(r"(0[1-9]|[1-7]\d|8[01])[A-Z]{1,3}\d{2,5}", compact):
        add("vehicle", "plate", "plate", text, "Plaka")
        return out

    try:
        dom = validate.domain(text)
        if "." in text:
            add("fullscan", "scan", "domain", dom, "Tam domain taraması (8 araç)")
            add("host", "profile", "target", dom, "Domain")
            add("dns", "records", "domain", dom, "DNS kayıtları")
            add("subdomain", "enumerate", "domain", dom, "Subdomain")
            add("tls", "analyze", "domain", dom, "SSL/TLS")
            add("site", "analyze", "url", f"https://{dom}/", "Site teknolojisi ve iletişim")
            add("wayback", "scan", "domain", dom, "Web arşivi")
            add("phishing", "typosquat", "domain", dom, "Taklit domainler")
            add("dorks", "generate", "domain", dom, "Google dork'ları")
            return out
    except ValueError:
        pass

    if " " in text.strip():
        add("name", "search", "name", text, "Ad soyad")
        return out
    try:
        user = validate.username(text)
    except ValueError:
        return out
    add("username", "scan", "username", user, "Kullanıcı adı")
    add("github", "profile", "username", user, "GitHub profili")
    add("reddit", "profile", "username", user, "Reddit profili")
    add("telegram", "profile", "username", user, "Telegram")
    return out
