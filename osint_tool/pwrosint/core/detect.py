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

    try:
        email = validate.email(text)
        add("email", "analyze", "email", email, "E-posta")
        add("hibp", "email", "email", email, "E-posta sızıntısı")
        add("username", "scan", "username", email.split("@")[0], "E-postadaki kullanıcı adı")
        return out
    except ValueError:
        pass

    if validate.is_ip(text):
        add("host", "profile", "target", text, "IP adresi")
        add("shodan", "host", "ip", text, "Shodan")
        add("virustotal", "ip", "ip", text, "VirusTotal")
        return out

    digits = re.sub(r"[\s()+.-]", "", text)
    if digits.isdigit() and 7 <= len(digits) <= 15:
        add("phone", "analyze", "phone", text, "Telefon numarası")
        return out

    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", text):
        add("virustotal", "file", "hash", text.lower(), "Dosya hash'i")
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
            add("host", "profile", "target", dom, "Domain")
            add("dns", "records", "domain", dom, "DNS kayıtları")
            add("subdomain", "enumerate", "domain", dom, "Subdomain")
            add("tls", "analyze", "domain", dom, "SSL/TLS")
            add("wayback", "scan", "domain", dom, "Web arşivi")
            return out
    except ValueError:
        pass

    if " " in text.strip():
        add("name", "search", "name", text, "Ad soyad")
        return out
    try:
        add("username", "scan", "username", validate.username(text), "Kullanıcı adı")
    except ValueError:
        pass
    return out
