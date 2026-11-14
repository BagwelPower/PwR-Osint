"""Girdi doğrulama ve normalleştirme. Hatalar ValueError ile, kullanıcıya
gösterilecek Türkçe mesajla fırlatılır."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_USERNAME = re.compile(r"^[A-Za-z0-9._-]{2,40}$")


def domain(value: str) -> str:
    """'https://www.Ornek.com/yol' → 'www.ornek.com'"""
    v = value.strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    v = v.split("/")[0].split(":")[0].rstrip(".")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise ValueError("Geçersiz domain") from e
    labels = v.split(".")
    if len(labels) < 2 or not all(_LABEL.match(p) for p in labels) or not _TLD.match(labels[-1]):
        raise ValueError("Geçersiz domain (ör. ornek.com)")
    return v


def ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as e:
        raise ValueError("Geçersiz IP adresi (ör. 8.8.8.8)") from e


def host(value: str) -> str:
    """IP ya da domain kabul eder."""
    try:
        return ip(value)
    except ValueError:
        pass
    try:
        return domain(value)
    except ValueError as e:
        raise ValueError("Geçersiz IP veya domain") from e


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def email(value: str) -> str:
    v = value.strip()
    if not _EMAIL.match(v) or ".." in v:
        raise ValueError("Geçersiz e-posta adresi")
    local, dom = v.rsplit("@", 1)
    return f"{local}@{domain(dom)}"


def username(value: str) -> str:
    v = value.strip().lstrip("@")
    if not _USERNAME.match(v):
        raise ValueError("Kullanıcı adı 2-40 karakter olmalı; harf, rakam, . _ - içerebilir")
    return v


def text(value: str, min_len: int = 2) -> str:
    v = " ".join(value.split())
    if len(v) < min_len:
        raise ValueError(f"En az {min_len} karakter girin")
    return v


def coordinates(value: str) -> tuple[float, float]:
    parts = re.split(r"[,\s;]+", value.strip())
    try:
        lat, lon = (float(p) for p in parts if p)
    except ValueError as e:
        raise ValueError("Format: 41.0082, 28.9784") from e
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError("Koordinat aralık dışında")
    return lat, lon


def mac(value: str) -> str:
    hexes = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(hexes) != 12:
        raise ValueError("BSSID/MAC 12 hex karakter olmalı (ör. 00:11:22:33:44:55)")
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()
