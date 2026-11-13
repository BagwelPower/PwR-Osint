"""Gerçek servislere karşı duman testleri. Sadece PWR_LIVE=1 ile çalışır
(CI'da internet erişimi olan ayrı bir adımda). Amaç: dış API'lerin
biçimi değişirse bunu fark etmek."""

import os

import pytest

from pwrosint.core.config import Settings
from pwrosint.core.context import Context
from pwrosint.core.registry import get_tool
from pwrosint.core.report import Level
from pwrosint.core.runner import run_action

pytestmark = pytest.mark.skipif(os.environ.get("PWR_LIVE") != "1", reason="canlı testler kapalı")


def run(tool_id, action_id=None, **values):
    tool = get_tool(tool_id)
    action = tool.action(action_id) if action_id else tool.actions[0]
    report = run_action(Context(Settings(timeout=20)), tool, action, values)
    print(report.to_text())
    return report


def section(report, prefix):
    return {i.label: i for s in report.sections if s.title.startswith(prefix) for i in s.items}


def test_dns():
    r = run("dns", domain="github.com")
    assert not r.errors
    recs = [i for s in r.sections if s.title == "Kayıtlar" for i in s.items]
    assert any(i.label == "A" for i in recs) and any(i.label == "MX" for i in recs)


def test_host_ip():
    r = run("host", target="8.8.8.8")
    assert section(r, "IP:")["Reverse DNS"].value == "dns.google"
    assert "53" in section(r, "Açık portlar")["Portlar"].value


def test_host_domain_rdap():
    r = run("host", target="github.com")
    whois = section(r, "WHOIS")
    assert "Kayıt tarihi" in whois and whois["Kayıt tarihi"].value.startswith("2007")


def test_tls():
    r = run("tls", domain="github.com")
    cert = section(r, "Sertifika")
    assert cert["Doğrulama"].level == Level.OK
    assert section(r, "HTTP güvenlik")["HSTS"].level == Level.OK


def test_tls_bad_cert():
    r = run("tls", domain="expired.badssl.com")
    assert section(r, "Sertifika")["Doğrulama"].level == Level.BAD


def test_username():
    r = run("username", username="torvalds")
    found = section(r, "Bulunan")
    assert "GitHub" in found


def test_email():
    r = run("email", email="test@gmail.com")
    assert section(r, "Posta")["Sağlayıcı"].value.startswith("Google")


def test_vin():
    r = run("vehicle", "vin", vin="1HGCM82633A004352")
    assert section(r, "Çözümleme")["Marka"].value.upper() == "HONDA"


def test_coords():
    r = run("geo", "coords", coords=(41.0082, 28.9784))
    assert "İstanbul" in section(r, "Adres")["Tam adres"].value


def test_wayback():
    r = run("wayback", domain="example.com")
    assert section(r, "Arşiv")["İlk kayıt"].value.startswith("200")


def test_pwned_password():
    r = run("hibp", "password", password="password")
    assert section(r, "Sonuç")["Durum"].level == Level.BAD
