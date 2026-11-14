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

OUTAGE = ("bağlantı kurulamadı", "zaman aşımı", "HTTP 502", "HTTP 503", "HTTP 504", "şu anda yoğun",
          "istek limiti", "limiti doldu", "sunucu hatası")


def skip_if_outage(report):
    """Dış servis kesintisi kodumuzun hatası değildir: 'atlandı' olarak raporla. Kod hataları
    ('Beklenmeyen hata') asla atlanmaz."""
    errs = [e for e in report.errors if not e.startswith("Beklenmeyen hata")]
    if errs and len(errs) == len(report.errors) and all(any(o in e for o in OUTAGE) for e in errs):
        pytest.skip("dış servis kesintisi: " + "; ".join(errs)[:200])


pytestmark = pytest.mark.skipif(os.environ.get("PWR_LIVE") != "1", reason="canlı testler kapalı")


def run(tool_id, action_id=None, **values):
    tool = get_tool(tool_id)
    action = tool.action(action_id) if action_id else tool.actions[0]
    report = run_action(Context(Settings(timeout=20)), tool, action, values)
    print(report.to_text())
    skip_if_outage(report)
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


# ---------------------------------------------------------------- 2.1 araçları

def test_github_profile():
    r = run("github", username="torvalds")
    assert section(r, "Profil")["Ad"].value == "Linus Torvalds"
    assert "C" in section(r, "Repolar")["Diller"].value


def test_reddit_profile():
    # Reddit bulut IP'lerini engelleyebilir; o durumda arşiv yolu da gerçek veri vermeli.
    r = run("reddit", username="spez")
    assert not r.errors
    prof = section(r, "Profil")
    first = prof.get("Oluşturulma") or prof.get("İlk görülen etkinlik")
    assert first and first.value[:4] in ("2005", "2006", "2007")
    assert "r/" in section(r, "Aktivite")["En çok yazdığı subreddit'ler"].value


def test_telegram_channel():
    r = run("telegram", username="durov")
    assert section(r, "Profil")["Tür"].value == "Kanal"


def test_site_analysis():
    from pwrosint.modules.web import parse_url
    r = run("site", url=parse_url("wordpress.org"))
    assert "WordPress" in section(r, "Teknolojiler")


def test_site_files():
    r = run("site", "files", domain="github.com")
    assert section(r, "robots.txt")["Durum"].level == Level.OK


def test_asn():
    r = run("asn", target="AS15169")
    assert "Google" in section(r, "AS15169")["Sahibi"].value


def test_asn_from_ip():
    r = run("asn", target="8.8.8.8")
    assert "AS15169" in section(r, "IP:")["ASN"].value


def test_blacklist_clean_ip():
    r = run("blacklist", ip="8.8.8.8")
    assert section(r, "Kara liste")  # en az bir liste yanıt vermeli
    assert not r.errors


def test_btc_genesis():
    r = run("crypto", "btc", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert section(r, "Adres")["İşlem sayısı"].value != "0"


def test_eth():
    r = run("crypto", "eth", address="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae")
    assert int(section(r, "Adres")["İşlem sayısı"].value) > 0


def test_typosquat():
    r = run("phishing", "typosquat", domain="google.com")
    assert len(section(r, "Kayıtlı")) > 5


def test_openphish_feed():
    r = run("phishing", "openphish", domain="ornek-olmayan-domain-12345.com")
    assert section(r, "OpenPhish")["Durum"].level == Level.OK


def test_urlscan():
    r = run("urlscan", domain="github.com")
    assert not r.errors and "tarama" in r.summary


def test_image_exif_gps():
    from pwrosint.modules.web import parse_url
    r = run("image", "analyze", url=parse_url("https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/gps/DSCN0010.jpg"))
    assert section(r, "EXIF")["Üretici"].value.startswith("NIKON")
    assert "GPS konumu" in [s.title for s in r.sections]


# ---------------------------------------------------------------- 2.2: yedek kaynaklar ve derinleştirmeler

def sources_ok(report):
    return {n: ok for n, ok, _ in report.sources}


def test_hibp_email_keyless_xposedornot():
    r = run("hibp", "email", email="test@gmail.com")
    assert not r.errors and not r.missing_key
    assert sources_ok(r).get("XposedOrNot") is True
    assert r.summary and "sızıntıda" in r.summary  # test@gmail.com çok sayıda sızıntıda


def test_shodan_host_keyless_internetdb():
    r = run("shodan", "host", ip="8.8.8.8")
    assert "53" in section(r, "Host")["Açık portlar"].value


def test_virustotal_keyless_otx():
    r = run("virustotal", "domain", domain="github.com")
    assert sources_ok(r).get("AlienVault OTX") is True, r.sources
    assert "Tehdit raporu (pulse)" in section(r, "Tehdit istihbaratı")


def test_name_real_records():
    r = run("name", name="Linus Torvalds")
    ok = sources_ok(r)
    assert ok.get("OpenAlex") and ok.get("Wikidata") and ok.get("ORCID"), r.sources
    assert any("Torvalds" in label for label in section(r, "Tanınmış"))


def test_email_gravatar_profile():
    # Gravatar'ın kendi destek adresi herkese açık bir profile sahiptir
    r = run("email", email="beau@automattic.com")
    assert sources_ok(r).get("Gravatar") is True
    assert sources_ok(r).get("XposedOrNot") is True


def test_reverse_ip_has_domains():
    r = run("reverseip", target="github.com")
    assert any(ok for _, ok, _ in r.sources)
    assert not r.errors


def test_username_deep_whatsmyname():
    import time
    t = time.monotonic()
    r = run("username", "deep", username="torvalds")
    took = time.monotonic() - t
    print(f"derin tarama süresi: {took:.0f} sn")
    assert not r.errors
    assert len(section(r, "Bulunan")) >= 10, r.summary
    assert took < 120, f"derin tarama çok yavaş: {took:.0f} sn"


def test_fullscan_real_domain():
    r = run("fullscan", "scan", domain="github.com")
    assert not r.errors
    prefixes = {s.title.split(" · ")[0] for s in r.sections}
    assert {"Altyapı", "DNS", "TLS", "Subdomain", "Site", "Arşiv", "Taklit"} <= prefixes, prefixes


# ---------------------------------------------------------------- DNS taşıyıcıları (her biri ayrı)

from pwrosint.core import dns as _dns  # noqa: E402


@pytest.mark.parametrize("name, transport", _dns.TRANSPORTS, ids=[n for n, _ in _dns.TRANSPORTS])
def test_dns_transport(name, transport):
    from pwrosint.core.config import Settings
    from pwrosint.core.context import Context
    ctx = Context(Settings(timeout=10))
    status, answers = transport(ctx, "github.com", "A")
    assert status == "NOERROR" and answers, (name, status, answers)
    if name != "Sistem çözümleyicisi":
        status, mx = transport(ctx, "gmail.com", "MX")
        assert any("google" in m.lower() for m in mx), (name, mx)
        status, txt = transport(ctx, "gmail.com", "TXT")
        assert any("v=spf1" in t for t in txt), (name, txt)
        status, _ = transport(ctx, "bu-domain-kesinlikle-yok-pwr-12345.com", "A")
        assert status == "NXDOMAIN", (name, status)


# ---------------------------------------------------------------- bilişimci araçları (2. aşama)

def test_cve_log4j_real():
    from pwrosint.modules.security import cve_id
    r = run("cve", "lookup", cve=cve_id("CVE-2021-44228"))
    assert not r.errors, r.errors
    sec = section(r, "CVE-2021-44228")
    assert sec["CVSS"].value.startswith("10.0"), sec["CVSS"].value
    exp = section(r, "İstismar")
    assert exp["CISA KEV"].level == Level.BAD
    assert "EPSS (30 gün içinde istismar olasılığı)" in exp
    assert len(section(r, "Etkilenen ürünler")) > 0


def test_cve_search_real():
    r = run("cve", "search", query="fortinet fortios ssl vpn")
    assert not r.errors and len(section(r, "Sonuçlar")) > 0


def test_netinfo_real():
    r = run("netinfo", "show")
    assert not r.errors
    assert section(r, "İnternet")["Public IPv4"].level == Level.OK
    assert "Çalışan DNS yolu" in section(r, "Gecikme")


def test_httpinspect_real():
    from pwrosint.modules.nettools import http_url
    r = run("httpinspect", "inspect", url=http_url("http://github.com"))
    assert not r.errors
    chain = [s for s in r.sections if s.title == "İstek zinciri"][0].items
    assert chain[0].label.startswith("1. 301") and chain[-1].label.split()[1] == "200"


def test_globalping_ping_real():
    r = run("globalping", "ping", target="github.com", location=None)
    assert not r.errors, r.errors
    rows = [s for s in r.sections if s.title.startswith("Ping")][0].items
    assert any(i.level == Level.OK for i in rows), [i.value for i in rows]


def test_globalping_traceroute_real():
    r = run("globalping", "traceroute", target="1.1.1.1", location="Europe")  # github.com ICMP filtreler
    assert not r.errors, r.errors
    traces = [s for s in r.sections if s.title.startswith("Traceroute")]
    assert traces
    # Sondalar zaman zaman tutarsız ham çıktı döndürebiliyor (gözlemlendi: traceroute yerine ping çıktısı);
    # araç bunu çökmeden 'Sonuç yok' olarak göstermeli. En az bir sonda atlama verdiyse yapı doğru olmalı.
    with_hops = [t for t in traces if t.items and t.items[0].label.startswith("1. ")]
    if not with_hops:
        pytest.skip("Globalping sondaları bu çalıştırmada traceroute atlaması döndürmedi")
    assert len(with_hops[0].items) >= 3


def test_portscan_localhost_listener():
    """Gerçek TCP taraması, ama yalnızca CI makinesinin kendi localhost'unda."""
    import socket
    import threading
    from pwrosint.modules import nettools
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8081))
    srv.listen(5)

    def serve():
        for _ in range(3):
            try:
                c, _ = srv.accept()
                c.sendall(b"HTTP/1.0 200 OK\r\nServer: pwr-test\r\n\r\n")
                c.close()
            except OSError:
                return
    threading.Thread(target=serve, daemon=True).start()
    try:
        r = run("portscan", "scan", target=nettools.scan_target("127.0.0.1"))
    finally:
        srv.close()
    assert not r.errors
    assert "pwr-test" in section(r, "Açık portlar")["8081/tcp"].value


# ---------------------------------------------------------------- telefondaki DNS engelinin benzetimi

# Kullanıcının telefonunda cloudflare-dns.com ve dns.google'a ulaşılamıyordu; o ağda E-posta 39.6 sn,
# Permutator 38.1 sn, Subdomain 85 sn, Kara Liste 67 sn sürmüş ve bazı araçlar hata vermişti.
BLOCKED_DOH_BUDGETS = [
    ("email", "analyze", {"email": "test@gmail.com"}, 20),
    ("email", "permutate", {"first": "Ahmet", "last": "Yılmaz", "domain": "github.com"}, 10),
    ("blacklist", "check", {"ip": "8.8.8.8"}, 30),
    ("subdomain", "enumerate", {"domain": "example.com"}, 75),
    ("dns", "records", {"domain": "github.com"}, 15),
    ("host", "profile", {"target": "github.com"}, 30),
]


@pytest.mark.parametrize("tool_id, action_id, raw, budget", BLOCKED_DOH_BUDGETS,
                         ids=[f"{t}-{a}" for t, a, _, _ in BLOCKED_DOH_BUDGETS])
def test_works_when_hostname_doh_is_blocked(tool_id, action_id, raw, budget):
    import time
    from pwrosint.core import dns
    from pwrosint.core.registry import parse_inputs
    dns.reset_health()
    with dns._lock:  # telefondaki durum: ad ile DoH sunucularına ulaşılamıyor
        for name in ("Cloudflare DoH", "Google DoH"):
            dns._dead_until[name] = time.monotonic() + 3600
    tool = get_tool(tool_id)
    action = tool.action(action_id)
    t = time.monotonic()
    report = run_action(Context(Settings(timeout=20)), tool, action, parse_inputs(action, raw))
    took = time.monotonic() - t
    print(report.to_text())
    print(f"süre: {took:.1f} sn · DNS yolu: {dns.active_transport()}")
    skip_if_outage(report)
    assert not report.errors, report.errors
    assert dns.active_transport() not in ("Cloudflare DoH", "Google DoH")
    assert took < budget, f"{tool_id}/{action_id} {took:.1f} sn sürdü (bütçe {budget} sn)"
    dns.reset_health()
