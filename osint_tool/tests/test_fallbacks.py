"""Anahtarsız yedek kaynaklar ve WhatsMyName derin taraması."""

from pwrosint.core.report import Level
from pwrosint.modules import person

from test_modules import items, run

WMN = {"license": ["CC BY-SA 4.0"], "sites": [
    {"name": "VarSite", "uri_check": "https://var.example/u/{account}", "e_code": 200, "e_string": "profile-card",
     "m_code": 404, "m_string": "Not Found", "cat": "social", "known": ["x"]},
    {"name": "YokSite", "uri_check": "https://yok.example/{account}", "e_code": 200, "e_string": "user-page",
     "m_code": 200, "m_string": "no such user", "cat": "coding", "known": ["x"]},
    {"name": "PostSite", "uri_check": "https://post.example/api", "post_body": '{"u":"{account}"}',
     "e_code": 200, "e_string": '"exists":true', "m_code": 200, "m_string": '"exists":false', "cat": "gaming",
     "uri_pretty": "https://post.example/{account}", "known": ["x"]},
    {"name": "Nsfw", "uri_check": "https://n.example/{account}", "e_code": 200, "e_string": "x", "m_code": 404,
     "m_string": "x", "cat": "xx NSFW xx", "known": ["x"]},
    {"name": "Bozuk", "uri_check": "https://b.example/sabit", "e_code": 200, "e_string": "x", "m_code": 404,
     "m_string": "x", "cat": "misc", "known": ["x"]},
]}


def test_wmn_deep_scan(ctx, http, monkeypatch):
    http.add(person.WMN_URL, WMN)
    http.add("https://var.example/u/ali", '<div class="profile-card">Ali</div>')
    http.add("https://yok.example/ali", "Sorry, no such user")
    posted = {}

    def fake_post(url, **kw):
        posted["body"] = kw.get("data")
        return http.get(url)
    http.add("https://post.example/api", '{"exists":true}')
    monkeypatch.setattr(http, "post", fake_post)

    report = run(ctx, "username", "deep", username="ali")
    assert not report.errors
    found = items(report, "Bulunan")
    assert set(found) == {"VarSite", "PostSite"}
    assert found["PostSite"].url == "https://post.example/ali"  # uri_pretty
    assert posted["body"] == '{"u":"ali"}'
    assert "3 site kontrol edildi: 2 profil bulundu, 1 sitede yok" in report.summary  # NSFW ve bozuk atlandı
    assert any("WhatsMyName" in n for n in report.notices)


def test_wmn_uses_cache_when_offline(ctx, http):
    from pwrosint.core.errors import OsintError
    http.add(person.WMN_URL, WMN)
    sites, origin = person.load_wmn(ctx)
    assert origin == "güncel" and len(sites) == 3
    http.add(person.WMN_URL, OsintError("ağ yok"))
    sites, origin = person.load_wmn(ctx)
    assert origin == "önbellek" and len(sites) == 3


def test_hibp_falls_back_to_xposedornot(ctx, http):
    http.add("https://api.xposedornot.com/v1/breach-analytics", {
        "ExposedBreaches": {"breaches_details": [
            {"breach": "Adobe", "xposed_date": "2013", "xposed_data": "Email addresses;Passwords",
             "xposed_records": 152445165, "password_risk": "easytocrack", "domain": "adobe.com"}]},
        "BreachMetrics": {"risk": [{"risk_label": "High", "risk_score": 80}]}})
    report = run(ctx, "hibp", "email", email="ali@ornek.com")
    assert not report.errors and not report.missing_key
    assert report.summary == "1 sızıntıda bulundu."
    adobe = items(report, "Adobe")
    assert adobe["Şifre saklama"].level == Level.BAD and adobe["Etkilenen hesap"].value == "152.445.165"
    assert any("XposedOrNot" in n for n in report.notices)


def test_hibp_fallback_clean(ctx, http):
    http.add("https://api.xposedornot.com/v1/breach-analytics", {"Error": "Not found"}, status=404)
    report = run(ctx, "hibp", "email", email="ali@ornek.com")
    assert items(report, "Sonuç")["Durum"].level == Level.OK


def test_shodan_host_falls_back_to_internetdb(ctx, http):
    http.add("https://internetdb.shodan.io/1.2.3.4", {"ports": [22, 80], "hostnames": ["a.ornek.com"],
                                                     "cpes": ["cpe:/a:openbsd:openssh:8.2"], "tags": [],
                                                     "vulns": ["CVE-2023-38408"]})
    report = run(ctx, "shodan", "host", ip="1.2.3.4")
    assert not report.errors and not report.missing_key
    assert items(report, "Host")["Açık portlar"].value == "22, 80"
    assert items(report, "Zafiyetler")["CVE-2023-38408"].url.startswith("https://nvd.nist.gov/")
    assert items(report, "Tespit edilen yazılımlar")["openbsd openssh"].value == "8.2"


def test_virustotal_falls_back_to_otx(ctx, http):
    http.add("https://otx.alienvault.com/api/v1/indicators/domain/kotu.com/general", {
        "pulse_info": {"count": 2, "pulses": [
            {"id": "p1", "name": "Phishing kampanyası", "created": "2025-01-02T00:00:00",
             "tags": ["phishing"], "malware_families": [{"display_name": "Emotet"}]}]},
        "validation": []})
    report = run(ctx, "virustotal", "domain", domain="kotu.com")
    sec = items(report, "Tehdit istihbaratı")
    assert sec["Tehdit raporu (pulse)"].level == Level.BAD
    assert sec["Zararlı aileleri"].value == "Emotet"
    assert any("OTX" in n for n in report.notices)


def test_hunter_falls_back_to_site_pages(ctx, http):
    http.add("https://ornek.com/", "", status=404)
    http.add("https://ornek.com/iletisim", "Bize yazın: info@ornek.com, destek@ornek.com · Tel: 0212 555 12 34")
    http.add("https://ornek.com/kvkk", "kvkk@ornek.com ve ajans@baska.com")
    report = run(ctx, "email", "hunter", domain="ornek.com")
    own = items(report, "Sitede yayınlanan")
    assert set(own) == {"info@ornek.com", "destek@ornek.com", "kvkk@ornek.com"}
    assert "ajans@baska.com" in items(report, "Sayfalarda geçen diğer")
    assert "+90 212 555 12 34" in items(report, "Telefonlar")


def test_reverse_ip_falls_back_to_urlscan(ctx, http):
    http.add("https://api.hackertarget.com/", "API count exceeded")
    http.add("https://urlscan.io/api/v1/search/", {"results": [{"page": {"domain": "a.com"}},
                                                               {"page": {"domain": "b.com"}}]})
    report = run(ctx, "reverseip", target="1.2.3.4")
    assert not report.errors
    assert set(items(report, "1.2.3.4")) == {"a.com", "b.com"}
    assert ("HackerTarget", False) in [(n, ok) for n, ok, _ in report.sources]
