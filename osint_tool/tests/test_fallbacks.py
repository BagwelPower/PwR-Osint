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
    assert found["VarSite"].url == "https://var.example/u/ali"
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


def test_name_returns_real_records(ctx, http):
    http.add("https://api.github.com/search/users", {"total_count": 1, "items": [
        {"login": "ayilmaz", "html_url": "https://github.com/ayilmaz"}]})
    http.add("https://api.github.com/users/ayilmaz", {"name": "Ahmet Yılmaz", "location": "İstanbul"})
    http.add("https://api.openalex.org/authors", {"results": [
        {"display_name": "Ahmet Yılmaz", "works_count": 42, "cited_by_count": 300, "orcid": "https://orcid.org/0000-1",
         "last_known_institutions": [{"display_name": "İTÜ"}], "topics": [{"display_name": "Makine öğrenmesi"}]}]})
    http.add("https://pub.orcid.org/", {"num-found": 1, "expanded-result": [
        {"orcid-id": "0000-0002", "given-names": "Ahmet", "family-names": "Yılmaz", "institution-name": ["ODTÜ"]}]})
    http.add("https://www.wikidata.org/", {"search": [{"label": "Ahmet Yılmaz", "description": "Türk futbolcu",
                                                      "concepturi": "http://www.wikidata.org/entity/Q1"}]})
    report = run(ctx, "name", name="Ahmet Yılmaz")
    assert not report.errors
    assert items(report, "GitHub")["ayilmaz"].value == "Ahmet Yılmaz · İstanbul"
    assert "42 yayın, 300 atıf" in items(report, "Akademik")["Ahmet Yılmaz"].value
    assert items(report, "ORCID")["Ahmet Yılmaz"].value == "ODTÜ"
    assert items(report, "Tanınmış")["Ahmet Yılmaz"].value == "Türk futbolcu"
    assert "Genel" in items(report, "Google dork")


def test_name_offline_still_gives_links(ctx, http):
    from pwrosint.core.errors import OsintError
    http.add("https://", OsintError("ağ yok"))
    report = run(ctx, "name", name="Ahmet Yılmaz")
    assert not report.errors and "Genel" in items(report, "Google dork")
    assert any("ulaşılamadı" in n for n in report.notices)


def test_email_gravatar_and_leaks(ctx, http):
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0})
    http.add("https://api.gravatar.com/v3/profiles/", {
        "display_name": "Ali Veli", "location": "Ankara", "profile_url": "https://gravatar.com/aliveli",
        "verified_accounts": [{"service_label": "GitHub", "url": "https://github.com/aliveli"}]})
    http.add("https://api.xposedornot.com/v1/check-email/", {"breaches": [["Adobe", "Canva"]]})
    http.add("https://rdap.org/domain/ornek.com", {"events": []})
    report = run(ctx, "email", email="ali@ornek.com")
    assert items(report, "Gravatar profili")["Görünen ad"].value == "Ali Veli"
    assert items(report, "Gravatar'da doğrulanmış")["GitHub"].url == "https://github.com/aliveli"
    assert items(report, "Sızıntı özeti")["Bulunduğu sızıntılar"].value.startswith("2: Adobe, Canva")
    assert any(s.title.startswith("WHOIS") for s in report.sections)  # kurumsal domain → domain yaşı


def test_unreachable_is_not_reported_as_absent(ctx, http):
    from pwrosint.core.errors import OsintError
    http.add("https://", OsintError("ağ yok"))
    report = run(ctx, "email", email="ali@gmail.com")
    assert "ulaşılamadı" in items(report, "Gravatar profili")["Profil"].value
    assert "ulaşılamadı" in items(report, "Sızıntı özeti")["Durum"].value


def test_fullscan_merges_all_tools(ctx, http, monkeypatch):
    import socket
    from pwrosint.core.errors import OsintError
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("ağ yok")))
    http.add("https://", OsintError("ağ yok"))
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
    report = run(ctx, "fullscan", domain="ornek.com")
    assert not [e for e in report.errors if "Beklenmeyen" in e]
    prefixes = {s.title.split(" · ")[0] for s in report.sections}
    assert {"Altyapı", "DNS"} <= prefixes
    assert report.summary.startswith("8 araç tamamlandı")
    assert any(n.startswith("TLS aracı") for n, ok, _ in report.sources if not ok)  # TLS hatası kaynak durumunda


def test_permutator_works_offline(ctx, http):
    from pwrosint.core.errors import OsintError
    http.add("https://", OsintError("ağ yok"))
    report = run(ctx, "email", "permutate", first="Ali", last="Veli", domain="ornek.com")
    assert not report.errors and "ali.veli@ornek.com" in items(report, "Olası adresler")


def test_offline_capable_tools_degrade_gracefully(ctx, http):
    from pwrosint.core.errors import OsintError
    from pwrosint.modules.misc import parse_vin
    http.add("https://", OsintError("ağ yok"))
    pw = run(ctx, "hibp", "password", password="galatasaray1905")
    assert not pw.errors and "Değerlendirme" in items(pw, "Şifre gücü")
    vin = run(ctx, "vehicle", "vin", vin=parse_vin("1HGCM82633A004352"))
    assert not vin.errors and items(vin, "Yapı")["Kontrol hanesi"].level == Level.OK
    assert "ulaşılamadı" in items(vin, "Çözümleme")["Sonuç"].value
    geo = run(ctx, "geo", "coords", coords=(41.0, 29.0))
    assert not geo.errors and "Google Maps" in items(geo, "Haritalar")


def test_wayback_listing_timeout_keeps_summary(ctx, http):
    from pwrosint.core.errors import OsintError
    cdx = "https://web.archive.org/cdx/search/cdx"
    http.add(cdx, [["timestamp"], ["20020101000000"]])
    http.add(cdx, OsintError("web.archive.org: zaman aşımı (45 sn)"), match_params={"url": "ornek.com/*"})
    report = run(ctx, "wayback", domain="ornek.com")
    assert not report.errors
    assert items(report, "Arşiv özeti")["İlk kayıt"].value.startswith("2002-01-01")
    assert any("sayfa listesini" in n for n in report.notices)


def test_subdomains_without_dns_are_not_reported_dead(ctx, http):
    from pwrosint.core.errors import OsintError
    http.add("https://cloudflare-dns.com/", OsintError("engelli"))
    http.add("https://dns.google/", OsintError("engelli"))
    http.add("https://1.1.1.1/", OsintError("engelli"))
    http.add("https://8.8.8.8/", OsintError("engelli"))
    http.add("https://9.9.9.9/", OsintError("engelli"))
    http.add("https://dns.quad9.net/", OsintError("engelli"))
    http.add("https://1.0.0.1/", OsintError("engelli"))
    http.add("https://crt.sh/", [{"name_value": "www.ornek.com\napi.ornek.com"}])
    for src in ("https://api.certspotter.com/", "https://jldc.me/"):
        http.add(src, [])
    http.add("https://api.hackertarget.com/", "error")
    http.add("https://otx.alienvault.com/", {"passive_dns": []})
    http.add("https://urlscan.io/", {"results": []})
    http.add("https://web.archive.org/", [])
    report = run(ctx, "subdomain", domain="ornek.com")
    assert not report.errors
    assert set(items(report, "Bulunan subdomain")) == {"www.ornek.com", "api.ornek.com"}
    assert not any(s.title == "Çözülmeyen" for s in report.sections)
    assert "canlılık kontrol edilemedi" in report.summary
