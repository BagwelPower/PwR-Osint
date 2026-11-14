from pwrosint.core.errors import OsintError
from pwrosint.core.report import Level
from pwrosint.modules import nettools, security

from test_modules import items, run

LOG4J = {"vulnerabilities": [{"cve": {
    "id": "CVE-2021-44228", "published": "2021-12-10T10:15:09.143", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI features ... remote code execution."}],
    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
        "baseScore": 10.0, "baseSeverity": "CRITICAL",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
    "weaknesses": [{"description": [{"value": "CWE-502"}, {"value": "CWE-917"}]}],
    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                                                  "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                                  "versionStartIncluding": "2.0.1", "versionEndExcluding": "2.12.2"}]}]}],
    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}]}}]}
KEV = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10",
                            "knownRansomwareCampaignUse": "Known", "requiredAction": "Güncelleyin"}]}


def test_cve_lookup_full(ctx, http):
    http.add(security.NVD, LOG4J)
    http.add(security.KEV_URL, KEV)
    http.add("https://api.first.org/", {"data": [{"cve": "CVE-2021-44228", "epss": "0.944", "percentile": "0.9999"}]})
    report = run(ctx, "cve", "lookup", cve=security.cve_id("cve-2021-44228"))
    assert not report.errors
    sec = items(report, "CVE-2021-44228")
    assert sec["CVSS"].value.startswith("10.0 · Kritik") and sec["CVSS"].level == Level.BAD
    assert sec["Zafiyet türü (CWE)"].value == "CWE-502, CWE-917"
    assert "Kimlik doğrulama ve kullanıcı etkileşimi gerekmiyor" in sec["Ön koşul"].value
    exp = items(report, "İstismar")
    assert exp["CISA KEV"].level == Level.BAD and "Fidye yazılımı" in exp
    assert exp["EPSS (30 gün içinde istismar olasılığı)"].value.startswith("%94.40")
    assert "apache log4j  ≥2.0.1 <2.12.2" in items(report, "Etkilenen ürünler")


def test_cve_falls_back_to_circl(ctx, http):
    http.add(security.NVD, OsintError("bağlantı kurulamadı"))
    http.add("https://cve.circl.lu/", {"cveMetadata": {"datePublished": "2024-01-01", "state": "PUBLISHED"},
                                      "containers": {"cna": {"descriptions": [{"lang": "en", "value": "bir açık"}],
                                                             "metrics": [{"cvssV3_1": {"baseScore": 7.5,
                                                                                      "baseSeverity": "HIGH",
                                                                                      "vectorString": "AV:N"}}]}}})
    http.add(security.KEV_URL, {"vulnerabilities": []})
    http.add("https://api.first.org/", {"data": []})
    report = run(ctx, "cve", "lookup", cve="CVE-2024-0001")
    assert not report.errors and items(report, "CVE-2024-0001")["CVSS"].value.startswith("7.5")
    assert items(report, "İstismar")["CISA KEV"].level == Level.OK


def test_cve_unknown_id(ctx, http):
    http.add(security.NVD, {"vulnerabilities": []})
    http.add("https://cve.circl.lu/", {}, status=404)
    report = run(ctx, "cve", "lookup", cve="CVE-2099-99999")
    assert not report.errors and "kayıtlı değil" in items(report, "Sonuç")["Durum"].value


def test_cve_search_marks_kev(ctx, http):
    http.add(security.NVD, {"totalResults": 1, **LOG4J})
    http.add(security.KEV_URL, KEV)
    report = run(ctx, "cve", "search", query="log4j")
    row = items(report, "Sonuçlar")["CVE-2021-44228 · 10.0"]
    assert row.level == Level.BAD and "KEV" in row.value


def test_netinfo(ctx, http):
    http.add("https://api.ipify.org", {"ip": "88.230.1.2"})
    http.add("https://api64.ipify.org", {"ip": "2a02:ff0::1"})
    http.add("https://ipinfo.io/", {"org": "AS9121 Turk Telekom", "city": "Istanbul", "country": "TR"})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
    report = run(ctx, "netinfo")
    sec = items(report, "İnternet")
    assert sec["Public IPv4"].value == "88.230.1.2" and sec["IPv6"].value == "2a02:ff0::1"
    assert sec["Yerel IP"].value == "192.168.1.23" and "router NAT" in sec["NAT"].value
    assert items(report, "Operatör")["Kurum / ASN"].value == "AS9121 Turk Telekom"
    assert items(report, "Gecikme")["Çalışan DNS yolu"].value == "Cloudflare DoH"


def test_cookie_flags():
    assert nettools._cookie_flags("sid=1; Path=/; Secure; HttpOnly; SameSite=Lax") == ("sid", [])
    assert nettools._cookie_flags("track=1; Path=/") == ("track", ["secure", "httponly", "SameSite"])


def test_http_inspect_chain(ctx, http, monkeypatch):
    import requests
    calls = []

    def fake_get(url, **kw):
        calls.append(url)
        r = requests.Response()
        r.url, r._content, r._content_consumed = url, b"", True
        if url == "http://ornek.com/":
            r.status_code, r.headers["Location"] = 301, "https://ornek.com/"
        else:
            r.status_code = 200
            r.headers.update({"Server": "cloudflare", "CF-RAY": "x", "Content-Type": "text/html",
                              "Set-Cookie": "sid=1; Path=/"})
        r.reason = "OK"
        return r
    monkeypatch.setattr(http, "get", fake_get)
    report = run(ctx, "httpinspect", url=nettools.http_url("http://ornek.com/"))
    assert not report.errors and calls == ["http://ornek.com/", "https://ornek.com/"]
    chain = next(s for s in report.sections if s.title == "İstek zinciri")
    assert chain.items[0].label.startswith("1. 301") and chain.items[-1].label.startswith("2. 200")
    assert items(report, "Yanıt")["CDN"].value == "Cloudflare"
    assert items(report, "Çerezler")["sid"].level == Level.WARN


def test_globalping_ping(ctx, http):
    http.add(nettools.GLOBALPING, {"id": "m1"})  # POST → kimlik
    http.add(nettools.GLOBALPING + "/m1", {"status": "finished", "results": [
        {"probe": {"city": "Istanbul", "country": "TR", "network": "Turk Telekom", "asn": 9121},
         "result": {"status": "finished", "stats": {"min": 10.0, "avg": 12.5, "max": 15.0, "loss": 0}}},
        {"probe": {"city": "Berlin", "country": "DE", "network": "Hetzner", "asn": 24940},
         "result": {"status": "failed", "stats": {}}}]})
    report = run(ctx, "globalping", "ping", target="github.com", location=None)
    sec = next(s for s in report.sections if s.title.startswith("Ping"))
    assert sec.items[0].value.startswith("ort 12.5 ms") and sec.items[0].level == Level.OK
    assert sec.items[1].level == Level.MUTED
    assert http.posted[0][1]["json"]["locations"] == [{"magic": "world"}]


def test_globalping_traceroute(ctx, http):
    http.add(nettools.GLOBALPING, {"id": "t1"})
    http.add(nettools.GLOBALPING + "/t1", {"status": "finished", "results": [
        {"probe": {"city": "Ankara", "country": "TR", "asn": 9121},
         "result": {"hops": [{"resolvedAddress": "10.0.0.1", "timings": [{"rtt": 1.2}]},
                             {"resolvedAddress": None, "timings": []},
                             {"resolvedAddress": "140.82.121.4", "resolvedHostname": "lb.github.com",
                              "asn": [36459], "timings": [{"rtt": 55.1}, {"rtt": 54.0}]}]}}]})
    report = run(ctx, "globalping", "traceroute", target="github.com", location="TR")
    sec = next(s for s in report.sections if s.title.startswith("Traceroute"))
    assert [i.label for i in sec.items] == ["1. 10.0.0.1", "2. *", "3. 140.82.121.4"]
    assert sec.items[2].value == "lb.github.com · 54.0 ms · AS36459"
    assert any("root" in n for n in report.notices)


def test_globalping_quota(ctx, http):
    http.add(nettools.GLOBALPING, {"error": {}}, status=429)
    report = run(ctx, "globalping", "ping", target="github.com", location=None)
    assert "limit" in report.errors[0]
