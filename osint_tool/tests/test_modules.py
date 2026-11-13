import hashlib

import pytest

from pwrosint.core.errors import OsintError
from pwrosint.core.registry import get_tool
from pwrosint.core.report import Level, Report
from pwrosint.core.runner import run_action
from pwrosint.modules import misc, network, person, threat

from conftest import add_dns


def run(ctx, tool_id, action_id=None, **values):
    tool = get_tool(tool_id)
    action = tool.action(action_id) if action_id else tool.actions[0]
    return run_action(ctx, tool, action, values)


def items(report, title_prefix):
    sec = next(s for s in report.sections if s.title.startswith(title_prefix))
    return {i.label: i for i in sec.items}


# ---------------------------------------------------------------- username

def test_check_site_strategies(ctx, http):
    gh = next(s for s in person.SITES if s.name == "GitHub")
    steam = next(s for s in person.SITES if s.name == "Steam")
    tg = next(s for s in person.SITES if s.name == "Telegram")

    http.add("https://api.github.com/users/var", {"login": "var"})
    http.add("https://api.github.com/users/yok", {}, status=404)
    assert person.check_site(ctx, gh, "var")[0] == person.FOUND
    assert person.check_site(ctx, gh, "yok")[0] == person.MISSING

    http.add("https://steamcommunity.com/id/yok", "<p>The specified profile could not be found.</p>")
    assert person.check_site(ctx, steam, "yok")[0] == person.MISSING

    http.add("https://t.me/var", '<div class="tgme_page_title">Var</div>')
    http.add("https://t.me/yok", "<html>Telegram</html>")
    assert person.check_site(ctx, tg, "var")[0] == person.FOUND
    assert person.check_site(ctx, tg, "yok")[0] == person.MISSING

    http.add("https://api.github.com/users/bot", "", status=429)
    assert person.check_site(ctx, gh, "bot") == (person.UNKNOWN, "HTTP 429")


def test_username_report_groups_results(ctx, http):
    http.add("https://", "", status=404)  # varsayılan: hiçbir yerde yok
    http.add("https://registry.npmjs.org/", '{"objects":[],"total":0}')
    http.add("https://api.github.com/users/ali", {"login": "ali"})
    http.add("https://gitlab.com/", "", status=503)
    report = run(ctx, "username", username="ali")
    assert not report.errors
    titles = [s.title for s in report.sections]
    assert titles[0] == "Bulunan profiller"
    assert "GitHub" in items(report, "Bulunan")
    assert "GitLab" in items(report, "Doğrulanamadı")
    assert "Instagram" in items(report, "Manuel")
    assert "1 bulundu" in report.summary


# ---------------------------------------------------------------- e-posta

def test_email_analysis(ctx, http):
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [
        {"type": 15, "data": "10 aspmx.l.google.com."}]}, match_params={"name": "ornek.com", "type": "MX"})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [
        {"type": 16, "data": '"v=spf1 include:_spf.google.com ~all"'}]},
        match_params={"name": "ornek.com", "type": "TXT"})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 3}, match_params={"name": "_dmarc.ornek.com"})
    http.add("https://www.gravatar.com/avatar/", "", status=404)
    report = run(ctx, "email", email="ali@ornek.com")
    mail = items(report, "Posta")
    assert mail["MX"].level == Level.OK
    assert mail["Sağlayıcı"].value.startswith("Google")
    assert mail["SPF"].level == Level.OK
    assert mail["DMARC"].level == Level.WARN
    grav = items(report, "Gravatar")
    assert grav["MD5"].value == hashlib.md5(b"ali@ornek.com").hexdigest()


def test_email_survives_dns_outage(ctx, http):
    http.add("https://cloudflare-dns.com/", OsintError("down"))
    http.add("https://dns.google/", OsintError("down"))
    http.add("https://www.gravatar.com/avatar/", "", status=404)
    report = run(ctx, "email", email="ali@mailinator.com")
    assert items(report, "Temel")["Tür"].level == Level.BAD
    assert items(report, "Posta")["Durum"].level == Level.MUTED
    assert ("DNS", False) in [(n, ok) for n, ok, _ in report.sources]


def test_permutations_transliterate_and_dedupe():
    perms = person.permutations("Çağrı", "Öztürk", "ornek.com")
    assert "cagri.ozturk@ornek.com" in perms
    assert "c.ozturk@ornek.com" in perms
    assert len(perms) == len(set(perms))


# ---------------------------------------------------------------- telefon

def test_phone_turkish_mobile(ctx):
    report = run(ctx, "phone", phone="0532 123 45 67")
    num = items(report, "Numara")
    assert num["Geçerli"].level == Level.OK
    assert num["Tür"].value == "Mobil"
    assert num["Operatör (tahsis)"].value == "Turkcell"
    assert items(report, "Formatlar")["E.164"].value == "+905321234567"


def test_phone_invalid(ctx):
    report = run(ctx, "phone", phone="+90 123")
    assert items(report, "Numara")["Geçerli"].level == Level.BAD


# ---------------------------------------------------------------- DNS

def test_dns_records_and_mail_security(ctx, http):
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0})
    add = lambda t, a: http.add("https://cloudflare-dns.com/dns-query",  # noqa: E731
                                {"Status": 0, "Answer": [{"type": {"A": 1, "TXT": 16, "MX": 15}[t], "data": x} for x in a]},
                                match_params={"name": "ornek.com", "type": t})
    add("A", ["93.184.216.34"])
    add("MX", ["10 mail.ornek.com."])
    add("TXT", ['"v=spf1 +all"', '"google-site-verification=abc"'])
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [
        {"type": 16, "data": '"v=DMARC1; p=reject"'}]}, match_params={"name": "_dmarc.ornek.com"})
    report = run(ctx, "dns", domain="ornek.com")
    assert not report.errors
    sec = items(report, "E-posta")
    assert sec["SPF uyarısı"].level == Level.BAD
    assert sec["DMARC"].level == Level.OK
    assert "google-site-verification" in sec["Doğrulama kayıtları"].value


def test_dns_total_outage_is_single_error(ctx, http):
    http.add("https://cloudflare-dns.com/", OsintError("x"))
    http.add("https://dns.google/", OsintError("y"))
    report = run(ctx, "dns", domain="ornek.com")
    assert len(report.errors) == 1 and not report.sections


def test_dns_falls_back_to_google(ctx, http):
    http.add("https://cloudflare-dns.com/", OsintError("down"))
    http.add("https://dns.google/resolve", {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
    from pwrosint.core import dns
    assert dns.resolve(ctx, "ornek.com") == ["1.2.3.4"]


# ---------------------------------------------------------------- IP

def test_private_ip_short_circuits(ctx):
    report = run(ctx, "host", target="192.168.1.10")
    assert items(report, "IP:")["Tür"].level == Level.WARN
    assert not report.errors


def test_public_ip_profile(ctx, http):
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 12, "data": "dns.google."}]})
    http.add("https://ipinfo.io/8.8.8.8/json", {"city": "Mountain View", "country": "US", "org": "AS15169 Google",
                                               "loc": "37.4,-122.1"})
    http.add("https://rdap.org/ip/8.8.8.8", {"name": "GOGL", "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@google.com"]]]}]})
    http.add("https://internetdb.shodan.io/8.8.8.8", {"ports": [53, 443], "hostnames": ["dns.google"],
                                                     "vulns": [], "tags": [], "cpes": []})
    report = run(ctx, "host", target="8.8.8.8")
    assert not report.errors
    assert items(report, "IP:")["Reverse DNS"].value == "dns.google"
    geo = items(report, "Konum")
    assert geo["Abuse iletişim"].value == "abuse@google.com"
    assert "openstreetmap" in geo["Harita"].url
    exp = items(report, "Açık portlar")
    assert exp["Portlar"].value == "53, 443"
    assert exp["Zafiyetler (CVE)"].level == Level.OK


def test_rdap_expiry_warning(ctx, http):
    from datetime import datetime, timedelta, timezone
    soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    http.add("https://rdap.org/domain/ornek.com", {"events": [
        {"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": soon}]})
    rep = Report("t")
    network._rdap_domain(ctx, rep, "ornek.com")
    whois = items(rep, "WHOIS")
    assert whois["Bitiş tarihi"].level == Level.WARN
    assert whois["Kayıt tarihi"].level == Level.INFO


# ---------------------------------------------------------------- subdomain

def test_clean_subdomains():
    raw = {"*.ornek.com", "A.ornek.com.", "ornek.com", "kotu-ornek.com", "x.baska.com", "b.ornek.com\n"}
    assert network.clean_subdomains(raw, "ornek.com") == {"ornek.com", "a.ornek.com", "b.ornek.com"}


def test_subdomains_merge_sources(ctx, http):
    http.add("https://crt.sh/", [{"name_value": "www.ornek.com\n*.dev.ornek.com"}])
    http.add("https://api.hackertarget.com/", "API count exceeded")
    http.add("https://otx.alienvault.com/", {"passive_dns": [{"hostname": "mail.ornek.com"}]})
    http.add("https://jldc.me/", ["www.ornek.com"])
    http.add("https://api.certspotter.com/", [])
    http.add("https://urlscan.io/", {"results": []})
    http.add("https://web.archive.org/", [])
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 3})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "1.1.1.1"}]},
             match_params={"name": "www.ornek.com"})
    report = run(ctx, "subdomain", domain="ornek.com")
    assert ("HackerTarget", False) in [(n, ok) for n, ok, _ in report.sources]
    assert list(items(report, "Aktif")) == ["www.ornek.com"]
    assert set(items(report, "Çözülmeyen")) == {"dev.ornek.com", "mail.ornek.com"}
    assert report.summary.startswith("3 benzersiz")


# ---------------------------------------------------------------- tehdit

def test_pwned_password_k_anonymity(ctx, http):
    digest = hashlib.sha1(b"password").hexdigest().upper()
    http.add(f"https://api.pwnedpasswords.com/range/{digest[:5]}", f"0000:1\r\n{digest[5:]}:42\r\n")
    assert threat.pwned_count(ctx, "password") == 42
    url, _ = http.calls[-1]
    assert digest[5:] not in url  # şifrenin tamamı asla gönderilmez


def test_hibp_email_breaches(ctx, http):
    ctx.settings.haveibeenpwned_api_key = "k"
    http.add("https://haveibeenpwned.com/api/v3/breachedaccount/", [
        {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "PwnCount": 152445165,
         "DataClasses": ["Email addresses", "Passwords"], "Description": "<b>Ekim</b> 2013"}])
    report = run(ctx, "hibp", "email", email="ali@ornek.com")
    assert report.summary == "1 sızıntıda bulundu."
    assert report.sections[0].note == "Ekim 2013"


def test_vt_file_hash_validation():
    assert threat.file_hash("44D88612FEA8A8F36DE82E1278ABB02F") == "44d88612fea8a8f36de82e1278abb02f"
    with pytest.raises(ValueError):
        threat.file_hash("xyz")


def test_vt_domain(ctx, http):
    ctx.settings.virustotal_api_key = "k"
    http.add("https://www.virustotal.com/api/v3/domains/ornek.com", {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 60},
        "last_analysis_results": {"EngineA": {"category": "malicious", "result": "phishing"}},
        "reputation": -5}}})
    report = run(ctx, "virustotal", "domain", domain="ornek.com")
    assert items(report, "Analiz")["Tespit"].level == Level.BAD
    assert items(report, "İşaretleyen")["EngineA"].value == "phishing"


# ---------------------------------------------------------------- araç

def test_vin_check_digit_and_year():
    assert misc.vin_check_digit("1HGCM82633A004352") == "3"
    assert misc.vin_check_digit("1M8GDM9AXKP042788") == "X"
    assert misc.vin_years("1HGCM82633A004352") == [2003, 2033]


@pytest.mark.parametrize("bad", ["123", "1HGCM82633A00435O", "1HGCM82633A0043521"])
def test_vin_rejects(bad):
    with pytest.raises(ValueError):
        misc.parse_vin(bad)


def test_plate_parsing():
    p = misc.parse_plate("34 abc 123")
    assert p["province"] == "İstanbul" and p["valid_format"]
    assert misc.parse_plate("06A1234")["province"] == "Ankara"
    assert not misc.parse_plate("06ABC1234")["valid_format"]
    for bad in ("99ABC123", "34QWE12", "ABC"):
        with pytest.raises(ValueError):
            misc.parse_plate(bad)
    assert misc.PROVINCES[80] == "Düzce" and len(misc.PROVINCES) == 81


def test_mac_flags_randomized(ctx, http):
    http.add("https://api.macvendors.com/", "", status=404)
    report = run(ctx, "geo", "bssid", mac="DA:A1:19:00:00:01")
    sec = items(report, "Adres")
    assert sec["Tür"].level == Level.WARN


def test_check_site_fallback_when_blocked(ctx, http):
    reddit = next(s for s in person.SITES if s.name == "Reddit")
    http.add("https://www.reddit.com/", "Blocked", status=403)
    http.add("https://arctic-shift.photon-reddit.com/", '{"data":[{"author":"ali"}]}')
    assert person.check_site(ctx, reddit, "ali")[0] == person.FOUND
    http.add("https://arctic-shift.photon-reddit.com/", '{"data":[]}')
    assert person.check_site(ctx, reddit, "ali")[0] == person.UNKNOWN  # yokluk kanıtlanamaz


def test_npm_by_search(ctx, http):
    npm = next(s for s in person.SITES if s.name == "npm")
    http.add("https://registry.npmjs.org/", '{"objects":[{}],"total":3}')
    assert person.check_site(ctx, npm, "sindresorhus")[0] == person.FOUND
    http.add("https://registry.npmjs.org/", '{"objects":[],"total":0}')
    assert person.check_site(ctx, npm, "yok")[0] == person.MISSING


def test_tls_uses_certifi_bundle():
    import certifi
    ctx = network._trust_store()
    assert ctx.verify_mode.name == "CERT_REQUIRED" and ctx.check_hostname
    assert ctx.cert_store_stats()["x509_ca"] > 50  # certifi paketi yüklendi
    assert certifi.where()
