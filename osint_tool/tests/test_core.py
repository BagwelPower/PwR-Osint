import json

import pytest

from pwrosint.core import validate
from pwrosint.core.config import Settings, load_settings, save_settings
from pwrosint.core.errors import MissingApiKey
from pwrosint.core.registry import InputError, all_tools, get_tool, parse_inputs
from pwrosint.core.report import Level, Report
from pwrosint.core.runner import run_action


@pytest.mark.parametrize("raw, expected", [
    ("Ornek.COM", "ornek.com"),
    ("https://www.ornek.com/yol?q=1", "www.ornek.com"),
    ("ornek.com.", "ornek.com"),
    ("ornek.com:8443", "ornek.com"),
    ("Türkçe.com", "türkçe.com".encode("idna").decode()),
])
def test_domain_normalizes(raw, expected):
    assert validate.domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "-a.com", "a..com", "1.2.3.4", "a" * 64 + ".com"])
def test_domain_rejects(raw):
    with pytest.raises(ValueError):
        validate.domain(raw)


def test_host_accepts_ip_and_domain():
    assert validate.host(" 8.8.8.8 ") == "8.8.8.8"
    assert validate.host("2001:4860:4860::8888") == "2001:4860:4860::8888"
    assert validate.host("ornek.com") == "ornek.com"
    with pytest.raises(ValueError):
        validate.host("999.1.1.1x")


def test_email_and_username():
    assert validate.email("Ali.Veli@Ornek.COM") == "Ali.Veli@ornek.com"
    for bad in ("ali", "ali@", "a..b@c.com", "ali@ornek"):
        with pytest.raises(ValueError):
            validate.email(bad)
    assert validate.username("@torvalds") == "torvalds"
    with pytest.raises(ValueError):
        validate.username("bad user")


def test_coordinates_and_mac():
    assert validate.coordinates("41.0082, 28.9784") == (41.0082, 28.9784)
    assert validate.coordinates("41.0082 28.9784") == (41.0082, 28.9784)
    with pytest.raises(ValueError):
        validate.coordinates("91, 0")
    assert validate.mac("00-11-22-aa-bb-cc") == "00:11:22:AA:BB:CC"
    with pytest.raises(ValueError):
        validate.mac("00:11:22")


def test_settings_roundtrip(tmp_path):
    path = tmp_path / "sub" / "config.json"
    s = Settings(shodan_api_key="abc", timeout=7)
    save_settings(s, path)
    assert load_settings(path) == s


def test_settings_tolerates_legacy_and_bad_values(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"shodan_api_key": " k ", "timeout": "abc", "censys_api_id": "x",
                                "disclaimer_accepted": "true"}))
    s = load_settings(path)
    assert s.shodan_api_key == "k"
    assert s.timeout == Settings().timeout  # geçersiz değer → varsayılan
    assert s.disclaimer_accepted is True


def test_load_settings_missing_or_corrupt(tmp_path):
    assert load_settings(tmp_path / "yok.json") == Settings()
    bad = tmp_path / "bad.json"
    bad.write_text("{bozuk")
    assert load_settings(bad) == Settings()


def test_registry_is_consistent():
    tools = all_tools()
    assert len({t.id for t in tools}) == len(tools)
    for t in tools:
        assert t.actions, t.id
        assert len({a.id for a in t.actions}) == len(t.actions)
        for a in t.actions:
            assert len({f.name for f in a.fields}) == len(a.fields)


def test_parse_inputs_reports_each_field():
    action = get_tool("email").action("permutate")
    with pytest.raises(InputError) as e:
        parse_inputs(action, {"first": "Ali", "last": "", "domain": "bozuk"})
    assert set(e.value.problems) == {"last", "domain"}


def test_report_text_and_json():
    r = Report("Test", "hedef")
    r.section("Bölüm").add("Anahtar", "değer", level=Level.OK).link("Link", "https://x.y")
    r.error("bir hata")
    text = r.to_text()
    assert "Anahtar" in text and "https://x.y" in text and "bir hata" in text
    data = json.loads(r.to_json())
    assert data["sections"][0]["items"][0]["level"] == "ok"


def test_missing_key_is_a_notice_not_an_error(ctx):
    tool = get_tool("shodan")
    report = run_action(ctx, tool, tool.action("search"), {"query": "port:22"})
    assert not report.errors
    assert report.missing_key == ("Shodan", "shodan_api_key")
    assert "API anahtarı gerekli" in report.to_text()


def test_runner_hides_passwords_from_target(ctx, http):
    http.add("https://api.pwnedpasswords.com/range/", "")
    tool = get_tool("hibp")
    report = run_action(ctx, tool, tool.action("password"), {"password": "gizli123"})
    assert "gizli123" not in report.target
    assert "gizli123" not in report.to_json()


def test_require_raises(ctx):
    with pytest.raises(MissingApiKey):
        ctx.require("shodan_api_key", "Shodan")


def test_every_tool_is_documented():
    from pwrosint.core.registry import CATEGORY_INFO
    for t in all_tools():
        assert len(t.description) > 60, t.id
        assert t.category in CATEGORY_INFO, t.id


def test_report_target_is_human_readable(ctx):
    from pwrosint.modules.misc import parse_plate
    tool = get_tool("vehicle")
    report = run_action(ctx, tool, tool.action("plate"), {"plate": parse_plate("34abc123")})
    assert report.target == "34 ABC 123"


def test_risky_ports_only_flag_dangerous_services():
    from pwrosint.core.ports import classify
    assert classify([53, 80, 443]) == []
    flagged = {p: lvl for p, _, lvl in classify([22, 3389, 6379, 443])}
    assert flagged == {3389: Level.BAD, 6379: Level.BAD}


def test_highlights_collapse_repeats():
    r = Report("t")
    for name in ("Adobe", "LinkedIn", "Canva", "Dropbox"):
        r.section(f"{name} — 2020").add("Sızan veriler", "e-posta, şifre", level=Level.BAD)
    r.section("Şifre").add("Durum", "sızmış", level=Level.BAD)
    hl = r.highlights()
    assert len(hl) == 2
    assert hl[0][1].label == "Sızan veriler" and "4 kayıtta: Adobe, LinkedIn" in hl[0][1].value


def test_pivot_only_on_plain_values():
    import main
    from pwrosint.core.report import Item
    assert main.pivot_target(Item("Abuse iletişim", "abuse@google.com")).tool == "email"
    assert main.pivot_target(Item("A", "140.82.112.3")).tool == "host"
    assert main.pivot_target(Item("www.github.com")).tool == "host"
    assert main.pivot_target(Item("Shodan", "https://www.shodan.io/host/8.8.8.8",
                                  url="https://www.shodan.io/host/8.8.8.8")) is None
    assert main.pivot_target(Item("Tür", "Ücretsiz e-posta sağlayıcısı")) is None
    assert main.pivot_target(Item("Domain", "gmail.com"), current_target="gmail.com") is None


def test_highlights_show_variety():
    r = Report("t")
    typo = r.section("Taklit · Kayıtlı benzer domainler")
    for n in range(20):
        typo.add(f"g{n}thub.com", "MX var", level=Level.BAD)
    r.section("TLS · Sertifika").add("Kalan süre", "5 gün", level=Level.WARN)
    r.section("Altyapı · Açık portlar").add("Port 3306 internete açık", "MySQL", level=Level.BAD)
    hl = r.highlights()
    titles = [t for t, _ in hl]
    assert "TLS · Sertifika" in titles and "Altyapı · Açık portlar" in titles
    assert any(i.label == "+17 benzer bulgu" for _, i in hl)
    assert len(hl) <= 8
