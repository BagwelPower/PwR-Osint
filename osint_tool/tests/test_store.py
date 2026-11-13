from pwrosint.core.report import Level, Report
from pwrosint.core.store import ReportStore, report_from_dict, to_html


def sample():
    r = Report("DNS Kayıtları · Sorgula", "ornek.com")
    r.summary = "özet"
    r.elapsed = 1.5
    r.section("Kayıtlar").add("A", "1.2.3.4").link("Kaynak", "https://x.y/?a=1&b=2")
    r.section("E-posta güvenliği").add("SPF", "Yok <script>alert(1)</script>", level=Level.BAD)
    r.notice("not")
    r.source("Cloudflare", True)
    r.source("Google", False, "zaman aşımı")
    return r


def test_roundtrip_dict():
    r = sample()
    back = report_from_dict(r.to_dict())
    assert back.to_dict()["sections"] == r.to_dict()["sections"]
    assert back.sources == r.sources and back.notices == ["not"]


def test_store_save_list_load_delete(tmp_path):
    store = ReportStore(tmp_path)
    rid = store.save(sample())
    saved = store.list()
    assert len(saved) == 1 and saved[0].target == "ornek.com" and saved[0].findings == 1
    assert store.load(rid).sections[1].items[0].level == Level.BAD
    store.delete(rid)
    assert store.list() == []


def test_html_escapes_and_links():
    h = to_html(sample())
    assert "<script>alert(1)</script>" not in h and "&lt;script&gt;" in h
    assert 'href="https://x.y/?a=1&amp;b=2"' in h
    assert "Önemli bulgular" in h and "Kaynak durumu" in h


def test_html_drops_dangerous_urls():
    r = Report("t", "x")
    r.section("s").add("kötü", "tıkla", url="javascript:alert(1)")
    assert "javascript:" not in to_html(r)
