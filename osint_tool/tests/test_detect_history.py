import pytest

from pwrosint.core.detect import suggest
from pwrosint.core.history import History
from pwrosint.core.registry import get_tool


@pytest.mark.parametrize("text, tool, action", [
    ("ali@ornek.com", "email", "analyze"),
    ("8.8.8.8", "host", "profile"),
    ("+90 532 123 45 67", "phone", "analyze"),
    ("44d88612fea8a8f36de82e1278abb02f", "virustotal", "file"),
    ("00:11:22:33:44:55", "geo", "bssid"),
    ("41.0082, 28.9784", "geo", "coords"),
    ("1HGCM82633A004352", "vehicle", "vin"),
    ("34 ABC 123", "vehicle", "plate"),
    ("github.com", "host", "profile"),
    ("Ahmet Yılmaz", "name", "search"),
    ("torvalds", "username", "scan"),
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "crypto", "btc"),
    ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "crypto", "btc"),
    ("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae", "crypto", "eth"),
    ("AS9121", "asn", "lookup"),
    ("https://ornek.com/foto.JPG", "image", "analyze"),
    ("https://ornek.com/hakkimizda", "site", "analyze"),
])
def test_suggest_first_choice(text, tool, action):
    s = suggest(text)
    assert s, text
    assert (s[0].tool, s[0].action) == (tool, action)
    get_tool(s[0].tool).action(s[0].action)  # öneri gerçekten var olan bir aracı göstermeli


def test_suggest_empty():
    assert suggest("   ") == []


def test_history_dedupes_and_skips_passwords(tmp_path):
    h = History(tmp_path / "history.json")
    dns = get_tool("dns").actions[0]
    h.add("dns", dns, {"domain": "a.com"})
    h.add("dns", dns, {"domain": "b.com"})
    h.add("dns", dns, {"domain": "a.com"})
    assert [e.values["domain"] for e in h.entries] == ["a.com", "b.com"]
    pw = get_tool("hibp").action("password")
    h.add("hibp", pw, {"password": "gizli"})
    assert all("gizli" not in str(e.values) for e in h.entries)
    assert History(tmp_path / "history.json").entries[0].values == {"domain": "a.com"}


def test_every_suggestion_points_to_real_field():
    samples = ["ali@ornek.com", "8.8.8.8", "github.com", "torvalds", "https://ornek.com/a.png",
               "AS15169", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Ahmet Yılmaz"]
    for text in samples:
        for s in suggest(text):
            action = get_tool(s.tool).action(s.action)
            assert s.field in {f.name for f in action.fields}, (text, s)
