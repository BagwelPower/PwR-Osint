import struct
from collections import Counter

import pytest

from pwrosint.core.errors import OsintError
from pwrosint.core.report import Level
from pwrosint.modules import crypto, media, network, social, threat, web

from test_modules import items, run


# ---------------------------------------------------------------- EXIF

def build_jpeg_with_exif(make="Apple", model="iPhone 15", lat=(41, 0, 29.52), lon=(28, 58, 42.24),
                         lat_ref="N", lon_ref="E", date="2024:05:01 12:34:56") -> bytes:
    """Küçük-endian TIFF/EXIF bloğu olan minimal bir JPEG üretir."""
    e = "<"
    entries0, entries_exif, entries_gps, blob = [], [], [], bytearray()

    def ascii_entry(tag, text):
        return (tag, 2, text.encode() + b"\0")

    def rational_entry(tag, values):
        raw = b"".join(struct.pack(e + "II", int(v * 100), 100) for v in values)
        return (tag, 5, raw)

    entries0 = [ascii_entry(0x010F, make), ascii_entry(0x0110, model)]
    entries_exif = [ascii_entry(0x9003, date)]
    entries_gps = [(1, 2, lat_ref.encode() + b"\0"), rational_entry(2, lat),
                   (3, 2, lon_ref.encode() + b"\0"), rational_entry(4, lon)]

    def ifd_size(n):
        return 2 + 12 * n + 4

    off0 = 8
    off_exif = off0 + ifd_size(len(entries0) + 2)
    off_gps = off_exif + ifd_size(len(entries_exif))
    data_off = off_gps + ifd_size(len(entries_gps))

    def pack_ifd(entries, extra=()):
        nonlocal data_off
        out = struct.pack(e + "H", len(entries) + len(extra))
        for tag, typ, raw in entries:
            count = len(raw) if typ == 2 else len(raw) // 8
            if len(raw) <= 4:
                out += struct.pack(e + "HHI", tag, typ, count) + raw.ljust(4, b"\0")
            else:
                out += struct.pack(e + "HHII", tag, typ, count, data_off)
                blob.extend(raw)
                data_off += len(raw)
        for tag, value in extra:
            out += struct.pack(e + "HHII", tag, 4, 1, value)
        return out + b"\0\0\0\0"

    ifd0 = pack_ifd(entries0, [(0x8769, off_exif), (0x8825, off_gps)])
    ifd_exif = pack_ifd(entries_exif)
    ifd_gps = pack_ifd(entries_gps)
    tiff = b"II*\0" + struct.pack(e + "I", off0) + ifd0 + ifd_exif + ifd_gps + bytes(blob)
    app1 = b"Exif\0\0" + tiff
    sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 480, 640, 1) + b"\x01\x11\x00"
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + sof + b"\xff\xd9"


def test_exif_and_gps():
    jpeg = build_jpeg_with_exif()
    exif = media.parse_exif(jpeg)
    assert exif["Make"] == "Apple" and exif["Model"] == "iPhone 15"
    assert exif["DateTimeOriginal"] == "2024:05:01 12:34:56"
    assert media.gps_coords(exif) == pytest.approx((41.0082, 28.9784), abs=1e-4)
    assert media.image_size(jpeg) == ("JPEG", 640, 480)


def test_gps_south_west():
    exif = media.parse_exif(build_jpeg_with_exif(lat=(33, 51, 0), lon=(151, 12, 0), lat_ref="S", lon_ref="W"))
    lat, lon = media.gps_coords(exif)
    assert lat < 0 and lon < 0


def test_exif_absent_or_garbage():
    assert media.parse_exif(b"\xff\xd8\xff\xd9") == {}
    assert media.parse_exif(b"not a jpeg") == {}
    assert media.parse_exif(b"\xff\xd8\xff\xe1\x00\x10Exif\0\0II*\0\xff\xff\xff\x7f") == {}  # bozuk işaretçi


def test_image_size_png_gif():
    png = b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + struct.pack(">II", 800, 600) + b"\0" * 8
    assert media.image_size(png) == ("PNG", 800, 600)
    gif = b"GIF89a" + struct.pack("<HH", 32, 16) + b"\0" * 4
    assert media.image_size(gif) == ("GIF", 32, 16)


def test_image_tool_end_to_end(ctx, http):
    http.add("https://ornek.com/foto.jpg", build_jpeg_with_exif())
    report = run(ctx, "image", url="https://ornek.com/foto.jpg")
    assert not report.errors
    gps = items(report, "GPS")
    assert gps["Koordinat"].level == Level.BAD and "41.0082" in gps["Koordinat"].value
    assert items(report, "EXIF")["Cihaz"].value == "iPhone 15"


# ---------------------------------------------------------------- kripto

@pytest.mark.parametrize("addr", [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
])
def test_btc_valid(addr):
    assert crypto.btc_address(addr)


@pytest.mark.parametrize("addr", [
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",           # bozuk sağlama
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx",   # bozuk bech32
    "0x123", "hello",
])
def test_btc_invalid(addr):
    with pytest.raises(ValueError):
        crypto.btc_address(addr)


def test_btc_kind_and_eth():
    assert crypto.btc_kind("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297").startswith("Taproot")
    assert crypto.eth_address("0xDE0B295669A9FD93D5F28D9EC85E40F4CB697BAE") == "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"
    with pytest.raises(ValueError):
        crypto.eth_address("0xzz")


def test_btc_report(ctx, http):
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    http.add("https://api.coingecko.com/", {"bitcoin": {"usd": 100000, "try": 3500000}})
    http.add(f"https://blockstream.info/api/address/{addr}/txs", [
        {"txid": "ab", "status": {"block_time": 1231006505}, "vin": [],
         "vout": [{"scriptpubkey_address": addr, "value": 5000000000}]}])
    http.add(f"https://blockstream.info/api/address/{addr}", {
        "chain_stats": {"funded_txo_sum": 5000000000, "spent_txo_sum": 0, "tx_count": 1}, "mempool_stats": {}})
    report = run(ctx, "crypto", "btc", address=addr)
    adr = items(report, "Adres")
    assert adr["Bakiye"].value.startswith("50.00000000 BTC") and "$5,000,000" in adr["Bakiye"].value
    assert adr["İlk görülme"].value == "2009-01-03"
    assert items(report, "Son işlemler")["2009-01-03 18:15"].value == "+50.00000000 BTC"


# ---------------------------------------------------------------- web

PAGE = """<html lang="tr"><head><title> Örnek  Mağaza </title>
<meta name="description" content="Açıklama &amp; test">
<meta name="generator" content="WordPress 6.5">
<link href="/wp-content/themes/x/style.css"><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script>gtag('config', 'G-ABC123DEF4'); fbq('init', '123456789012345');</script>
<script async src="https://pagead2.googlesyndication.com/pagead/js?client=ca-pub-1234567890123456"></script>
</head><body>
<a href="mailto:info@ornek.com">info@ornek.com</a> logo@2x.png bilgi@ornek.com
Tel: 0 (212) 555 12 34 · +90 532 123 45 67
<a href="https://www.instagram.com/ornekmagaza/">IG</a> <a href="https://x.com/ornek_tr">X</a>
<a href="https://twitter.com/intent/tweet?text=a">paylaş</a> <a href="https://wa.me/905321234567">WA</a>
</body></html>"""


def test_extract_contacts_and_ids():
    found = web.extract(PAGE)
    assert found["emails"] == ["bilgi@ornek.com", "info@ornek.com"]
    assert "+90 212 555 12 34" in found["phones"] and "+90 532 123 45 67" in found["phones"]
    assert "Instagram|ornekmagaza" in found["social"] and "X / Twitter|ornek_tr" in found["social"]
    assert not any(s.endswith("|intent") for s in found["social"])
    assert "WhatsApp|905321234567" in found["social"]
    ids = dict(x.split("|") for x in found["ids"])
    assert ids["Google Analytics 4"] == "G-ABC123DEF4"
    assert ids["Google AdSense"] == "ca-pub-1234567890123456"
    assert ids["Meta Pixel"] == "123456789012345"


def test_detect_tech():
    page = web.Page("https://ornek.com/", 200, {"server": "cloudflare", "x-powered-by": "PHP/8.2"},
                    ["PHPSESSID"], PAGE, [])
    names = {n for n, _, _ in web.detect_tech(page)}
    assert {"WordPress", "jQuery", "Cloudflare", "PHP", "Google Analytics", "Google AdSense"} <= names
    assert "Shopify" not in names


def test_parse_url():
    assert web.parse_url("Ornek.com") == "https://ornek.com/"
    assert web.parse_url("http://ornek.com/a?b=1") == "http://ornek.com/a?b=1"
    with pytest.raises(ValueError):
        web.parse_url("ftp://ornek.com")


def test_parse_robots():
    disallow, sitemaps = web.parse_robots(
        "User-agent: *\nDisallow: /admin/ # gizli\nDisallow:\nDisallow: /admin/\nSitemap: https://o.com/s.xml\n")
    assert disallow == ["/admin/"] and sitemaps == ["https://o.com/s.xml"]


def test_site_tool(ctx, http):
    http.add("https://ornek.com/", PAGE)
    report = run(ctx, "site", url=web.parse_url("ornek.com"))
    assert not report.errors
    assert items(report, "Sayfa")["Başlık"].value == "Örnek Mağaza"
    assert "WordPress" in items(report, "Teknolojiler")
    assert items(report, "Takip kimlikleri")["Google Analytics 4"].url.startswith("https://publicwww.com/")


def test_dorks_are_scoped():
    for title, q in web.dorks("ornek.com"):
        assert "ornek.com" in q, title


# ---------------------------------------------------------------- sosyal

def test_commit_identities():
    events = [
        {"type": "PushEvent", "payload": {"commits": [
            {"author": {"name": "Ali", "email": "Ali@Ornek.com"}},
            {"author": {"name": "Ali", "email": "ali@ornek.com"}},
            {"author": {"name": "Bot", "email": "1+bot@users.noreply.github.com"}}]}},
        {"type": "WatchEvent"},
    ]
    ids = social.commit_identities(events)
    assert ids[("Ali", "ali@ornek.com")] == 2
    assert len(ids) == 2


def test_guess_timezone():
    # UTC 23:00-05:00 arası sessiz → yerel 02:00 = UTC 23:00 → UTC+3
    hours = Counter({h: 10 for h in range(24) if h not in (23, 0, 1, 2, 3, 4)})
    assert social.guess_timezone(hours) == "UTC+3 civarı"
    assert social.guess_timezone(Counter({1: 3})) == "Yetersiz veri"


def test_github_report(ctx, http):
    http.add("https://api.github.com/users/ali/repos", [
        {"name": "proje", "stargazers_count": 10, "language": "Python", "fork": False, "pushed_at": "2025-01-01T00:00:00Z",
         "html_url": "https://github.com/ali/proje"},
        {"name": "fork", "stargazers_count": 999, "language": "C", "fork": True}])
    http.add("https://api.github.com/users/ali/orgs", [{"login": "acme"}])
    http.add("https://api.github.com/users/ali/events/public", [
        {"type": "PushEvent", "created_at": "2025-01-01T10:00:00Z",
         "payload": {"commits": [{"author": {"name": "Ali V", "email": "ali@ornek.com"}}]}}])
    http.add("https://api.github.com/users/ali", {"login": "ali", "name": "Ali Veli", "blog": "ali.dev",
                                                   "public_repos": 2, "html_url": "https://github.com/ali"})
    report = run(ctx, "github", username="ali")
    assert not report.errors
    assert items(report, "Profil")["Web sitesi"].url == "https://ali.dev"
    repos = items(report, "Repolar")
    assert repos["Toplam yıldız"].value == "10" and "fork" not in repos
    assert items(report, "Commit")["ali@ornek.com"].level == Level.WARN


def test_github_rate_limit_vs_other_403(ctx, http, monkeypatch):
    http.add("https://api.github.com/users/ali", {}, status=403)
    report = run(ctx, "github", username="ali")
    assert report.errors == ["api.github.com: HTTP 403"]  # limit değilse limit demiyoruz

    orig = http.get

    def limited(url, **kw):
        resp = orig(url, **kw)
        resp.headers["X-RateLimit-Remaining"] = "0"
        return resp

    monkeypatch.setattr(http, "get", limited)
    report = run(ctx, "github", username="ali")
    assert "limit" in report.errors[0] and "token" in report.errors[0]


def test_telegram(ctx, http):
    http.add("https://t.me/kanal", '<meta property="og:title" content="Haber Kanalı">'
             '<div class="tgme_page_title">x</div><div class="tgme_page_extra">12 345 subscribers</div>')
    report = run(ctx, "telegram", username="kanal")
    prof = items(report, "Profil")
    assert prof["Tür"].value == "Kanal" and prof["Ad"].value == "Haber Kanalı"


def test_fediverse_handle():
    assert social.fediverse_handle("@ali@Mastodon.Social") == ("ali", "mastodon.social")
    with pytest.raises(ValueError):
        social.fediverse_handle("ali")


# ---------------------------------------------------------------- ağ & tehdit

def test_asn_or_ip():
    assert network.asn_or_ip("as 9121") == "AS9121"
    assert network.asn_or_ip("15169") == "AS15169"
    assert network.asn_or_ip("8.8.8.8") == "8.8.8.8"
    with pytest.raises(ValueError):
        network.asn_or_ip("bozuk")


def test_typosquats():
    c = threat.typosquats("garanti.com.tr")
    assert "garamti.com.tr" in c or "garanit.com.tr" in c
    assert "garanti.com" in c and c["garanti.com"] == "farklı uzantı"
    assert "garanti-giris.com.tr" in c
    assert "garanti.com.tr" not in c
    assert all(len(d.split(".")[0]) <= 63 for d in c)
    assert threat.split_domain("a.b.co.uk") == ("b", "co.uk")


def test_typosquat_tool(ctx, http):
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 3})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "6.6.6.6"}]},
             match_params={"name": "garanti-giris.com.tr", "type": "A"})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 15, "data": "10 mx."}]},
             match_params={"name": "garanti-giris.com.tr", "type": "MX"})
    report = run(ctx, "phishing", "typosquat", domain="garanti.com.tr")
    sec = items(report, "Kayıtlı")
    assert list(sec) == ["garanti-giris.com.tr"] and sec["garanti-giris.com.tr"].level == Level.BAD


def test_dnsbl(ctx, http):
    assert threat.dnsbl_name("1.2.3.4", "zen.spamhaus.org") == "4.3.2.1.zen.spamhaus.org"
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 3})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "127.0.0.2"}]},
             match_params={"name": "4.3.2.1.bl.spamcop.net"})
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "127.255.255.254"}]},
             match_params={"name": "4.3.2.1.zen.spamhaus.org"})
    report = run(ctx, "blacklist", ip="1.2.3.4")
    sec = items(report, "Kara liste")
    assert sec["SpamCop"].level == Level.BAD
    assert "Spamhaus ZEN" not in sec  # genel DNS engeli ≠ listede; kaynak durumuna taşınır
    assert ("Spamhaus ZEN", False) in [(n, ok) for n, ok, _ in report.sources]
    assert sec["Barracuda"].level == Level.OK
    assert report.summary.startswith("1 kara listede")


def test_openphish(ctx, http):
    http.add("https://openphish.com/feed.txt", "https://login.ornek.com/x\nhttps://baska.com/ornek.com\n")
    report = run(ctx, "phishing", "openphish", domain="ornek.com")
    assert list(items(report, "OpenPhish")) == ["https://login.ornek.com/x"]


def test_reverse_ip_limit_message(ctx, http):
    http.add("https://api.hackertarget.com/reverseiplookup/", "API count exceeded - Increase Quota")
    report = run(ctx, "reverseip", target="8.8.8.8")
    assert "limit" in report.errors[0]


def test_reddit_direct(ctx, http):
    http.add("https://www.reddit.com/user/ali/about.json", {"data": {"created_utc": 1136073600, "link_karma": 5,
                                                                     "comment_karma": 7, "is_mod": True}})
    http.add("https://www.reddit.com/user/ali/comments.json",
             {"data": {"children": [{"data": {"subreddit": "Turkey", "created_utc": 1700000000}}]}})
    http.add("https://www.reddit.com/user/ali/submitted.json", {"data": {"children": []}})
    report = run(ctx, "reddit", username="ali")
    assert not report.errors
    assert items(report, "Profil")["Oluşturulma"].value.startswith("2006-01-01")
    assert "r/Turkey (1)" in items(report, "Aktivite")["En çok yazdığı subreddit'ler"].value


def test_reddit_blocked_falls_back_to_archive(ctx, http):
    for host in ("https://www.reddit.com", "https://old.reddit.com", "https://api.reddit.com"):
        http.add(host, "Blocked", status=403)
    http.add("https://arctic-shift.photon-reddit.com/api/comments/search",
             {"data": [{"subreddit": "Turkey", "created_utc": 1600000000}]})
    http.add("https://arctic-shift.photon-reddit.com/api/posts/search",
             {"data": [{"subreddit": "istanbul", "created_utc": 1500000000}]})
    report = run(ctx, "reddit", username="ali")
    assert not report.errors
    prof = items(report, "Profil")
    assert prof["İlk görülen etkinlik"].value.startswith("2017-07-14")
    assert "Arctic Shift" in next(s.title for s in report.sections if s.title.startswith("Aktivite"))


def test_reddit_not_found(ctx, http):
    http.add("https://www.reddit.com/user/yok/about.json", {"error": 404}, status=404)
    report = run(ctx, "reddit", username="yok")
    assert items(report, "Sonuç")["Durum"].level == Level.MUTED and not report.errors


def test_password_strength():
    from pwrosint.modules.threat import password_strength
    weak = dict((l, (v, lv)) for l, v, lv in password_strength("galatasaray1905"))
    assert weak["Değerlendirme"][1] == Level.BAD and "Tahmin edilebilir kalıp" in weak
    strong = dict((l, (v, lv)) for l, v, lv in password_strength("k9#Vq!2zR@pL7m$w"))
    assert strong["Değerlendirme"][0].startswith("Güçlü")
