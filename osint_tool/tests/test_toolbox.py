import ipaddress

import pytest

from pwrosint.core.report import Level
from pwrosint.core.samples import SAMPLE_JWT
from pwrosint.modules import security, toolbox

from test_modules import items, run

PHISH = """Received: from mx.alici.com (mx.alici.com [198.51.100.10])
        by imap.alici.com with LMTP; Tue, 14 Jan 2025 09:00:09 +0300
Received: from smtp.kotu-host.ru (smtp.kotu-host.ru [45.155.205.233])
        by mx.alici.com with ESMTP id abc; Tue, 14 Jan 2025 09:00:05 +0300
Received: from [192.168.1.20] (unknown [185.220.101.4])
        by smtp.kotu-host.ru with ESMTPSA; Tue, 14 Jan 2025 06:00:01 +0000
Authentication-Results: mx.alici.com; spf=fail smtp.mailfrom=garanti-destek.ru; dkim=none; dmarc=fail header.from=garantibbva.com.tr
Authentication-Results: sahte.ornek; spf=pass dkim=pass dmarc=pass
From: "Garanti BBVA Güvenlik" <guvenlik@garantibbva.com.tr>
Reply-To: destek@garanti-destek.ru
Return-Path: <bounce@garanti-destek.ru>
To: kurban@alici.com
Subject: Hesabınız askıya alındı
Date: Tue, 14 Jan 2025 06:00:00 +0000
Message-ID: <x1@smtp.kotu-host.ru>
"""


def test_email_header_phishing():
    from pwrosint.core.config import Settings
    from pwrosint.core.context import Context
    from pwrosint.core.registry import get_tool
    from pwrosint.core.runner import run_action
    tool = get_tool("emailheader")
    report = run_action(Context(Settings()), tool, tool.actions[0], {"headers": security.parse_headers(PHISH)})
    assert not report.errors and report.target == ""  # hassas alan başlığa yazılmaz
    auth = items(report, "Kimlik doğrulama")
    assert auth["SPF"].level == Level.BAD and auth["DMARC"].level == Level.BAD  # sahte alt başlık yok sayıldı
    flags = items(report, "Sahtecilik")
    assert flags["Reply-To farklı domain"].level == Level.BAD
    assert "Message-ID farklı domain" in flags
    src = items(report, "Kaynak")
    assert src["İlk public IP (Received zinciri)"].value == "185.220.101.4"  # alttan ilk public IP, 192.168 değil
    path = next(s for s in report.sections if s.title.startswith("Teslim yolu"))
    assert len(path.items) == 3 and path.items[0].label.startswith("1. [192.168.1.20]")


def test_email_header_rejects_non_headers():
    with pytest.raises(ValueError):
        security.parse_headers("merhaba dünya, bu bir başlık değil")


def test_received_parsing():
    hop = security.parse_received("from a.com (a.com [8.8.8.8]) by b.com with ESMTPS; Mon, 13 Jan 2025 10:00:00 +0000")
    assert hop["from"] == "a.com" and hop["by"] == "b.com" and hop["ips"] == ["8.8.8.8"]
    assert hop["time"].year == 2025


@pytest.mark.parametrize("value, net, host", [
    ("192.168.1.10/24", "192.168.1.0/24", "192.168.1.10"),
    ("10.0.0.0 255.255.0.0", "10.0.0.0/16", None),
    ("2001:db8::1/48", "2001:db8::/48", "2001:db8::1"),
])
def test_parse_network(value, net, host):
    p = toolbox.parse_network(value)
    assert p["network"] == ipaddress.ip_network(net) and p["host"] == host


def test_subnet_report(ctx):
    report = run(ctx, "subnet", net=toolbox.parse_network("192.168.1.10/26"))
    sec = items(report, "Ağ:")
    assert sec["Yayın (broadcast)"].value == "192.168.1.63"
    assert sec["Kullanılabilir aralık"].value == "192.168.1.1 – 192.168.1.62"
    assert sec["Tür"].value.startswith("Özel ağ")
    cg = run(ctx, "subnet", net=toolbox.parse_network("100.64.5.0/24"))
    assert "CGNAT" in items(cg, "Ağ:")["Tür"].value
    assert items(run(ctx, "subnet", net=toolbox.parse_network("10.1.2.0/24")), "Ağ:")["Ters DNS bölgesi"].value == \
        "2.1.10.in-addr.arpa"


def test_jwt_decode_and_risks(ctx):
    report = run(ctx, "decoder", "jwt", token=toolbox.jwt_input("Bearer " + SAMPLE_JWT))
    assert items(report, "İçerik")["Ad"].value == "Ali Veli"
    risk = items(report, "Güvenlik")
    assert risk["Algoritma"].level == Level.WARN  # HS256
    assert "doldu" in risk["Süre"].value
    assert report.target == ""  # token rapor başlığına yazılmaz
    none = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
    assert items(run(ctx, "decoder", "jwt", token=none), "Güvenlik")["Algoritma"].level == Level.BAD
    with pytest.raises(ValueError):
        toolbox.jwt_input("abc.def")


def test_auto_decode(ctx):
    import base64
    import gzip
    report = run(ctx, "decoder", "auto", text="SGVsbG8gV29ybGQ=")
    assert items(report, "Çözümler")["Base64"].value == "Hello World"
    report = run(ctx, "decoder", "auto", text="48656c6c6f")
    assert items(report, "Çözümler")["Hex"].value == "Hello"
    gz = base64.b64encode(gzip.compress(b"gizli veri")).decode()
    assert items(run(ctx, "decoder", "auto", text=gz), "Çözümler")["gzip açılmış"].value == "gizli veri"
    assert items(run(ctx, "decoder", "auto", text="a%20b%2Fc"), "Çözümler")["URL kodlaması"].value == "a b/c"


def test_timestamp(ctx):
    assert toolbox.parse_time("1700000000000") == 1700000000  # milisaniye algılanır
    report = run(ctx, "decoder", "time", time=toolbox.parse_time("1700000000"))
    sec = items(report, "Dönüşüm")
    assert sec["UTC"].value == "2023-11-14 22:13:20" and sec["Türkiye (UTC+3)"].value == "2023-11-15 01:13:20"
    assert toolbox.parse_time("2024-01-31") == 1706659200


@pytest.mark.parametrize("value, expected", [
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5"),
    ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "SHA-1"),
    ("$2y$10$abcdefghijklmnopqrstuuJ8vQmA9b7wY2l9w0w6g7v9wQeKk6x2.", "bcrypt"),
    ("$6$rounds=5000$salt$hash", "SHA-512 crypt (Linux /etc/shadow)"),
    ("$argon2id$v=19$m=65536,t=3,p=4$abc$def", "Argon2"),
])
def test_identify_hash(value, expected):
    assert toolbox.identify_hash(value)[0][0] == expected


def test_hash_generate(ctx):
    report = run(ctx, "hash", "generate", text="password")
    sec = items(report, "Özetler")
    assert sec["MD5"].value == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert sec["SHA-256"].value.startswith("5e884898da28047151d0e56f8dc6292773603d0d")
    if "NTLM" in sec:
        assert sec["NTLM"].value == "8846f7eaee8fb117ad06bdd830b7586c"
    assert report.target == ""


def test_password_generator(ctx):
    report = run(ctx, "password", length=24)
    pws = [i.label for i in next(s for s in report.sections if s.title.startswith("Rastgele")).items]
    assert len(pws) == 5 and all(len(p) == 24 for p in pws) and len(set(pws)) == 5
    assert all(any(c.isupper() for c in p) and any(not c.isalnum() for c in p) for p in pws)
    with pytest.raises(ValueError):
        toolbox.parse_length("4")


def test_sensitive_fields_never_reach_history(tmp_path):
    from pwrosint.core.history import History
    from pwrosint.core.registry import get_tool
    h = History(tmp_path / "h.json")
    for tid, aid, raw in (("decoder", "jwt", {"token": SAMPLE_JWT}), ("emailheader", "analyze", {"headers": PHISH}),
                          ("hash", "generate", {"text": "gizli"})):
        h.add(tid, get_tool(tid).action(aid), raw)
    assert h.entries == []
