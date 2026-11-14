"""Yedekli DNS çözümleyici: paket kodlama/çözme ve taşıyıcı zinciri."""

import struct

import pytest

from pwrosint.core import dns
from pwrosint.core.errors import OsintError


def _name(n: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in n.rstrip(".").split(".")) + b"\0"


def response(qname: str, qtype: str, answers: list[tuple[int, bytes]], rcode: int = 0) -> bytes:
    """Sorudaki ada sıkıştırma işaretçisi (0xC00C) kullanan gerçek biçimli bir DNS yanıtı."""
    head = struct.pack(">HHHHHH", 0, 0x8180 | rcode, 1, len(answers), 0, 0)
    q = _name(qname) + struct.pack(">HH", dns.TYPE_CODES[qtype], 1)
    body = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", t, 1, 300, len(rd)) + rd for t, rd in answers)
    return head + q + body


def test_build_query_layout():
    q = dns.build_query("ornek.com", "MX", qid=0x1234)
    assert q[:2] == b"\x12\x34" and q[12:] == _name("ornek.com") + b"\x00\x0f\x00\x01"


def test_parse_a_aaaa_mx_txt_soa_caa():
    a = response("ornek.com", "A", [(1, bytes([93, 184, 216, 34])), (5, _name("x.com"))])
    assert dns.parse_response(a, "A") == ("NOERROR", ["93.184.216.34"])  # CNAME ayıklanır

    aaaa = response("ornek.com", "AAAA", [(28, bytes(15) + b"\x01")])
    assert dns.parse_response(aaaa, "AAAA")[1] == ["::1"]

    # MX hedefi, sorudaki ada işaret eden sıkıştırılmış bir ad: mail.<0xC00C>
    mx = response("ornek.com", "MX", [(15, b"\x00\x0a" + b"\x04mail\xc0\x0c")])
    assert dns.parse_response(mx, "MX")[1] == ["10 mail.ornek.com."]

    txt = response("ornek.com", "TXT", [(16, b"\x07v=spf1 " + b"\x04-all")])
    assert dns.parse_response(txt, "TXT")[1] == ['"v=spf1 -all"']  # çok parçalı TXT birleşir

    soa_rd = _name("ns1.ornek.com") + _name("admin.ornek.com") + struct.pack(">IIIII", 2024, 3600, 600, 86400, 300)
    soa = response("ornek.com", "SOA", [(6, soa_rd)])
    assert dns.parse_response(soa, "SOA")[1] == ["ns1.ornek.com. admin.ornek.com. 2024 3600 600 86400 300"]

    caa = response("ornek.com", "CAA", [(257, b"\x00\x05issueletsencrypt.org")])
    assert dns.parse_response(caa, "CAA")[1] == ['0 issue "letsencrypt.org"']


def test_parse_nxdomain_and_garbage():
    assert dns.parse_response(response("yok.com", "A", [], rcode=3), "A") == ("NXDOMAIN", [])
    with pytest.raises(ValueError):
        dns.parse_response(b"\x00\x01", "A")
    loop = response("ornek.com", "MX", [(15, b"\x00\x0a\xc0\x2b")])  # kendine işaret eden döngü
    with pytest.raises((ValueError, IndexError, struct.error)):
        dns.parse_response(loop[:-2] + b"\xc0" + bytes([len(loop) - 2]), "MX")


def test_falls_back_to_ip_doh_when_hostname_doh_blocked(ctx, http):
    http.add("https://cloudflare-dns.com/", OsintError("bağlantı kurulamadı"))
    http.add("https://dns.google/", OsintError("bağlantı kurulamadı"))
    http.add("https://1.1.1.1/dns-query", {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
    assert dns.resolve(ctx, "ornek.com") == ["1.2.3.4"]
    assert dns.active_transport() == "Cloudflare DoH (IP)"


def test_falls_back_to_wire_doh(ctx, http):
    http.add("https://", OsintError("engelli"))
    wire = response("ornek.com", "MX", [(15, b"\x00\x05\x02mx\xc0\x0c")])
    http.add("https://9.9.9.9/dns-query", wire)
    assert dns.resolve(ctx, "ornek.com", "MX") == ["5 mx.ornek.com."]


def test_dead_transports_are_skipped_next_time(ctx, http):
    http.add("https://cloudflare-dns.com/", OsintError("engelli"))
    http.add("https://dns.google/", {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]})
    dns.resolve(ctx, "a.com")
    before = len(http.calls)
    dns.resolve(ctx, "b.com")
    assert len(http.calls) - before == 1  # engelli Cloudflare tekrar denenip beklenmedi
    assert "dns.google" in http.calls[-1][0]


def test_all_transports_fail_with_helpful_message(ctx, http):
    http.add("https://", OsintError("engelli"))
    with pytest.raises(OsintError) as e:
        dns.query(ctx, "ornek.com", "A")
    assert "farklı bir ağ ya da VPN" in str(e.value)


def test_system_resolver_maps_nxdomain(monkeypatch, ctx):
    import socket

    def fail(*a, **k):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    assert dns._system(ctx, "yok.invalid", "A") == ("NXDOMAIN", [])
    with pytest.raises(OsintError):
        dns._system(ctx, "ornek.com", "MX")
