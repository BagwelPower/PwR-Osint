"""Yedekli DNS çözümleyici.

Bazı ağlar (operatörler, şirket ağları, bazı ülkeler) belirli DNS-over-HTTPS
sunucularını engeller ya da adlarını çözmez. Bu yüzden sorgular bir taşıyıcı
zincirinden geçer ve ilk yanıt veren kullanılır:

1. JSON DoH, sunucu adıyla       (cloudflare-dns.com, dns.google)
2. JSON DoH, IP adresiyle         (1.1.1.1, 8.8.8.8) — ad çözümlemesi engellense de çalışır
3. RFC 8484 DoH (DNS paket biçimi) (1.0.0.1, 8.8.4.4, AdGuard)
4. Klasik DNS, UDP/TCP 53          (1.1.1.1, 8.8.8.8, 9.9.9.9)
5. Sistem çözümleyicisi            (yalnızca A/AAAA)

Başarısız olan taşıyıcı bir süre atlanır, son çalışan öne alınır; böylece
engellenmiş bir ağda her sorgu aynı zaman aşımını beklemez.
"""

from __future__ import annotations

import base64
import ipaddress
import random
import socket
import struct
import threading
import time
from collections.abc import Callable

from .context import Context
from .errors import OsintError

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
              "AAAA": 28, "SRV": 33, "CAA": 257}
_TYPE_NAMES = {v: k for k, v in TYPE_CODES.items()}
_TYPE_CODES = TYPE_CODES  # geriye dönük uyumluluk

DNS_TIMEOUT = 5          # sn; tek bir taşıyıcı denemesi
DEAD_FOR = 300           # sn; başarısız taşıyıcı bu süre atlanır

Answer = tuple[str, list[str]]


# ---------------------------------------------------------------- DNS paket biçimi (RFC 1035)

def build_query(name: str, rtype: str, qid: int | None = None) -> bytes:
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 soru
    qname = b"".join(bytes([len(p)]) + p for p in (lbl.encode("idna") for lbl in name.rstrip(".").split(".") if lbl))
    return header + qname + b"\0" + struct.pack(">HH", TYPE_CODES[rtype], 1)


def _read_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    jumped_end = None
    while True:
        if pos >= len(msg) or depth > 20:
            raise ValueError("bozuk DNS adı")
        length = msg[pos]
        if length & 0xC0 == 0xC0:  # sıkıştırma işaretçisi
            if pos + 1 >= len(msg):
                raise ValueError("bozuk işaretçi")
            ptr = ((length & 0x3F) << 8) | msg[pos + 1]
            if jumped_end is None:
                jumped_end = pos + 2
            pos, depth = ptr, depth + 1
            continue
        pos += 1
        if length == 0:
            break
        labels.append(msg[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels) + ".", (jumped_end if jumped_end is not None else pos)


def _rdata_text(msg: bytes, rtype: int, start: int, rdlen: int) -> str:
    rd = msg[start:start + rdlen]
    if rtype == 1 and rdlen == 4:
        return str(ipaddress.IPv4Address(rd))
    if rtype == 28 and rdlen == 16:
        return str(ipaddress.IPv6Address(rd))
    if rtype in (2, 5, 12):
        return _read_name(msg, start)[0]
    if rtype == 15:
        pref = struct.unpack(">H", rd[:2])[0]
        return f"{pref} {_read_name(msg, start + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            n = rd[i]
            parts.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return '"' + "".join(parts) + '"'
    if rtype == 6:
        mname, p = _read_name(msg, start)
        rname, p = _read_name(msg, p)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", msg[p:p + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    if rtype == 33:
        prio, weight, port = struct.unpack(">HHH", rd[:6])
        return f"{prio} {weight} {port} {_read_name(msg, start + 6)[0]}"
    if rtype == 257:
        flags, tlen = rd[0], rd[1]
        tag = rd[2:2 + tlen].decode("ascii", "replace")
        value = rd[2 + tlen:].decode("utf-8", "replace")
        return f'{flags} {tag} "{value}"'
    return rd.hex()


def parse_response(msg: bytes, rtype: str) -> Answer:
    if len(msg) < 12:
        raise ValueError("kısa DNS yanıtı")
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    status = RCODES.get(flags & 0x0F, str(flags & 0x0F))
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(msg, pos)
        pos += 4
    want = TYPE_CODES[rtype]
    answers = []
    for _ in range(an):
        _, pos = _read_name(msg, pos)
        atype, _, _, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        if atype == want:
            answers.append(_rdata_text(msg, atype, pos, rdlen))
        pos += rdlen
    return status, answers


def is_truncated(msg: bytes) -> bool:
    return len(msg) >= 4 and bool(msg[2] & 0x02)


# ---------------------------------------------------------------- taşıyıcılar

def _json_doh(url: str, host_header: str | None = None) -> Callable[[Context, str, str], Answer]:
    def run(ctx: Context, name: str, rtype: str) -> Answer:
        headers = {"Accept": "application/dns-json"}
        data = ctx.fast_http.json(url, params={"name": name, "type": rtype}, headers=headers,
                                  timeout=DNS_TIMEOUT)
        if not data:
            raise OsintError(f"{url}: boş yanıt")
        status = RCODES.get(data.get("Status", 2), str(data.get("Status")))
        want = TYPE_CODES.get(rtype)
        answers = [str(a["data"]) for a in data.get("Answer") or []
                   if isinstance(a, dict) and "data" in a and (want is None or a.get("type") == want)]
        return status, answers
    return run


def _wire_doh(url: str) -> Callable[[Context, str, str], Answer]:
    def run(ctx: Context, name: str, rtype: str) -> Answer:
        q = base64.urlsafe_b64encode(build_query(name, rtype, 0)).rstrip(b"=").decode()
        resp = ctx.fast_http.get(url, params={"dns": q}, headers={"Accept": "application/dns-message"},
                                 timeout=DNS_TIMEOUT)
        if resp.status_code != 200 or not resp.content:
            raise OsintError(f"{url}: HTTP {resp.status_code}")
        try:
            return parse_response(resp.content, rtype)
        except (ValueError, struct.error, IndexError) as e:
            raise OsintError(f"{url}: geçersiz DNS yanıtı") from e
    return run


def _udp(server: str) -> Callable[[Context, str, str], Answer]:
    def run(ctx: Context, name: str, rtype: str) -> Answer:
        query_bytes = build_query(name, rtype)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(DNS_TIMEOUT)
                s.sendto(query_bytes, (server, 53))
                msg, _ = s.recvfrom(4096)
            if is_truncated(msg):  # yanıt büyük: TCP ile tekrar
                with socket.create_connection((server, 53), timeout=DNS_TIMEOUT) as s:
                    s.sendall(struct.pack(">H", len(query_bytes)) + query_bytes)
                    length = struct.unpack(">H", _recv_exact(s, 2))[0]
                    msg = _recv_exact(s, length)
            if msg[:2] != query_bytes[:2]:
                raise OsintError(f"{server}: kimlik uyuşmadı")
            return parse_response(msg, rtype)
        except (OSError, ValueError, struct.error, IndexError) as e:
            raise OsintError(f"{server}:53 yanıt vermedi") from e
    return run


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("bağlantı kapandı")
        buf += chunk
    return buf


def _system(ctx: Context, name: str, rtype: str) -> Answer:
    if rtype not in ("A", "AAAA"):
        raise OsintError("sistem çözümleyicisi yalnızca A/AAAA destekler")
    family = socket.AF_INET if rtype == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
    except socket.gaierror as e:
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return "NXDOMAIN" if rtype == "A" else "NOERROR", []
        raise OsintError(f"sistem çözümleyicisi: {e}") from e
    return "NOERROR", sorted({i[4][0] for i in infos})


TRANSPORTS: list[tuple[str, Callable[[Context, str, str], Answer]]] = [
    ("Cloudflare DoH", _json_doh("https://cloudflare-dns.com/dns-query")),
    ("Google DoH", _json_doh("https://dns.google/resolve")),
    ("Cloudflare DoH (IP)", _json_doh("https://1.1.1.1/dns-query")),
    ("Google DoH (IP)", _json_doh("https://8.8.8.8/resolve")),
    # RFC 8484 (paket biçimi). Not: Quad9 DoH yalnızca HTTP/2 kabul ediyor (HTTP 505), kullanılmıyor.
    ("Cloudflare DoH (1.0.0.1)", _wire_doh("https://1.0.0.1/dns-query")),
    ("Google DoH (8.8.4.4)", _wire_doh("https://8.8.4.4/dns-query")),
    ("AdGuard DoH", _wire_doh("https://dns.adguard-dns.com/dns-query")),
    ("DNS 1.1.1.1:53", _udp("1.1.1.1")),
    ("DNS 8.8.8.8:53", _udp("8.8.8.8")),
    ("DNS 9.9.9.9:53", _udp("9.9.9.9")),
    ("Sistem çözümleyicisi", _system),
]

_lock = threading.Lock()
_dead_until: dict[str, float] = {}
_preferred: list[str] = []  # son çalışan taşıyıcı başta


def reset_health() -> None:
    with _lock:
        _dead_until.clear()
        _preferred.clear()


def _ordered() -> list[tuple[str, Callable[[Context, str, str], Answer]]]:
    now = time.monotonic()
    with _lock:
        pref = list(_preferred)
        dead = {n for n, until in _dead_until.items() if until > now}
    alive = [t for t in TRANSPORTS if t[0] not in dead]
    alive.sort(key=lambda t: (t[0] not in pref, pref.index(t[0]) if t[0] in pref else 0))
    # Hepsi ölü işaretliyse yine de denensin (ağ geri gelmiş olabilir).
    return alive or list(TRANSPORTS)


def active_transport() -> str | None:
    with _lock:
        return _preferred[0] if _preferred else None


def query(ctx: Context, name: str, rtype: str) -> Answer:
    """(durum, [kayıtlar]) döndürür. Durum NOERROR, NXDOMAIN vb."""
    errors: list[str] = []
    for tname, transport in _ordered():
        ctx.check_cancelled()
        try:
            result = transport(ctx, name, rtype)
        except OsintError as e:
            errors.append(f"{tname}: {str(e).split(': ', 1)[-1]}")
            if "yalnızca A/AAAA" not in str(e):
                with _lock:
                    _dead_until[tname] = time.monotonic() + DEAD_FOR
                    if tname in _preferred:
                        _preferred.remove(tname)
            continue
        with _lock:
            _dead_until.pop(tname, None)
            if tname in _preferred:
                _preferred.remove(tname)
            _preferred.insert(0, tname)
        return result
    raise OsintError("DNS sorgusu başarısız: hiçbir DNS sunucusuna ulaşılamadı (DNS-over-HTTPS ve 53. port "
                     "denendi). Ağınız DNS trafiğini engelliyor olabilir; farklı bir ağ ya da VPN deneyin.")


def resolve(ctx: Context, name: str, rtype: str = "A") -> list[str]:
    return query(ctx, name, rtype)[1]


def ptr_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer
