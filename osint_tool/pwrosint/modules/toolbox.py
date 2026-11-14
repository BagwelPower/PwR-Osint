"""Araç Kutusu: çevrimdışı çalışan günlük bilişim araçları.

Hiçbiri ağa çıkmaz; girdiler cihazdan ayrılmaz.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import secrets
import string
import zlib
from datetime import datetime, timezone
from urllib.parse import unquote

from ..core.context import Context
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

# ---------------------------------------------------------------- subnet


def parse_network(value: str) -> dict:
    """'192.168.1.10/24', '10.0.0.0 255.255.255.0' ya da '2001:db8::/48' kabul eder."""
    v = " ".join(value.strip().split())
    host = None
    if " " in v:  # IP + maske
        ip, mask = v.split(" ", 1)
        v = f"{ip}/{mask}"
    try:
        iface = ipaddress.ip_interface(v if "/" in v else v + ("/32" if ":" not in v else "/128"))
    except ValueError as e:
        raise ValueError("Format: 192.168.1.10/24, 10.0.0.0 255.255.255.0 ya da 2001:db8::/48") from e
    if iface.ip != iface.network.network_address:
        host = str(iface.ip)
    return {"network": iface.network, "host": host, "display": v}


def _subnet(ctx: Context, rep: Report, v: dict) -> None:
    net: ipaddress._BaseNetwork = v["net"]["network"]
    host = v["net"]["host"]
    v4 = net.version == 4
    sec = rep.section(f"Ağ: {net}")
    sec.add("Ağ adresi", net.network_address)
    if v4:
        sec.add("Alt ağ maskesi", f"{net.netmask}  (/{net.prefixlen})")
        sec.add("Wildcard maskesi", net.hostmask)
        sec.add("Yayın (broadcast)", net.broadcast_address)
    else:
        sec.add("Önek", f"/{net.prefixlen}")
    total = net.num_addresses
    if v4 and net.prefixlen <= 30:
        usable = total - 2
        first, last = net.network_address + 1, net.broadcast_address - 1
    elif v4:  # /31 (noktadan noktaya) ve /32
        usable, first, last = total, net.network_address, net.broadcast_address
    else:
        usable, first, last = total, net.network_address, net.network_address + (total - 1)
    sec.add("Kullanılabilir aralık", f"{first} – {last}")
    sec.add("Adres sayısı", f"{total:,} toplam · {usable:,} kullanılabilir".replace(",", "."))
    kinds = [(net.is_private, "Özel ağ (RFC 1918 / ULA)"), (net.is_loopback, "Loopback"),
             (net.is_link_local, "Link-local"), (net.is_multicast, "Multicast"),
             (v4 and net.subnet_of(ipaddress.ip_network("100.64.0.0/10")), "CGNAT (operatör NAT'ı)"),
             (net.is_reserved, "Ayrılmış")]
    kind = next((k for cond, k in kinds if cond), "Public (internete yönlendirilebilir)")
    sec.add("Tür", kind)
    if v4:
        cls = "A" if net.network_address < ipaddress.IPv4Address("128.0.0.0") else \
              "B" if net.network_address < ipaddress.IPv4Address("192.0.0.0") else \
              "C" if net.network_address < ipaddress.IPv4Address("224.0.0.0") else "D/E"
        sec.add("Eski sınıf", cls)
        sec.add("Maske (ikili)", ".".join(f"{int(o):08b}" for o in str(net.netmask).split(".")))
        if net.prefixlen in (8, 16, 24):
            octets = str(net.network_address).split(".")[:net.prefixlen // 8]
            sec.add("Ters DNS bölgesi", ".".join(reversed(octets)) + ".in-addr.arpa")
    if host:
        h = rep.section(f"Adres: {host}")
        hip = ipaddress.ip_address(host)
        h.add("Ağdaki sırası", f"{int(hip) - int(net.network_address)}. adres")
        if v4 and hip in (net.network_address, net.broadcast_address) and net.prefixlen <= 30:
            h.add("Uyarı", "Bu adres ağ/yayın adresi; bir cihaza atanamaz", level=Level.WARN)
    if v4 and net.prefixlen < 30:
        split = rep.section("Daha küçük alt ağlara bölme")
        for new_prefix in range(net.prefixlen + 1, min(net.prefixlen + 5, 31)):
            subs = list(net.subnets(new_prefix=new_prefix))
            hosts = subs[0].num_addresses - 2
            preview = ", ".join(str(s) for s in subs[:4]) + (" …" if len(subs) > 4 else "")
            split.add(f"/{new_prefix}: {len(subs)} alt ağ × {hosts} host", preview)


# ---------------------------------------------------------------- kod çözücü

def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.strip().split(".")
    if len(parts) not in (2, 3):
        raise ValueError("JWT üç parçadan oluşur: başlık.içerik.imza")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, binascii.Error) as e:
        raise ValueError("JWT çözülemedi (geçersiz base64url veya JSON)") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT başlığı ve içeriği JSON nesnesi olmalı")
    return header, payload, parts[2] if len(parts) == 3 else ""


def jwt_input(value: str) -> str:
    v = value.strip()
    if v.lower().startswith("bearer "):
        v = v[7:].strip()
    decode_jwt(v)  # doğrula
    return v


def _ts(value) -> str:
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value)


CLAIMS = {"iss": "Yayıncı (iss)", "sub": "Konu (sub)", "aud": "Hedef kitle (aud)", "exp": "Bitiş (exp)",
          "nbf": "Geçerlilik başlangıcı (nbf)", "iat": "Oluşturulma (iat)", "jti": "Token kimliği (jti)",
          "email": "E-posta", "name": "Ad", "scope": "Yetkiler (scope)", "role": "Rol", "roles": "Roller"}


def _jwt(ctx: Context, rep: Report, v: dict) -> None:
    header, payload, sig = decode_jwt(v["token"])
    now = datetime.now(timezone.utc).timestamp()
    sec = rep.section("Başlık (header)")
    for k, val in header.items():
        sec.add(k, json.dumps(val, ensure_ascii=False) if not isinstance(val, str) else val)
    alg = str(header.get("alg", "")).upper()
    risk = rep.section("Güvenlik değerlendirmesi")
    if alg in ("NONE", ""):
        risk.add("Algoritma", "'none' — imzasız token; sunucu kabul ediyorsa kritik açık", level=Level.BAD)
    elif alg.startswith("HS"):
        risk.add("Algoritma", f"{alg} (paylaşılan gizli anahtar) — zayıf anahtar kaba kuvvetle kırılabilir",
                 level=Level.WARN)
    else:
        risk.add("Algoritma", f"{alg} (açık anahtarlı imza)", level=Level.OK)
    if not sig and alg not in ("NONE", ""):
        risk.add("İmza", "Eksik", level=Level.BAD)
    if "exp" in payload:
        try:
            left = float(payload["exp"]) - now
            if left < 0:
                risk.add("Süre", f"{abs(left) / 3600:.1f} saat önce doldu", level=Level.MUTED)
            else:
                days = left / 86400
                risk.add("Süre", f"{days:.1f} gün daha geçerli" if days >= 1 else f"{left / 60:.0f} dk daha geçerli",
                         level=Level.WARN if days > 30 else Level.OK)
                if days > 30:
                    risk.note = "Uzun ömürlü token: çalınırsa uzun süre kullanılabilir."
        except (TypeError, ValueError):
            risk.add("Süre", "exp alanı sayı değil", level=Level.WARN)
    else:
        risk.add("Süre", "exp yok — token süresiz geçerli", level=Level.WARN)
    if header.get("jku") or header.get("x5u"):
        risk.add("Anahtar adresi", "jku/x5u başlığı var — anahtar dışarıdan alınıyorsa SSRF/anahtar enjeksiyonu riski",
                 level=Level.WARN)
    if header.get("kid") and re.search(r"[./\\\\]|\.\.|'|;", str(header["kid"])):
        risk.add("kid", "Yol/SQL karakterleri içeriyor — kid enjeksiyonu açısından inceleyin", level=Level.WARN)
    body = rep.section("İçerik (payload)")
    for k, val in payload.items():
        label = CLAIMS.get(k, k)
        text = _ts(val) if k in ("exp", "nbf", "iat", "auth_time") else (
            val if isinstance(val, str) else json.dumps(val, ensure_ascii=False))
        body.add(label, str(text)[:400])
    rep.notice("Token yalnızca cihazda çözüldü; hiçbir yere gönderilmedi ve geçmişe kaydedilmedi. "
               "İmza doğrulanmadı (gizli anahtar gerekir).")


def _decode(ctx: Context, rep: Report, v: dict) -> None:
    text: str = v["text"]
    found = False
    sec = rep.section("Çözümler")
    candidates = []
    compact = "".join(text.split())
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{4,}", compact) and len(compact) % 4 in (0, 2, 3):
        try:
            raw = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_" if re.search(r"[-_]", compact) else None)
            candidates.append(("Base64", raw))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", compact):
        candidates.append(("Hex", bytes.fromhex(compact)))
    if "%" in text and re.search(r"%[0-9A-Fa-f]{2}", text):
        candidates.append(("URL kodlaması", unquote(text).encode()))
    for name, raw in candidates:
        for label, data in ((name, raw), *(_decompress(raw))):
            try:
                decoded = data.decode("utf-8")
                printable = sum(c.isprintable() or c in "\r\n\t" for c in decoded) / max(1, len(decoded))
            except UnicodeDecodeError:
                decoded, printable = None, 0
            if decoded is not None and printable > 0.9:
                sec.add(label, decoded[:2000], level=Level.OK)
                found = True
            else:
                sec.add(f"{label} (ikili veri)", f"{len(data)} bayt · hex: {data[:48].hex()}{'…' if len(data) > 48 else ''}")
                found = True
    if not found:
        sec.add("Tanınan bir kodlama yok", "Base64, hex veya URL kodlaması bulunamadı", level=Level.MUTED)
    enc = rep.section("Kodlamalar (girdinin kendisi)")
    b = text.encode("utf-8")
    enc.add("Base64", base64.b64encode(b).decode())
    enc.add("Base64 (URL güvenli)", base64.urlsafe_b64encode(b).decode().rstrip("="))
    enc.add("Hex", b.hex())
    from urllib.parse import quote
    enc.add("URL kodlaması", quote(text, safe=""))


def _decompress(raw: bytes) -> list[tuple[str, bytes]]:
    out = []
    if raw[:2] == b"\x1f\x8b":
        try:
            out.append(("gzip açılmış", zlib.decompress(raw, 16 + zlib.MAX_WBITS)))
        except zlib.error:
            pass
    elif raw[:1] == b"\x78":
        try:
            out.append(("zlib açılmış", zlib.decompress(raw)))
        except zlib.error:
            pass
    return out


def parse_time(value: str):
    v = value.strip()
    if re.fullmatch(r"-?\d{9,13}(\.\d+)?", v):
        num = float(v)
        return num / 1000 if abs(num) > 1e11 else num  # milisaniye
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d.%m.%Y %H:%M", "%d.%m.%Y"):
        try:
            return datetime.strptime(v.replace("Z", ""), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
    except ValueError as e:
        raise ValueError("Unix zaman damgası (1700000000) veya tarih (2025-01-31 14:00) girin") from e


def _timestamp(ctx: Context, rep: Report, v: dict) -> None:
    ts: float = v["time"]
    dt = datetime.fromtimestamp(ts, timezone.utc)
    sec = rep.section("Dönüşüm")
    sec.add("UTC", dt.strftime("%Y-%m-%d %H:%M:%S"))
    sec.add("Türkiye (UTC+3)", datetime.fromtimestamp(ts + 3 * 3600, timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    sec.add("ISO 8601", dt.isoformat().replace("+00:00", "Z"))
    sec.add("Unix (saniye)", int(ts))
    sec.add("Unix (milisaniye)", int(ts * 1000))
    diff = ts - datetime.now(timezone.utc).timestamp()
    sec.add("Şu andan farkı", ("+" if diff >= 0 else "−") + _human(abs(diff)))
    sec.add("Windows FILETIME", int((ts + 11644473600) * 10_000_000))


def _human(seconds: float) -> str:
    for unit, size in (("yıl", 31557600), ("gün", 86400), ("saat", 3600), ("dk", 60)):
        if seconds >= size:
            return f"{seconds / size:.1f} {unit}"
    return f"{seconds:.0f} sn"


# ---------------------------------------------------------------- hash

HASH_PATTERNS: list[tuple[str, str, str]] = [
    (r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", "Güçlü, yavaş parola hash'i"),
    (r"^\$argon2(id|i|d)\$", "Argon2", "Modern, güçlü parola hash'i"),
    (r"^\$6\$", "SHA-512 crypt (Linux /etc/shadow)", "Tuzlu, yinelemeli"),
    (r"^\$5\$", "SHA-256 crypt (Linux /etc/shadow)", "Tuzlu, yinelemeli"),
    (r"^\$1\$", "MD5 crypt", "Eski; kolay kırılır"),
    (r"^\$y\$", "yescrypt (güncel Linux /etc/shadow)", "Güçlü parola hash'i"),
    (r"^\$P\$|^\$H\$", "phpass (WordPress/phpBB)", "Orta"),
    (r"^pbkdf2_sha256\$", "PBKDF2-SHA256 (Django)", "Güçlü"),
    (r"^\{SSHA\}", "Salted SHA-1 (LDAP)", "Zayıf"),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", "LM:NTLM (Windows SAM)", "Kolay kırılır"),
    (r"^\*[A-F0-9]{40}$", "MySQL 4.1+ (SHA1(SHA1))", "Tuzsuz"),
]
HEX_LENGTHS = {
    32: ["MD5", "NTLM", "MD4"], 40: ["SHA-1", "RIPEMD-160"], 56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"], 96: ["SHA-384", "SHA3-384"], 128: ["SHA-512", "SHA3-512", "BLAKE2b"],
    8: ["CRC32", "Adler-32"], 16: ["MySQL 3.x (eski)", "Half MD5"],
}


def identify_hash(value: str) -> list[tuple[str, str]]:
    v = value.strip()
    for pattern, name, note in HASH_PATTERNS:
        if re.search(pattern, v):
            return [(name, note)]
    if re.fullmatch(r"[a-fA-F0-9]+", v) and len(v) in HEX_LENGTHS:
        weak = {"MD5", "NTLM", "MD4", "SHA-1", "CRC32", "Adler-32", "MySQL 3.x (eski)", "Half MD5"}
        return [(n, "Tuzsuz; parola için kullanılıyorsa kolay kırılır" if n in weak else "Tuzsuz özet")
                for n in HEX_LENGTHS[len(v)]]
    if re.fullmatch(r"[A-Za-z0-9+/]{27,88}={0,2}", v):
        try:
            n = len(base64.b64decode(v + "=" * (-len(v) % 4)))
            by_len = {16: "MD5 (base64)", 20: "SHA-1 (base64)", 32: "SHA-256 (base64)", 64: "SHA-512 (base64)"}
            if n in by_len:
                return [(by_len[n], "Base64 ile kodlanmış özet")]
        except (binascii.Error, ValueError):
            pass
    return []


def _hash_id(ctx: Context, rep: Report, v: dict) -> None:
    value = v["hash"]
    matches = identify_hash(value)
    sec = rep.section("Olası türler")
    if not matches:
        sec.add("Tanınmadı", f"{len(value)} karakter; bilinen bir hash biçimine uymuyor", level=Level.MUTED)
    for name, note in matches:
        sec.add(name, note, level=Level.WARN if "kolay kırılır" in note.lower() else Level.INFO)
    if len(matches) > 1:
        sec.note = "Uzunluk birden fazla algoritmaya uyuyor; kaynağın bağlamına bakın (ör. Windows → NTLM)."
    hashcat = {"MD5": 0, "SHA-1": 100, "SHA-256": 1400, "SHA-512": 1700, "NTLM": 1000, "bcrypt": 3200,
               "SHA-512 crypt (Linux /etc/shadow)": 1800, "MD5 crypt": 500, "phpass (WordPress/phpBB)": 400,
               "PBKDF2-SHA256 (Django)": 10000, "LM:NTLM (Windows SAM)": 1000, "MySQL 4.1+ (SHA1(SHA1))": 300,
               "SHA-256 crypt (Linux /etc/shadow)": 7400, "Argon2": 34000, "yescrypt (güncel Linux /etc/shadow)": None}
    modes = [f"{n}: -m {hashcat[n]}" for n, _ in matches if hashcat.get(n) is not None]
    if modes:
        rep.section("Hashcat modları").add("Mod", " · ".join(modes))
    if len(value) in (32, 40, 64) and re.fullmatch(r"[a-fA-F0-9]+", value):
        rep.section("Dış kaynaklar").link("VirusTotal'de dosya olarak ara", f"https://www.virustotal.com/gui/file/{value}")


def _hash_gen(ctx: Context, rep: Report, v: dict) -> None:
    data = v["text"].encode("utf-8")
    sec = rep.section(f"Özetler ({len(data)} bayt girdi)")
    for name, fn in (("MD5", hashlib.md5), ("SHA-1", hashlib.sha1), ("SHA-256", hashlib.sha256),
                     ("SHA-512", hashlib.sha512), ("SHA3-256", hashlib.sha3_256), ("BLAKE2b", hashlib.blake2b)):
        sec.add(name, fn(data).hexdigest())
    sec.add("CRC32", f"{zlib.crc32(data) & 0xFFFFFFFF:08x}")
    try:
        ntlm = hashlib.new("md4", v["text"].encode("utf-16le")).hexdigest()
        sec.add("NTLM", ntlm)
    except ValueError:  # bazı OpenSSL kurulumlarında MD4 kapalı
        pass
    sec.note = "Girdi cihazdan çıkmadı ve geçmişe kaydedilmedi."


# ---------------------------------------------------------------- şifre üretici

WORDS = ("elma armut kiraz deniz dağ orman nehir güneş ay yıldız bulut rüzgar kar yağmur toprak taş kum ateş "
         "kitap kalem masa kapı pencere köprü yol şehir köy liman gemi tren uçak bisiklet saat anahtar kilit "
         "kartal aslan kaplan tilki kurt ayı balık kuş kedi köpek at fil zürafa penguen yunus arı karınca "
         "mavi yeşil kırmızı sarı mor turuncu beyaz siyah gri pembe altın gümüş bakır demir çelik kristal").split()


def strength_bits(length: int, pool: int) -> float:
    return length * math.log2(pool) if pool > 1 else 0.0


def _password(ctx: Context, rep: Report, v: dict) -> None:
    length = v["length"]
    pool = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
    ambiguous = set("Il1O0")
    sec = rep.section(f"Rastgele şifreler ({length} karakter)")
    for _ in range(5):
        while True:
            pw = "".join(secrets.choice(pool) for _ in range(length))
            if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                    and any(not c.isalnum() for c in pw)):
                break
        sec.add(pw)
    bits = strength_bits(length, len(pool))
    sec.note = f"Entropi ≈ {bits:.0f} bit (her biri). 80+ bit çevrimdışı kaba kuvvete karşı güçlüdür."
    clean = "".join(c for c in string.ascii_letters + string.digits if c not in ambiguous)
    simple = rep.section("Okunaklı (karışan karakter yok, sembolsüz)")
    for _ in range(3):
        simple.add("".join(secrets.choice(clean) for _ in range(length)))
    phrase = rep.section("Parola cümlesi (akılda kalır)")
    n_words = max(4, min(8, length // 4))
    for _ in range(3):
        words = [secrets.choice(WORDS) for _ in range(n_words)]
        phrase.add("-".join(words) + "-" + str(secrets.randbelow(100)))
    phrase.note = (f"{n_words} kelime ≈ {strength_bits(n_words, len(WORDS)) + math.log2(100):.0f} bit. "
                   "Türkçe karakterli kelimeler bazı sistemlerde sorun çıkarabilir.")
    rep.notice("Şifreler cihazda, kriptografik rastgele üreteçle (secrets) oluşturuldu; hiçbir yere "
               "gönderilmedi ve kaydedilmedi.")


def parse_length(value: str) -> int:
    try:
        n = int(value.strip())
    except ValueError as e:
        raise ValueError("8 ile 128 arası bir sayı girin") from e
    if not 8 <= n <= 128:
        raise ValueError("8 ile 128 arası bir sayı girin")
    return n


def _nonempty(value: str) -> str:
    if not value.strip():
        raise ValueError("Boş olamaz")
    if len(value) > 200_000:
        raise ValueError("Girdi çok büyük (en fazla 200 KB)")
    return value


register(Tool("subnet", "Subnet Hesaplayıcı", "CIDR, maske, aralık, alt ağlara bölme (IPv4/IPv6)",
              "CALCULATE", "Araç Kutusu", [
                  Action("calc", "Hesapla", (Field("net", "Ağ / adres", "192.168.1.10/24", parse=parse_network),),
                         _subnet)]))
register(Tool("decoder", "Kod Çözücü", "JWT, Base64/Hex/URL, zaman damgası", "DATA_OBJECT", "Araç Kutusu", [
    Action("jwt", "JWT", (Field("token", "JWT", "eyJhbGciOi…", "multiline", jwt_input, sensitive=True),), _jwt),
    Action("auto", "Base64 / Hex / URL", (Field("text", "Kodlanmış metin", "SGVsbG8=", "multiline", _nonempty,
                                                sensitive=True),), _decode),
    Action("time", "Zaman damgası", (Field("time", "Unix zamanı veya tarih", "1700000000", parse=parse_time),),
           _timestamp)]))
register(Tool("hash", "Hash Araçları", "Hash türünü tanı, metinden hash üret", "FINGERPRINT", "Araç Kutusu", [
    Action("identify", "Türünü tanı", (Field("hash", "Hash", "5f4dcc3b5aa765d61d8327deb882cf99",
                                             parse=_nonempty, sensitive=True),), _hash_id),
    Action("generate", "Hash üret", (Field("text", "Metin", "metin", "multiline", _nonempty, sensitive=True),),
           _hash_gen)]))
register(Tool("password", "Şifre Üretici", "Güçlü şifre ve parola cümlesi (cihazda)", "PASSWORD", "Araç Kutusu", [
    Action("generate", "Üret", (Field("length", "Uzunluk", "20", "number", parse_length),), _password)]))

