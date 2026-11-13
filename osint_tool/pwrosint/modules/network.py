"""Ağ ve domain araçları: IP/domain profili, DNS, TLS, subdomain, arşiv."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any, Optional

from ..core import dns, validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report, Section

# ---------------------------------------------------------------- IP & domain


def _host(ctx: Context, rep: Report, v: dict) -> None:
    target: str = v["target"]
    ip: Optional[str] = target if validate.is_ip(target) else None

    if not ip:
        sec = rep.section("Çözümleme")
        status, a = dns.query(ctx, target, "A")
        aaaa = dns.resolve(ctx, target, "AAAA")
        if status == "NXDOMAIN":
            sec.add("Durum", "Domain mevcut değil (NXDOMAIN)", level=Level.BAD)
        for rec in a:
            sec.add("A", rec, level=Level.OK)
        for rec in aaaa:
            sec.add("AAAA", rec, level=Level.OK)
        if status != "NXDOMAIN" and not (a or aaaa):
            sec.add("Durum", "Adres kaydı yok", level=Level.WARN)
        rep.changed()
        _rdap_domain(ctx, rep, target)
        ip = next((x for x in a if validate.is_ip(x)), None)

    if ip:
        _ip_profile(ctx, rep, ip)

    links = rep.section("Dış kaynaklar")
    if ip:
        links.link("Shodan", f"https://www.shodan.io/host/{ip}")
        links.link("Censys", f"https://search.censys.io/hosts/{ip}")
        links.link("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip}")
        links.link("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip}")
        links.link("BGP.he.net", f"https://bgp.he.net/ip/{ip}")
    if not validate.is_ip(target):
        links.link("SecurityTrails", f"https://securitytrails.com/domain/{target}/dns")
        links.link("ICANN Lookup", f"https://lookup.icann.org/en/lookup?name={target}")
        links.link("urlscan.io", f"https://urlscan.io/search/#domain:{target}")
        links.link("BuiltWith", f"https://builtwith.com/{target}")


def _ip_profile(ctx: Context, rep: Report, ip: str) -> None:
    addr = ipaddress.ip_address(ip)
    sec = rep.section(f"IP: {ip}")
    sec.add("Sürüm", f"IPv{addr.version}")
    if not addr.is_global:
        kind = ("Özel ağ (private)" if addr.is_private else "Loopback" if addr.is_loopback
                else "Link-local" if addr.is_link_local else "Ayrılmış / global değil")
        sec.add("Tür", kind, level=Level.WARN)
        rep.changed()
        return
    sec.add("Tür", "Public", level=Level.OK)
    try:
        ptr = dns.resolve(ctx, dns.ptr_name(ip), "PTR")
        sec.add("Reverse DNS", ", ".join(p.rstrip(".") for p in ptr) if ptr else "Yok")
    except OsintError as e:
        sec.add("Reverse DNS", str(e), level=Level.MUTED)
    rep.changed()

    # Konum ve ağ sahibi
    geo = rep.section("Konum & ağ")
    try:
        params = {"token": ctx.settings.ipinfo_token} if ctx.settings.ipinfo_token else None
        info = ctx.http.json(f"https://ipinfo.io/{ip}/json", params=params)
        place = ", ".join(x for x in (info.get("city"), info.get("region"), info.get("country")) if x)
        geo.add("Konum", place or "—")
        geo.add("Kurum / ASN", info.get("org", "—"))
        if info.get("hostname"):
            geo.add("Hostname", info["hostname"])
        if loc := info.get("loc"):
            geo.add("Harita", loc, url=f"https://www.openstreetmap.org/?mlat={loc.split(',')[0]}"
                                       f"&mlon={loc.split(',')[1]}#map=11/{loc.replace(',', '/')}")
        geo.note = "Konum, IP bloğunun kayıtlı yeridir; kişinin bulunduğu yer olmayabilir."
    except OsintError as e:
        geo.add("ipinfo.io", str(e), level=Level.MUTED)
    try:
        rd = ctx.http.json(f"https://rdap.org/ip/{ip}", ok=(200,))
        geo.add("Ağ adı", rd.get("name", "—"))
        if rd.get("startAddress"):
            geo.add("Blok", f"{rd['startAddress']} – {rd.get('endAddress', '')}")
        if rd.get("country"):
            geo.add("Kayıt ülkesi", rd["country"])
        if abuse := _rdap_abuse(rd):
            geo.add("Abuse iletişim", abuse)
    except OsintError as e:
        geo.add("RDAP", str(e), level=Level.MUTED)
    rep.changed()

    # Shodan InternetDB: anahtarsız, ücretsiz port/zafiyet özeti
    exp = rep.section("Açık portlar (Shodan InternetDB)")
    try:
        db = ctx.http.json(f"https://internetdb.shodan.io/{ip}", ok=(200, 404))
    except OsintError as e:
        exp.add("InternetDB", str(e), level=Level.MUTED)
        db = None
    if db is None or "ports" not in (db or {}):
        if db is not None:
            exp.add("Sonuç", "Kayıt yok", level=Level.MUTED)
    else:
        exp.add("Portlar", ", ".join(map(str, db["ports"])) or "—",
                level=Level.WARN if db["ports"] else Level.OK)
        if db.get("hostnames"):
            exp.add("Hostname'ler", ", ".join(db["hostnames"][:10]))
        if db.get("tags"):
            exp.add("Etiketler", ", ".join(db["tags"]))
        if db.get("cpes"):
            exp.add("Yazılımlar", ", ".join(c.split(":", 3)[-1] for c in db["cpes"][:8]))
        vulns = db.get("vulns") or []
        exp.add("Zafiyetler (CVE)", ", ".join(vulns[:15]) + (" …" if len(vulns) > 15 else "")
                if vulns else "Bilinen yok", level=Level.BAD if vulns else Level.OK)
    rep.changed()


def _rdap_abuse(rd: dict) -> Optional[str]:
    for ent in rd.get("entities", []) or []:
        if "abuse" in (ent.get("roles") or []):
            for entry in (ent.get("vcardArray") or [None, []])[1]:
                if entry[0] == "email":
                    return entry[3]
        for sub in ent.get("entities", []) or []:
            if "abuse" in (sub.get("roles") or []):
                for entry in (sub.get("vcardArray") or [None, []])[1]:
                    if entry[0] == "email":
                        return entry[3]
    return None


def _rdap_domain(ctx: Context, rep: Report, domain: str) -> None:
    sec = rep.section("WHOIS (RDAP)")
    try:
        rd = ctx.http.json(f"https://rdap.org/domain/{domain}")
    except OsintError as e:
        sec.add("RDAP", str(e), level=Level.MUTED)
        sec.note = "Bazı ülke uzantıları (ör. .tr) RDAP sunmaz; ICANN/NIC linklerini kullanın."
        rep.changed()
        return
    for ent in rd.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            vcard = (ent.get("vcardArray") or [None, []])[1]
            name = next((e[3] for e in vcard if e[0] == "fn"), None)
            if name:
                sec.add("Kayıt firması", name)
    labels = {"registration": "Kayıt tarihi", "expiration": "Bitiş tarihi",
              "last changed": "Son değişiklik"}
    for ev in rd.get("events", []) or []:
        if ev.get("eventAction") in labels:
            when = ev.get("eventDate", "")[:10]
            level = Level.INFO
            if ev["eventAction"] == "expiration":
                days = _days_until(ev.get("eventDate", ""))
                if days is not None:
                    when += f"  ({days} gün kaldı)"
                    level = Level.BAD if days < 0 else Level.WARN if days < 30 else Level.OK
            elif ev["eventAction"] == "registration":
                days = _days_until(ev.get("eventDate", ""))
                if days is not None and -days < 90:
                    when += "  (yeni kayıt — oltalama göstergesi olabilir)"
                    level = Level.WARN
            sec.add(labels[ev["eventAction"]], when, level=level)
    if ns := rd.get("nameservers"):
        sec.add("Name server", ", ".join(n.get("ldhName", "").lower() for n in ns))
    if st := rd.get("status"):
        sec.add("Durum", ", ".join(st))
    rep.changed()


def _days_until(iso: str) -> Optional[int]:
    try:
        when = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - datetime.now(timezone.utc)).days


# ---------------------------------------------------------------- DNS

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


def _dns(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    results = ctx.parallel(lambda t: (t, *_safe_query(ctx, domain, t)), RECORD_TYPES)
    statuses = {status for _, status, _ in results}
    if not statuses & {"NOERROR", "NXDOMAIN"}:
        raise OsintError(next(iter(statuses)))  # hiçbir sorgu yanıt alamadı: tek hata göster
    if statuses == {"NXDOMAIN"}:
        rep.section("Durum").add("Domain", "Mevcut değil (NXDOMAIN)", level=Level.BAD)
        return
    sec = rep.section("Kayıtlar")
    for rtype, status, records in results:
        if status not in ("NOERROR", "NXDOMAIN"):
            sec.add(rtype, status, level=Level.MUTED)
        for r in records:
            sec.add(rtype, r.strip('"') if rtype == "TXT" else r.rstrip("."))
    rep.changed()

    txt = next(r for t, _, r in results if t == "TXT")
    caa = next(r for t, _, r in results if t == "CAA")
    spf = [t.strip('"') for t in txt if t.lower().strip('"').startswith("v=spf1")]
    dmarc = [t.strip('"') for t in _safe_query(ctx, f"_dmarc.{domain}", "TXT")[1]
             if "v=dmarc1" in t.lower()]
    sec = rep.section("E-posta güvenliği")
    if not spf:
        sec.add("SPF", "Yok — domain adına sahte e-posta gönderilebilir", level=Level.BAD)
    else:
        rule = spf[0].split()[-1]
        level = Level.OK if rule in ("-all", "~all") else Level.WARN
        sec.add("SPF", spf[0], level=level)
        if rule == "+all":
            sec.add("SPF uyarısı", "+all herkese izin verir!", level=Level.BAD)
    if not dmarc:
        sec.add("DMARC", "Yok", level=Level.WARN)
    else:
        policy = next((p.split("=")[1] for p in dmarc[0].replace(" ", "").split(";")
                       if p.startswith("p=")), "?")
        sec.add("DMARC", dmarc[0], level=Level.OK if policy in ("reject", "quarantine") else Level.WARN)
    sec.add("CAA", "Var" if caa else "Yok — her sertifika otoritesi sertifika verebilir",
            level=Level.OK if caa else Level.MUTED)
    verifs = [t.strip('"').split("=")[0] for t in txt if "verification" in t.lower() or "-site-" in t.lower()]
    if verifs:
        sec.add("Doğrulama kayıtları", ", ".join(sorted(set(verifs))))
        sec.note = "Doğrulama TXT kayıtları domainin kullandığı servisleri ele verir."

    links = rep.section("Dış araçlar")
    links.link("DNSViz", f"https://dnsviz.net/d/{domain}/analyze/")
    links.link("MXToolbox", f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}")
    links.link("SecurityTrails geçmiş", f"https://securitytrails.com/domain/{domain}/history/a")


def _safe_query(ctx: Context, name: str, rtype: str) -> tuple[str, list[str]]:
    try:
        return dns.query(ctx, name, rtype)
    except OsintError as e:
        return str(e), []


# ---------------------------------------------------------------- TLS

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def fetch_certificate(host: str, port: int, timeout: int) -> dict[str, Any]:
    """Sertifikayı alır. Doğrulama başarısız olsa da ham sertifikayı döndürür."""
    out: dict[str, Any] = {"verified": True, "error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            out.update(cert=tls.getpeercert(), der=tls.getpeercert(binary_form=True),
                       version=tls.version(), cipher=tls.cipher())
            return out
    except ssl.SSLCertVerificationError as e:
        out.update(verified=False, error=e.verify_message or str(e))
    except (socket.timeout, TimeoutError) as e:
        raise OsintError(f"{host}:{port} zaman aşımı") from e
    except OSError as e:
        raise OsintError(f"{host}:{port} bağlantı hatası: {e}") from e

    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock, \
            insecure.wrap_socket(sock, server_hostname=host) as tls:
        der = tls.getpeercert(binary_form=True)
        out.update(der=der, version=tls.version(), cipher=tls.cipher(), cert=_decode_der(der))
    return out


def _decode_der(der: bytes) -> dict:
    """Doğrulanmamış sertifikayı CPython'un dahili ayrıştırıcısıyla çözer."""
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if not decode or not der:
        return {}
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
        return decode(path)
    except Exception:
        return {}
    finally:
        os.unlink(path)


def _tls(ctx: Context, rep: Report, v: dict) -> None:
    host: str = v["domain"]
    info = fetch_certificate(host, 443, ctx.settings.timeout)
    cert, der = info.get("cert") or {}, info.get("der") or b""

    sec = rep.section("Sertifika")
    if info["verified"]:
        sec.add("Doğrulama", "Geçerli ve güvenilir", level=Level.OK)
    else:
        sec.add("Doğrulama", f"BAŞARISIZ: {info['error']}", level=Level.BAD)
    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    sec.add("Konu (CN)", subject.get("commonName", "—"))
    if subject.get("organizationName"):
        sec.add("Kurum", subject["organizationName"])
    sec.add("Sağlayıcı", " / ".join(x for x in (issuer.get("organizationName"),
                                                 issuer.get("commonName")) if x) or "—")
    if "notAfter" in cert:
        start = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
        end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days = (end - datetime.now(timezone.utc)).days
        sec.add("Geçerlilik", f"{start:%Y-%m-%d} → {end:%Y-%m-%d}")
        sec.add("Kalan süre", f"{days} gün" if days >= 0 else f"{-days} gün önce doldu",
                level=Level.BAD if days < 0 else Level.WARN if days < 21 else Level.OK)
    if cert.get("serialNumber"):
        sec.add("Seri no", cert["serialNumber"])
    if der:
        sec.add("SHA-256", hashlib.sha256(der).hexdigest().upper())
    rep.changed()

    conn = rep.section("Bağlantı")
    version = info.get("version") or "?"
    conn.add("Protokol", version, level=Level.OK if version in ("TLSv1.3", "TLSv1.2") else Level.BAD)
    if info.get("cipher"):
        name, _, bits = info["cipher"]
        conn.add("Şifreleme", f"{name} ({bits} bit)")

    sans = [val for typ, val in cert.get("subjectAltName", ()) if typ == "DNS"]
    if sans:
        san = rep.section(f"Alternatif isimler (SAN) — {len(sans)}")
        for name in sans[:100]:
            san.add(name)
    rep.changed()

    _security_headers(ctx, rep, host, verify=info["verified"])
    links = rep.section("Dış araçlar")
    links.link("SSL Labs", f"https://www.ssllabs.com/ssltest/analyze.html?d={host}&hideResults=on")
    links.link("crt.sh geçmişi", f"https://crt.sh/?q={host}")
    links.link("securityheaders.com", f"https://securityheaders.com/?q={host}&followRedirects=on")


def _security_headers(ctx: Context, rep: Report, host: str, verify: bool = True) -> None:
    sec = rep.section("HTTP güvenlik başlıkları")
    if not verify:
        sec.note = "Sertifika geçersiz olduğu için başlıklar doğrulamasız bağlantıyla okundu."
    try:
        import urllib3
        with urllib3.warnings.catch_warnings():
            urllib3.warnings.simplefilter("ignore")
            resp = ctx.http.get(f"https://{host}/", allow_redirects=True, stream=True, verify=verify)
        resp.close()
    except OsintError as e:
        sec.add("HTTP", str(e), level=Level.MUTED)
        return
    sec.add("Son adres", f"{resp.url}  (HTTP {resp.status_code})")
    headers = {k.lower(): v for k, v in resp.headers.items()}
    for key, label in SECURITY_HEADERS.items():
        val = headers.get(key)
        sec.add(label, val[:120] if val else "Eksik", level=Level.OK if val else Level.WARN)
    leaks = [f"{k}: {headers[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if k in headers]
    if leaks:
        sec.add("Sürüm sızıntısı", "; ".join(leaks), level=Level.INFO)


# ---------------------------------------------------------------- subdomain

def _crtsh(ctx: Context, domain: str) -> set[str]:
    data = ctx.http.json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                         timeout=max(30, ctx.settings.timeout), expect=list)
    return {n for e in data or [] if isinstance(e, dict) for n in str(e.get("name_value", "")).split("\n")}


def _hackertarget(ctx: Context, domain: str) -> set[str]:
    resp = ctx.http.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    if resp.status_code != 200 or resp.text.startswith("error") or "API count" in resp.text:
        raise OsintError("hackertarget: limit aşıldı veya hata")
    return {line.split(",")[0] for line in resp.text.splitlines() if "," in line}


def _otx(ctx: Context, domain: str) -> set[str]:
    data = ctx.http.json(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
    return {str(r.get("hostname", "")) for r in (data or {}).get("passive_dns") or [] if isinstance(r, dict)}


def _anubis(ctx: Context, domain: str) -> set[str]:
    return {str(x) for x in ctx.http.json(f"https://jldc.me/anubis/subdomains/{domain}", expect=list) or []}


def _certspotter(ctx: Context, domain: str) -> set[str]:
    data = ctx.http.json("https://api.certspotter.com/v1/issuances",
                         params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                         expect=list)
    return {str(n) for e in data or [] if isinstance(e, dict) for n in e.get("dns_names") or []}


def _urlscan_hosts(ctx: Context, domain: str) -> set[str]:
    data = ctx.http.json("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 100})
    out = set()
    for r in (data or {}).get("results") or []:
        if isinstance(r, dict):
            for key in ("domain", "apexDomain"):
                if (val := (r.get("page") or {}).get(key)):
                    out.add(str(val))
    return out


def _wayback_hosts(ctx: Context, domain: str) -> set[str]:
    rows = ctx.http.json("https://web.archive.org/cdx/search/cdx",
                         params={"url": f"*.{domain}", "output": "json", "fl": "original",
                                 "collapse": "urlkey", "limit": 2000},
                         timeout=max(30, ctx.settings.timeout), expect=list) or []
    from urllib.parse import urlsplit
    out = set()
    for row in rows[1:]:
        if isinstance(row, list) and row:
            url = str(row[0])
            host = urlsplit(url if "://" in url else "http://" + url).hostname
            if host:
                out.add(host)
    return out


SUBDOMAIN_SOURCES = (("crt.sh", _crtsh), ("CertSpotter", _certspotter), ("HackerTarget", _hackertarget),
                     ("AlienVault OTX", _otx), ("Anubis", _anubis), ("urlscan.io", _urlscan_hosts),
                     ("Wayback Machine", _wayback_hosts))


def clean_subdomains(names: set[str], domain: str) -> set[str]:
    out = set()
    for n in names:
        n = n.strip().lower().rstrip(".").removeprefix("*.")
        if n == domain or n.endswith("." + domain):
            out.add(n)
    return out


def _subdomains(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    found: set[str] = set()
    src = rep.section("Kaynaklar")

    def collect(item):
        name, fn = item
        try:
            return name, clean_subdomains(fn(ctx, domain), domain), None
        except OsintError as e:
            return name, set(), str(e)

    for name, names, err in ctx.parallel(collect, SUBDOMAIN_SOURCES):
        if err:
            src.add(name, err, level=Level.MUTED)
        else:
            src.add(name, f"{len(names)} kayıt", level=Level.OK)
            found |= names
    rep.changed()
    if not found:
        rep.summary = "Hiç subdomain bulunamadı."
        return

    limit = 300
    names = sorted(found)
    resolved = ctx.parallel(lambda n: (n, _safe_query(ctx, n, "A")[1]), names[:limit])
    live = rep.section("Aktif (IP'ye çözülen)")
    dead = rep.section("Çözülmeyen", note="Eski veya iç ağ kayıtları olabilir.")
    for name, ips in resolved:
        ips = [i for i in ips if validate.is_ip(i)]
        if ips:
            live.add(name, ", ".join(ips[:3]), url=f"https://{name}", level=Level.OK)
        else:
            dead.add(name, level=Level.MUTED)
    if len(names) > limit:
        extra = rep.section(f"Çözümlenmedi (limit {limit})")
        for name in names[limit:]:
            extra.add(name, level=Level.MUTED)
    rep.summary = f"{len(found)} benzersiz subdomain; {len(live.items)} tanesi aktif."


# ---------------------------------------------------------------- wayback

def _wayback(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    cdx = "https://web.archive.org/cdx/search/cdx"
    sec = rep.section("Arşiv özeti")
    first = ctx.http.json(cdx, params={"url": domain, "output": "json", "fl": "timestamp", "limit": 1},
                          timeout=max(30, ctx.settings.timeout), expect=list)
    last = ctx.http.json(cdx, params={"url": domain, "output": "json", "fl": "timestamp", "limit": -1},
                         timeout=max(30, ctx.settings.timeout), expect=list)
    if not first or len(first) < 2:
        sec.add("Sonuç", "Bu domain hiç arşivlenmemiş", level=Level.MUTED)
        return
    f_ts, l_ts = first[1][0], (last[1][0] if last and len(last) > 1 else first[1][0])
    sec.add("İlk kayıt", _ts(f_ts), url=f"https://web.archive.org/web/{f_ts}/{domain}")
    sec.add("Son kayıt", _ts(l_ts), url=f"https://web.archive.org/web/{l_ts}/{domain}")
    rep.changed()

    rows = ctx.http.json(cdx, params={
        "url": f"{domain}/*", "output": "json", "fl": "timestamp,original,statuscode,mimetype",
        "collapse": "urlkey", "filter": "statuscode:200", "limit": 400,
    }, timeout=max(30, ctx.settings.timeout), expect=list) or []
    urls = [r for r in rows[1:] if isinstance(r, list) and len(r) >= 2]
    interesting_ext = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".sql", ".zip", ".bak",
                       ".env", ".json", ".xml", ".txt", ".log", ".conf", ".config")
    files = [r for r in urls if r[1].lower().split("?")[0].endswith(interesting_ext)]
    params = [r for r in urls if "?" in r[1] and r not in files]
    if files:
        s = rep.section(f"İlginç dosyalar ({len(files)})")
        for ts, orig, *_ in files[:40]:
            s.add(orig, _ts(ts)[:10], url=f"https://web.archive.org/web/{ts}/{orig}")
    if params:
        s = rep.section(f"Parametreli URL'ler ({len(params)})")
        for ts, orig, *_ in params[:25]:
            s.add(orig, _ts(ts)[:10], url=f"https://web.archive.org/web/{ts}/{orig}")
    s = rep.section(f"Arşivlenen sayfalar (ilk {min(len(urls), 40)} / {len(urls)})")
    for ts, orig, *_ in urls[:40]:
        s.add(orig, _ts(ts)[:10], url=f"https://web.archive.org/web/{ts}/{orig}")
    links = rep.section("Linkler")
    links.link("Wayback takvimi", f"https://web.archive.org/web/*/{domain}")
    links.link("Tüm URL'ler", f"https://web.archive.org/web/*/{domain}/*")
    links.link("archive.today", f"https://archive.ph/{domain}")


def _ts(ts: str) -> str:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}" if len(ts) >= 12 else ts


# ---------------------------------------------------------------- kayıt

DOMAIN = Field("domain", "Domain", "ornek.com", "url", validate.domain)

register(Tool("host", "IP & Domain", "WHOIS, konum, açık port, CVE", "LANGUAGE", "Ağ & Domain", [
    Action("profile", "Sorgula", (Field("target", "IP veya domain", "ornek.com / 8.8.8.8", "url",
                                        validate.host),), _host)]))
register(Tool("dns", "DNS Kayıtları", "Tüm kayıtlar + SPF/DMARC analizi", "DNS", "Ağ & Domain", [
    Action("records", "Sorgula", (DOMAIN,), _dns)]))
register(Tool("tls", "SSL / TLS", "Sertifika, protokol, güvenlik başlıkları", "LOCK", "Ağ & Domain", [
    Action("analyze", "Analiz", (DOMAIN,), _tls)]))
register(Tool("subdomain", "Subdomain", "7 pasif kaynak + canlılık kontrolü", "ACCOUNT_TREE",
              "Ağ & Domain", [Action("enumerate", "Keşfet", (DOMAIN,), _subdomains)]))
register(Tool("wayback", "Web Arşivi", "Wayback Machine: eski sayfa ve dosyalar", "HISTORY",
              "Ağ & Domain", [Action("scan", "Tara", (DOMAIN,), _wayback)]))


# ---------------------------------------------------------------- reverse IP

def _resolve_target(ctx: Context, target: str) -> str:
    if validate.is_ip(target):
        return target
    ips = [x for x in dns.resolve(ctx, target, "A") if validate.is_ip(x)]
    if not ips:
        raise OsintError(f"{target} bir IP adresine çözülemedi")
    return ips[0]


def _reverse_ip(ctx: Context, rep: Report, v: dict) -> None:
    ip = _resolve_target(ctx, v["target"])
    resp = ctx.http.get("https://api.hackertarget.com/reverseiplookup/", params={"q": ip})
    text = resp.text.strip()
    if resp.status_code != 200 or text.lower().startswith("error") or "API count" in text:
        raise OsintError("HackerTarget: günlük ücretsiz limit doldu, yarın tekrar deneyin")
    domains = sorted({d.strip().lower() for d in text.splitlines() if d.strip() and " " not in d.strip()})
    sec = rep.section(f"{ip} üzerindeki domainler ({len(domains)})")
    if not domains:
        sec.add("Sonuç", "Bu IP için kayıtlı domain yok", level=Level.MUTED)
    for d in domains[:300]:
        sec.add(d, url=f"https://{d}")
    if len(domains) > 50:
        rep.summary = ("Çok sayıda domain: büyük olasılıkla paylaşımlı hosting veya CDN; "
                       "aynı sahibe ait olduklarını göstermez.")
    rep.section("Dış araçlar").link("ViewDNS", f"https://viewdns.info/reverseip/?host={ip}&t=1")


# ---------------------------------------------------------------- ASN / BGP

def asn_or_ip(value: str) -> str:
    v = value.strip().upper().replace(" ", "")
    if v.startswith("AS") and v[2:].isdigit():
        return v
    if v.isdigit():
        return f"AS{v}"
    return validate.ip(value)


def _ripe(ctx: Context, endpoint: str, resource: str) -> dict:
    data = ctx.http.json(f"https://stat.ripe.net/data/{endpoint}/data.json", params={"resource": resource},
                         timeout=max(20, ctx.settings.timeout))
    return (data or {}).get("data") or {}


def _asn(ctx: Context, rep: Report, v: dict) -> None:
    target: str = v["target"]
    if not target.startswith("AS"):
        net = _ripe(ctx, "network-info", target)
        sec = rep.section(f"IP: {target}")
        sec.add("Duyurulan blok", net.get("prefix") or "Duyurulmuyor (BGP'de görünmüyor)",
                level=Level.OK if net.get("prefix") else Level.WARN)
        asns = net.get("asns") or []
        if not asns:
            return
        sec.add("ASN", ", ".join(f"AS{a}" for a in asns))
        target = f"AS{asns[0]}"
        rep.changed()

    ov = _ripe(ctx, "as-overview", target)
    sec = rep.section(target)
    sec.add("Sahibi", ov.get("holder") or "—", level=Level.OK)
    sec.add("BGP'de görünüyor", "Evet" if ov.get("announced") else "Hayır",
            level=Level.OK if ov.get("announced") else Level.WARN)
    block = ov.get("block") or {}
    if block.get("desc"):
        sec.add("Kayıt bloğu", block["desc"])
    rep.changed()

    prefixes = [p["prefix"] for p in (_ripe(ctx, "announced-prefixes", target).get("prefixes") or [])
                if isinstance(p, dict) and p.get("prefix")]
    v4 = [p for p in prefixes if ":" not in p]
    v6 = [p for p in prefixes if ":" in p]
    total = sum(ipaddress.ip_network(p).num_addresses for p in v4)
    pre = rep.section(f"Duyurulan bloklar ({len(prefixes)})")
    pre.add("IPv4", f"{len(v4)} blok · {total:,} adres".replace(",", "."))
    pre.add("IPv6", f"{len(v6)} blok")
    for p in v4[:40]:
        pre.add(p)
    neigh = _ripe(ctx, "asn-neighbours", target).get("neighbours") or []
    if neigh:
        up = [n for n in neigh if n.get("type") == "left"]
        n = rep.section("Komşular", note="'Üst' komşular bu ağa internet erişimi sağlayan sağlayıcılardır.")
        n.add("Üst sağlayıcılar", ", ".join(f"AS{x.get('asn')}" for x in sorted(up, key=lambda x: -x.get("power", 0))[:10]) or "—")
        n.add("Toplam komşu", len(neigh))
    links = rep.section("Dış araçlar")
    num = target[2:]
    links.link("bgp.he.net", f"https://bgp.he.net/{target}")
    links.link("PeeringDB", f"https://www.peeringdb.com/asn/{num}")
    links.link("RIPEstat", f"https://stat.ripe.net/{target}")


register(Tool("reverseip", "Reverse IP", "Aynı sunucudaki diğer siteler", "DEVICE_HUB", "Ağ & Domain", [
    Action("lookup", "Bul", (Field("target", "IP veya domain", "ornek.com", "url", validate.host),), _reverse_ip)]))
register(Tool("asn", "ASN / BGP", "Ağ sahibi, IP blokları, üst sağlayıcılar", "HUB", "Ağ & Domain", [
    Action("lookup", "Sorgula", (Field("target", "ASN veya IP", "AS9121 / 8.8.8.8", parse=asn_or_ip),), _asn)]))
