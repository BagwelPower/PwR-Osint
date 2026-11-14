"""Ağ Araçları: sistem ve ağ yöneticisinin saha araçları."""

from __future__ import annotations

import ipaddress
import socket
import statistics
import time
from typing import Optional
from urllib.parse import urljoin, urlsplit

from ..core import dns, validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report
from .web import parse_url

# ---------------------------------------------------------------- yardımcılar


def local_ip() -> Optional[str]:
    """Cihazın yerel IP'si (UDP 'connect' paket göndermez; yalnızca çıkış arayüzünü seçer)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def tcp_rtt(host: str, port: int = 443, timeout: float = 3.0) -> Optional[float]:
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - start) * 1000
    except OSError:
        return None


# ---------------------------------------------------------------- Bağlantım

def _netinfo(ctx: Context, rep: Report, v: dict) -> None:
    sec = rep.section("İnternet bağlantısı")
    v4 = v6 = None
    try:
        v4 = (ctx.http.json("https://api.ipify.org", params={"format": "json"}) or {}).get("ip")
        rep.source("ipify (IPv4)", True)
    except OsintError as e:
        rep.source("ipify (IPv4)", False, str(e).split(": ", 1)[-1])
    try:
        cand = (ctx.http.json("https://api64.ipify.org", params={"format": "json"}) or {}).get("ip")
        v6 = cand if cand and ":" in cand else None
        rep.source("ipify (IPv6)", True)
    except OsintError as e:
        rep.source("ipify (IPv6)", False, str(e).split(": ", 1)[-1])
    if not v4 and not v6:
        raise OsintError("Public IP alınamadı; internet bağlantısını kontrol edin")
    sec.add("Public IPv4", v4 or "—", level=Level.OK if v4 else Level.MUTED)
    sec.add("IPv6", v6 or "Yok (operatör/ağ IPv6 vermiyor)", level=Level.OK if v6 else Level.MUTED)
    lip = local_ip()
    if lip:
        sec.add("Yerel IP", lip)
        addr = ipaddress.ip_address(lip)
        if addr in ipaddress.ip_network("100.64.0.0/10"):
            sec.add("NAT", "Operatör NAT'ı (CGNAT) arkasındasınız — gelen bağlantılar size ulaşmaz", level=Level.WARN)
        elif addr.is_private:
            sec.add("NAT", "Yerel ağ (router NAT'ı) arkasındasınız")
        elif v4 and lip == v4:
            sec.add("NAT", "Doğrudan public IP (NAT yok) — cihaz internete açık", level=Level.WARN)
    if v4:
        try:
            info = ctx.http.json(f"https://ipinfo.io/{v4}/json",
                                 params={"token": ctx.settings.ipinfo_token} if ctx.settings.ipinfo_token else None)
            isp = rep.section("Operatör")
            isp.add("Kurum / ASN", info.get("org", "—"))
            isp.add("Konum (IP bloğu)", ", ".join(x for x in (info.get("city"), info.get("region"), info.get("country"))
                                                   if x) or "—")
            if info.get("hostname"):
                isp.add("Reverse DNS", info["hostname"])
            rep.source("ipinfo.io", True)
        except OsintError as e:
            rep.source("ipinfo.io", False, str(e).split(": ", 1)[-1])
    rep.changed()

    perf = rep.section("Gecikme (TCP bağlantı süresi)")
    for name, host in (("Cloudflare", "1.1.1.1"), ("Google", "8.8.8.8"), ("Quad9", "9.9.9.9")):
        samples = [r for r in (tcp_rtt(host, 443 if host != "9.9.9.9" else 443) for _ in range(3)) if r is not None]
        if samples:
            med = statistics.median(samples)
            perf.add(name, f"{med:.0f} ms (min {min(samples):.0f}, max {max(samples):.0f})",
                     level=Level.OK if med < 80 else Level.WARN if med < 250 else Level.BAD)
        else:
            perf.add(name, "Ulaşılamadı", level=Level.MUTED)
    try:
        dns.query(ctx, "github.com", "A")
        perf.add("Çalışan DNS yolu", dns.active_transport() or "—", level=Level.OK)
    except OsintError:
        perf.add("DNS", "Hiçbir DNS yolu çalışmıyor", level=Level.BAD)


# ---------------------------------------------------------------- HTTP İnceleme

CDN_HEADERS = (("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-akamai-transformed", "Akamai"),
               ("x-fastly-request-id", "Fastly"), ("x-vercel-id", "Vercel"), ("x-nf-request-id", "Netlify"),
               ("x-azure-ref", "Azure Front Door"), ("x-goog-generation", "Google Cloud"))


def _cookie_flags(raw: str) -> tuple[str, list[str]]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else "") for p in parts[1:]}
    missing = [f for f in ("secure", "httponly") if f not in attrs]
    if "samesite" not in attrs:
        missing.append("SameSite")
    elif attrs["samesite"].lower() == "none" and "secure" not in attrs:
        missing.append("SameSite=None+Secure")
    return name, missing


def _http(ctx: Context, rep: Report, v: dict) -> None:
    url: str = v["url"]
    chain = rep.section("İstek zinciri")
    final = None
    for hop in range(10):
        start = time.perf_counter()
        resp = ctx.http.get(url, allow_redirects=False, stream=True)
        ms = (time.perf_counter() - start) * 1000
        resp.close()
        loc = resp.headers.get("Location")
        code = resp.status_code
        level = Level.OK if code < 300 else Level.INFO if code < 400 else Level.WARN if code < 500 else Level.BAD
        chain.add(f"{hop + 1}. {code} {resp.reason or ''}".strip(), f"{url}  ({ms:.0f} ms)", url=url, level=level)
        if hop == 0 and urlsplit(url).scheme == "http" and not (loc and loc.startswith("https://")):
            chain.add("HTTPS yönlendirmesi", "HTTP istekleri HTTPS'e yönlendirilmiyor", level=Level.WARN)
        if code in (301, 302, 303, 307, 308) and loc:
            url = urljoin(url, loc)
            continue
        final = resp
        break
    if final is None:
        raise OsintError("10'dan fazla yönlendirme (döngü olabilir)")
    rep.changed()

    h = {k.lower(): val for k, val in final.headers.items()}
    info = rep.section("Yanıt")
    info.add("Son adres", url)
    info.add("İçerik türü", h.get("content-type", "—"))
    if h.get("content-length"):
        info.add("Boyut", f"{int(h['content-length']) / 1024:,.1f} KB")
    info.add("Sıkıştırma", h.get("content-encoding", "Yok"))
    for label, key in (("Sunucu", "server"), ("Uygulama", "x-powered-by"), ("Önbellek", "cache-control"),
                       ("Önbellek durumu", "x-cache"), ("Yaş", "age"), ("Alt-Svc (HTTP/3)", "alt-svc")):
        if h.get(key):
            info.add(label, h[key][:200])
    cdns = [name for key, name in CDN_HEADERS if key in h]
    if "akamai" in h.get("server", "").lower():
        cdns.append("Akamai")
    if cdns:
        info.add("CDN", ", ".join(dict.fromkeys(cdns)))

    cookies = final.raw.headers.getlist("Set-Cookie") if hasattr(final.raw, "headers") and \
        hasattr(final.raw.headers, "getlist") else ([h["set-cookie"]] if "set-cookie" in h else [])
    if cookies:
        c = rep.section(f"Çerezler ({len(cookies)})")
        for raw in cookies:
            name, missing = _cookie_flags(raw)
            c.add(name, "Eksik bayrak: " + ", ".join(missing) if missing else "Secure · HttpOnly · SameSite",
                  level=Level.WARN if missing else Level.OK)
        c.note = "Oturum çerezlerinde Secure ve HttpOnly eksikliği çalınma riskini artırır."
    allh = rep.section(f"Tüm başlıklar ({len(h)})")
    for k, val in sorted(h.items()):
        allh.add(k, val[:300])


def http_url(value: str) -> str:
    v = value.strip()
    if v.lower().startswith("http://"):
        host = urlsplit(v).hostname or ""
        validate.host(host)
        return v
    return parse_url(v)


# ---------------------------------------------------------------- Globalping

GLOBALPING = "https://api.globalping.io/v1/measurements"
GLOBALPING_RETRY_DELAY = 3  # sn (testlerde 0)


def _location(value: str) -> str:
    return " ".join(value.split())[:60]


def _measure(ctx: Context, rep: Report, mtype: str, target: str, location: Optional[str],
             options: Optional[dict] = None) -> list[dict]:
    loc = location or "world"
    body = {"type": mtype, "target": target, "limit": 5 if loc == "world" else 3,
            "locations": [{"magic": loc}]}
    if options:
        body["measurementOptions"] = options
    resp = ctx.http.post(GLOBALPING, json=body, timeout=max(20, ctx.settings.timeout))
    if resp.status_code >= 500:  # geçici sunucu hatası: kısa bekleyip bir kez daha
        ctx.cancel_event.wait(GLOBALPING_RETRY_DELAY)
        resp = ctx.http.post(GLOBALPING, json=body, timeout=max(20, ctx.settings.timeout))
        if resp.status_code >= 500:
            raise OsintError(f"Globalping sunucu hatası (HTTP {resp.status_code}); biraz sonra tekrar deneyin")
    if resp.status_code == 429:
        raise OsintError("Globalping: saatlik ücretsiz ölçüm limiti doldu, daha sonra deneyin")
    if resp.status_code == 422:
        try:
            body = resp.json()
            msg = ((body.get("error") or {}).get("message", "")) if isinstance(body, dict) else ""
        except ValueError:
            msg = ""
        raise OsintError(f"Globalping ölçümü reddetti: {msg or 'geçersiz hedef veya konum'}")
    if resp.status_code not in (200, 202):
        raise OsintError(f"Globalping: HTTP {resp.status_code}")
    from ..core.http import parse_json
    mid = parse_json(resp, dict).get("id")
    if not mid:
        raise OsintError("Globalping: ölçüm kimliği alınamadı")
    rep.source("Globalping", True, f"ölçüm {mid}")
    deadline = time.monotonic() + 45
    data: dict = {}
    while time.monotonic() < deadline:
        ctx.check_cancelled()
        data = ctx.http.json(f"{GLOBALPING}/{mid}") or {}
        if data.get("status") != "in-progress":
            break
        rep.summary = f"Ölçülüyor… ({len(data.get('results') or [])} sonda)"
        rep.changed()
        ctx.cancel_event.wait(0.8)
    return [r for r in data.get("results") or [] if isinstance(r, dict)]


def _probe_name(r: dict) -> str:
    p = r.get("probe") or {}
    return f"{p.get('city', '?')}, {p.get('country', '?')} · {p.get('network', '')} AS{p.get('asn', '')}".strip()


def _gp_ping(ctx: Context, rep: Report, v: dict) -> None:
    results = _measure(ctx, rep, "ping", v["target"], v.get("location"), {"packets": 4})
    sec = rep.section("Ping (uzak sondalardan)")
    for r in sorted(results, key=lambda r: ((r.get("result") or {}).get("stats") or {}).get("avg") or 1e9):
        res = r.get("result") or {}
        st = res.get("stats") or {}
        if res.get("status") != "finished" or st.get("avg") is None:
            sec.add(_probe_name(r), "Yanıt yok / ICMP engelli", level=Level.MUTED)
            continue
        loss = st.get("loss", 0)
        sec.add(_probe_name(r), f"ort {st['avg']:.1f} ms (min {st.get('min', 0):.1f}, maks {st.get('max', 0):.1f}) · "
                f"kayıp %{loss}", level=Level.BAD if loss and loss >= 50 else Level.WARN if loss else Level.OK)
    sec.note = "Ölçüm telefondan değil, Globalping ağındaki gönüllü sondalardan yapıldı."
    rep.summary = None


def _gp_trace(ctx: Context, rep: Report, v: dict, mtype: str = "traceroute") -> None:
    results = _measure(ctx, rep, mtype, v["target"], v.get("location"))
    for r in results[:3]:
        res = r.get("result") or {}
        hops = [h for h in res.get("hops") or [] if isinstance(h, dict)]
        sec = rep.section(f"{'MTR' if mtype == 'mtr' else 'Traceroute'} · {_probe_name(r)} ({len(hops)} atlama)")
        for i, hop in enumerate(hops, 1):
            addr = hop.get("resolvedAddress") or "*"
            name = hop.get("resolvedHostname") or ""
            if mtype == "mtr":
                st = hop.get("stats") or {}
                avg, loss = st.get("avg"), st.get("loss")
                if avg is None:  # yanıt vermeyen yönlendirici
                    val, level = "* * *", Level.MUTED
                else:
                    val = f"ort {avg:.1f} ms · kayıp %{loss if loss is not None else '?'}"
                    level = Level.WARN if loss else Level.INFO
            else:
                rtts = [t.get("rtt") for t in hop.get("timings") or [] if t.get("rtt") is not None]
                val = f"{min(rtts):.1f} ms" if rtts else "* * *"
                level = Level.INFO if rtts else Level.MUTED
            asn = hop.get("asn")
            sec.add(f"{i}. {addr}", " · ".join(x for x in (name if name != addr else "", val,
                                                           f"AS{asn[0] if isinstance(asn, list) and asn else asn}"
                                                           if asn else "") if x), level=level)
        if not hops:
            sec.add("Sonuç yok", (res.get("rawOutput") or "")[:200], level=Level.MUTED)
    rep.notice("Traceroute telefondan değil, Globalping sondalarından yapıldı (Android'de root olmadan "
               "traceroute mümkün değil).")
    rep.summary = None


def _gp_http(ctx: Context, rep: Report, v: dict) -> None:
    target = v["target"]
    results = _measure(ctx, rep, "http", target, v.get("location"),
                       {"protocol": "HTTPS", "request": {"method": "HEAD", "path": "/"}})
    sec = rep.section("Dünyadan erişilebilirlik (HTTPS)")
    for r in results:
        res = r.get("result") or {}
        code = res.get("statusCode")
        t = res.get("timings") or {}
        if not code:
            sec.add(_probe_name(r), "Erişilemedi", level=Level.BAD)
            continue
        sec.add(_probe_name(r), f"HTTP {code} · toplam {t.get('total', '?')} ms (DNS {t.get('dns', '?')}, TCP "
                f"{t.get('tcp', '?')}, TLS {t.get('tls', '?')}, ilk bayt {t.get('firstByte', '?')})",
                level=Level.OK if code < 400 else Level.WARN)
    rep.summary = None


TARGET = Field("target", "Hedef (domain veya IP)", "github.com", "url", validate.host)
LOCATION = Field("location", "Konum (isteğe bağlı)", "TR, Germany, Europe, AS9121 …", parse=_location, optional=True)

register(Tool("netinfo", "Bağlantım", "Public IP, IPv6, operatör, NAT/CGNAT, gecikme, DNS yolu", "WIFI",
              "Ağ Araçları", [Action("show", "Göster", (), _netinfo)]))
register(Tool("httpinspect", "HTTP İnceleme", "Yönlendirme zinciri, süreler, başlıklar, çerez güvenliği, CDN",
              "HTTP", "Ağ Araçları", [
                  Action("inspect", "İncele", (Field("url", "Adres", "ornek.com", "url", http_url),), _http)]))
register(Tool("globalping", "Küresel Ölçüm", "Dünyadan ping, traceroute, MTR ve erişilebilirlik", "PUBLIC",
              "Ağ Araçları", [
                  Action("ping", "Ping", (TARGET, LOCATION), _gp_ping),
                  Action("traceroute", "Traceroute", (TARGET, LOCATION), _gp_trace),
                  Action("mtr", "MTR", (TARGET, LOCATION), lambda c, r, v: _gp_trace(c, r, v, "mtr")),
                  Action("http", "Erişilebilirlik", (TARGET, LOCATION), _gp_http)]))


# ---------------------------------------------------------------- Port Tarama (aktif)

# En yaygın TCP portları (nmap top-ports ve sahada sık görülen servisler)
TOP_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP-alt", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog", 515: "LPD", 548: "AFP", 554: "RTSP",
    587: "SMTP-submission", 631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel-SSL", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS", 3000: "Dev/Grafana",
    3128: "Squid", 3306: "MySQL", 3389: "RDP", 3690: "SVN", 4443: "HTTPS-alt", 4848: "GlassFish", 5000: "Dev/UPnP",
    5060: "SIP", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP", 5900: "VNC", 5938: "TeamViewer",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API", 6667: "IRC", 7001: "WebLogic", 7547: "TR-069",
    8000: "HTTP-alt", 8008: "HTTP-alt/Chromecast", 8009: "AJP/Chromecast", 8080: "HTTP-proxy", 8081: "HTTP-alt",
    8086: "InfluxDB", 8088: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "Portainer/PHP-FPM",
    9090: "Prometheus/Cockpit", 9100: "Yazıcı (JetDirect)", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9443: "HTTPS-alt", 10000: "Webmin", 10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ",
    27017: "MongoDB", 32400: "Plex", 49152: "UPnP", 62078: "iPhone/iPad (lockdown)",
}
SCAN_TIMEOUT = 1.5
SCAN_WORKERS = 64


def probe_port(host: str, port: int, timeout: float = SCAN_TIMEOUT, banner: bool = True) -> tuple[str, str]:
    """('open'|'closed'|'filtered', banner). 'closed' = bağlantı reddedildi: host canlı, port kapalı."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            text = ""
            if banner:
                s.settimeout(1.0)
                try:
                    if port in (80, 81, 8000, 8008, 8080, 8081, 8088, 8888, 3000, 5000, 9000, 9090):
                        s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    data = s.recv(256)
                    text = data.decode("latin-1", "replace").strip()
                except OSError:
                    pass
            return "open", text
    except ConnectionRefusedError:
        return "closed", ""
    except OSError:
        return "filtered", ""


def _banner_summary(port: int, text: str) -> str:
    if not text:
        return ""
    first = text.splitlines()[0][:100]
    if text.startswith("HTTP/"):
        server = next((ln.split(":", 1)[1].strip() for ln in text.splitlines() if ln.lower().startswith("server:")), "")
        return f"{first.split(' ', 1)[-1]}{' · ' + server if server else ''}"
    return first


def _portscan(ctx: Context, rep: Report, v: dict) -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from ..core.ports import RISKY_PORTS
    target: str = v["target"]
    ip = target if validate.is_ip(target) else next(
        (x for x in dns.resolve(ctx, target, "A") if validate.is_ip(x)), None)
    if not ip:
        raise OsintError(f"{target} bir IP adresine çözülemedi")
    ports = sorted(TOP_PORTS)
    found: list[tuple[int, str]] = []
    closed = filtered = 0
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
        futs = {pool.submit(probe_port, ip, p): p for p in ports}
        for fut in as_completed(futs):
            if ctx.cancel_event.is_set():
                for f in futs:
                    f.cancel()
                break
            state, banner = fut.result()
            port = futs[fut]
            if state == "open":
                found.append((port, banner))
                rep.summary = f"Taranıyor… {len(found)} açık port"
                rep.changed()
            elif state == "closed":
                closed += 1
            else:
                filtered += 1
    took = time.monotonic() - start
    sec = rep.section(f"Açık portlar · {ip}")
    for port, banner in sorted(found):
        risk = RISKY_PORTS.get(port)
        val = " · ".join(x for x in (TOP_PORTS.get(port, "?"), _banner_summary(port, banner),
                                     risk[0] if risk else "") if x)
        sec.add(f"{port}/tcp", val, level=risk[1] if risk else Level.OK)
    if not found:
        sec.add("Açık port bulunamadı", level=Level.MUTED)
    stat = rep.section("Tarama özeti")
    stat.add("Hedef", f"{target} ({ip})" if target != ip else ip)
    stat.add("Taranan", f"{len(ports)} yaygın TCP portu · {took:.1f} sn")
    stat.add("Kapalı (yanıt: reddedildi)", closed)
    stat.add("Filtreli (yanıt yok/güvenlik duvarı)", filtered)
    if filtered > len(ports) * 0.9 and not found:
        stat.note = "Neredeyse tüm portlar yanıtsız: güvenlik duvarı ya da host kapalı olabilir."
    rep.summary = f"{len(found)} açık port bulundu ({len(ports)} port tarandı)."


def scan_target(value: str) -> str:
    v = value.strip()
    if "/" in v or "-" in v.split(".")[-1] or "*" in v:
        raise ValueError("Yalnızca tek bir host (IP veya domain) taranabilir; ağ aralığı kabul edilmez")
    return validate.host(v)


# ---------------------------------------------------------------- Yerel Ağ Keşfi (aktif)

LAN_PORTS = (80, 443, 22, 445, 139, 53, 8080, 554, 9100, 631, 62078, 8008, 8009, 3389, 5000, 1900, 7000, 515)
DEVICE_HINTS = (
    ({62078}, "iPhone / iPad"), ({8008, 8009}, "Chromecast / Google TV"), ({9100}, "Yazıcı"),
    ({631}, "Yazıcı (IPP)"), ({515}, "Yazıcı (LPD)"), ({554}, "IP kamera / NVR (RTSP)"),
    ({3389}, "Windows (Uzak Masaüstü)"), ({445, 139}, "Windows / NAS (dosya paylaşımı)"),
    ({7000}, "Apple TV / AirPlay"), ({53}, "Router / DNS sunucusu"), ({22}, "Linux / sunucu / NAS"),
    ({5000}, "NAS (Synology) / geliştirme sunucusu"),
)


def guess_device(open_ports: set[int], is_gateway: bool) -> str:
    if is_gateway:
        return "Router / ağ geçidi"
    for ports, name in DEVICE_HINTS:
        if ports & open_ports:
            return name
    if open_ports & {80, 443, 8080}:
        return "Web arayüzlü cihaz"
    return "Bilinmeyen cihaz"


MOBILE_IFACES = ("rmnet", "ccmni", "wwan", "pdp", "v4-rmnet", "rev_rmnet", "seth", "radio", "usb")
LOCAL_IFACES = ("wlan", "wl", "eth", "en", "ap", "swlan", "p2p")


def interface_for_ip(ip: str) -> Optional[str]:
    """Yerel IP'nin ait olduğu ağ arayüzünün adı (Linux/Android, SIOCGIFCONF). Bulunamazsa None."""
    try:
        import array
        import fcntl
        import struct
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            buf = array.array("B", b"\0" * 8192)
            out = fcntl.ioctl(s.fileno(), 0x8912, struct.pack("iL", 8192, buf.buffer_info()[0]))
            size = struct.unpack("iL", out)[0]
        data = buf.tobytes()
        step = 40 if struct.calcsize("L") == 8 else 32
        for i in range(0, size, step):
            name = data[i:i + 16].split(b"\0", 1)[0].decode(errors="replace")
            if socket.inet_ntoa(data[i + 20:i + 24]) == ip:
                return name
    except (ImportError, OSError, ValueError, OverflowError):
        return None
    return None


def on_android() -> bool:
    import os
    import sys
    return hasattr(sys, "getandroidapilevel") or "ANDROID_ROOT" in os.environ


def lan_network(lip: Optional[str], iface: Optional[str] = None,
                connectivity: Optional[set[str]] = None) -> ipaddress.IPv4Network:
    """Yalnızca cihazın kendi Wi-Fi/ethernet ağı. Mobil veride operatörler de özel (10.x) IP verebilir;
    bu yüzden IP'nin özel olması yetmez, bağlantının Wi-Fi/ethernet arayüzünden gittiği doğrulanır."""
    wifi_msg = "Yerel ağ taraması yalnızca Wi-Fi (veya ethernet) bağlantısında yapılabilir. Wi-Fi'ye bağlanın."
    if not lip:
        raise OsintError("Yerel IP bulunamadı; Wi-Fi'ye bağlı olduğunuzdan emin olun")
    addr = ipaddress.ip_address(lip)
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        raise OsintError("Operatör (CGNAT) ağındasınız. " + wifi_msg)
    if not addr.is_private or addr.is_loopback:
        raise OsintError("Cihaz özel bir yerel ağda değil (mobil veri veya public IP). " + wifi_msg)
    if connectivity is not None and not connectivity & {"wifi", "ethernet"}:
        raise OsintError("Cihaz şu anda Wi-Fi'de değil (bağlantı: " + (", ".join(sorted(connectivity)) or "yok")
                         + "). " + wifi_msg)
    if iface:
        low = iface.lower()
        if low.startswith(MOBILE_IFACES):
            raise OsintError(f"Bağlantı mobil veri arayüzünden ({iface}) gidiyor. " + wifi_msg)
        if not low.startswith(LOCAL_IFACES) and on_android():
            raise OsintError(f"Ağ arayüzü ({iface}) Wi-Fi olarak doğrulanamadı. " + wifi_msg)
    elif on_android() and not (connectivity and connectivity & {"wifi", "ethernet"}):
        raise OsintError("Ağ arayüzü belirlenemedi; güvenlik için tarama yapılmadı. " + wifi_msg)
    return ipaddress.ip_network(f"{lip}/24", strict=False)


def _lan(ctx: Context, rep: Report, v: dict) -> None:
    from concurrent.futures import ThreadPoolExecutor

    lip = local_ip()
    iface = interface_for_ip(lip) if lip else None
    net = lan_network(lip, iface, ctx.connectivity)
    hosts = [str(h) for h in net.hosts()]
    gateway = str(net.network_address + 1)

    def probe_host(ip: str) -> tuple[str, set[int]]:
        if ctx.cancel_event.is_set():
            return ip, set()
        alive, open_ports = False, set()
        for port in LAN_PORTS:
            state, _ = probe_port(ip, port, timeout=0.6, banner=False)
            if state == "open":
                alive = True
                open_ports.add(port)
            elif state == "closed":
                alive = True  # bağlantı reddedildi: cihaz var, port kapalı
            if alive and len(open_ports) >= 4:
                break
        return (ip, open_ports) if alive else ("", set())

    start = time.monotonic()
    found: list[tuple[str, set[int]]] = []
    with ThreadPoolExecutor(max_workers=48) as pool:
        for ip, ports in pool.map(probe_host, hosts):
            if ip:
                found.append((ip, ports))
                rep.summary = f"Taranıyor… {len(found)} cihaz bulundu"
                rep.changed()
    if ctx.cancel_event.is_set():
        rep.notice("Tarama iptal edildi; bulunanlar gösteriliyor.")
    sec = rep.section(f"Cihazlar ({len(found)}) · {net}")
    for ip, ports in sorted(found, key=lambda x: ipaddress.ip_address(x[0])):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except OSError:
            name = ""
        kind = guess_device(ports, ip == gateway)
        me = " · BU CİHAZ" if ip == lip else ""
        sec.add(ip + me, " · ".join(x for x in (kind, name, ("portlar: " + ", ".join(map(str, sorted(ports))))
                                                if ports else "") if x),
                level=Level.WARN if ports & {23, 3389, 445, 5900} and ip != lip else Level.INFO)
    info = rep.section("Tarama")
    info.add("Ağ", f"{net} · bu cihaz {lip} · ağ geçidi (tahmini) {gateway}" + (f" · arayüz {iface}" if iface else ""))
    info.add("Süre", f"{time.monotonic() - start:.0f} sn · {len(hosts)} adres × {len(LAN_PORTS)} port")
    info.note = ("Android 10+ MAC adreslerini uygulamalardan gizlediği için cihaz türü açık portlardan tahmin "
                 "edilir. Port açmayan ve ICMP dışında yanıt vermeyen cihazlar görünmeyebilir.")
    rep.summary = f"Yerel ağda {len(found)} cihaz bulundu."


# ---------------------------------------------------------------- Hız Testi (aktif: veri harcar)

SPEED = "https://speed.cloudflare.com"


def _speed(ctx: Context, rep: Report, v: dict, upload: bool = False) -> None:
    http = ctx.fast_http
    lat = []
    for _ in range(8):
        ctx.check_cancelled()
        t = time.perf_counter()
        r = http.get(f"{SPEED}/__down", params={"bytes": 0}, timeout=8)
        if r.status_code != 200:
            raise OsintError(f"Hız sunucusu: HTTP {r.status_code}")
        lat.append((time.perf_counter() - t) * 1000)
    lat.sort()
    core = lat[1:-1] if len(lat) > 4 else lat
    sec = rep.section("Sonuç (Cloudflare)")
    med = statistics.median(core)
    jitter = statistics.mean(abs(a - b) for a, b in zip(core, core[1:])) if len(core) > 1 else 0
    sec.add("Gecikme (HTTP)", f"{med:.0f} ms", level=Level.OK if med < 60 else Level.WARN if med < 150 else Level.BAD)
    sec.add("Titreşim (jitter)", f"{jitter:.0f} ms", level=Level.OK if jitter < 20 else Level.WARN)
    rep.changed()
    used = 0
    if not upload:
        speeds = []
        for size in (1_000_000, 5_000_000, (v.get("mb") or 10) * 1_000_000):
            ctx.check_cancelled()
            t = time.perf_counter()
            r = http.get(f"{SPEED}/__down", params={"bytes": size}, timeout=60, stream=True)
            n = 0
            try:
                for chunk in r.iter_content(256 * 1024):  # bellekte tutmadan say
                    n += len(chunk)
                    if ctx.cancel_event.is_set():
                        break
            finally:
                r.close()
            secs = time.perf_counter() - t
            used += n
            if n and secs > 0:
                speeds.append(n * 8 / secs / 1e6)
            rep.summary = f"İndiriliyor… {used / 1e6:.0f} MB"
            rep.changed()
        best = max(speeds) if speeds else 0
        sec.add("İndirme", f"{best:.1f} Mbps", level=Level.OK if best >= 25 else Level.WARN if best >= 5 else Level.BAD)
    else:
        speeds = []
        for size in (1_000_000, 3_000_000):
            ctx.check_cancelled()
            payload = b"0" * size
            t = time.perf_counter()
            r = http.post(f"{SPEED}/__up", data=payload, timeout=60)
            secs = time.perf_counter() - t
            used += size
            if r.status_code == 200 and secs > 0:
                speeds.append(size * 8 / secs / 1e6)
        best = max(speeds) if speeds else 0
        sec.add("Yükleme", f"{best:.1f} Mbps", level=Level.OK if best >= 10 else Level.WARN if best >= 2 else Level.BAD)
    sec.add("Kullanılan veri", f"{used / 1e6:.1f} MB")
    rep.summary = None


def speed_mb(value: str) -> int:
    try:
        n = int(value.strip() or 10)
    except ValueError as e:
        raise ValueError("5 ile 100 arası MB") from e
    if not 5 <= n <= 100:
        raise ValueError("5 ile 100 arası MB")
    return n


ACTIVE = ("Bu araç hedefe doğrudan bağlantı açar. Yalnızca sahibi olduğunuz ya da test için yazılı izin "
          "aldığınız sistemlerde kullanın; izinsiz tarama birçok ülkede suçtur (TCK 243).")

register(Tool("portscan", "Port Tarama", f"Tek hostta {len(TOP_PORTS)} yaygın TCP portu, servis ve banner", "LAN",
              "Ağ Araçları", [
                  Action("scan", "Tara", (Field("target", "Hedef (tek IP veya domain)", "192.168.1.1", "url",
                                                scan_target),), _portscan, consent=ACTIVE)]))
register(Tool("lan", "Yerel Ağ Keşfi", "Wi-Fi ağınızdaki cihazlar ve türleri", "ROUTER", "Ağ Araçları", [
    Action("scan", "Tara", (), _lan,
           consent="Bağlı olduğunuz Wi-Fi ağındaki tüm adreslere bağlantı denemesi yapılır. Yalnızca kendi "
                   "ağınızda ya da yöneticisi olduğunuz ağlarda kullanın.")]))
register(Tool("speedtest", "Hız Testi", "Gecikme, titreşim, indirme/yükleme hızı", "SPEED", "Ağ Araçları", [
    Action("download", "İndirme", (Field("mb", "Test boyutu (MB)", "10", "number", speed_mb, optional=True),),
           _speed, consent="Hız testi mobil veride yaklaşık 15-110 MB veri harcar. Devam edilsin mi?"),
    Action("upload", "Yükleme", (), lambda c, r, v: _speed(c, r, v, upload=True),
           consent="Yükleme testi yaklaşık 4 MB veri gönderir. Devam edilsin mi?")]))
