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
                val = f"ort {st.get('avg', 0):.1f} ms · kayıp %{st.get('loss', 0)}"
                level = Level.WARN if st.get("loss") else Level.INFO
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
