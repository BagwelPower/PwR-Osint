"""Web sitesi istihbaratı: teknoloji, iletişim bilgileri, analytics kimlikleri,
herkese açık dosyalar, urlscan geçmişi ve Google dork'ları."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html import unescape
from urllib.parse import quote_plus, urljoin, urlsplit

from ..core import validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

MAX_PAGE = 2_000_000  # bayt; dev sayfalar telefonu yormasın


def parse_url(value: str) -> str:
    v = value.strip()
    if "://" not in v:
        v = "https://" + v
    parts = urlsplit(v)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Yalnızca http/https adresleri")
    host = validate.host(parts.hostname or "")
    return f"{parts.scheme}://{host}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")


@dataclass
class Page:
    url: str
    status: int
    headers: dict[str, str]
    cookies: list[str]
    html: str
    history: list[tuple[int, str]]


def fetch_page(ctx: Context, url: str) -> Page:
    resp = ctx.http.get(url, allow_redirects=True, stream=True)
    try:
        chunks, size = [], 0
        for chunk in resp.iter_content(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_PAGE:
                break
    finally:
        resp.close()
    html = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
    return Page(resp.url, resp.status_code, {k.lower(): v for k, v in resp.headers.items()},
                list(resp.cookies.keys()), html, [(r.status_code, r.url) for r in resp.history])


# ---------------------------------------------------------------- teknoloji

# (ad, kategori, [(nerede, regex)]) — nerede: html | header:<ad> | cookie
SIGNATURES: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("WordPress", "CMS", [("html", r"/wp-content/|/wp-includes/"), ("html", r'generator" content="WordPress')]),
    ("Joomla", "CMS", [("html", r'generator" content="Joomla'), ("html", r"/media/jui/")]),
    ("Drupal", "CMS", [("html", r"Drupal\.settings|/sites/default/files/"), ("header:x-generator", r"Drupal")]),
    ("Ghost", "CMS", [("html", r'generator" content="Ghost')]),
    ("Wix", "Site kurucu", [("html", r"static\.wixstatic\.com|wix-bolt")]),
    ("Squarespace", "Site kurucu", [("html", r"static1\.squarespace\.com")]),
    ("Webflow", "Site kurucu", [("html", r"webflow\.js|data-wf-site")]),
    ("Shopify", "E-ticaret", [("html", r"cdn\.shopify\.com"), ("header:x-shopid", r".")]),
    ("WooCommerce", "E-ticaret", [("html", r"woocommerce")]),
    ("Magento", "E-ticaret", [("html", r"Mage\.Cookies|/static/version\d+/frontend/")]),
    ("PrestaShop", "E-ticaret", [("html", r"prestashop"), ("cookie", r"^PrestaShop")]),
    ("OpenCart", "E-ticaret", [("html", r"catalog/view/theme")]),
    ("ikas", "E-ticaret (TR)", [("html", r"cdn\.myikas\.com|ikas\.com")]),
    ("Ticimax", "E-ticaret (TR)", [("html", r"ticimax")]),
    ("IdeaSoft", "E-ticaret (TR)", [("html", r"ideasoft|myideasoft")]),
    ("T-Soft", "E-ticaret (TR)", [("html", r"tsoft|T-Soft")]),
    ("Next.js", "JS framework", [("html", r"/_next/static/|__NEXT_DATA__"), ("header:x-powered-by", r"Next\.js")]),
    ("Nuxt", "JS framework", [("html", r"/_nuxt/|__NUXT__")]),
    ("Gatsby", "JS framework", [("html", r"___gatsby")]),
    ("React", "JS kütüphanesi", [("html", r"data-reactroot|react(?:\.production)?(?:\.min)?\.js")]),
    ("Vue.js", "JS kütüphanesi", [("html", r"vue(?:\.min)?\.js|data-v-[0-9a-f]{8}")]),
    ("Angular", "JS framework", [("html", r"ng-version=")]),
    ("Svelte", "JS framework", [("html", r"svelte-[a-z0-9]{5,}")]),
    ("jQuery", "JS kütüphanesi", [("html", r"jquery[.-]?(\d[\d.]*)?(\.min)?\.js")]),
    ("Bootstrap", "CSS", [("html", r"bootstrap(\.min)?\.(css|js)")]),
    ("Tailwind CSS", "CSS", [("html", r"tailwind")]),
    ("Hugo", "Statik site", [("html", r'generator" content="Hugo')]),
    ("Jekyll", "Statik site", [("html", r'generator" content="Jekyll')]),
    ("Laravel", "Backend", [("cookie", r"laravel_session|XSRF-TOKEN")]),
    ("Django", "Backend", [("cookie", r"^csrftoken$|^sessionid$")]),
    ("Ruby on Rails", "Backend", [("cookie", r"_session$"), ("header:x-runtime", r".")]),
    ("PHP", "Dil", [("header:x-powered-by", r"PHP"), ("cookie", r"^PHPSESSID$")]),
    ("ASP.NET", "Backend", [("header:x-aspnet-version", r"."), ("header:x-powered-by", r"ASP\.NET"),
                            ("cookie", r"ASP\.NET_SessionId|\.ASPXAUTH")]),
    ("Express", "Backend", [("header:x-powered-by", r"Express")]),
    ("Java", "Dil", [("cookie", r"^JSESSIONID$")]),
    ("nginx", "Web sunucu", [("header:server", r"nginx")]),
    ("Apache", "Web sunucu", [("header:server", r"Apache")]),
    ("LiteSpeed", "Web sunucu", [("header:server", r"LiteSpeed")]),
    ("Microsoft IIS", "Web sunucu", [("header:server", r"IIS")]),
    ("Caddy", "Web sunucu", [("header:server", r"Caddy")]),
    ("Cloudflare", "CDN / koruma", [("header:server", r"cloudflare"), ("header:cf-ray", r".")]),
    ("Akamai", "CDN", [("header:x-akamai-transformed", r"."), ("header:server", r"AkamaiGHost")]),
    ("Fastly", "CDN", [("header:x-served-by", r"cache-"), ("header:fastly-debug-digest", r".")]),
    ("Amazon CloudFront", "CDN", [("header:x-amz-cf-id", r"."), ("header:via", r"CloudFront")]),
    ("Vercel", "Barındırma", [("header:server", r"Vercel"), ("header:x-vercel-id", r".")]),
    ("Netlify", "Barındırma", [("header:server", r"Netlify"), ("header:x-nf-request-id", r".")]),
    ("GitHub Pages", "Barındırma", [("header:server", r"GitHub\.com")]),
    ("Varnish", "Önbellek", [("header:via", r"varnish"), ("header:x-varnish", r".")]),
    ("Google Analytics", "Analitik", [("html", r"google-analytics\.com|gtag\(|googletagmanager\.com/gtag")]),
    ("Google Tag Manager", "Analitik", [("html", r"googletagmanager\.com/gtm\.js")]),
    ("Yandex Metrica", "Analitik", [("html", r"mc\.yandex\.ru")]),
    ("Hotjar", "Analitik", [("html", r"static\.hotjar\.com")]),
    ("Meta Pixel", "Reklam", [("html", r"connect\.facebook\.net/[^\"']*fbevents")]),
    ("Google AdSense", "Reklam", [("html", r"pagead2\.googlesyndication\.com")]),
    ("reCAPTCHA", "Güvenlik", [("html", r"google\.com/recaptcha|grecaptcha")]),
    ("hCaptcha", "Güvenlik", [("html", r"hcaptcha\.com")]),
    ("Cloudflare Turnstile", "Güvenlik", [("html", r"challenges\.cloudflare\.com/turnstile")]),
    ("Font Awesome", "Font", [("html", r"font-?awesome")]),
    ("Google Fonts", "Font", [("html", r"fonts\.googleapis\.com")]),
]


def detect_tech(page: Page) -> list[tuple[str, str, str]]:
    """(teknoloji, kategori, kanıt) listesi."""
    found = []
    for name, cat, rules in SIGNATURES:
        for where, pattern in rules:
            if where == "html":
                m = re.search(pattern, page.html, re.I)
                evidence = "sayfa kaynağı" if m else ""
            elif where == "cookie":
                hit = next((c for c in page.cookies if re.search(pattern, c, re.I)), None)
                m, evidence = hit, f"çerez: {hit}" if hit else ""
            else:
                hname = where.split(":", 1)[1]
                val = page.headers.get(hname, "")
                m = re.search(pattern, val, re.I) if val else None
                evidence = f"{hname}: {val[:40]}" if m else ""
            if m:
                found.append((name, cat, evidence))
                break
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', page.html, re.I)
    if gen and not any(gen.group(1).lower().startswith(f[0].lower()) for f in found):
        found.append((unescape(gen.group(1)), "Generator", "meta generator"))
    return found


# ---------------------------------------------------------------- çıkarım

SOCIAL = {
    "X / Twitter": r"(?:twitter|x)\.com/(?!share|intent|home|search|hashtag)([A-Za-z0-9_]{2,15})",
    "Instagram": r"instagram\.com/(?!p/|reel/|explore/)([A-Za-z0-9_.]{2,30})",
    "Facebook": r"facebook\.com/(?!sharer|share|dialog|plugins|tr/)([A-Za-z0-9.\-]{2,60})",
    "LinkedIn": r"linkedin\.com/(?:company|in)/([A-Za-z0-9\-_%]{2,100})",
    "YouTube": r"youtube\.com/(?:@|c/|channel/|user/)([A-Za-z0-9_\-]{2,60})",
    "TikTok": r"tiktok\.com/@([A-Za-z0-9_.]{2,30})",
    "Telegram": r"(?:t\.me|telegram\.me)/(?!share)([A-Za-z0-9_]{4,32})",
    "WhatsApp": r"(?:wa\.me|api\.whatsapp\.com/send\?phone=)/?(\+?\d{8,15})",
    "GitHub": r"github\.com/([A-Za-z0-9\-]{2,39})(?:[/\"'?#]|$)",
    "Pinterest": r"pinterest\.(?:com|com\.tr)/([A-Za-z0-9_]{3,30})",
}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
_IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".css", ".js")
_PHONE_TR = re.compile(r"(?:\+90|0090|\b0)[\s(.-]*([2-5]\d{2})[\s).-]*(\d{3})[\s.-]*(\d{2})[\s.-]*(\d{2})\b")
ANALYTICS = {
    "Google Analytics (UA)": r"\bUA-\d{4,10}-\d{1,4}\b",
    "Google Analytics 4": r"\bG-[A-Z0-9]{8,12}\b",
    "Google Tag Manager": r"\bGTM-[A-Z0-9]{5,8}\b",
    "Google AdSense": r"\bca-pub-\d{10,20}\b",
    "Meta Pixel": r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})",
    "Yandex Metrica": r"ym\(\s*(\d{6,10})\s*,\s*['\"]init",
}


def extract(html: str) -> dict[str, list[str]]:
    text = unescape(html)
    emails = sorted({e.lower() for e in _EMAIL.findall(text)
                     if not e.lower().endswith(_IMG_EXT) and "example" not in e.lower()
                     and not re.search(r"@\d+x\.", e)})
    phones = sorted({f"+90 {a} {b} {c} {d}" for a, b, c, d in _PHONE_TR.findall(text)})
    social: list[str] = []
    for name, pattern in SOCIAL.items():
        for handle in dict.fromkeys(re.findall(pattern, text, re.I)):
            social.append(f"{name}|{handle.rstrip('.')}")
    ids: list[str] = []
    for name, pattern in ANALYTICS.items():
        for m in dict.fromkeys(re.findall(pattern, text)):
            ids.append(f"{name}|{m}")
    return {"emails": emails[:30], "phones": phones[:20], "social": social[:40], "ids": ids}


SOCIAL_URL = {
    "X / Twitter": "https://x.com/{}", "Instagram": "https://www.instagram.com/{}/",
    "Facebook": "https://www.facebook.com/{}", "LinkedIn": "https://www.linkedin.com/search/results/all/?keywords={}",
    "YouTube": "https://www.youtube.com/@{}", "TikTok": "https://www.tiktok.com/@{}",
    "Telegram": "https://t.me/{}", "WhatsApp": "https://wa.me/{}", "GitHub": "https://github.com/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
}


def _site(ctx: Context, rep: Report, v: dict) -> None:
    url: str = v["url"]
    page = fetch_page(ctx, url)
    sec = rep.section("Sayfa")
    if page.history:
        chain = " → ".join(f"{code} {u}" for code, u in page.history)
        sec.add("Yönlendirme", f"{chain} → {page.status} {page.url}", level=Level.INFO)
    sec.add("Son adres", page.url, url=page.url)
    sec.add("HTTP durumu", page.status, level=Level.OK if page.status < 400 else Level.WARN)
    if m := re.search(r"<title[^>]*>(.*?)</title>", page.html, re.I | re.S):
        sec.add("Başlık", unescape(" ".join(m.group(1).split()))[:200])
    for label, pattern in (("Açıklama", r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)'),
                           ("Dil", r'<html[^>]+lang=["\']([^"\']+)')):
        if m := re.search(pattern, page.html, re.I):
            sec.add(label, unescape(m.group(1))[:300])
    rep.changed()

    tech = detect_tech(page)
    t = rep.section(f"Teknolojiler ({len(tech)})")
    for name, cat, evidence in tech:
        t.add(name, f"{cat} · {evidence}")
    if not tech:
        t.add("Tespit edilemedi", level=Level.MUTED)
    rep.changed()

    found = extract(page.html)
    if found["emails"] or found["phones"]:
        c = rep.section("İletişim bilgileri")
        for e in found["emails"]:
            c.add("E-posta", e, level=Level.OK)
        for p in found["phones"]:
            c.add("Telefon", p, url=f"tel:{p.replace(' ', '')}", level=Level.OK)
    if found["social"]:
        s = rep.section("Sosyal medya hesapları")
        for entry in found["social"]:
            name, handle = entry.split("|", 1)
            s.add(name, handle, url=SOCIAL_URL[name].format(handle))
    if found["ids"]:
        a = rep.section("Takip kimlikleri",
                        note="Aynı kimliği kullanan siteler genellikle aynı kişiye/şirkete aittir.")
        for entry in found["ids"]:
            name, ident = entry.split("|", 1)
            a.add(name, ident, url=f"https://publicwww.com/websites/%22{ident}%22/", level=Level.WARN)
    links = rep.section("Dış araçlar")
    host = urlsplit(page.url).hostname or ""
    links.link("BuiltWith", f"https://builtwith.com/{host}")
    links.link("Wappalyzer", f"https://www.wappalyzer.com/lookup/{host}/")
    links.link("urlscan.io", f"https://urlscan.io/search/#domain:{host}")


# ---------------------------------------------------------------- herkese açık dosyalar

def parse_robots(text: str) -> tuple[list[str], list[str]]:
    disallow, sitemaps = [], []
    for line in text.splitlines():
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.split("#")[0].strip()
        if key == "disallow" and val:
            disallow.append(val)
        elif key == "sitemap" and val:
            sitemaps.append(val)
    return list(dict.fromkeys(disallow)), list(dict.fromkeys(sitemaps))


def _files(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    base = f"https://{domain}"

    def get(path):
        try:
            r = ctx.http.get(urljoin(base, path), allow_redirects=True)
        except OsintError:
            return None
        ctype = r.headers.get("content-type", "")
        return r.text if r.status_code == 200 and "html" not in ctype.lower() else None

    robots = get("/robots.txt")
    sec = rep.section("robots.txt")
    sitemaps: list[str] = []
    if robots is None:
        sec.add("Durum", "Yok", level=Level.MUTED)
    else:
        disallow, sitemaps = parse_robots(robots)
        sec.add("Durum", f"Var · {len(disallow)} gizlenen yol", url=f"{base}/robots.txt", level=Level.OK)
        sec.note = "Disallow satırları sahibinin arama motorlarından saklamak istediği yerleri gösterir."
        for path in disallow[:60]:
            sec.add(path, url=urljoin(base, path) if "*" not in path else None)
    rep.changed()

    sm = rep.section("Sitemap")
    sm_url = sitemaps[0] if sitemaps else f"{base}/sitemap.xml"
    try:
        r = ctx.http.get(sm_url)
        body = r.text if r.status_code == 200 else ""
    except OsintError:
        body = ""
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)
    if locs:
        nested = sum(1 for _ in re.finditer(r"<sitemap>", body))
        sm.add("Adres", sm_url, url=sm_url, level=Level.OK)
        sm.add("Kayıt", f"{len(locs)} URL" + (f" ({nested} alt sitemap)" if nested else ""))
        for loc in locs[:15]:
            sm.add(loc, url=loc)
    else:
        sm.add("Durum", "Bulunamadı", level=Level.MUTED)
    rep.changed()

    sec_txt = get("/.well-known/security.txt") or get("/security.txt")
    st = rep.section("security.txt")
    if sec_txt:
        for line in sec_txt.splitlines():
            key, _, val = line.partition(":")
            if key.strip().lower() in ("contact", "policy", "hiring", "expires", "encryption"):
                st.add(key.strip(), val.strip(), url=val.strip() if val.strip().startswith("http") else None,
                       level=Level.OK)
    else:
        st.add("Durum", "Yok — güvenlik açığı bildirim adresi tanımlanmamış", level=Level.MUTED)
    humans = get("/humans.txt")
    if humans:
        h = rep.section("humans.txt", note="Site ekibi hakkında bilgi içerebilir.")
        for line in [ln.strip() for ln in humans.splitlines() if ln.strip()][:20]:
            h.add(line[:150])


# ---------------------------------------------------------------- urlscan

def _urlscan(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    data = ctx.http.json("https://urlscan.io/api/v1/search/", params={"q": f"domain:{domain}", "size": 50})
    results = [r for r in (data or {}).get("results") or [] if isinstance(r, dict)]
    rep.summary = f"urlscan.io'da {(data or {}).get('total', len(results))} tarama bulundu."
    if not results:
        rep.section("Sonuç").add("Durum", "Bu domain için urlscan.io'da tarama yok", level=Level.MUTED)
        rep.section("Dış araçlar").link("Yeni tarama başlat", f"https://urlscan.io/")
        return
    ips = sorted({(r.get("page") or {}).get("ip", "") for r in results} - {""})
    countries = sorted({(r.get("page") or {}).get("country", "") for r in results} - {""})
    servers = sorted({(r.get("page") or {}).get("server", "") for r in results} - {""})
    summ = rep.section("Özet")
    summ.add("Görülen IP'ler", ", ".join(ips[:15]))
    if countries:
        summ.add("Ülkeler", ", ".join(countries))
    if servers:
        summ.add("Sunucular", ", ".join(servers[:8]))
    scans = rep.section("Son taramalar")
    for r in results[:25]:
        page = r.get("page") or {}
        when = (r.get("task") or {}).get("time", "")[:10]
        verdict = (r.get("verdicts") or {}).get("overall", {}) if r.get("verdicts") else {}
        level = Level.BAD if verdict.get("malicious") else Level.INFO
        scans.add(page.get("url", "")[:100], f"{when} · {page.get('ip', '')}",
                  url=r.get("result", "").replace("/api/v1/result/", "/result/"), level=level)


# ---------------------------------------------------------------- dork'lar

def dorks(domain: str) -> list[tuple[str, str]]:
    d = f"site:{domain}"
    return [
        ("İndekslenen tüm sayfalar", d),
        ("Belgeler", f"{d} (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:ppt OR ext:pptx)"),
        ("Veri / yapılandırma dosyaları", f"{d} (ext:sql OR ext:env OR ext:log OR ext:bak OR ext:conf OR ext:ini OR ext:json OR ext:xml)"),
        ("Dizin listeleme", f'{d} intitle:"index of"'),
        ("Giriş / yönetim panelleri", f"{d} (inurl:login OR inurl:admin OR inurl:panel OR inurl:wp-admin OR inurl:signin)"),
        ("Hata mesajları", f'{d} ("sql syntax" OR "warning: mysql" OR "stack trace" OR "fatal error")'),
        ("Alt domainler", f"site:*.{domain} -site:www.{domain}"),
        ("E-posta adresleri", f'"@{domain}" -site:{domain}'),
        ("Paste siteleri", f'"{domain}" (site:pastebin.com OR site:ghostbin.com OR site:justpaste.it OR site:rentry.co)'),
        ("Kod depoları", f'"{domain}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)'),
        ("Bulut depolama", f'"{domain}" (site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com OR site:drive.google.com)'),
        ("Trello / Notion / dokümanlar", f'"{domain}" (site:trello.com OR site:notion.site OR site:docs.google.com)'),
    ]


def _dorks(ctx: Context, rep: Report, v: dict) -> None:
    sec = rep.section("Google dork'ları", note="Linke dokunarak aramayı açın. Bulduklarınızı izinsiz kullanmayın.")
    for title, query in dorks(v["domain"]):
        sec.add(title, query, url=f"https://www.google.com/search?q={quote_plus(query)}")
    other = rep.section("Diğer arama motorları")
    q = quote_plus(f"site:{v['domain']}")
    other.link("Bing", f"https://www.bing.com/search?q={q}")
    other.link("DuckDuckGo", f"https://duckduckgo.com/?q={q}")
    other.link("Yandex", f"https://yandex.com.tr/search/?text={q}")


# ---------------------------------------------------------------- kayıt

DOMAIN = Field("domain", "Domain", "ornek.com", "url", validate.domain)

register(Tool("site", "Site Analizi", "Teknoloji, iletişim, sosyal hesaplar, takip kimlikleri", "WEB", "Web", [
    Action("analyze", "Analiz", (Field("url", "Adres", "ornek.com", "url", parse_url),), _site),
    Action("files", "robots / sitemap", (DOMAIN,), _files)]))
register(Tool("urlscan", "urlscan.io", "Geçmiş taramalar, IP'ler, zararlı işaretleri", "IMAGE_SEARCH", "Web", [
    Action("search", "Ara", (DOMAIN,), _urlscan)]))
register(Tool("dorks", "Google Dork", "Domain için hazır 12 dork", "MANAGE_SEARCH", "Web", [
    Action("generate", "Üret", (DOMAIN,), _dorks)]))
