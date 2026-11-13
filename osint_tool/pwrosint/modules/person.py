"""Kişi odaklı araçlar: kullanıcı adı, e-posta, telefon, isim."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, quote_plus

from ..core import dns, validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.http import BROWSER_UA
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

# ---------------------------------------------------------------- kullanıcı adı


@dataclass(frozen=True)
class Site:
    name: str
    profile: str                     # kullanıcıya gösterilen profil adresi
    check: Optional[str] = None      # sorgulanan adres (yoksa profile); None+manual → link
    absent: Optional[str] = None     # bu metin varsa profil YOK
    present: Optional[str] = None    # bu metin yoksa profil YOK
    manual: bool = False             # otomatik doğrulanamıyor (giriş/bot koruması)
    fallback: Optional[str] = None   # site 403/429 ile engellerse sorulacak yedek kaynak
    fallback_present: Optional[str] = None  # yedek yanıtta bu metin varsa profil VAR


SITES: tuple[Site, ...] = (
    Site("GitHub", "https://github.com/{}", "https://api.github.com/users/{}"),
    Site("GitLab", "https://gitlab.com/{}", "https://gitlab.com/api/v4/users?username={}", absent="[]"),
    Site("Reddit", "https://www.reddit.com/user/{}", "https://www.reddit.com/user/{}/about.json",
         fallback="https://arctic-shift.photon-reddit.com/api/comments/search?author={}&limit=1",
         fallback_present='"author"'),
    Site("Keybase", "https://keybase.io/{}",
         "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", absent='"them":[null]'),
    Site("Docker Hub", "https://hub.docker.com/u/{}", "https://hub.docker.com/v2/users/{}/"),
    Site("PyPI", "https://pypi.org/user/{}/"),
    Site("npm", "https://www.npmjs.com/~{}",
         "https://registry.npmjs.org/-/v1/search?text=maintainer:{}&size=1", absent='"total":0'),
    Site("Hacker News", "https://news.ycombinator.com/user?id={}",
         "https://hacker-news.firebaseio.com/v0/user/{}.json", absent="null"),
    Site("Dev.to", "https://dev.to/{}", "https://dev.to/api/users/by_username?url={}"),
    Site("Codeforces", "https://codeforces.com/profile/{}",
         "https://codeforces.com/api/user.info?handles={}", present='"status":"OK"'),
    Site("Chess.com", "https://www.chess.com/member/{}", "https://api.chess.com/pub/player/{}"),
    Site("Lichess", "https://lichess.org/@/{}", "https://lichess.org/api/user/{}"),
    Site("Steam", "https://steamcommunity.com/id/{}",
         absent="The specified profile could not be found"),
    Site("Telegram", "https://t.me/{}", present="tgme_page_title"),
    Site("Gravatar", "https://gravatar.com/{}", "https://en.gravatar.com/{}.json"),
    Site("SoundCloud", "https://soundcloud.com/{}"),
    Site("Vimeo", "https://vimeo.com/{}"),
    Site("Kaggle", "https://www.kaggle.com/{}"),
    Site("Replit", "https://replit.com/@{}"),
    Site("Bitbucket", "https://bitbucket.org/{}/", "https://api.bitbucket.org/2.0/workspaces/{}"),
    Site("Hugging Face", "https://huggingface.co/{}", "https://huggingface.co/api/users/{}/overview"),
    Site("Mastodon (social)", "https://mastodon.social/@{}",
         "https://mastodon.social/api/v1/accounts/lookup?acct={}"),
    Site("Bluesky", "https://bsky.app/profile/{}.bsky.social",
         "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social"),
    # Giriş zorunlu / agresif bot koruması: güvenilir otomatik kontrol yok.
    Site("Instagram", "https://www.instagram.com/{}/", manual=True),
    Site("X / Twitter", "https://x.com/{}", manual=True),
    Site("TikTok", "https://www.tiktok.com/@{}", manual=True),
    Site("Facebook", "https://www.facebook.com/{}", manual=True),
    Site("LinkedIn", "https://www.linkedin.com/in/{}", manual=True),
    Site("YouTube", "https://www.youtube.com/@{}", manual=True),
    Site("Twitch", "https://www.twitch.tv/{}", manual=True),
    Site("Pinterest", "https://www.pinterest.com/{}/", manual=True),
    Site("Medium", "https://medium.com/@{}", manual=True),
    Site("Spotify", "https://open.spotify.com/user/{}", manual=True),
    Site("Codeberg", "https://codeberg.org/{}", manual=True),
)

FOUND, MISSING, UNKNOWN = "found", "missing", "unknown"


def check_site(ctx: Context, site: Site, user: str) -> tuple[str, str]:
    """(durum, açıklama) döndürür."""
    url = (site.check or site.profile).format(quote(user, safe=""))
    try:
        resp = ctx.http.get(url, headers={"User-Agent": BROWSER_UA}, allow_redirects=True)
    except OsintError as e:
        return UNKNOWN, str(e).split(": ", 1)[-1]
    code = resp.status_code
    if code in (404, 410):
        return MISSING, "404"
    if code in (403, 429) and site.fallback:
        try:
            fb = ctx.http.get(site.fallback.format(quote(user, safe="")))
            if fb.status_code == 200 and site.fallback_present and site.fallback_present in fb.text:
                return FOUND, ""
        except OsintError:
            pass
        return UNKNOWN, f"HTTP {code} (site engelledi)"
    if code != 200:
        return UNKNOWN, f"HTTP {code}"
    body = resp.text
    if site.absent is not None and site.absent in body:
        return MISSING, "profil yok"
    if site.present is not None and site.present not in body:
        return MISSING, "profil yok"
    return FOUND, ""


def _username(ctx: Context, rep: Report, v: dict) -> None:
    user = v["username"]
    auto = [s for s in SITES if not s.manual]
    results = ctx.parallel(lambda s: (s, *check_site(ctx, s, user)), auto)

    found = rep.section("Bulunan profiller")
    unknown = rep.section("Doğrulanamadı", note="Site bot koruması uyguladı veya erişilemedi.")
    missing = rep.section("Bulunamadı")
    for site, status, why in results:
        url = site.profile.format(user)
        if status == FOUND:
            found.add(site.name, url, url=url, level=Level.OK)
        elif status == MISSING:
            missing.add(site.name, why, level=Level.MUTED)
        else:
            unknown.add(site.name, why, url=url, level=Level.WARN)
    manual = rep.section("Manuel kontrol", note="Bu siteler giriş istediği için otomatik doğrulanamaz.")
    for s in SITES:
        if s.manual:
            manual.link(s.name, s.profile.format(user))
    for sec in (found, unknown, missing):
        if not sec.items:
            rep.sections.remove(sec)
    rep.summary = (f"{len(auto)} sitede tarandı: {len(found.items)} bulundu, "
                   f"{len(missing.items)} yok, {len(unknown.items)} belirsiz")


# ---------------------------------------------------------------- WhatsMyName (derin tarama)

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
WMN_MAX_AGE = 7 * 24 * 3600
WMN_CATEGORIES = {
    "social": "Sosyal medya", "gaming": "Oyun", "tech": "Teknoloji", "hobby": "Hobi", "coding": "Yazılım",
    "misc": "Diğer", "finance": "Finans", "business": "İş", "music": "Müzik", "shopping": "Alışveriş",
    "images": "Görsel", "blog": "Blog", "art": "Sanat", "dating": "Arkadaşlık", "video": "Video",
    "political": "Siyaset", "news": "Haber", "archived": "Arşiv", "health": "Sağlık",
}


def load_wmn(ctx: Context) -> tuple[list[dict], str]:
    """WhatsMyName veri setini önbellekten ya da GitHub'dan yükler: (siteler, kaynak açıklaması)."""
    import json as _json
    import os
    import time
    from ..core.config import config_path

    cache = config_path().with_name("wmn-data.json")
    cached = None
    try:
        if cache.exists():
            cached = _json.loads(cache.read_text(encoding="utf-8"))
            if time.time() - cache.stat().st_mtime < WMN_MAX_AGE:
                return _wmn_sites(cached), "önbellek"
    except (OSError, ValueError):
        cached = None
    try:
        data = ctx.http.json(WMN_URL, timeout=max(20, ctx.settings.timeout))
        sites = _wmn_sites(data)
        if not sites:
            raise OsintError("WhatsMyName: boş veri")
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_text(_json.dumps(data), encoding="utf-8")
            os.replace(tmp, cache)
        except OSError:
            pass
        return sites, "güncel"
    except OsintError:
        if cached:
            return _wmn_sites(cached), "eski önbellek"
        raise


def _wmn_sites(data) -> list[dict]:
    sites = (data or {}).get("sites") if isinstance(data, dict) else None
    out = []
    for s in sites or []:
        if not isinstance(s, dict) or s.get("valid") is False or not s.get("uri_check"):
            continue
        if "{account}" not in str(s["uri_check"]) + str(s.get("post_body", "")):
            continue
        if s.get("cat") == "xx NSFW xx":
            continue
        out.append(s)
    return out


def wmn_check(ctx: Context, site: dict, user: str, timeout: int = 8) -> tuple[str, str]:
    name = user
    for ch in site.get("strip_bad_char") or "":
        name = name.replace(ch, "")
    acct = quote(name, safe="")
    url = site["uri_check"].replace("{account}", acct)
    headers = {"User-Agent": BROWSER_UA, **(site.get("headers") or {})}
    try:
        if site.get("post_body"):
            resp = ctx.http.post(url, data=site["post_body"].replace("{account}", name), headers=headers,
                                 timeout=timeout, allow_redirects=True)
        else:
            resp = ctx.http.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    except OsintError as e:
        return UNKNOWN, str(e).split(": ", 1)[-1]
    body = resp.text if len(resp.content) < 3_000_000 else resp.text[:3_000_000]
    if resp.status_code == site.get("e_code") and site.get("e_string", "") in body:
        return FOUND, ""
    if resp.status_code == site.get("m_code") and site.get("m_string", "") in body:
        return MISSING, ""
    if resp.status_code == site.get("m_code") and site.get("m_code") != site.get("e_code"):
        return MISSING, ""
    return UNKNOWN, f"HTTP {resp.status_code}"


def _username_deep(ctx: Context, rep: Report, v: dict) -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    user = v["username"]
    sites, origin = load_wmn(ctx)
    rep.source("WhatsMyName", True, f"{len(sites)} site ({origin})")
    found_sec = rep.section("Bulunan profiller")
    counts = {FOUND: 0, MISSING: 0, UNKNOWN: 0}
    by_cat: dict[str, int] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=max(16, ctx.settings.max_workers * 2)) as pool:
        futures = {pool.submit(wmn_check, ctx, s, user): s for s in sites}
        for fut in as_completed(futures):
            if ctx.cancel_event.is_set():
                for f in futures:
                    f.cancel()
                rep.notice(f"Tarama iptal edildi ({done}/{len(sites)} site kontrol edilmişti).")
                break
            site = futures[fut]
            status, why = fut.result()
            counts[status] += 1
            done += 1
            if status == FOUND:
                pretty = (site.get("uri_pretty") or site["uri_check"]).replace("{account}", user)
                cat = WMN_CATEGORIES.get(site.get("cat", ""), site.get("cat", ""))
                by_cat[cat] = by_cat.get(cat, 0) + 1
                found_sec.add(site["name"], f"{cat} · {pretty}", url=pretty, level=Level.OK)
                rep.summary = f"{done}/{len(sites)} site kontrol edildi · {counts[FOUND]} profil bulundu"
                rep.changed()
    found_sec.items.sort(key=lambda i: i.label.lower())
    if not found_sec.items:
        found_sec.add("Hiçbir sitede profil bulunamadı", level=Level.MUTED)
    if by_cat:
        cats = rep.section("Kategorilere göre")
        for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
            cats.add(cat, f"{n} profil")
    rep.summary = (f"{done} site kontrol edildi: {counts[FOUND]} profil bulundu, "
                   f"{counts[MISSING]} sitede yok, {counts[UNKNOWN]} site yanıt vermedi/engelledi.")
    rep.notice("Site listesi: WhatsMyName projesi (CC BY-SA 4.0, github.com/WebBreacher/WhatsMyName). "
               "Bulunan profilleri açarak doğrulayın; aynı ad farklı kişilere ait olabilir.")


# ---------------------------------------------------------------- e-posta

FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.de",
    "yandex.com", "yandex.ru", "mail.ru", "zoho.com", "hotmail.com.tr", "windowslive.com",
}
DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "throwawaymail.com", "yopmail.com", "trashmail.com", "getnada.com", "sharklasers.com",
    "dispostable.com", "maildrop.cc", "mohmal.com", "emailondeck.com", "fakeinbox.com",
}


def _email(ctx: Context, rep: Report, v: dict) -> None:
    addr: str = v["email"]
    local, domain = addr.rsplit("@", 1)
    basic = rep.section("Temel bilgiler")
    basic.add("Kullanıcı kısmı", local)
    basic.add("Domain", domain)
    if domain in DISPOSABLE:
        basic.add("Tür", "Geçici (disposable) e-posta — şüpheli", level=Level.BAD)
    elif domain in FREE_PROVIDERS:
        basic.add("Tür", "Ücretsiz e-posta sağlayıcısı")
    else:
        basic.add("Tür", "Kurumsal / özel domain", level=Level.OK)
    rep.changed()

    mail = rep.section("Posta altyapısı")
    try:
        _mail_checks(ctx, mail, domain)
    except OsintError as e:
        rep.source("DNS", False, str(e))
        mail.add("Durum", "DNS sorgulanamadı; posta altyapısı kontrol edilemedi", level=Level.MUTED)
    rep.changed()

    md5 = hashlib.md5(addr.lower().encode()).hexdigest()
    sha256 = hashlib.sha256(addr.lower().encode()).hexdigest()
    _gravatar(ctx, rep, sha256, md5)
    rep.changed()

    # Sızıntı özeti (anahtarsız XposedOrNot)
    leak = rep.section("Sızıntı özeti")
    try:
        data = ctx.http.json(f"https://api.xposedornot.com/v1/check-email/{quote(addr)}", ok=(200, 404))
        names = sorted({str(x) for row in (data or {}).get("breaches") or [] for x in
                        (row if isinstance(row, list) else [row])})
        rep.source("XposedOrNot", True)
        if names:
            leak.add("Bulunduğu sızıntılar", f"{len(names)}: " + ", ".join(names[:25]), level=Level.BAD)
            leak.note = "Ayrıntılar (sızan veri türleri, tarihler) için Sızıntı Kontrolü aracını kullanın."
        else:
            leak.add("Durum", "Bilinen sızıntılarda yok", level=Level.OK)
    except OsintError as e:
        rep.source("XposedOrNot", False, str(e).split(": ", 1)[-1])
        leak.add("Durum", "Sızıntı veritabanına ulaşılamadı", level=Level.MUTED)
    rep.changed()

    if domain not in FREE_PROVIDERS and domain not in DISPOSABLE:
        from .network import _rdap_domain
        _rdap_domain(ctx, rep, domain)

    links = rep.section("Araştırma linkleri")
    q = quote_plus(f'"{addr}"')
    links.link("Google", f"https://www.google.com/search?q={q}")
    links.link("Have I Been Pwned", f"https://haveibeenpwned.com/account/{quote(addr)}")
    links.link("Epieos", "https://epieos.com/")
    links.link("Aynı kullanıcı adı (GitHub)", f"https://github.com/{quote(local)}")


def _gravatar(ctx: Context, rep: Report, sha256: str, md5: str) -> None:
    grav = rep.section("Gravatar profili")
    reached = True
    try:
        prof = ctx.http.json(f"https://api.gravatar.com/v3/profiles/{sha256}", ok=(200, 404))
        rep.source("Gravatar", True)
    except OsintError as e:
        rep.source("Gravatar", False, str(e).split(": ", 1)[-1])
        prof, reached = None, False
    if prof and (prof.get("display_name") or prof.get("profile_url")):
        for label, key in (("Görünen ad", "display_name"), ("Konum", "location"), ("Meslek", "job_title"),
                           ("Şirket", "company"), ("Hakkında", "description"), ("Zamirler", "pronouns")):
            if prof.get(key):
                grav.add(label, prof[key], level=Level.OK if key == "display_name" else Level.INFO)
        if prof.get("profile_url"):
            grav.add("Profil", prof["profile_url"], url=prof["profile_url"])
        if prof.get("avatar_url"):
            grav.add("Fotoğraf", prof["avatar_url"], url=prof["avatar_url"] + "?s=400")
        accounts = [a for a in prof.get("verified_accounts") or [] if isinstance(a, dict)]
        if accounts:
            acc = rep.section(f"Gravatar'da doğrulanmış hesaplar ({len(accounts)})")
            for a in accounts:
                acc.add(a.get("service_label") or a.get("service_type", "?"), a.get("url", ""), url=a.get("url"),
                        level=Level.WARN)
        for link in [x for x in prof.get("links") or [] if isinstance(x, dict)][:10]:
            grav.add(link.get("label") or "Link", link.get("url", ""), url=link.get("url"))
    elif reached:
        grav.add("Profil", "Bu adrese bağlı Gravatar profili yok", level=Level.MUTED)
    else:
        grav.add("Profil", "Gravatar'a ulaşılamadı; profil kontrol edilemedi", level=Level.MUTED)
    grav.add("MD5", md5)
    grav.add("SHA-256", sha256)


def _mail_checks(ctx: Context, mail, domain: str) -> None:
    status, mx = dns.query(ctx, domain, "MX")
    if status == "NXDOMAIN":
        mail.add("Domain", "Mevcut değil (NXDOMAIN) — adres geçersiz", level=Level.BAD)
    elif not mx:
        mail.add("MX", "Kayıt yok — bu domain e-posta alamaz", level=Level.BAD)
    else:
        for rec in sorted(mx, key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 0):
            mail.add("MX", rec.rstrip("."), level=Level.OK)
        mail.add("Sağlayıcı", _mail_provider(" ".join(mx)))
        spf = [t for t in dns.resolve(ctx, domain, "TXT") if "v=spf1" in t.lower()]
        dmarc = [t for t in dns.resolve(ctx, f"_dmarc.{domain}", "TXT") if "v=dmarc1" in t.lower()]
        mail.add("SPF", spf[0].strip('"') if spf else "Yok — sahte gönderime açık",
                 level=Level.OK if spf else Level.WARN)
        mail.add("DMARC", dmarc[0].strip('"') if dmarc else "Yok",
                 level=Level.OK if dmarc else Level.WARN)



def _mail_provider(mx: str) -> str:
    mx = mx.lower()
    for key, name in (("google", "Google Workspace / Gmail"), ("outlook", "Microsoft 365"),
                      ("yandex", "Yandex"), ("zoho", "Zoho"), ("protonmail", "Proton"),
                      ("mimecast", "Mimecast"), ("pphosted", "Proofpoint"), ("icloud", "Apple iCloud"),
                      ("yahoodns", "Yahoo")):
        if key in mx:
            return name
    return "Kendi sunucusu / bilinmiyor"


def permutations(first: str, last: str, domain: str) -> list[str]:
    tr = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosuCGIOSU")
    f = "".join(first.translate(tr).lower().split())
    l = "".join(last.translate(tr).lower().split())
    patterns = ["{f}", "{l}", "{f}{l}", "{f}.{l}", "{f}_{l}", "{f}-{l}", "{fi}{l}", "{fi}.{l}",
                "{f}{li}", "{f}.{li}", "{l}{f}", "{l}.{f}", "{l}{fi}", "{fi}{li}"]
    seen: dict[str, None] = {}
    for p in patterns:
        seen[p.format(f=f, l=l, fi=f[:1], li=l[:1]) + "@" + domain] = None
    return list(seen)


def _permutator(ctx: Context, rep: Report, v: dict) -> None:
    perms = permutations(v["first"], v["last"], v["domain"])
    sec = rep.section("Olası adresler")
    for p in perms:
        sec.add(p)
    status, mx = dns.query(ctx, v["domain"], "MX")
    rep.summary = (f"{len(perms)} olasılık. " +
                   ("Domain e-posta alıyor." if mx else "Uyarı: domainin MX kaydı yok."))


CONTACT_PATHS = ("/", "/iletisim", "/iletisim/", "/contact", "/contact/", "/contact-us", "/hakkimizda",
                 "/about", "/kvkk", "/impressum", "/kunye", "/ekibimiz", "/team")


def site_emails(ctx: Context, rep: Report, domain: str) -> None:
    """Anahtarsız yedek: domainin kendi sayfalarındaki e-posta adresleri."""
    from .web import extract
    found: dict[str, str] = {}
    phones: set[str] = set()
    pages = 0

    def fetch(path):
        try:
            r = ctx.http.get(f"https://{domain}{path}", allow_redirects=True)
            return path, r.text if r.status_code == 200 else ""
        except OsintError:
            return path, ""

    for path, html in ctx.parallel(fetch, CONTACT_PATHS):
        if not html:
            continue
        pages += 1
        ex = extract(html)
        for e in ex["emails"]:
            found.setdefault(e, path)
        phones.update(ex["phones"])
    rep.source(f"{domain} sayfaları", pages > 0, f"{pages} sayfa tarandı")
    if not pages:
        raise OsintError(f"{domain} sitesine ulaşılamadı; sayfalar taranamadı")
    own = {e: p for e, p in found.items() if e.endswith("@" + domain) or e.endswith("." + domain)}
    other = {e: p for e, p in found.items() if e not in own}
    sec = rep.section(f"Sitede yayınlanan adresler ({len(own)})")
    for e, p in sorted(own.items()):
        sec.add(e, f"sayfa: {p}", level=Level.OK)
    if not own:
        sec.add("Domaine ait adres bulunamadı", level=Level.MUTED)
    if other:
        o = rep.section("Sayfalarda geçen diğer adresler")
        for e, p in sorted(other.items()):
            o.add(e, f"sayfa: {p}")
    if phones:
        t = rep.section("Telefonlar")
        for ph in sorted(phones):
            t.add(ph, url=f"tel:{ph.replace(' ', '')}")
    local = sorted({e.split("@")[0] for e in own})
    if local:
        rep.section("Adres şablonu ipucu").add("Kullanılan yerel kısımlar", ", ".join(local),
                                               level=Level.INFO)


def _hunter(ctx: Context, rep: Report, v: dict) -> None:
    if not ctx.settings.hunter_api_key:
        rep.notice("Hunter.io anahtarı yok; domainin kendi sayfalarındaki adresler tarandı.")
        site_emails(ctx, rep, v["domain"])
        return
    key = ctx.settings.hunter_api_key
    data = (ctx.http.json("https://api.hunter.io/v2/domain-search",
                          params={"domain": v["domain"], "api_key": key, "limit": 50}) or {}).get("data")
    if not isinstance(data, dict):
        raise OsintError("Hunter.io: beklenmeyen yanıt")
    info = rep.section("Domain")
    info.add("Organizasyon", data.get("organization") or "—")
    info.add("Adres şablonu", data.get("pattern") or "—")
    emails = data.get("emails") or []
    sec = rep.section(f"E-postalar ({len(emails)})")
    for e in emails:
        who = " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x)
        extra = ", ".join(x for x in (who, e.get("position"), f"%{e.get('confidence')}") if x)
        sec.add(e.get("value", ""), extra, level=Level.OK)


# ---------------------------------------------------------------- telefon

def _phone(ctx: Context, rep: Report, v: dict) -> None:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    from phonenumbers import PhoneNumberFormat as F, PhoneNumberType as T

    raw: str = v["phone"]
    try:
        num = phonenumbers.parse(raw, None if raw.startswith("+") else "TR")
    except phonenumbers.NumberParseException as e:
        raise OsintError(f"Numara çözümlenemedi: {e}") from e

    valid = phonenumbers.is_valid_number(num)
    types = {T.MOBILE: "Mobil", T.FIXED_LINE: "Sabit hat", T.FIXED_LINE_OR_MOBILE: "Sabit/Mobil",
             T.TOLL_FREE: "Ücretsiz (0800)", T.PREMIUM_RATE: "Ücretli (0900)", T.VOIP: "VoIP",
             T.SHARED_COST: "Paylaşımlı ücret", T.PERSONAL_NUMBER: "Kişisel numara",
             T.UAN: "Kurumsal (UAN)", T.PAGER: "Çağrı cihazı"}

    sec = rep.section("Numara")
    sec.add("Geçerli", "Evet" if valid else "Hayır — numara planına uymuyor",
            level=Level.OK if valid else Level.BAD)
    sec.add("Ülke", f"{geocoder.country_name_for_number(num, 'tr') or '?'} "
                    f"({phonenumbers.region_code_for_number(num) or '?'})")
    if region := geocoder.description_for_number(num, "tr"):
        sec.add("Bölge", region)
    sec.add("Tür", types.get(phonenumbers.number_type(num), "Bilinmiyor"))
    if op := carrier.name_for_number(num, "tr"):
        sec.add("Operatör (tahsis)", op, level=Level.INFO)
        sec.note = "Operatör, numara bloğunun ilk tahsisidir; numara taşınmış olabilir."
    if zones := timezone.time_zones_for_number(num):
        sec.add("Saat dilimi", ", ".join(z for z in zones if z != "Etc/Unknown") or "?")

    e164 = phonenumbers.format_number(num, F.E164)
    fmt = rep.section("Formatlar")
    fmt.add("E.164", e164)
    fmt.add("Uluslararası", phonenumbers.format_number(num, F.INTERNATIONAL))
    fmt.add("Ulusal", phonenumbers.format_number(num, F.NATIONAL))

    digits = e164.lstrip("+")
    links = rep.section("Araştırma linkleri")
    links.link("WhatsApp", f"https://wa.me/{digits}")
    links.link("Telegram", f"https://t.me/+{digits}")
    links.link("Truecaller", f"https://www.truecaller.com/search/{(phonenumbers.region_code_for_number(num) or 'tr').lower()}/{digits}")
    links.link("Sync.ME", f"https://sync.me/search/?number={digits}")
    links.link("Google", "https://www.google.com/search?q=" +
               quote_plus(f'"{e164}" OR "{phonenumbers.format_number(num, F.NATIONAL)}"'))


# ---------------------------------------------------------------- isim

def _name_github(ctx: Context, rep: Report, name: str) -> None:
    from .social import _gh
    res = _gh(ctx, f"search/users?q={quote(f'fullname:{chr(34)}{name}{chr(34)}')}&per_page=8") or {}
    users = [u for u in res.get("items") or [] if isinstance(u, dict)]
    rep.source("GitHub", True, f"{res.get('total_count', len(users))} eşleşme")
    if not users:
        return
    sec = rep.section(f"GitHub kullanıcıları ({res.get('total_count', len(users))})")
    details = ctx.parallel(lambda u: _safe_gh_user(ctx, u["login"]), users[:6])
    for u, d in zip(users, details):
        extra = " · ".join(x for x in ((d or {}).get("name"), (d or {}).get("location"), (d or {}).get("company")) if x)
        sec.add(u["login"], extra, url=u.get("html_url"), level=Level.OK)


def _safe_gh_user(ctx: Context, login: str):
    from .social import _gh
    try:
        return _gh(ctx, f"users/{quote(login)}")
    except OsintError:
        return None


def _name_openalex(ctx: Context, rep: Report, name: str) -> None:
    data = ctx.http.json("https://api.openalex.org/authors", params={"search": name, "per_page": 10},
                         timeout=max(20, ctx.settings.timeout))
    results = [r for r in (data or {}).get("results") or [] if isinstance(r, dict)]
    rep.source("OpenAlex", True, f"{len(results)} yazar")
    if not results:
        return
    sec = rep.section("Akademik yazarlar (OpenAlex)")
    for r in results:
        inst = ", ".join(i.get("display_name", "") for i in (r.get("last_known_institutions") or [])
                         if isinstance(i, dict))[:120]
        topics = ", ".join(t.get("display_name", "") for t in (r.get("topics") or [])[:2] if isinstance(t, dict))
        info = " · ".join(x for x in (inst, f"{r.get('works_count', 0)} yayın, {r.get('cited_by_count', 0)} atıf",
                                      topics) if x)
        url = r.get("orcid") or str(r.get("id", "")).replace("https://openalex.org/", "https://openalex.org/authors/")
        sec.add(r.get("display_name", "?"), info, url=url)


def _name_orcid(ctx: Context, rep: Report, name: str) -> None:
    parts = name.split()
    if len(parts) < 2:
        return
    given, family = " ".join(parts[:-1]), parts[-1]
    q = f"given-names:({given}) AND family-name:({family})"
    data = ctx.http.json("https://pub.orcid.org/v3.0/expanded-search/", params={"q": q, "rows": 10},
                         headers={"Accept": "application/json"}, timeout=max(20, ctx.settings.timeout))
    rows = [r for r in (data or {}).get("expanded-result") or [] if isinstance(r, dict)]
    rep.source("ORCID", True, f"{(data or {}).get('num-found', len(rows))} kayıt")
    if not rows:
        return
    sec = rep.section(f"ORCID kayıtları ({(data or {}).get('num-found', len(rows))})")
    for r in rows:
        full = f"{r.get('given-names', '')} {r.get('family-names', '')}".strip()
        inst = ", ".join(str(x) for x in (r.get("institution-name") or [])[:3])
        sec.add(full or r.get("orcid-id", "?"), inst, url=f"https://orcid.org/{r.get('orcid-id')}")


def _name_wikidata(ctx: Context, rep: Report, name: str) -> None:
    data = ctx.http.json("https://www.wikidata.org/w/api.php", params={
        "action": "wbsearchentities", "search": name, "language": "tr", "uselang": "tr", "format": "json",
        "type": "item", "limit": 8}, headers={"User-Agent": ctx.settings.user_agent})
    hits = [h for h in (data or {}).get("search") or [] if isinstance(h, dict)]
    rep.source("Wikidata", True, f"{len(hits)} kayıt")
    if not hits:
        return
    sec = rep.section("Tanınmış kişiler / kayıtlar (Wikidata)")
    for h in hits:
        sec.add(h.get("label", "?"), h.get("description", ""), url=h.get("concepturi"))


def _name(ctx: Context, rep: Report, v: dict) -> None:
    name: str = v["name"]

    def safe(fn):
        try:
            fn(ctx, rep, name)
        except OsintError as e:
            rep.source(fn.__name__.replace("_name_", "").title(), False, str(e).split(": ", 1)[-1])

    ctx.parallel(safe, (_name_github, _name_openalex, _name_orcid, _name_wikidata))
    if not any(ok for _, ok, _ in rep.sources):
        rep.notice("Çevrimiçi kaynaklara ulaşılamadı; yalnızca arama linkleri gösteriliyor.")
    elif not rep.sections:
        rep.section("Sonuç").add("Kayıtlı kaynaklarda eşleşme yok", level=Level.MUTED)
    rep.changed()
    _name_links(rep, name)


def _name_links(rep: Report, name: str) -> None:
    q = quote_plus(f'"{name}"')
    parts = name.split()
    first, last = parts[0], parts[-1] if len(parts) > 1 else ""

    g = "https://www.google.com/search?q="
    dorks = rep.section("Google dork'ları")
    dorks.link("Genel", g + q)
    dorks.link("Belgeler (PDF/DOC)", g + q + quote_plus(" (filetype:pdf OR filetype:docx OR filetype:doc)"))
    dorks.link("Tablolar (XLS/CSV)", g + q + quote_plus(" (filetype:xlsx OR filetype:xls OR filetype:csv)"))
    dorks.link("CV / Özgeçmiş", g + q + quote_plus(" (cv OR özgeçmiş OR resume)"))
    dorks.link("Sosyal medya", g + q + quote_plus(
        " (site:linkedin.com OR site:instagram.com OR site:x.com OR site:facebook.com)"))
    dorks.link("Görseller", f"https://www.google.com/search?tbm=isch&q={q}")
    dorks.link("Haberler", f"https://news.google.com/search?q={q}&hl=tr")

    social = rep.section("Platform aramaları")
    social.link("LinkedIn", "https://www.linkedin.com/search/results/people/?keywords=" + quote_plus(name))
    social.link("Facebook", "https://www.facebook.com/search/people/?q=" + quote_plus(name))
    social.link("X / Twitter", f"https://x.com/search?q={quote_plus(name)}&f=user")
    social.link("GitHub", f"https://github.com/search?type=users&q={quote_plus(name)}")

    public = rep.section("Akademik / kamu kaynakları")
    public.link("Google Akademik", f"https://scholar.google.com/scholar?q={q}")
    public.link("DergiPark", f"https://dergipark.org.tr/tr/search?q={quote_plus(name)}&section=articles")
    public.link("YÖK Akademik", "https://akademik.yok.gov.tr/AkademikArama/view/searchResultviewListAuthor.jsp")
    public.link("Resmî Gazete", g + q + quote_plus(" site:resmigazete.gov.tr"))
    if last:
        f, l = first.lower(), last.lower()
        cands = rep.section("Kullanıcı adı adayları", note="Kullanıcı Adı aracında deneyebilirsiniz.")
        for c in dict.fromkeys((f + l, f + "." + l, f + "_" + l, f[0] + l, l + f)):
            cands.add(c)


# ---------------------------------------------------------------- kayıt

DOMAIN = Field("domain", "Domain", "ornek.com", "url", validate.domain)

register(Tool("username", "Kullanıcı Adı", f"{len(SITES)} platformda profil taraması",
              "PERSON_SEARCH", "Kişi", [
                  Action("scan", "Hızlı tara", (Field("username", "Kullanıcı adı", "ornek_kullanici",
                                                       parse=validate.username),), _username),
                  Action("deep", "Derin tara (600+ site)", (Field("username", "Kullanıcı adı", "ornek_kullanici",
                                                                  parse=validate.username),), _username_deep)]))
register(Tool("email", "E-posta", "MX/SPF/DMARC, Gravatar, permutator",
              "ALTERNATE_EMAIL", "Kişi", [
                  Action("analyze", "Analiz", (Field("email", "E-posta", "kisi@ornek.com", "email",
                                                     validate.email),), _email),
                  Action("permutate", "Permutator", (
                      Field("first", "Ad", "Ahmet", "name", lambda s: validate.text(s, 1)),
                      Field("last", "Soyad", "Yılmaz", "name", lambda s: validate.text(s, 1)),
                      DOMAIN), _permutator),
                  Action("hunter", "Domain e-postaları", (DOMAIN,), _hunter, better_with="hunter_api_key")]))
register(Tool("phone", "Telefon", "Geçerlilik, operatör, bölge, formatlar",
              "PHONE_ANDROID", "Kişi", [
                  Action("analyze", "Analiz", (Field("phone", "Telefon", "+90 5xx xxx xx xx", "phone",
                                                     lambda s: validate.text(s, 4)),), _phone)]))
register(Tool("name", "İsim / Soyisim", "Dork'lar ve arama linkleri", "BADGE", "Kişi", [
    Action("search", "Ara", (Field("name", "Ad Soyad", "Ad Soyad", "name", validate.text),), _name)]))
