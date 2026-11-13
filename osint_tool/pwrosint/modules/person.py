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


SITES: tuple[Site, ...] = (
    Site("GitHub", "https://github.com/{}", "https://api.github.com/users/{}"),
    Site("GitLab", "https://gitlab.com/{}", "https://gitlab.com/api/v4/users?username={}", absent="[]"),
    Site("Reddit", "https://www.reddit.com/user/{}", "https://www.reddit.com/user/{}/about.json"),
    Site("Keybase", "https://keybase.io/{}",
         "https://keybase.io/_/api/1.0/user/lookup.json?usernames={}", absent='"them":[null]'),
    Site("Docker Hub", "https://hub.docker.com/u/{}", "https://hub.docker.com/v2/users/{}/"),
    Site("PyPI", "https://pypi.org/user/{}/"),
    Site("npm", "https://www.npmjs.com/~{}", "https://registry.npmjs.org/-/user/org.couchdb.user:{}"),
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
    Site("Codeberg", "https://codeberg.org/{}", "https://codeberg.org/api/v1/users/{}"),
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
        mail.add("DNS", str(e), level=Level.MUTED)
    rep.changed()

    md5 = hashlib.md5(addr.lower().encode()).hexdigest()
    sha256 = hashlib.sha256(addr.lower().encode()).hexdigest()
    grav = rep.section("Gravatar")
    try:
        has = ctx.http.get(f"https://www.gravatar.com/avatar/{sha256}?d=404&s=200").status_code == 200
    except OsintError:
        has = None
    if has:
        grav.add("Profil fotoğrafı", f"https://www.gravatar.com/avatar/{sha256}?s=400",
                 url=f"https://www.gravatar.com/avatar/{sha256}?s=400", level=Level.OK)
        grav.link("Profil", f"https://gravatar.com/{sha256}")
    else:
        grav.add("Profil fotoğrafı", "Yok" if has is False else "Kontrol edilemedi", level=Level.MUTED)
    grav.add("MD5", md5)
    grav.add("SHA-256", sha256)

    links = rep.section("Araştırma linkleri")
    q = quote_plus(f'"{addr}"')
    links.link("Google", f"https://www.google.com/search?q={q}")
    links.link("Have I Been Pwned", f"https://haveibeenpwned.com/account/{quote(addr)}")
    links.link("Epieos", "https://epieos.com/")
    links.link("Aynı kullanıcı adı (GitHub)", f"https://github.com/{quote(local)}")
    rep.summary = "Sızıntı kontrolü için 'Have I Been Pwned' aracını kullanın."


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


def _hunter(ctx: Context, rep: Report, v: dict) -> None:
    key = ctx.require("hunter_api_key", "Hunter.io")
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

def _name(ctx: Context, rep: Report, v: dict) -> None:
    name: str = v["name"]
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
                  Action("scan", "Tara", (Field("username", "Kullanıcı adı", "ornek_kullanici",
                                                 parse=validate.username),), _username)]))
register(Tool("email", "E-posta", "MX/SPF/DMARC, Gravatar, permutator",
              "ALTERNATE_EMAIL", "Kişi", [
                  Action("analyze", "Analiz", (Field("email", "E-posta", "kisi@ornek.com", "email",
                                                     validate.email),), _email),
                  Action("permutate", "Permutator", (
                      Field("first", "Ad", "Ahmet", "name", lambda s: validate.text(s, 1)),
                      Field("last", "Soyad", "Yılmaz", "name", lambda s: validate.text(s, 1)),
                      DOMAIN), _permutator),
                  Action("hunter", "Hunter.io", (DOMAIN,), _hunter, needs_key="hunter_api_key")]))
register(Tool("phone", "Telefon", "Geçerlilik, operatör, bölge, formatlar",
              "PHONE_ANDROID", "Kişi", [
                  Action("analyze", "Analiz", (Field("phone", "Telefon", "+90 5xx xxx xx xx", "phone",
                                                     lambda s: validate.text(s, 4)),), _phone)]))
register(Tool("name", "İsim / Soyisim", "Dork'lar ve arama linkleri", "BADGE", "Kişi", [
    Action("search", "Ara", (Field("name", "Ad Soyad", "Ad Soyad", "name", validate.text),), _name)]))
