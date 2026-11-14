"""Sosyal medya profil analizi: GitHub, Reddit, Telegram, Fediverse."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from html import unescape
from urllib.parse import quote

from ..core import validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

# ---------------------------------------------------------------- GitHub


def _gh(ctx: Context, path: str, ok=(200,)):
    headers = {"Accept": "application/vnd.github+json"}
    if ctx.settings.github_token:
        headers["Authorization"] = f"Bearer {ctx.settings.github_token}"
    resp = ctx.http.get(f"https://api.github.com/{path}", headers=headers)
    if resp.status_code in (403, 429) and resp.headers.get("X-RateLimit-Remaining") == "0":
        raise OsintError("GitHub istek limiti doldu (token olmadan saatte 60). Ayarlar'a GitHub token ekleyin.")
    if resp.status_code == 401:
        raise OsintError("GitHub token geçersiz")
    if resp.status_code not in ok:
        raise OsintError(f"api.github.com: HTTP {resp.status_code}")
    from ..core.http import parse_json
    return parse_json(resp, list if path.split("?")[0].endswith(("repos", "orgs", "public")) else dict)


def commit_identities(events: list[dict]) -> Counter:
    """Herkese açık push olaylarındaki commit yazarları: (isim, e-posta) → sayı."""
    seen: Counter = Counter()
    for ev in events:
        if ev.get("type") != "PushEvent":
            continue
        for c in (ev.get("payload") or {}).get("commits") or []:
            author = c.get("author") or {}
            email = (author.get("email") or "").lower()
            if email:
                seen[(author.get("name") or "", email)] += 1
    return seen


def _github(ctx: Context, rep: Report, v: dict) -> None:
    user = v["username"]
    u = _gh(ctx, f"users/{quote(user)}", ok=(200, 404))
    if not u or u.get("message") == "Not Found":
        rep.section("Sonuç").add("Durum", "Böyle bir GitHub kullanıcısı yok", level=Level.MUTED)
        return
    sec = rep.section("Profil")
    for label, key in (("Ad", "name"), ("Şirket", "company"), ("Konum", "location"), ("E-posta", "email"),
                       ("Biyografi", "bio"), ("Twitter", "twitter_username")):
        if u.get(key):
            sec.add(label, u[key], level=Level.OK if key == "email" else Level.INFO)
    if u.get("blog"):
        blog = u["blog"] if u["blog"].startswith("http") else "https://" + u["blog"]
        sec.add("Web sitesi", blog, url=blog)
    sec.add("Hesap türü", "Organizasyon" if u.get("type") == "Organization" else "Kullanıcı")
    sec.add("Oluşturulma", (u.get("created_at") or "")[:10])
    sec.add("Takipçi / takip", f"{u.get('followers', 0)} / {u.get('following', 0)}")
    sec.add("Profil", u.get("html_url", ""), url=u.get("html_url"))
    if u.get("avatar_url"):
        sec.add("Avatar", u["avatar_url"], url=u["avatar_url"])
    rep.changed()

    repos = _gh(ctx, f"users/{quote(user)}/repos?per_page=100&sort=pushed") or []
    own = [r for r in repos if not r.get("fork")]
    stats = rep.section(f"Repolar ({u.get('public_repos', len(repos))})")
    stats.add("Toplam yıldız", sum(r.get("stargazers_count", 0) for r in own))
    langs = Counter(r["language"] for r in own if r.get("language"))
    if langs:
        stats.add("Diller", ", ".join(f"{lang} ({n})" for lang, n in langs.most_common(6)))
    if repos:
        stats.add("Son aktivite", (repos[0].get("pushed_at") or "")[:10])
    for r in sorted(own, key=lambda r: r.get("stargazers_count", 0), reverse=True)[:8]:
        stats.add(r["name"], f"★{r.get('stargazers_count', 0)} · {r.get('description') or ''}"[:120],
                  url=r.get("html_url"))
    rep.changed()

    orgs = _gh(ctx, f"users/{quote(user)}/orgs") or []
    if orgs:
        o = rep.section("Organizasyonlar")
        for org in orgs:
            o.add(org["login"], url=f"https://github.com/{org['login']}")

    events = _gh(ctx, f"users/{quote(user)}/events/public?per_page=100") or []
    ids = commit_identities(events)
    leak = rep.section("Commit kimlikleri",
                       note="Git commit'lerine yazılan isim/e-posta herkese açıktır; gerçek adres sızabilir.")
    for (name, email), n in ids.most_common(10):
        hidden = email.endswith("users.noreply.github.com")
        leak.add(email, f"{name} · {n} commit", level=Level.MUTED if hidden else Level.WARN)
    if not ids:
        leak.add("Son 90 günde herkese açık push yok", level=Level.MUTED)
    if events:
        hours = Counter(datetime.fromisoformat(e["created_at"].replace("Z", "+00:00")).hour for e in events)
        rep.section("Aktivite").add("En aktif saatler (UTC)", _top_hours(hours))


def _top_hours(hours: Counter) -> str:
    return ", ".join(f"{h:02d}:00 ({n})" for h, n in hours.most_common(3))


# ---------------------------------------------------------------- Reddit

REDDIT_HOSTS = ("https://www.reddit.com", "https://old.reddit.com", "https://api.reddit.com")
ARCTIC = "https://arctic-shift.photon-reddit.com/api"


def _reddit_json(ctx: Context, path: str, **params):
    """Reddit bulut IP'lerini sık sık 403 ile engeller; farklı ön yüzleri sırayla dener.
    (veri, engellendi_mi) döndürür."""
    headers = {"User-Agent": ctx.settings.user_agent}
    blocked = False
    for host in REDDIT_HOSTS:
        try:
            resp = ctx.http.get(host + path, headers=headers, params=params or None)
        except OsintError:
            continue
        if resp.status_code == 404:
            return None, False
        if resp.status_code in (403, 429):
            blocked = True
            continue
        if resp.status_code == 200:
            try:
                return resp.json(), False
            except ValueError:
                continue
    return None, blocked


def _arctic(ctx: Context, kind: str, user: str, sort: str = "desc", limit: int = 100) -> list[dict]:
    # Arctic Shift API'si zaman zaman parametre kurallarını değiştiriyor (ör. HTTP 422); reddedilirse
    # daha sade parametrelerle tekrar dener.
    variants = [{"author": user, "limit": limit, "sort": sort},
                {"author": user, "limit": min(limit, 25), "sort": sort},
                {"author": user, "limit": min(limit, 25)}]
    last: OsintError | None = None
    data = None
    for params in variants:
        try:
            data = ctx.http.json(f"{ARCTIC}/{kind}/search", params=params, timeout=max(20, ctx.settings.timeout))
            break
        except OsintError as e:
            last = e
            if "HTTP 4" not in str(e):
                raise
    else:
        raise last  # type: ignore[misc]
    return [x for x in (data or {}).get("data") or [] if isinstance(x, dict) and x.get("created_utc")]


def _reddit(ctx: Context, rep: Report, v: dict) -> None:
    user = v["username"]
    about, blocked = _reddit_json(ctx, f"/user/{quote(user)}/about.json")
    data = (about or {}).get("data")
    items: list[dict] = []
    source = "Reddit"

    if data:
        if data.get("is_suspended"):
            rep.section("Sonuç").add("Durum", "Hesap askıya alınmış", level=Level.WARN)
            return
        sec = rep.section("Profil")
        created = datetime.fromtimestamp(data.get("created_utc", 0), timezone.utc)
        sec.add("Oluşturulma", f"{created:%Y-%m-%d}  ({(datetime.now(timezone.utc) - created).days // 365} yıl)")
        sec.add("Karma (gönderi / yorum)", f"{data.get('link_karma', 0):,} / {data.get('comment_karma', 0):,}")
        flags = [x for x, k in (("doğrulanmış e-posta", "has_verified_email"), ("moderatör", "is_mod"),
                                ("Reddit çalışanı", "is_employee"), ("premium", "is_gold")) if data.get(k)]
        if flags:
            sec.add("Özellikler", ", ".join(flags))
        sec.link("Profil", f"https://www.reddit.com/user/{user}")
        rep.changed()
        for kind in ("comments", "submitted"):
            listing, _ = _reddit_json(ctx, f"/user/{quote(user)}/{kind}.json", limit=100)
            items += [c["data"] for c in (listing or {}).get("data", {}).get("children", [])]
    elif not blocked:
        rep.section("Sonuç").add("Durum", "Böyle bir Reddit kullanıcısı yok", level=Level.MUTED)
        return

    if not items:  # Reddit engelledi ya da liste boş: herkese açık arşive başvur
        try:
            items = _arctic(ctx, "comments", user) + _arctic(ctx, "posts", user)
            source = "Arctic Shift arşivi"
        except OsintError as e:
            if not data:
                raise OsintError(f"Reddit bu ağdan erişimi engelledi ve arşive ulaşılamadı ({e})") from e
        if not data:
            if not items:
                rep.section("Sonuç").add(
                    "Durum", "Reddit erişimi engelledi; arşivde bu kullanıcıya ait gönderi yok", level=Level.MUTED)
                return
            sec = rep.section("Profil", note="Reddit bu ağdan doğrudan erişimi engelledi; "
                                             "veriler herkese açık Arctic Shift arşivinden alındı.")
            try:
                firsts = _arctic(ctx, "comments", user, "asc", 1) + _arctic(ctx, "posts", user, "asc", 1)
            except OsintError:
                firsts = []
            oldest = min(int(i["created_utc"]) for i in firsts + items)
            sec.add("İlk görülen etkinlik", f"{datetime.fromtimestamp(oldest, timezone.utc):%Y-%m-%d}  "
                    f"(hesap en az {(datetime.now(timezone.utc) - datetime.fromtimestamp(oldest, timezone.utc)).days // 365} yaşında)")
            sec.link("Profil", f"https://www.reddit.com/user/{user}")
            rep.changed()

    if not items:
        return
    subs = Counter(i.get("subreddit") for i in items if i.get("subreddit"))
    act = rep.section(f"Aktivite (son {len(items)} gönderi/yorum · {source})")
    act.add("En çok yazdığı subreddit'ler", ", ".join(f"r/{s} ({n})" for s, n in subs.most_common(8)))
    hours = Counter(datetime.fromtimestamp(int(i["created_utc"]), timezone.utc).hour for i in items)
    act.add("En aktif saatler (UTC)", _top_hours(hours))
    act.add("Tahmini saat dilimi", guess_timezone(hours))
    act.note = "Saat dilimi tahmini, uyku saatlerine denk gelen sessiz 6 saatlik pencereye dayanır."
    first = min(int(i["created_utc"]) for i in items)
    act.add("İncelenen aralık", f"{datetime.fromtimestamp(first, timezone.utc):%Y-%m-%d} → bugün")


def guess_timezone(hours: Counter) -> str:
    """En sessiz 6 saatlik pencereyi yerel 02:00-08:00 kabul ederek UTC farkı tahmin eder."""
    if sum(hours.values()) < 20:
        return "Yetersiz veri"
    quietest = min(range(24), key=lambda start: sum(hours.get((start + k) % 24, 0) for k in range(6)))
    offset = (2 - quietest) % 24
    if offset > 12:
        offset -= 24
    return f"UTC{offset:+d} civarı"


# ---------------------------------------------------------------- Telegram

def _meta(html: str, prop: str) -> str:
    m = re.search(rf'<meta[^>]+property="{re.escape(prop)}"[^>]+content="([^"]*)"', html)
    return unescape(m.group(1)).strip() if m else ""


def _telegram(ctx: Context, rep: Report, v: dict) -> None:
    name = v["username"]
    resp = ctx.http.get(f"https://t.me/{quote(name)}")
    html = resp.text
    title = _meta(html, "og:title")
    if resp.status_code not in (200, 404):
        raise OsintError(f"t.me: HTTP {resp.status_code} (erişim engellendi veya limit)")
    if resp.status_code == 404 or "tgme_page_title" not in html:
        rep.section("Sonuç").add("Durum", "Böyle bir Telegram kullanıcısı / kanalı yok", level=Level.MUTED)
        return
    extra = re.search(r'<div class="tgme_page_extra">([^<]+)</div>', html)
    extra_text = unescape(extra.group(1)).strip() if extra else ""
    kind = ("Kanal" if "subscriber" in extra_text else "Grup" if "member" in extra_text
            else "Bot" if name.lower().endswith("bot") else "Kullanıcı")
    sec = rep.section("Profil")
    sec.add("Ad", title, level=Level.OK)
    sec.add("Tür", kind)
    if extra_text:
        sec.add("Bilgi", extra_text)
    if desc := _meta(html, "og:description"):
        sec.add("Açıklama", desc)
    if img := _meta(html, "og:image"):
        sec.add("Profil fotoğrafı", img, url=img)
    sec.link("Profil", f"https://t.me/{name}")
    if kind == "Kanal":
        sec.link("Herkese açık gönderiler", f"https://t.me/s/{name}")


# ---------------------------------------------------------------- Fediverse

def fediverse_handle(value: str) -> tuple[str, str]:
    v = value.strip().lstrip("@")
    if v.count("@") != 1:
        raise ValueError("Format: kullanici@sunucu (ör. ali@mastodon.social)")
    user, host = v.split("@")
    return validate.username(user), validate.domain(host)


def _fediverse(ctx: Context, rep: Report, v: dict) -> None:
    user, host = v["handle"]
    acct = ctx.http.json(f"https://{host}/api/v1/accounts/lookup", params={"acct": user}, ok=(200, 404))
    if not acct or "id" not in acct:
        rep.section("Sonuç").add("Durum", f"{host} üzerinde böyle bir hesap yok", level=Level.MUTED)
        return
    sec = rep.section("Profil")
    sec.add("Görünen ad", acct.get("display_name") or user)
    if note := re.sub(r"<[^>]+>", " ", acct.get("note") or "").strip():
        sec.add("Biyografi", unescape(" ".join(note.split())))
    sec.add("Oluşturulma", (acct.get("created_at") or "")[:10])
    sec.add("Takipçi / takip / gönderi",
            f"{acct.get('followers_count', 0)} / {acct.get('following_count', 0)} / {acct.get('statuses_count', 0)}")
    if acct.get("bot"):
        sec.add("Tür", "Bot", level=Level.WARN)
    sec.add("Profil", acct.get("url", ""), url=acct.get("url"))
    fields = acct.get("fields") or []
    if fields:
        f = rep.section("Profil alanları")
        for fld in fields:
            value = unescape(re.sub(r"<[^>]+>", "", fld.get("value", "")))
            f.add(fld.get("name", ""), value, level=Level.OK if fld.get("verified_at") else Level.INFO)
        f.note = "Yeşil alanlar sunucu tarafından doğrulanmış linklerdir."


# ---------------------------------------------------------------- kayıt

USER = Field("username", "Kullanıcı adı", "ornek_kullanici", parse=validate.username)

register(Tool("github", "GitHub", "Profil, repolar, commit'lerden sızan e-postalar", "CODE", "Sosyal Medya", [
    Action("profile", "Analiz", (USER,), _github)]))
register(Tool("reddit", "Reddit", "Hesap yaşı, subreddit'ler, saat dilimi tahmini", "FORUM", "Sosyal Medya", [
    Action("profile", "Analiz", (USER,), _reddit)]))
register(Tool("telegram", "Telegram", "Kullanıcı, kanal ve grup bilgisi", "SEND", "Sosyal Medya", [
    Action("profile", "Sorgula", (Field("username", "Kullanıcı / kanal adı", "durov", parse=validate.username),),
           _telegram)]))
register(Tool("fediverse", "Mastodon", "Fediverse hesabı ve doğrulanmış linkler", "PUBLIC", "Sosyal Medya", [
    Action("profile", "Sorgula", (Field("handle", "Hesap", "kullanici@mastodon.social", parse=fediverse_handle),),
           _fediverse)]))
