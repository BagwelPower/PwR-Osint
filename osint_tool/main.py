"""PwR Osint — Android / mobil arayüz (Flet).

Terminal sürümündeki modülleri olduğu gibi kullanır: her modülün print()
çıktısı yakalanır, colorama renk kodları çözülür ve telefon ekranında
terminal görünümlü, tıklanabilir linkli bir konsola basılır.

Masaüstünde denemek için:  flet run main.py
Android APK için:          flet build apk
"""

import contextlib
import io
import re
import threading
import time
import traceback

import flet as ft

from config import DEFAULT_CONFIG, load_config, save_config

# ---------------------------------------------------------------- tema
ACCENT = "#00E5FF"
BG = "#0A0E14"
SURFACE = "#121821"
SURFACE_HI = "#1A2230"
MUTED = "#7A8899"
MONO = "monospace"

ANSI_COLORS = {
    30: "#5C6773", 31: "#FF5370", 32: "#C3E88D", 33: "#FFCB6B",
    34: "#82AAFF", 35: "#C792EA", 36: "#89DDFF", 37: "#E6EDF3",
    90: "#7A8899", 91: "#FF7A90", 92: "#D7F7A8", 93: "#FFE08A",
    94: "#A6C4FF", 95: "#DDB4F5", 96: "#B2EBFF", 97: "#FFFFFF",
}
DEFAULT_FG = "#D0D7DE"

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
URL_RE = re.compile(r"https?://[^\s'\"<>)]+")


# ---------------------------------------------------------------- araçlar
def _f(name, label, hint="", kb=ft.KeyboardType.TEXT, password=False):
    return {"name": name, "label": label, "hint": hint, "kb": kb, "password": password}


def _act(label, fields, run):
    return {"label": label, "fields": fields, "run": run}


def _coords(v):
    from osint_modules.advanced import reverse_geocode
    try:
        lat, lon = v["coords"].split(",")
    except ValueError:
        print("\x1b[31mFormat: 41.0082, 28.9784\x1b[0m")
        return
    reverse_geocode(lat.strip(), lon.strip())


def _lazy(module, func, *keys):
    """Modülü ilk kullanımda içe aktarır, alan değerlerini sırayla geçirir."""
    def run(v):
        mod = __import__(f"osint_modules.{module}", fromlist=[func])
        getattr(mod, func)(*[v[k] for k in keys])
    return run


DOMAIN = _f("domain", "Domain", "ornek.com", ft.KeyboardType.URL)
IP = _f("ip", "IP adresi", "8.8.8.8", ft.KeyboardType.NUMBER)

TOOLS = [
    {"id": "username", "title": "Kullanıcı Adı", "sub": "37 platformda profil taraması",
     "icon": ft.Icons.PERSON_SEARCH, "actions": [
        _act("Tara", [_f("u", "Kullanıcı adı", "ornek_kullanici")],
             _lazy("username", "search_username", "u"))]},
    {"id": "email", "title": "E-posta", "sub": "Domain, Gravatar, profil linkleri",
     "icon": ft.Icons.ALTERNATE_EMAIL, "actions": [
        _act("Analiz", [_f("e", "E-posta", "kisi@ornek.com", ft.KeyboardType.EMAIL)],
             _lazy("email", "analyze_email", "e"))]},
    {"id": "phone", "title": "Telefon", "sub": "Ülke, operatör, E.164",
     "icon": ft.Icons.PHONE_ANDROID, "actions": [
        _act("Analiz", [_f("p", "Telefon", "+905xxxxxxxxx", ft.KeyboardType.PHONE)],
             _lazy("phone", "analyze_phone", "p"))]},
    {"id": "name", "title": "İsim / Soyisim", "sub": "Dork'lar ve arama linkleri",
     "icon": ft.Icons.BADGE, "actions": [
        _act("Ara", [_f("n", "Ad Soyad", "Ad Soyad", ft.KeyboardType.NAME)],
             _lazy("name", "search_name", "n"))]},
    {"id": "ip", "title": "IP & Domain", "sub": "Reverse DNS, WHOIS, GeoIP",
     "icon": ft.Icons.LANGUAGE, "actions": [
        _act("Sorgula", [_f("t", "IP veya Domain", "ornek.com", ft.KeyboardType.URL)],
             _lazy("ip_domain", "analyze_ip_domain", "t"))]},
    {"id": "advanced", "title": "Gelişmiş", "sub": "Konum, BSSID, plaka, VIN, arşiv",
     "icon": ft.Icons.TRAVEL_EXPLORE, "actions": [
        _act("Koordinat", [_f("coords", "Koordinat (lat,lon)", "41.0082, 28.9784")], _coords),
        _act("BSSID", [_f("b", "BSSID / MAC", "00:11:22:33:44:55")],
             _lazy("advanced", "bssid_location", "b")),
        _act("Plaka", [_f("pl", "Plaka", "34ABC123")], _lazy("advanced", "plate_lookup", "pl")),
        _act("VIN", [_f("vin", "VIN (17 karakter)", "WVWZZZ1JZXW000001")],
             _lazy("advanced", "vin_lookup", "vin")),
        _act("Wayback", [DOMAIN], _lazy("advanced", "wayback_scan", "domain"))]},
    {"id": "dns", "title": "DNS Kayıtları", "sub": "A, MX, NS, TXT, SOA + DoH",
     "icon": ft.Icons.DNS, "actions": [
        _act("Sorgula", [DOMAIN], _lazy("dns_records", "get_dns_records", "domain"))]},
    {"id": "ssl", "title": "SSL / TLS", "sub": "Sertifika, SAN, geçerlilik",
     "icon": ft.Icons.LOCK, "actions": [
        _act("Analiz", [DOMAIN], _lazy("ssl_cert", "analyze_ssl", "domain"))]},
    {"id": "subdomain", "title": "Subdomain", "sub": "crt.sh, HackerTarget",
     "icon": ft.Icons.ACCOUNT_TREE, "actions": [
        _act("Keşfet", [DOMAIN], _lazy("subdomain", "enumerate_subdomains", "domain"))]},
    {"id": "email_extra", "title": "E-posta Araçları", "sub": "Permutator, Hunter.io",
     "icon": ft.Icons.MARK_EMAIL_READ, "actions": [
        _act("Permutator", [_f("first", "Ad"), _f("last", "Soyad"), DOMAIN],
             _lazy("email_extra", "generate_permutations", "first", "last", "domain")),
        _act("Hunter.io", [DOMAIN], _lazy("email_extra", "hunter_search", "domain"))]},
    {"id": "hibp", "title": "Have I Been Pwned", "sub": "E-posta ve şifre sızıntısı",
     "icon": ft.Icons.GPP_MAYBE, "actions": [
        _act("E-posta", [_f("e", "E-posta", "kisi@ornek.com", ft.KeyboardType.EMAIL)],
             _lazy("hibp", "hibp_check_email", "e")),
        _act("Şifre", [_f("pw", "Şifre", "Sadece hash öneki gönderilir", password=True)],
             _lazy("hibp", "hibp_check_password", "pw"))]},
    {"id": "shodan", "title": "Shodan", "sub": "Host ve arama (API key)",
     "icon": ft.Icons.RADAR, "actions": [
        _act("Host", [IP], _lazy("shodan_api", "shodan_host", "ip")),
        _act("Arama", [_f("q", "Sorgu", "port:22 country:TR")],
             _lazy("shodan_api", "shodan_search", "q"))]},
    {"id": "vt", "title": "VirusTotal", "sub": "Domain / IP itibarı (API key)",
     "icon": ft.Icons.SHIELD, "actions": [
        _act("Domain", [DOMAIN], _lazy("virustotal", "vt_check_domain", "domain")),
        _act("IP", [IP], _lazy("virustotal", "vt_check_ip", "ip"))]},
]
TOOLS_BY_ID = {t["id"]: t for t in TOOLS}

API_FIELDS = [
    ("shodan_api_key", "Shodan"),
    ("virustotal_api_key", "VirusTotal"),
    ("hunter_api_key", "Hunter.io"),
    ("haveibeenpwned_api_key", "Have I Been Pwned"),
    ("securitytrails_api_key", "SecurityTrails"),
    ("censys_api_id", "Censys API ID"),
    ("censys_api_secret", "Censys API Secret"),
    ("whoisxml_api_key", "WhoisXML"),
]

# Modüller stdout'a yazar; redirect_stdout global olduğundan aynı anda tek
# sorgu çalıştırılır.
RUN_LOCK = threading.Lock()


# ---------------------------------------------------------------- konsol
def ansi_to_spans(line):
    """colorama/ANSI kodlu satırı renkli (ve linkli) TextSpan listesine çevirir."""
    spans, color, bold, pos = [], DEFAULT_FG, False, 0

    def emit(text):
        if not text:
            return
        last = 0
        for m in URL_RE.finditer(text):
            if m.start() > last:
                spans.append(_span(text[last:m.start()], color, bold))
            url = m.group(0).rstrip(".,;")
            spans.append(ft.TextSpan(
                url, url=url,
                style=ft.TextStyle(color=ACCENT, decoration=ft.TextDecoration.UNDERLINE,
                                   decoration_color=ACCENT, font_family=MONO)))
            if len(url) < len(m.group(0)):
                spans.append(_span(m.group(0)[len(url):], color, bold))
            last = m.end()
        if last < len(text):
            spans.append(_span(text[last:], color, bold))

    for m in ANSI_RE.finditer(line):
        emit(line[pos:m.start()])
        pos = m.end()
        for code in [int(c) for c in (m.group(1) or "0").split(";") if c]:
            if code == 0:
                color, bold = DEFAULT_FG, False
            elif code == 1:
                bold = True
            elif code == 22:
                bold = False
            elif code == 39:
                color = DEFAULT_FG
            elif code in ANSI_COLORS:
                color = ANSI_COLORS[code]
    emit(line[pos:])
    return spans


def _span(text, color, bold):
    return ft.TextSpan(text, style=ft.TextStyle(
        color=color, weight=ft.FontWeight.BOLD if bold else None, font_family=MONO))


class LineStream(io.TextIOBase):
    """print() çıktısını satır satır geri çağırıma ileten akış."""

    def __init__(self, on_line):
        self._buf, self._on_line = "", on_line

    def writable(self):
        return True

    def write(self, s):
        self._buf += s
        *lines, self._buf = self._buf.split("\n")
        for line in lines:
            self._on_line(line)
        return len(s)

    def flush_rest(self):
        if self._buf:
            self._on_line(self._buf)
            self._buf = ""


# ---------------------------------------------------------------- uygulama
def main(page: ft.Page):
    page.title = "PwR Osint"
    page.bgcolor = BG
    page.theme_mode = ft.ThemeMode.DARK
    page.dark_theme = page.theme = ft.Theme(
        color_scheme_seed=ACCENT,
        color_scheme=ft.ColorScheme(primary=ACCENT, surface=SURFACE, on_primary=BG),
    )
    cfg = load_config()
    launcher = ft.UrlLauncher()
    clipboard = ft.Clipboard()

    def toast(msg):
        page.show_dialog(ft.SnackBar(ft.Text(msg), duration=2000))

    # ------------------------------------------------ ana ekran
    def tool_card(tool):
        return ft.Container(
            bgcolor=SURFACE, border_radius=16, padding=14, ink=True,
            border=ft.Border.all(1, SURFACE_HI),
            on_click=lambda e, t=tool["id"]: page.run_task(page.push_route, f"/tool/{t}"),
            content=ft.Column(spacing=6, controls=[
                ft.Container(
                    bgcolor=ft.Colors.with_opacity(0.12, ACCENT), border_radius=12,
                    padding=8, content=ft.Icon(tool["icon"], color=ACCENT, size=24)),
                ft.Text(tool["title"], weight=ft.FontWeight.BOLD, size=15,
                        max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(tool["sub"], size=12, color=MUTED, max_lines=2,
                        overflow=ft.TextOverflow.ELLIPSIS),
            ]))

    def home_view():
        header = ft.Container(
            padding=ft.Padding.only(left=4, right=4, top=8, bottom=12),
            content=ft.Column(spacing=2, controls=[
                ft.Text(spans=[
                    ft.TextSpan("PwR", ft.TextStyle(color=ACCENT, weight=ft.FontWeight.BOLD)),
                    ft.TextSpan(" Osint", ft.TextStyle(weight=ft.FontWeight.BOLD)),
                ], size=30, font_family=MONO),
                ft.Text("> open source intelligence framework_", color=MUTED,
                        size=12, font_family=MONO),
            ]))
        grid = ft.GridView(
            expand=True, max_extent=220, child_aspect_ratio=1.3,
            spacing=12, run_spacing=12, controls=[tool_card(t) for t in TOOLS])
        return ft.View(
            route="/", bgcolor=BG, padding=16,
            appbar=ft.AppBar(
                title=ft.Text("PwR Osint", font_family=MONO), bgcolor=BG,
                actions=[ft.IconButton(ft.Icons.SETTINGS, tooltip="API anahtarları",
                                       on_click=lambda e: page.run_task(page.push_route, "/settings"))]),
            controls=[ft.SafeArea(expand=True, content=ft.Column(
                expand=True, controls=[header, grid]))])

    # ------------------------------------------------ araç ekranı
    def tool_view(tool):
        state = {"action": 0, "running": False}
        fields_col = ft.Column(spacing=10, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        inputs = {}
        console = ft.ListView(expand=True, spacing=1, auto_scroll=True, padding=12)
        status = ft.Text("Hazır", size=12, color=MUTED, font_family=MONO)
        progress = ft.ProgressBar(visible=False, color=ACCENT, bgcolor=SURFACE_HI)
        plain_lines = []

        def build_fields():
            fields_col.controls.clear()
            inputs.clear()
            for fd in tool["actions"][state["action"]]["fields"]:
                tf = ft.TextField(
                    label=fd["label"], hint_text=fd["hint"], keyboard_type=fd["kb"],
                    password=fd["password"], can_reveal_password=fd["password"],
                    border_radius=12, filled=True, fill_color=SURFACE, dense=True,
                    border_color=SURFACE_HI, focused_border_color=ACCENT,
                    text_style=ft.TextStyle(font_family=MONO),
                    autocorrect=False, enable_suggestions=False,
                    capitalization=ft.TextCapitalization.NONE,
                    on_submit=lambda e: run())
                inputs[fd["name"]] = tf
                fields_col.controls.append(tf)

        def on_action_change(e):
            state["action"] = int(e.control.selected[0])
            build_fields()
            page.update()

        pending = []
        last_flush = [0.0]

        def add_line(line):
            plain_lines.append(ANSI_RE.sub("", line))
            pending.append(ft.Text(spans=ansi_to_spans(line) or [ft.TextSpan(" ")],
                                   size=12.5, selectable=True))
            now = time.monotonic()
            if now - last_flush[0] > 0.15:
                flush()

        def flush():
            last_flush[0] = time.monotonic()
            if pending:
                console.controls.extend(pending)
                pending.clear()
            page.update()

        def worker(action, values):
            stream = LineStream(add_line)
            started = time.monotonic()
            with RUN_LOCK:
                try:
                    with contextlib.redirect_stdout(stream):
                        action["run"](values)
                except Exception:
                    stream.flush_rest()
                    for ln in traceback.format_exc().splitlines():
                        add_line("\x1b[31m" + ln)
                finally:
                    stream.flush_rest()
            state["running"] = False
            progress.visible = False
            run_btn.disabled = False
            status.value = f"Bitti · {len(plain_lines)} satır · {time.monotonic() - started:.1f} sn"
            flush()

        def run():
            if state["running"]:
                return
            values = {k: (tf.value or "").strip() for k, tf in inputs.items()}
            if not all(values.values()):
                toast("Lütfen tüm alanları doldurun")
                return
            action = tool["actions"][state["action"]]
            console.controls.clear()
            plain_lines.clear()
            state["running"] = True
            progress.visible = True
            run_btn.disabled = True
            status.value = "Çalışıyor…"
            page.update()
            page.run_thread(worker, action, values)

        async def copy_output(e):
            if not plain_lines:
                toast("Kopyalanacak çıktı yok")
                return
            await clipboard.set("\n".join(plain_lines))
            toast("Çıktı panoya kopyalandı")

        def clear_output(e):
            console.controls.clear()
            plain_lines.clear()
            status.value = "Hazır"
            page.update()

        run_btn = ft.FilledButton(
            "Çalıştır", icon=ft.Icons.PLAY_ARROW, on_click=lambda e: run(),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12),
                                 padding=ft.Padding.symmetric(vertical=14)))

        top = [fields_col, ft.Row([ft.Container(run_btn, expand=True)])]
        if len(tool["actions"]) > 1:
            top.insert(0, ft.Row(scroll=ft.ScrollMode.AUTO, controls=[ft.SegmentedButton(
                selected=["0"], show_selected_icon=False, on_change=on_action_change,
                segments=[ft.Segment(value=str(i), label=a["label"])
                          for i, a in enumerate(tool["actions"])])]))
        build_fields()

        terminal = ft.Container(
            expand=True, bgcolor="#05080C", border_radius=14,
            border=ft.Border.all(1, SURFACE_HI),
            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
            content=ft.Column(spacing=0, expand=True, controls=[
                ft.Container(
                    bgcolor=SURFACE, padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                    content=ft.Row(controls=[
                        ft.Icon(ft.Icons.TERMINAL, size=16, color=ACCENT),
                        ft.Container(status, expand=True),
                        ft.IconButton(ft.Icons.CONTENT_COPY, icon_size=18, tooltip="Kopyala",
                                      on_click=copy_output),
                        ft.IconButton(ft.Icons.DELETE_SWEEP, icon_size=18, tooltip="Temizle",
                                      on_click=clear_output),
                    ])),
                progress,
                console,
            ]))

        return ft.View(
            route=f"/tool/{tool['id']}", bgcolor=BG, padding=16,
            appbar=ft.AppBar(title=ft.Text(tool["title"]), bgcolor=BG),
            controls=[ft.SafeArea(expand=True, content=ft.Column(
                expand=True, spacing=12, controls=[*top, terminal]))])

    # ------------------------------------------------ ayarlar
    def settings_view():
        fields = {}
        controls = [ft.Text("API anahtarları yalnızca bu cihazda saklanır.",
                            color=MUTED, size=12)]
        for key, label in API_FIELDS:
            fields[key] = ft.TextField(
                label=label, value=str(cfg.get(key, "")), password=True,
                can_reveal_password=True, border_radius=12, filled=True,
                fill_color=SURFACE, dense=True, border_color=SURFACE_HI,
                focused_border_color=ACCENT, text_style=ft.TextStyle(font_family=MONO))
            controls.append(fields[key])
        timeout = ft.TextField(
            label="Zaman aşımı (sn)", value=str(cfg.get("timeout", 10)),
            keyboard_type=ft.KeyboardType.NUMBER, border_radius=12, filled=True,
            fill_color=SURFACE, dense=True, border_color=SURFACE_HI,
            focused_border_color=ACCENT)
        controls.append(timeout)

        def save(e):
            for key, tf in fields.items():
                cfg[key] = (tf.value or "").strip()
            try:
                cfg["timeout"] = max(1, int(timeout.value))
            except (TypeError, ValueError):
                cfg["timeout"] = DEFAULT_CONFIG["timeout"]
            toast("Kaydedildi" if save_config(cfg) else "Kaydedilemedi!")

        controls.append(ft.FilledButton("Kaydet", icon=ft.Icons.SAVE, on_click=save))
        controls.append(ft.Divider(color=SURFACE_HI))
        controls.append(ft.Text(
            "Bu araç yalnızca eğitim, araştırma ve izinli güvenlik testleri içindir. "
            "Başkalarına ait verileri izinsiz toplamak KVKK/GDPR kapsamında suçtur. "
            "Sorumluluk kullanıcıya aittir.", color=MUTED, size=12))
        controls.append(ft.Text("Coded by BagwelPower", color=ACCENT, size=12,
                                font_family=MONO))
        return ft.View(
            route="/settings", bgcolor=BG, padding=16,
            appbar=ft.AppBar(title=ft.Text("Ayarlar"), bgcolor=BG),
            controls=[ft.SafeArea(expand=True, content=ft.Column(
                spacing=12, scroll=ft.ScrollMode.AUTO, controls=controls))])

    # ------------------------------------------------ yönlendirme
    def route_change(e=None):
        page.views.clear()
        page.views.append(home_view())
        route = page.route or "/"
        if route.startswith("/tool/") and route[6:] in TOOLS_BY_ID:
            page.views.append(tool_view(TOOLS_BY_ID[route[6:]]))
        elif route == "/settings":
            page.views.append(settings_view())
        page.update()

    async def view_pop(e):
        if len(page.views) > 1:
            page.views.pop()
            await page.push_route(page.views[-1].route)

    page.on_route_change = route_change
    page.on_view_pop = view_pop
    route_change()

    # ------------------------------------------------ ilk açılış uyarısı
    if not cfg.get("disclaimer_accepted"):
        def accept(e):
            cfg["disclaimer_accepted"] = True
            save_config(cfg)
            page.pop_dialog()

        page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("⚠️ Yasal Uyarı"),
            content=ft.Text(
                "PwR Osint yalnızca eğitim, araştırma ve kendi sistemleriniz/izinli "
                "hedefler üzerindeki güvenlik testleri içindir. Kişisel verileri izinsiz "
                "toplamak yasadışıdır (KVKK, GDPR). Tüm sorumluluk kullanıcıya aittir."),
            actions=[ft.TextButton("Anladım, kabul ediyorum", on_click=accept)]))


if __name__ == "__main__":
    ft.run(main)
