"""PwR Osint — Android / mobil arayüz (Flet).

Arayüz tamamen ``pwrosint`` çekirdeğinin üzerine kuruludur: araç listesi
registry'den gelir, sonuçlar yapılandırılmış ``Report`` nesneleri olarak
kartlara dönüştürülür.

Masaüstünde denemek için:  flet run main.py
Android APK için:          flet build apk
"""

from __future__ import annotations

import time
from typing import Optional

import flet as ft

from pwrosint import __version__
from pwrosint.core.config import API_KEY_FIELDS, Settings, load_settings, save_settings
from pwrosint.core.context import Context
from pwrosint.core.detect import suggest
from pwrosint.core.history import History
from pwrosint.core.registry import (CATEGORIES, CATEGORY_INFO, Action, InputError, Tool, all_tools, get_tool,
                                    parse_inputs)
from pwrosint.core.samples import NEEDS_KEY, SAMPLES
from pwrosint.core.store import ReportStore, to_html
from pwrosint.core.report import Item, Level, Report
from pwrosint.core.runner import run_action

# ---------------------------------------------------------------- tema
ACCENT = "#00E5FF"
BG = "#0A0E14"
SURFACE = "#121821"
SURFACE_HI = "#1C2533"
TEXT = "#E6EDF3"
MUTED = "#7A8899"
MONO = "monospace"

LEVEL_COLOR = {Level.OK: "#3FD68F", Level.WARN: "#FFC857", Level.BAD: "#FF5C7A",
               Level.MUTED: MUTED, Level.INFO: TEXT}
LEVEL_ICON = {Level.OK: ft.Icons.CHECK_CIRCLE, Level.WARN: ft.Icons.WARNING_AMBER_ROUNDED,
              Level.BAD: ft.Icons.ERROR, Level.MUTED: ft.Icons.REMOVE_CIRCLE_OUTLINE,
              Level.INFO: ft.Icons.CHEVRON_RIGHT}
KEYBOARD = {"email": ft.KeyboardType.EMAIL, "phone": ft.KeyboardType.PHONE,
            "number": ft.KeyboardType.NUMBER, "url": ft.KeyboardType.URL,
            "name": ft.KeyboardType.NAME}


def icon(name: str) -> ft.IconData:
    return getattr(ft.Icons, name, ft.Icons.EXTENSION)


def text_field(label: str, **kw) -> ft.TextField:
    kw.setdefault("border_radius", 12)
    kw.setdefault("filled", True)
    kw.setdefault("fill_color", SURFACE)
    kw.setdefault("border_color", SURFACE_HI)
    kw.setdefault("focused_border_color", ACCENT)
    kw.setdefault("dense", True)
    return ft.TextField(label=label, **kw)


PIVOT_TOOLS = {"email", "host", "crypto", "virustotal", "asn"}


def _fold(text: str) -> str:
    """Türkçe duyarlı küçük harf + aksan sadeleştirme (arama için)."""
    t = text.replace("I", "ı").replace("İ", "i").lower()
    return t.translate(str.maketrans("çğıöşü", "cgiosu"))


def find_tools(query: str, tools) -> list:
    """Araç adı, alt başlığı, kategorisi ve açıklamasında arama; ada uyanlar önce."""
    q = _fold(query.strip())
    if len(q) < 2:
        return []
    words = q.split()
    scored = []
    for t in tools:
        title, rest = _fold(t.title), _fold(f"{t.subtitle} {t.category} {t.description}")
        if all(w in title or w in rest for w in words):
            scored.append((0 if all(w in title for w in words) else 1, t.title, t))
    return [t for _, _, t in sorted(scored, key=lambda x: (x[0], x[1]))]


def pivot_target(it: Item, current_target: str = ""):
    """Bir sonuç satırının başka bir araçla araştırılabilir değeri varsa öneriyi döndürür.
    Link satırları (Dış araçlar, profil adresleri) pivotlanmaz; yalnızca düz değerler."""
    from pwrosint.core.detect import suggest
    if it.url:
        return None
    for candidate in (it.value.strip(), it.label.strip()):
        if not candidate or len(candidate) > 100 or " " in candidate or "://" in candidate:
            continue
        if candidate.lower() == current_target.lower():
            continue
        hits = [x for x in suggest(candidate) if x.tool in PIVOT_TOOLS]
        if hits and ("." in candidate or "@" in candidate or hits[0].tool == "crypto"):
            return hits[0]
    return None


# ---------------------------------------------------------------- uygulama

class App:
    def __init__(self, page: ft.Page):
        self.page = page
        self.settings: Settings = load_settings()
        self.history = History()
        self.tools = all_tools()
        self.launcher = ft.UrlLauncher()
        self.clipboard = ft.Clipboard()
        self.share = ft.Share()
        self.file_picker = ft.FilePicker()
        self.connectivity = ft.Connectivity()
        self.store = ReportStore()
        self.prefill: dict = {}

        page.title = "PwR Osint"
        page.bgcolor = BG
        page.theme_mode = ft.ThemeMode.DARK
        page.dark_theme = page.theme = ft.Theme(
            color_scheme_seed=ACCENT,
            color_scheme=ft.ColorScheme(primary=ACCENT, on_primary=BG, surface=SURFACE),
        )
        page.on_route_change = self.route_change
        page.on_view_pop = self.view_pop
        self.route_change()
        if not self.settings.disclaimer_accepted:
            self.show_disclaimer()

    # ------------------------------------------------ yardımcılar
    def toast(self, msg: str) -> None:
        self.page.show_dialog(ft.SnackBar(ft.Text(msg), duration=2000))

    def go(self, route: str) -> None:
        self.page.run_task(self.page.push_route, route)

    async def open_url(self, url: str) -> None:
        try:
            await self.launcher.launch_url(url)
        except Exception as e:  # tarayıcı yoksa vb.
            self.toast(f"Açılamadı: {e}")

    async def copy(self, text: str, what: str = "Kopyalandı") -> None:
        await self.clipboard.set(text)
        self.toast(what)

    def save_settings(self) -> bool:
        try:
            save_settings(self.settings)
            return True
        except OSError as e:
            self.toast(f"Kaydedilemedi: {e}")
            return False

    # ------------------------------------------------ yönlendirme
    def route_change(self, e=None) -> None:
        page = self.page
        page.views.clear()
        page.views.append(self.home_view())
        route = page.route or "/"
        if route.startswith("/tool/"):
            parts = route.split("/")
            try:
                tool = get_tool(parts[2])
                action = tool.action(parts[3]) if len(parts) > 3 else tool.actions[0]
                page.views.append(ToolScreen(self, tool, action).view())
            except (KeyError, IndexError):
                pass
        elif route == "/settings":
            page.views.append(self.settings_view())
        elif route == "/saved":
            page.views.append(self.saved_view())
        elif route.startswith("/saved/"):
            page.views.append(self.saved_view())
            try:
                report = self.store.load(route[7:])
                tool = get_tool(report.tool_id) if report.tool_id else None
            except (OSError, ValueError, KeyError):
                report, tool = None, None
            if report and tool:
                screen = ToolScreen(self, tool, tool.action(report.action_id) if report.action_id else tool.actions[0])
                page.views.append(screen.saved_view(report, route))
        elif route == "/diagnostics":
            page.views.append(self.settings_view())
            page.views.append(Diagnostics(self).view())
        page.update()

    async def view_pop(self, e) -> None:
        if len(self.page.views) > 1:
            self.page.views.pop()
            await self.page.push_route(self.page.views[-1].route or "/")

    # ------------------------------------------------ ana ekran
    def home_view(self) -> ft.View:
        suggestions = ft.Column(spacing=6, visible=False)

        def on_search(e):
            text = e.control.value or ""
            items = suggest(text)
            controls = [self.suggestion_tile(s) for s in items[:8]]
            # Tanınan bir tür değilse (ya da ek olarak) araç adı/açıklamasıyla eşleşen araçlar
            shown = {s.tool for s in items}
            controls += [self.tool_match_tile(t) for t in find_tools(text, self.tools) if t.id not in shown][:6]
            suggestions.controls = controls
            suggestions.visible = bool(controls)
            self.page.update()

        search = text_field(
            "Ne aramak istiyorsun?", hint_text="e-posta, IP, domain, telefon, kullanıcı adı…",
            prefix_icon=ft.Icons.SEARCH, on_change=on_search, autocorrect=False,
            enable_suggestions=False, capitalization=ft.TextCapitalization.NONE,
            on_submit=lambda e: suggestions.controls and suggestions.controls[0].on_click(None))

        body: list[ft.Control] = [
            ft.Container(padding=ft.Padding.only(top=4, bottom=4), content=ft.Column(spacing=0, controls=[
                ft.Text(spans=[ft.TextSpan("PwR", ft.TextStyle(color=ACCENT)), ft.TextSpan(" Osint")],
                        size=30, weight=ft.FontWeight.BOLD, font_family=MONO),
                ft.Text("> open source intelligence framework_", color=MUTED, size=12, font_family=MONO),
            ])),
            search, suggestions,
        ]
        if self.history.entries:
            body.append(self.section_title("Son aramalar", action=ft.TextButton(
                "Temizle", on_click=lambda e: (self.history.clear(), self.route_change()))))
            body.append(ft.Row(scroll=ft.ScrollMode.AUTO, spacing=8, controls=[
                self.history_chip(h) for h in self.history.entries[:12]]))
        for cat in CATEGORIES:
            tools = [t for t in self.tools if t.category == cat]
            if not tools:
                continue
            body.append(self.section_title(cat))
            body.append(ft.Text(CATEGORY_INFO[cat], size=11, color=MUTED))
            body.append(ft.ResponsiveRow(spacing=10, run_spacing=10, controls=[
                self.tool_card(t) for t in tools]))
        body.append(ft.Container(height=24))

        return ft.View(
            route="/", bgcolor=BG, padding=0,
            appbar=ft.AppBar(
                title=ft.Text("PwR Osint", font_family=MONO, weight=ft.FontWeight.BOLD), bgcolor=BG,
                actions=[ft.IconButton(ft.Icons.FOLDER_OPEN, tooltip="Kayıtlı raporlar",
                                       on_click=lambda e: self.go("/saved")),
                         ft.IconButton(ft.Icons.TUNE, tooltip="Ayarlar", on_click=lambda e: self.go("/settings"))]),
            controls=[ft.SafeArea(expand=True, content=ft.ListView(
                expand=True, padding=ft.Padding.symmetric(horizontal=16), spacing=12, controls=body))])

    def section_title(self, text: str, action: Optional[ft.Control] = None) -> ft.Control:
        row = [ft.Text(text.upper(), size=12, color=MUTED, weight=ft.FontWeight.BOLD)]
        if action:
            row += [ft.Container(expand=True), action]
        return ft.Container(padding=ft.Padding.only(top=8), content=ft.Row(row))

    def tool_card(self, tool: Tool) -> ft.Control:
        locked = all(a.needs_key and not getattr(self.settings, a.needs_key) for a in tool.actions)
        return ft.Container(
            col={"xs": 6, "sm": 4, "md": 3}, height=118, bgcolor=SURFACE, border_radius=16, padding=14,
            ink=True, border=ft.Border.all(1, SURFACE_HI),
            on_click=lambda e, t=tool.id: self.go(f"/tool/{t}"),
            content=ft.Column(spacing=4, controls=[
                ft.Row([
                    ft.Container(bgcolor=ft.Colors.with_opacity(0.12, ACCENT), border_radius=10, padding=7,
                                 content=ft.Icon(icon(tool.icon), color=ACCENT, size=22)),
                    ft.Container(expand=True),
                    ft.Icon(ft.Icons.KEY, size=14, color=MUTED, tooltip="API anahtarı gerekli",
                            visible=locked),
                ]),
                ft.Text(tool.title, weight=ft.FontWeight.BOLD, size=14, max_lines=1,
                        overflow=ft.TextOverflow.ELLIPSIS),
                ft.Text(tool.subtitle, size=11, color=MUTED, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
            ]))

    def suggestion_tile(self, s) -> ft.Control:
        tool = get_tool(s.tool)

        def open_(e):
            self.prefill = {s.field: s.value, "_autorun": True}
            self.go(f"/tool/{s.tool}/{s.action}")

        return ft.Container(
            bgcolor=SURFACE, border_radius=12, ink=True, on_click=open_,
            padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            content=ft.Row(spacing=12, controls=[
                ft.Icon(icon(tool.icon), color=ACCENT, size=20),
                ft.Column(spacing=0, expand=True, controls=[
                    ft.Text(f"{tool.title} · {tool.action(s.action).title}", weight=ft.FontWeight.BOLD, size=13),
                    ft.Text(f"{s.reason}: {s.value}", size=11, color=MUTED, max_lines=1,
                            overflow=ft.TextOverflow.ELLIPSIS),
                ]),
                ft.Icon(ft.Icons.ARROW_FORWARD, size=16, color=MUTED),
            ]))

    def tool_match_tile(self, tool: Tool) -> ft.Control:
        return ft.Container(
            bgcolor=SURFACE, border_radius=12, ink=True, on_click=lambda e, t=tool.id: self.go(f"/tool/{t}"),
            padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            content=ft.Row(spacing=12, controls=[
                ft.Icon(icon(tool.icon), color=MUTED, size=20),
                ft.Column(spacing=0, expand=True, controls=[
                    ft.Text(tool.title, weight=ft.FontWeight.BOLD, size=13),
                    ft.Text(f"{tool.category} · {tool.subtitle}", size=11, color=MUTED, max_lines=1,
                            overflow=ft.TextOverflow.ELLIPSIS)]),
                ft.Icon(ft.Icons.CHEVRON_RIGHT, size=16, color=MUTED)]))

    def history_chip(self, h) -> ft.Control:
        try:
            tool = get_tool(h.tool)
        except KeyError:
            return ft.Text("")

        def open_(e):
            self.prefill = dict(h.values)
            self.go(f"/tool/{h.tool}/{h.action}")

        return ft.Chip(label=ft.Text(h.label, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS, width=None),
                       leading=ft.Icon(icon(tool.icon), size=16, color=ACCENT), on_click=open_,
                       bgcolor=SURFACE)

    # ------------------------------------------------ kayıtlı raporlar
    def saved_view(self) -> ft.View:
        import datetime as _dt
        items = self.store.list()
        rows: list[ft.Control] = []
        if not items:
            rows.append(ft.Text("Henüz kayıtlı rapor yok. Bir sorgunun sonucunda 🔖 Kaydet'e dokunun.",
                                color=MUTED, size=13))
        for s in items:
            when = _dt.datetime.fromtimestamp(s.saved_at).strftime("%d.%m.%Y %H:%M")

            def delete(e, rid=s.id):
                self.store.delete(rid)
                self.route_change()

            rows.append(ft.Container(
                bgcolor=SURFACE, border_radius=12, ink=True, padding=12,
                on_click=lambda e, rid=s.id: self.go(f"/saved/{rid}"),
                content=ft.Row(controls=[
                    ft.Column(spacing=0, expand=True, tight=True, controls=[
                        ft.Text(s.target or s.title, weight=ft.FontWeight.BOLD, size=14, max_lines=1,
                                overflow=ft.TextOverflow.ELLIPSIS),
                        ft.Text(f"{s.title} · {when}", size=11, color=MUTED),
                        *([ft.Text(f"{s.findings} önemli bulgu", size=11, color=LEVEL_COLOR[Level.BAD])]
                          if s.findings else [])]),
                    ft.IconButton(ft.Icons.DELETE_OUTLINE, icon_color=MUTED, tooltip="Sil", on_click=delete)])))
        return ft.View(route="/saved", bgcolor=BG, padding=0,
                       appbar=ft.AppBar(title=ft.Text(f"Kayıtlı raporlar ({len(items)})"), bgcolor=BG),
                       controls=[ft.SafeArea(expand=True, content=ft.ListView(
                           expand=True, padding=16, spacing=8, controls=rows))])

    # ------------------------------------------------ ayarlar
    def settings_view(self) -> ft.View:
        fields: dict[str, ft.TextField] = {}
        controls: list[ft.Control] = [ft.Text(
            "API anahtarları yalnızca bu cihazda saklanır ve sadece ilgili servise gönderilir.",
            color=MUTED, size=12)]
        for key, label, url in API_KEY_FIELDS:
            fields[key] = text_field(
                label, value=getattr(self.settings, key), password=True, can_reveal_password=True,
                text_style=ft.TextStyle(font_family=MONO), autocorrect=False, enable_suggestions=False,
                suffix=ft.IconButton(ft.Icons.OPEN_IN_NEW, icon_size=16, tooltip="Anahtar al",
                                     on_click=lambda e, u=url: self.page.run_task(self.open_url, u)))
            controls.append(fields[key])
        timeout = text_field("Zaman aşımı (sn)", value=str(self.settings.timeout),
                             keyboard_type=ft.KeyboardType.NUMBER)
        controls.append(timeout)

        def save(e):
            for key, tf in fields.items():
                setattr(self.settings, key, (tf.value or "").strip())
            try:
                self.settings.timeout = min(120, max(1, int(timeout.value or 10)))
            except ValueError:
                timeout.error = "Sayı girin"
                self.page.update()
                return
            if self.save_settings():
                self.toast("Kaydedildi")

        controls += [
            ft.FilledButton("Kaydet", icon=ft.Icons.SAVE, on_click=save),
            ft.OutlinedButton("Tanılama: tüm araçları bu cihazda test et", icon=ft.Icons.FACT_CHECK,
                              on_click=lambda e: self.go("/diagnostics")),
            ft.Divider(color=SURFACE_HI),
            ft.Text("Bu araç yalnızca eğitim, araştırma ve izinli güvenlik testleri içindir. "
                    "Kişisel verileri izinsiz toplamak KVKK/GDPR kapsamında suçtur. "
                    "Sorumluluk kullanıcıya aittir.", color=MUTED, size=12),
            ft.Text(f"PwR Osint v{__version__} · Coded by BagwelPower", color=ACCENT, size=12, font_family=MONO),
        ]
        return ft.View(
            route="/settings", bgcolor=BG, padding=0,
            appbar=ft.AppBar(title=ft.Text("Ayarlar"), bgcolor=BG),
            controls=[ft.SafeArea(expand=True, content=ft.ListView(
                expand=True, padding=16, spacing=12, controls=controls))])

    def show_disclaimer(self) -> None:
        def accept(e):
            self.settings.disclaimer_accepted = True
            self.save_settings()
            self.page.pop_dialog()

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("Yasal uyarı"),
            content=ft.Text(
                "PwR Osint yalnızca eğitim, araştırma ve kendi sistemleriniz ya da izinli hedefler "
                "üzerindeki güvenlik testleri içindir. Kişisel verileri izinsiz toplamak yasadışıdır "
                "(KVKK, GDPR). Tüm sorumluluk kullanıcıya aittir."),
            actions=[ft.TextButton("Anladım, kabul ediyorum", on_click=accept)]))


# ---------------------------------------------------------------- araç ekranı

class ToolScreen:
    def __init__(self, app: App, tool: Tool, action: Action):
        self.app, self.page, self.tool, self.action = app, app.page, tool, action
        self.ctx: Optional[Context] = None
        self.report: Optional[Report] = None
        self.last_render = 0.0
        self.inputs: dict[str, ft.TextField] = {}

        self.fields_col = ft.Column(spacing=10, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        self.key_banner = ft.Container(visible=False)
        self.results = ft.Column(spacing=10, horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
        self.progress = ft.ProgressBar(visible=False, color=ACCENT, bgcolor=SURFACE_HI, border_radius=2)
        self.run_btn = ft.FilledButton(
            "Çalıştır", icon=ft.Icons.PLAY_ARROW, expand=True, on_click=lambda e: self.run(),
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12),
                                 padding=ft.Padding.symmetric(vertical=14)))
        self.cancel_btn = ft.OutlinedButton(
            "İptal", icon=ft.Icons.STOP, visible=False, on_click=self.cancel,
            style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=12),
                                 padding=ft.Padding.symmetric(vertical=14, horizontal=18)))
        self.build_fields()

    # ------------------------------------------------ girdiler
    def build_fields(self) -> None:
        prefill, self.app.prefill = self.app.prefill, {}
        self.autorun = bool(prefill.pop("_autorun", False))
        self.inputs.clear()
        self.fields_col.controls.clear()
        for f in self.action.fields:
            if f.kind == "file":
                tf = text_field(f.label, hint_text=f.placeholder, value=prefill.get(f.name, ""), read_only=True,
                                prefix_icon=ft.Icons.IMAGE)
                self.inputs[f.name] = tf
                self.fields_col.controls.append(tf)
                self.fields_col.controls.append(ft.OutlinedButton(
                    "Fotoğraf seç" if f.accept else "Dosya seç",
                    icon=ft.Icons.PHOTO_LIBRARY if f.accept else ft.Icons.ATTACH_FILE,
                    on_click=lambda e, t=tf, fld=f: self.page.run_task(self.pick_file, t, fld)))
                continue
            multiline = f.kind == "multiline"
            tf = text_field(
                f.label, hint_text=f.placeholder, value=prefill.get(f.name, ""),
                multiline=multiline, min_lines=5 if multiline else None, max_lines=12 if multiline else None,
                keyboard_type=ft.KeyboardType.MULTILINE if multiline else KEYBOARD.get(f.kind, ft.KeyboardType.TEXT),
                password=f.kind == "password", can_reveal_password=f.kind == "password",
                text_style=ft.TextStyle(font_family=MONO), autocorrect=False, enable_suggestions=False,
                capitalization=(ft.TextCapitalization.WORDS if f.kind == "name"
                                else ft.TextCapitalization.NONE),
                on_submit=None if multiline else (lambda e: self.run()), on_change=self.clear_error)
            self.inputs[f.name] = tf
            self.fields_col.controls.append(tf)

        required, optional = self.action.needs_key, self.action.better_with
        key = required or optional
        if key and not getattr(self.app.settings, key):
            label = next((lbl for k, lbl, _ in API_KEY_FIELDS if k == key), key)
            color = LEVEL_COLOR[Level.WARN] if required else ACCENT
            text = (f"{label} API anahtarı gerekli" if required else
                    f"Anahtarsız yedek kaynakla çalışır. {label} anahtarı eklerseniz daha ayrıntılı sonuç alırsınız.")
            self.key_banner.content = ft.Container(
                bgcolor=ft.Colors.with_opacity(0.10, color), border_radius=12, padding=12,
                content=ft.Row([
                    ft.Icon(ft.Icons.KEY if required else ft.Icons.INFO_OUTLINE, color=color, size=18),
                    ft.Text(text, expand=True, size=12),
                    ft.TextButton("Ayarlar", on_click=lambda e: self.app.go("/settings")),
                ]))
        else:
            self.key_banner.content = None
        self.key_banner.visible = self.key_banner.content is not None

    async def pick_file(self, target: ft.TextField, field) -> None:
        # Not: Android'in "Fotoğraf Seçici"si (IMAGE türü) GPS bilgisini siler; belge seçici
        # (CUSTOM + uzantı listesi ya da ANY) orijinal dosyayı verir.
        try:
            if field.accept:
                files = await self.app.file_picker.pick_files(
                    dialog_title="Analiz edilecek fotoğraf", file_type=ft.FilePickerFileType.CUSTOM,
                    allowed_extensions=list(field.accept), with_data=self.page.web)
            else:
                files = await self.app.file_picker.pick_files(
                    dialog_title="Analiz edilecek dosya", file_type=ft.FilePickerFileType.ANY,
                    with_data=self.page.web)
        except Exception as ex:
            self.app.toast(f"Dosya seçilemedi: {ex}")
            return
        if not files:
            return
        f = files[0]
        path = f.path
        if not path and f.bytes:
            import os
            import tempfile
            tmp_dir = os.path.join(os.environ.get("FLET_APP_STORAGE_TEMP") or tempfile.gettempdir(),
                                   "pwr-osint-secimler")
            os.makedirs(tmp_dir, exist_ok=True)
            path = os.path.join(tmp_dir, os.path.basename(f.name) or "foto.jpg")
            with open(path, "wb") as fh:
                fh.write(f.bytes)
        if not path:
            self.app.toast("Dosyaya erişilemedi")
            return
        target.value = path
        target.error = None
        self.page.update()

    @staticmethod
    def clear_error(e) -> None:
        if e.control.error:
            e.control.error = None
            e.control.update()

    def on_action_change(self, e) -> None:
        self.action = self.tool.action(e.control.selected[0])
        self.build_fields()
        self.results.controls.clear()
        self.page.update()

    # ------------------------------------------------ çalıştırma
    def run(self) -> None:
        if self.ctx is not None:
            return
        raw = {k: tf.value or "" for k, tf in self.inputs.items()}
        try:
            values = parse_inputs(self.action, raw)
        except InputError as e:
            for name, msg in e.problems.items():
                self.inputs[name].error = msg
            self.page.update()
            return
        if self.action.consent:
            def proceed(e):
                self.page.pop_dialog()
                self._start(values, raw)

            self.page.show_dialog(ft.AlertDialog(
                modal=True, title=ft.Row([ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=LEVEL_COLOR[Level.WARN]),
                                          ft.Text("Aktif tarama onayı")]),
                content=ft.Text(self.action.consent),
                actions=[ft.TextButton("İptal", on_click=lambda e: self.page.pop_dialog()),
                         ft.FilledButton("Yetkiliyim, başlat", on_click=proceed)]))
            return
        self._start(values, raw)

    def _start(self, values: dict, raw: dict) -> None:
        self.app.history.add(self.tool.id, self.action, raw)
        self.ctx = Context(self.app.settings)
        self.results.controls.clear()
        self.set_running(True)
        if self.tool.id == "lan":
            self.page.run_task(self._start_with_connectivity, self.ctx, values)
        else:
            self.page.run_thread(self.worker, self.ctx, values)

    async def _start_with_connectivity(self, ctx: Context, values: dict) -> None:
        """Yerel ağ taraması yalnızca Wi-Fi/ethernet'te: bağlantı türünü cihazdan öğren."""
        try:
            kinds = await self.app.connectivity.get_connectivity()
            ctx.connectivity = {str(getattr(k, "value", k)).lower() for k in kinds or []}
        except Exception:
            ctx.connectivity = None  # bilinmiyor: çekirdek arayüz adına göre karar verir (Android'de kapalı)
        self.page.run_thread(self.worker, ctx, values)

    def worker(self, ctx: Context, values: dict) -> None:
        report = run_action(ctx, self.tool, self.action, values, on_change=self.on_progress)
        self.ctx = None
        self.report = report
        self.set_running(False)
        self.render(report)

    def on_progress(self, report: Report) -> None:
        now = time.monotonic()
        if now - self.last_render > 1.0:  # canlı güncelleme, ama telefonu boğmadan
            self.last_render = now
            self.render(report, partial=True)

    def cancel(self, e) -> None:
        if self.ctx:
            self.ctx.cancel_event.set()
            self.cancel_btn.disabled = True
            self.page.update()

    def set_running(self, running: bool) -> None:
        self.progress.visible = running
        self.run_btn.visible = not running
        self.cancel_btn.visible = running
        self.cancel_btn.disabled = False
        for tf in self.inputs.values():
            tf.read_only = running
        self.page.update()

    # ------------------------------------------------ sonuçlar
    def render(self, report: Report, partial: bool = False, update: bool = True) -> None:
        controls: list[ft.Control] = [self.header(report, partial)]
        if report.summary:
            controls.append(ft.Container(
                bgcolor=ft.Colors.with_opacity(0.10, ACCENT), border_radius=12, padding=12,
                content=ft.Text(report.summary, size=13)))
        for msg in list(report.notices):
            controls.append(self.banner(ft.Icons.INFO_OUTLINE, ACCENT, msg))
        if report.missing_key:
            service, _ = report.missing_key
            controls.append(self.banner(ft.Icons.KEY, LEVEL_COLOR[Level.WARN],
                                        f"Bu işlem için {service} API anahtarı gerekli.",
                                        ft.TextButton("Ayarlar", on_click=lambda e: self.app.go("/settings"))))
        for msg in report.errors:
            controls.append(self.banner(ft.Icons.ERROR_OUTLINE, LEVEL_COLOR[Level.BAD], msg))
        if not partial and (hl := report.highlights()):
            controls.append(self.highlights_card(hl))
        for sec in list(report.sections):
            if sec.items or sec.note:
                controls.append(self.section_card(sec))
        if not partial and report.sources:
            controls.append(self.sources_card(report.sources))
        self.results.controls = controls
        if update:
            self.page.update()

    def header(self, report: Report, partial: bool) -> ft.Control:
        status = "Çalışıyor…" if partial else (
            f"{sum(len(s.items) for s in report.sections)} sonuç · {report.elapsed or 0:.1f} sn")
        return ft.Row([
            ft.Text(status, size=12, color=MUTED, expand=True),
            ft.IconButton(ft.Icons.CONTENT_COPY, icon_size=18, tooltip="Metni kopyala", disabled=partial,
                          on_click=lambda e: self.page.run_task(self.app.copy, report.to_text(),
                                                                "Rapor panoya kopyalandı")),
            ft.IconButton(ft.Icons.DATA_OBJECT, icon_size=18, tooltip="JSON kopyala", disabled=partial,
                          on_click=lambda e: self.page.run_task(self.app.copy, report.to_json(),
                                                                "JSON panoya kopyalandı")),
            ft.IconButton(ft.Icons.SHARE, icon_size=18, tooltip="Paylaş", disabled=partial,
                          on_click=lambda e: self.page.run_task(self.share_report, report)),
            ft.IconButton(ft.Icons.BOOKMARK_ADD_OUTLINED, icon_size=18, tooltip="Raporu kaydet",
                          disabled=partial, on_click=lambda e: self.save_report(report)),
            ft.IconButton(ft.Icons.DOWNLOAD, icon_size=18, tooltip="HTML olarak dışa aktar", disabled=partial,
                          on_click=lambda e: self.page.run_task(self.export_html, report)),
        ], spacing=0)

    def save_report(self, report: Report) -> None:
        try:
            self.app.store.save(report)
            self.app.toast("Rapor kaydedildi (ana ekran → 📁)")
        except OSError as ex:
            self.app.toast(f"Kaydedilemedi: {ex}")

    async def export_html(self, report: Report) -> None:
        import re as _re
        data = to_html(report, f"PwR Osint {__version__}").encode("utf-8")
        name = _re.sub(r"[^A-Za-z0-9._-]+", "_", f"pwr-osint_{report.target or 'rapor'}")[:60] + ".html"
        try:
            path = await self.app.file_picker.save_file(dialog_title="Raporu kaydet", file_name=name,
                                                        allowed_extensions=["html"], src_bytes=data)
            if path:
                self.app.toast("HTML rapor kaydedildi")
        except Exception:
            try:
                await self.app.share.share_files([ft.ShareFile.from_bytes(data, mime_type="text/html", name=name)])
            except Exception as ex:
                self.app.toast(f"Dışa aktarılamadı: {ex}")

    @staticmethod
    def banner(icon_name, color, text: str, action: Optional[ft.Control] = None) -> ft.Control:
        row = [ft.Icon(icon_name, color=color, size=18), ft.Text(text, expand=True, size=12, selectable=True)]
        if action:
            row.append(action)
        return ft.Container(bgcolor=ft.Colors.with_opacity(0.10, color), border_radius=12, padding=12,
                            content=ft.Row(row, vertical_alignment=ft.CrossAxisAlignment.START))

    def highlights_card(self, hl) -> ft.Control:
        rows: list[ft.Control] = [ft.Row([ft.Icon(ft.Icons.PRIORITY_HIGH, color=LEVEL_COLOR[Level.BAD], size=18),
                                          ft.Text("Önemli bulgular", weight=ft.FontWeight.BOLD, size=14)])]
        for title, it in hl:
            text = f"{it.label}: {it.value}" if it.value else it.label
            rows.append(ft.Row(spacing=8, vertical_alignment=ft.CrossAxisAlignment.START, controls=[
                ft.Icon(LEVEL_ICON[it.level], size=14, color=LEVEL_COLOR[it.level]),
                ft.Column(spacing=0, expand=True, tight=True, controls=[
                    ft.Text(text, size=12, color=TEXT, selectable=True),
                    ft.Text(title, size=10, color=MUTED)])]))
        return ft.Container(bgcolor=ft.Colors.with_opacity(0.08, LEVEL_COLOR[Level.BAD]), border_radius=14,
                            border=ft.Border.all(1, ft.Colors.with_opacity(0.35, LEVEL_COLOR[Level.BAD])),
                            padding=12, content=ft.Column(spacing=6, tight=True, controls=rows))

    def sources_card(self, sources) -> ft.Control:
        ok = sum(1 for _, good, _ in sources if good)
        rows = [ft.Row(spacing=8, controls=[
            ft.Icon(ft.Icons.CHECK_CIRCLE if good else ft.Icons.REMOVE_CIRCLE_OUTLINE, size=14,
                    color=LEVEL_COLOR[Level.OK] if good else MUTED),
            ft.Text(name, size=12, width=130),
            ft.Text(detail, size=11, color=MUTED, expand=True)]) for name, good, detail in sources]
        return ft.ExpansionTile(
            title=ft.Text(f"Kaynak durumu · {ok}/{len(sources)} yanıt verdi", size=13),
            subtitle=ft.Text("Limitli veya erişilemeyen kaynaklar sonucu bozmaz", size=11, color=MUTED),
            leading=ft.Icon(ft.Icons.DNS_OUTLINED, color=MUTED, size=18), bgcolor=SURFACE, collapsed_bgcolor=SURFACE,
            controls_padding=ft.Padding.only(left=16, right=12, bottom=10),
            shape=ft.RoundedRectangleBorder(radius=14), collapsed_shape=ft.RoundedRectangleBorder(radius=14),
            controls=rows)

    async def share_report(self, report: Report) -> None:
        try:
            await self.app.share.share_text(report.to_text(), subject=report.title)
        except Exception:
            await self.app.copy(report.to_text(), "Paylaşım desteklenmiyor; panoya kopyalandı")

    def section_card(self, sec) -> ft.Control:
        rows: list[ft.Control] = [ft.Text(sec.title, weight=ft.FontWeight.BOLD, size=14)]
        if sec.note:
            rows.append(ft.Text(sec.note, size=11, color=MUTED, italic=True))
        rows += [self.item_row(it) for it in sec.items[:200]]
        if len(sec.items) > 200:
            rows.append(ft.Text(f"… ve {len(sec.items) - 200} satır daha (tamamı için JSON/metin kopyalayın)",
                                size=11, color=MUTED))
        return ft.Container(bgcolor=SURFACE, border_radius=14, border=ft.Border.all(1, SURFACE_HI),
                            padding=ft.Padding.only(left=14, right=10, top=12, bottom=8),
                            content=ft.Column(spacing=2, tight=True, controls=rows))

    def item_row(self, it: Item) -> ft.Control:
        color = LEVEL_COLOR[it.level]
        value_color = ACCENT if it.url and it.level in (Level.INFO,) else color
        if it.value:
            body = ft.Column(spacing=0, expand=True, tight=True, controls=[
                ft.Text(it.label, size=11, color=MUTED),
                # Not: selectable + max_lines birlikte kullanılınca Flutter her zaman
                # max_lines kadar yükseklik ayırıyor; bu yüzden max_lines yok.
                ft.Text(it.value, size=13, color=value_color, font_family=MONO, selectable=not it.url),
            ])
        else:
            body = ft.Text(it.label, size=13, color=color, expand=True, font_family=MONO, selectable=not it.url)

        copy_text = it.url or it.value or it.label
        pivot = self.pivot_button(it)
        return ft.Container(
            padding=ft.Padding.symmetric(vertical=6), border_radius=8,
            ink=bool(it.url),
            on_click=(lambda e, u=it.url: self.page.run_task(self.app.open_url, u)) if it.url else None,
            on_long_press=lambda e, t=copy_text: self.page.run_task(self.app.copy, t, "Kopyalandı"),
            content=ft.Row(spacing=10, vertical_alignment=ft.CrossAxisAlignment.START, controls=[
                ft.Icon(LEVEL_ICON[it.level], size=16, color=color if it.level != Level.INFO else MUTED),
                body, *([pivot] if pivot else []),
                *([ft.Icon(ft.Icons.OPEN_IN_NEW, size=14, color=MUTED)] if it.url else [])]))

    def pivot_button(self, it: Item) -> Optional[ft.Control]:
        """Sonuçtaki e-posta / IP / domain / kullanıcı adını başka bir araçla araştırma kısayolu."""
        s = pivot_target(it, self.report.target if self.report else "")
        if not s:
            return None

        def go(e):
            self.app.prefill = {s.field: s.value, "_autorun": True}
            self.app.go(f"/tool/{s.tool}/{s.action}")

        return ft.IconButton(ft.Icons.TRAVEL_EXPLORE, icon_size=16, icon_color=ACCENT, on_click=go,
                             tooltip=f"Araştır: {get_tool(s.tool).title}", width=30, height=30,
                             style=ft.ButtonStyle(padding=0))

    # ------------------------------------------------ görünüm
    def view(self) -> ft.View:
        top: list[ft.Control] = []
        if len(self.tool.actions) > 1:
            top.append(ft.Row(scroll=ft.ScrollMode.AUTO, controls=[ft.SegmentedButton(
                selected=[self.action.id], show_selected_icon=False, on_change=self.on_action_change,
                segments=[ft.Segment(value=a.id, label=a.title) for a in self.tool.actions])]))
        top.insert(0, self.info_tile())
        top += [self.key_banner, self.fields_col, ft.Row([self.run_btn, self.cancel_btn]), self.progress,
                self.results]
        view = ft.View(
            route=f"/tool/{self.tool.id}/{self.action.id}", bgcolor=BG, padding=0,
            appbar=ft.AppBar(title=ft.Text(self.tool.title), bgcolor=BG),
            controls=[ft.SafeArea(expand=True, content=ft.ListView(
                expand=True, padding=16, spacing=12, controls=top))])
        if self.autorun:
            self.page.run_thread(self._autorun)
        return view

    def info_tile(self) -> ft.Control:
        t = self.tool
        rows: list[ft.Control] = [ft.Text(t.description, size=12, color=TEXT)]
        if t.sources:
            rows.append(ft.Text("Kaynaklar: " + ", ".join(t.sources), size=11, color=MUTED))
        if t.limits:
            rows.append(ft.Row(spacing=6, vertical_alignment=ft.CrossAxisAlignment.START, controls=[
                ft.Icon(ft.Icons.INFO_OUTLINE, size=13, color=LEVEL_COLOR[Level.WARN]),
                ft.Text(t.limits, size=11, color=MUTED, expand=True)]))
        return ft.ExpansionTile(
            title=ft.Text(t.subtitle, size=13), subtitle=ft.Text("Bu araç ne yapar?", size=11, color=ACCENT),
            leading=ft.Icon(icon(t.icon), color=ACCENT), bgcolor=SURFACE, collapsed_bgcolor=SURFACE,
            controls_padding=ft.Padding.only(left=16, right=16, bottom=12),
            shape=ft.RoundedRectangleBorder(radius=14), collapsed_shape=ft.RoundedRectangleBorder(radius=14),
            controls=[ft.Column(spacing=6, tight=True, controls=rows)])

    def saved_view(self, report: Report, route: str) -> ft.View:
        """Kayıtlı bir raporu, girdi alanları olmadan, aynı kart düzeniyle gösterir."""
        self.report = report
        self.render(report, update=False)
        return ft.View(
            route=route, bgcolor=BG, padding=0,
            appbar=ft.AppBar(title=ft.Text(report.target or self.tool.title), bgcolor=BG),
            controls=[ft.SafeArea(expand=True, content=ft.ListView(
                expand=True, padding=16, spacing=12, controls=[
                    ft.Text(report.title, size=12, color=MUTED), self.results]))])

    def _autorun(self) -> None:
        time.sleep(0.05)  # görünüm ekrana yerleşsin
        self.run()


# ---------------------------------------------------------------- tanılama

# Tanılamada atlananlar: derin tarama çok uzun; dosya seçimi kullanıcı etkileşimi ister.
DIAG_SKIP = {("username", "deep"), ("image", "file"), ("filescan", "analyze"), ("fullscan", "scan"),
             # Globalping ücretsiz ölçüm kotası kullanır; tanılamada harcanmasın
             ("globalping", "ping"), ("globalping", "traceroute"), ("globalping", "mtr"), ("globalping", "http"),
             # Aktif araçlar tanılamada kendiliğinden çalışmaz (onay ister, veri harcar ya da ağa bağlantı açar)
             ("portscan", "scan"), ("lan", "scan"), ("speedtest", "download"), ("speedtest", "upload")}


class Diagnostics:
    """Her aracı örnek girdiyle bu cihazda çalıştırır; telefondaki gerçek durumu gösterir."""

    def __init__(self, app: App):
        self.app, self.page = app, app.page
        self.rows = ft.Column(spacing=4)
        self.status = ft.Text("Henüz çalıştırılmadı", size=12, color=MUTED)
        self.progress = ft.ProgressBar(value=0, color=ACCENT, bgcolor=SURFACE_HI, visible=False)
        self.lines: list[str] = []
        self.ctx: Optional[Context] = None

    def start(self, e=None) -> None:
        if self.ctx:
            return
        self.ctx = Context(self.app.settings)
        self.rows.controls.clear()
        self.lines.clear()
        self.progress.visible = True
        self.page.update()
        self.page.run_thread(self.worker)

    def worker(self) -> None:
        jobs = [(t, a) for t in all_tools() for a in t.actions
                if (t.id, a.id) in SAMPLES and (t.id, a.id) not in DIAG_SKIP]
        counts = {"ok": 0, "warn": 0, "bad": 0}
        for i, (tool, action) in enumerate(jobs, 1):
            if self.ctx.cancel_event.is_set():
                break
            self.status.value = f"{i}/{len(jobs)} · {tool.title} · {action.title}"
            self.progress.value = i / len(jobs)
            self.page.update()
            try:
                values = parse_inputs(action, SAMPLES[(tool.id, action.id)])
                rep = run_action(self.ctx, tool, action, values)
                items = sum(len(s.items) for s in rep.sections)
                if rep.errors:
                    state, detail = "bad", rep.errors[0]
                elif rep.missing_key:
                    state, detail = ("ok" if (tool.id, action.id) in NEEDS_KEY else "warn"), "API anahtarı gerekli"
                elif items < 2:
                    state, detail = "warn", "çok az veri döndü"
                else:
                    failed = [n for n, ok, _ in rep.sources if not ok]
                    state = "ok"
                    detail = f"{items} sonuç · {rep.elapsed or 0:.1f} sn" + (
                        f" · yanıtsız kaynak: {', '.join(failed)}" if failed else "")
            except Exception as ex:  # tanılama ekranı asla çökmemeli
                state, detail = "bad", f"{type(ex).__name__}: {ex}"
            counts[state] += 1
            color = {"ok": LEVEL_COLOR[Level.OK], "warn": LEVEL_COLOR[Level.WARN], "bad": LEVEL_COLOR[Level.BAD]}[state]
            mark = {"ok": "✔", "warn": "!", "bad": "✖"}[state]
            self.lines.append(f"{mark} {tool.id}/{action.id}: {detail}")
            self.rows.controls.append(ft.Row(spacing=8, vertical_alignment=ft.CrossAxisAlignment.START, controls=[
                ft.Icon(ft.Icons.CIRCLE, size=10, color=color),
                ft.Column(spacing=0, expand=True, tight=True, controls=[
                    ft.Text(f"{tool.title} · {action.title}", size=12),
                    ft.Text(detail, size=11, color=MUTED, selectable=True)])]))
        from pwrosint.core import dns as _dns
        self.status.value = (f"Bitti: {counts['ok']} çalışıyor, {counts['warn']} uyarı, {counts['bad']} hata "
                             f"({len(jobs)} işlem) · DNS yolu: {_dns.active_transport() or 'hiçbiri çalışmadı'}")
        self.progress.visible = False
        self.ctx = None
        self.page.update()

    async def copy(self, e) -> None:
        await self.app.copy(f"PwR Osint {__version__} tanılama\n{self.status.value}\n" + "\n".join(self.lines),
                            "Tanılama sonucu kopyalandı")

    def view(self) -> ft.View:
        return ft.View(
            route="/diagnostics", bgcolor=BG, padding=0,
            appbar=ft.AppBar(title=ft.Text("Tanılama"), bgcolor=BG, actions=[
                ft.IconButton(ft.Icons.CONTENT_COPY, tooltip="Sonucu kopyala",
                              on_click=lambda e: self.page.run_task(self.copy, e))]),
            controls=[ft.SafeArea(expand=True, content=ft.ListView(expand=True, padding=16, spacing=10, controls=[
                ft.Text("Her aracı örnek bir girdiyle bu cihazdan gerçek servislere karşı çalıştırır. "
                        "Sonucu kopyalayıp geliştiriciye gönderebilirsiniz. Bağlantı hızına göre birkaç dakika sürer.",
                        size=12, color=MUTED),
                ft.FilledButton("Testi başlat", icon=ft.Icons.PLAY_ARROW, on_click=self.start),
                self.status, self.progress, self.rows]))])


def main(page: ft.Page) -> None:
    App(page)


if __name__ == "__main__":
    ft.run(main)
