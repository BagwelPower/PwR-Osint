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
from pwrosint.core.registry import CATEGORIES, Action, InputError, Tool, all_tools, get_tool, parse_inputs
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
        page.update()

    async def view_pop(self, e) -> None:
        if len(self.page.views) > 1:
            self.page.views.pop()
            await self.page.push_route(self.page.views[-1].route or "/")

    # ------------------------------------------------ ana ekran
    def home_view(self) -> ft.View:
        suggestions = ft.Column(spacing=6, visible=False)

        def on_search(e):
            items = suggest(e.control.value or "")
            suggestions.controls = [self.suggestion_tile(s) for s in items[:8]]
            suggestions.visible = bool(items)
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
            body.append(ft.ResponsiveRow(spacing=10, run_spacing=10, controls=[
                self.tool_card(t) for t in tools]))
        body.append(ft.Container(height=24))

        return ft.View(
            route="/", bgcolor=BG, padding=0,
            appbar=ft.AppBar(
                title=ft.Text("PwR Osint", font_family=MONO, weight=ft.FontWeight.BOLD), bgcolor=BG,
                actions=[ft.IconButton(ft.Icons.TUNE, tooltip="Ayarlar", on_click=lambda e: self.go("/settings"))]),
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
            tf = text_field(
                f.label, hint_text=f.placeholder, value=prefill.get(f.name, ""),
                keyboard_type=KEYBOARD.get(f.kind, ft.KeyboardType.TEXT),
                password=f.kind == "password", can_reveal_password=f.kind == "password",
                text_style=ft.TextStyle(font_family=MONO), autocorrect=False, enable_suggestions=False,
                capitalization=(ft.TextCapitalization.WORDS if f.kind == "name"
                                else ft.TextCapitalization.NONE),
                on_submit=lambda e: self.run(), on_change=self.clear_error)
            self.inputs[f.name] = tf
            self.fields_col.controls.append(tf)

        key = self.action.needs_key
        if key and not getattr(self.app.settings, key):
            label = next((lbl for k, lbl, _ in API_KEY_FIELDS if k == key), key)
            self.key_banner.content = ft.Container(
                bgcolor=ft.Colors.with_opacity(0.12, LEVEL_COLOR[Level.WARN]), border_radius=12, padding=12,
                content=ft.Row([
                    ft.Icon(ft.Icons.KEY, color=LEVEL_COLOR[Level.WARN], size=18),
                    ft.Text(f"{label} API anahtarı gerekli", expand=True, size=13),
                    ft.TextButton("Ayarlar", on_click=lambda e: self.app.go("/settings")),
                ]))
        else:
            self.key_banner.content = None
        self.key_banner.visible = self.key_banner.content is not None

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
        self.app.history.add(self.tool.id, self.action, raw)
        self.ctx = Context(self.app.settings)
        self.results.controls.clear()
        self.set_running(True)
        self.page.run_thread(self.worker, self.ctx, values)

    def worker(self, ctx: Context, values: dict) -> None:
        report = run_action(ctx, self.tool, self.action, values, on_change=self.on_progress)
        self.ctx = None
        self.report = report
        self.set_running(False)
        self.render(report)

    def on_progress(self, report: Report) -> None:
        now = time.monotonic()
        if now - self.last_render > 0.25:  # canlı güncelleme, ama ekranı boğmadan
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
    def render(self, report: Report, partial: bool = False) -> None:
        controls: list[ft.Control] = [self.header(report, partial)]
        if report.summary:
            controls.append(ft.Container(
                bgcolor=ft.Colors.with_opacity(0.10, ACCENT), border_radius=12, padding=12,
                content=ft.Text(report.summary, size=13)))
        for msg in report.errors:
            controls.append(ft.Container(
                bgcolor=ft.Colors.with_opacity(0.12, LEVEL_COLOR[Level.BAD]), border_radius=12, padding=12,
                content=ft.Row([ft.Icon(ft.Icons.ERROR_OUTLINE, color=LEVEL_COLOR[Level.BAD], size=18),
                                ft.Text(msg, expand=True, size=13, selectable=True)])))
        for sec in list(report.sections):
            if sec.items or sec.note:
                controls.append(self.section_card(sec))
        self.results.controls = controls
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
        ])

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
        return ft.Container(
            padding=ft.Padding.symmetric(vertical=6), border_radius=8,
            ink=bool(it.url),
            on_click=(lambda e, u=it.url: self.page.run_task(self.app.open_url, u)) if it.url else None,
            on_long_press=lambda e, t=copy_text: self.page.run_task(self.app.copy, t, "Kopyalandı"),
            content=ft.Row(spacing=10, vertical_alignment=ft.CrossAxisAlignment.START, controls=[
                ft.Icon(LEVEL_ICON[it.level], size=16, color=color if it.level != Level.INFO else MUTED),
                body, *([ft.Icon(ft.Icons.OPEN_IN_NEW, size=14, color=MUTED)] if it.url else [])]))

    # ------------------------------------------------ görünüm
    def view(self) -> ft.View:
        top: list[ft.Control] = []
        if len(self.tool.actions) > 1:
            top.append(ft.Row(scroll=ft.ScrollMode.AUTO, controls=[ft.SegmentedButton(
                selected=[self.action.id], show_selected_icon=False, on_change=self.on_action_change,
                segments=[ft.Segment(value=a.id, label=a.title) for a in self.tool.actions])]))
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

    def _autorun(self) -> None:
        time.sleep(0.05)  # görünüm ekrana yerleşsin
        self.run()


def main(page: ft.Page) -> None:
    App(page)


if __name__ == "__main__":
    ft.run(main)
