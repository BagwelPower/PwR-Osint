"""Terminal arayüzü.

Etkileşimli:   python -m pwrosint
Tek komut:     python -m pwrosint dns ornek.com
               python -m pwrosint email permutate Ahmet Yılmaz ornek.com
               python -m pwrosint host 8.8.8.8 --json
Liste:         python -m pwrosint --list
"""

from __future__ import annotations

import argparse
import getpass
import sys
import threading

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from . import __version__
from .core.config import API_KEY_FIELDS, config_path, load_settings, save_settings
from .core.context import Context
from .core.registry import Action, InputError, Tool, all_tools, get_tool, parse_inputs
from .core.report import Level, Report
from .core.runner import run_action

STYLE = {Level.OK: "green", Level.WARN: "yellow", Level.BAD: "bold red",
         Level.MUTED: "grey50", Level.INFO: "white"}
ICON = {Level.OK: "✔", Level.WARN: "!", Level.BAD: "✖", Level.MUTED: "·", Level.INFO: "›"}

BANNER = r"""[cyan bold]
 ██████╗ ██╗    ██╗██████╗      ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔══██╗██║    ██║██╔══██╗    ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██████╔╝██║ █╗ ██║██████╔╝    ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██╔═══╝ ██║███╗██║██╔══██╗    ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ██║     ╚███╔███╔╝██║  ██║    ╚██████╔╝███████║██║██║ ╚████║   ██║
 ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝[/]
[grey50]  v{version} · open source intelligence framework · Coded by BagwelPower[/]
"""

console = Console()


# ---------------------------------------------------------------- çıktı

def render(report: Report) -> None:
    head = Text(report.title, style="bold cyan")
    if report.target:
        head.append(f"  {report.target}", style="white")
    console.print()
    console.rule(head, align="left", style="cyan")
    if report.summary:
        console.print(f"[bold]{report.summary}[/]")
    for note in report.notices:
        console.print(f"[cyan]ℹ {note}[/]")
    if report.missing_key:
        console.print(f"[yellow]! {report.missing_key[0]} API anahtarı gerekli — ana menüden 'A' ile ekleyin "
                      f"({report.missing_key[1]})[/]")
    hl = report.highlights()
    if hl:
        lines = [Text.assemble((ICON[i.level] + " ", STYLE[i.level]), (i.label, "bold"),
                               (f": {i.value}" if i.value else "", STYLE[i.level]), (f"  [{t}]", "grey50"))
                 for t, i in hl]
        console.print(Panel(Group(*lines), title="[bold red]Önemli bulgular[/]", title_align="left",
                            border_style="red", box=box.ROUNDED, padding=(0, 1)))
    for sec in report.sections:
        table = Table(box=None, show_header=False, padding=(0, 1), expand=False)
        table.add_column(width=1)
        table.add_column(style="grey70", no_wrap=False, max_width=28)
        table.add_column(overflow="fold")
        for it in sec.items:
            style = STYLE[it.level]
            value = Text(it.value, style=style)
            if it.url:
                value.stylize(f"link {it.url}")
                if it.value != it.url:
                    value.append(f"  {it.url}", style=f"grey50 link {it.url}")
            if it.value:
                table.add_row(Text(ICON[it.level], style=style), it.label, value)
            else:
                table.add_row(Text(ICON[it.level], style=style), Text(it.label, style=style), "")
        body = [table] if sec.items else [Text("—", style="grey50")]
        if sec.note:
            body.append(Text(sec.note, style="italic grey50"))
        console.print(Panel(Group(*body), title=f"[bold]{sec.title}[/]", title_align="left",
                            border_style="grey30", box=box.ROUNDED, padding=(0, 1)))
    if report.sources:
        ok = sum(1 for _, good, _ in report.sources if good)
        parts = [f"[green]✔ {n}[/]" if good else f"[grey50]· {n} ({d})[/]" for n, good, d in report.sources]
        console.print(f"[grey50]Kaynaklar {ok}/{len(report.sources)}:[/] " + "  ".join(parts))
    for err in report.errors:
        console.print(f"[bold red]✖ {err}[/]")
    if report.elapsed is not None:
        console.print(f"[grey50]{report.elapsed:.1f} sn[/]")


def execute(ctx: Context, tool: Tool, action: Action, values: dict) -> Report:
    """Çalıştırır; Ctrl+C sorguyu iptal eder ama programı kapatmaz."""
    result: dict = {}
    worker = threading.Thread(target=lambda: result.setdefault(
        "r", run_action(ctx, tool, action, values)), daemon=True)
    with console.status(f"[cyan]{tool.title} · {action.title} çalışıyor… (iptal: Ctrl+C)"):
        worker.start()
        try:
            while worker.is_alive():
                worker.join(0.1)
        except KeyboardInterrupt:
            ctx.cancel_event.set()
            worker.join()
    ctx.cancel_event.clear()
    return result["r"]


# ---------------------------------------------------------------- etkileşimli

def ask_inputs(action: Action) -> dict | None:
    while True:
        raw = {}
        for f in action.fields:
            label = f"[cyan]{f.label}[/]" + (f" [grey50]({f.placeholder})[/]" if f.placeholder else "")
            if f.kind == "password":
                console.print(label + ": ", end="")
                raw[f.name] = getpass.getpass("")
            elif f.kind == "multiline":
                console.print(label + " [grey50](yapıştırın; bitirmek için boş satırda Enter, ya da @dosya)[/]")
                lines = []
                while True:
                    line = input()
                    if not line.strip() and lines:
                        break
                    lines.append(line)
                raw[f.name] = _read_multiline("\n".join(lines))
            else:
                raw[f.name] = Prompt.ask(label, default="", show_default=False)
            if not raw[f.name].strip() and not f.optional:
                return None
        try:
            return parse_inputs(action, raw)
        except InputError as e:
            for name, msg in e.problems.items():
                console.print(f"[red]✖ {name}: {msg}[/]")


def _read_multiline(value: str) -> str:
    """'@dosya' dosyadan, '-' standart girdiden okur; aksi halde değeri olduğu gibi döndürür."""
    v = value.strip()
    if v == "-":
        return sys.stdin.read()
    if v.startswith("@") and len(v) > 1:
        with open(v[1:], encoding="utf-8", errors="replace") as f:
            return f.read()
    return value


def interactive() -> None:
    settings = load_settings()
    if not settings.disclaimer_accepted:
        console.print(Panel(
            "PwR Osint yalnızca eğitim, araştırma ve [bold]izinli[/] güvenlik testleri içindir.\n"
            "Kişisel verileri izinsiz toplamak KVKK/GDPR kapsamında suçtur. Sorumluluk kullanıcıya aittir.",
            title="⚠ Yasal uyarı", border_style="yellow"))
        if Prompt.ask("Kabul ediyor musunuz?", choices=["e", "h"], default="e") != "e":
            return
        settings.disclaimer_accepted = True
        _save(settings)

    tools = all_tools()
    while True:
        console.clear()
        console.print(BANNER.format(version=__version__))
        table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False)
        table.add_column("#", style="bold cyan", justify="right")
        table.add_column("Araç", style="bold")
        table.add_column("Açıklama", style="grey70")
        table.add_column("Kategori", style="grey50")
        for i, t in enumerate(tools, 1):
            table.add_row(str(i), t.title, t.subtitle, t.category)
        table.add_row("A", "Ayarlar", "API anahtarları", "")
        table.add_row("0", "Çıkış", "", "")
        console.print(table)
        choice = Prompt.ask("[cyan]Seçim[/]").strip().lower()
        if choice in ("0", "q", "exit"):
            return
        if choice == "a":
            settings_menu(settings)
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(tools):
            continue
        tool_menu(tools[int(choice) - 1], settings)


def tool_menu(tool: Tool, settings) -> None:
    ctx = Context(settings)
    action = tool.actions[0]
    console.print(Panel(Text(tool.description, style="white") + Text(
        ("\nKaynaklar: " + ", ".join(tool.sources)) if tool.sources else "", style="grey50") + Text(
        ("\nSınır: " + tool.limits) if tool.limits else "", style="yellow"),
        title=f"[bold cyan]{tool.title}[/]", border_style="grey30"))
    if len(tool.actions) > 1:
        for i, a in enumerate(tool.actions, 1):
            console.print(f"  [bold cyan]{i}[/] {a.title}")
        pick = Prompt.ask("[cyan]İşlem[/]", choices=[str(i) for i in range(1, len(tool.actions) + 1)],
                          default="1")
        action = tool.actions[int(pick) - 1]
    if action.needs_key and not getattr(settings, action.needs_key):
        console.print(f"[yellow]! Bu işlem için API anahtarı gerekli ({action.needs_key}). "
                      f"Ana menüden 'A' ile ekleyebilirsiniz.[/]")
    while True:
        values = ask_inputs(action)
        if values is None:
            return
        if action.consent:
            console.print(f"[yellow]! {action.consent}[/]")
            if Prompt.ask("Devam edilsin mi?", choices=["e", "h"], default="h") != "e":
                continue
        render(execute(ctx, tool, action, values))
        if Prompt.ask("\n[grey50]Yeni sorgu? (Enter = menü)[/]", choices=["e", ""], default="",
                      show_choices=False) != "e":
            return


def settings_menu(settings) -> None:
    while True:
        console.clear()
        console.print(f"[bold cyan]Ayarlar[/] [grey50]{config_path()}[/]\n")
        for i, (key, label, url) in enumerate(API_KEY_FIELDS, 1):
            val = getattr(settings, key)
            masked = f"{val[:4]}…{val[-4:]}" if len(val) > 10 else ("•" * len(val) if val else "[grey50](boş)[/]")
            console.print(f"  [bold cyan]{i}[/] {label:<24} {masked}   [grey50]{url}[/]")
        n = len(API_KEY_FIELDS)
        console.print(f"  [bold cyan]{n + 1}[/] {'Zaman aşımı (sn)':<24} {settings.timeout}")
        console.print("  [bold cyan]0[/] Geri")
        choice = Prompt.ask("[cyan]Seçim[/]")
        if not choice.isdigit() or choice == "0":
            return
        idx = int(choice)
        if 1 <= idx <= n:
            key = API_KEY_FIELDS[idx - 1][0]
            setattr(settings, key, getpass.getpass("Yeni değer (boş = sil): ").strip())
        elif idx == n + 1:
            try:
                settings.timeout = max(1, int(Prompt.ask("Saniye", default=str(settings.timeout))))
            except ValueError:
                continue
        _save(settings)


def _save(settings) -> None:
    try:
        path = save_settings(settings)
        console.print(f"[green]✔ Kaydedildi: {path}[/]")
    except OSError as e:
        console.print(f"[red]✖ Kaydedilemedi: {e}[/]")


# ---------------------------------------------------------------- tek komut

def list_tools() -> None:
    table = Table(box=box.SIMPLE_HEAD)
    for col in ("Araç", "İşlem", "Girdiler"):
        table.add_column(col)
    for t in all_tools():
        for i, a in enumerate(t.actions):
            table.add_row(t.id if i == 0 else "", a.id + (" (varsayılan)" if i == 0 else ""),
                          " ".join(f"<{f.name}>" for f in a.fields))
    console.print(table)


def one_shot(args: argparse.Namespace) -> int:
    try:
        tool = get_tool(args.tool)
    except KeyError:
        console.print(f"[red]Bilinmeyen araç: {args.tool}[/] (liste: --list)")
        return 2
    rest = list(args.values)
    action = tool.actions[0]
    if rest and rest[0] in {a.id for a in tool.actions}:
        action = tool.action(rest.pop(0))
    if len(rest) != len(action.fields):
        need = " ".join(f"<{f.name}>" for f in action.fields)
        console.print(f"[red]Kullanım:[/] pwrosint {tool.id} {action.id} {need}")
        return 2
    raw = {f.name: (_read_multiline(v) if f.kind == "multiline" else v) for f, v in zip(action.fields, rest)}
    try:
        values = parse_inputs(action, raw)
    except InputError as e:
        console.print(f"[red]✖ {e}[/]")
        return 2
    if action.consent and not args.yes:
        console.print(f"[yellow]! {action.consent}[/]")
        if not sys.stdin.isatty() or Prompt.ask("Devam edilsin mi?", choices=["e", "h"], default="h") != "e":
            console.print("[grey50]İptal edildi (onay için --yes).[/]")
            return 2
    ctx = Context(load_settings())
    if args.json:
        report = run_action(ctx, tool, action, values)
        print(report.to_json())
    else:
        report = execute(ctx, tool, action, values)
        render(report)
    if args.html:
        from .core.store import to_html
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(to_html(report, f"PwR Osint {__version__}"))
        if not args.json:
            console.print(f"[green]✔ HTML rapor kaydedildi: {args.html}[/]")
    return 1 if report.errors and not report.sections else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pwrosint", description="PwR Osint — OSINT framework")
    parser.add_argument("tool", nargs="?", help="araç (ör. dns, host, username)")
    parser.add_argument("values", nargs="*", help="[işlem] girdiler")
    parser.add_argument("--json", action="store_true", help="sonucu JSON olarak yaz")
    parser.add_argument("--html", metavar="DOSYA", help="raporu tek dosyalık HTML olarak kaydet")
    parser.add_argument("--yes", action="store_true", help="aktif araçların onay sorusunu atla")
    parser.add_argument("--list", action="store_true", help="araçları listele")
    parser.add_argument("--version", action="version", version=f"PwR Osint {__version__}")
    args = parser.parse_args(argv)
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    if args.list:
        list_tools()
        return 0
    if args.tool:
        return one_shot(args)
    try:
        interactive()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[grey50]Görüşmek üzere![/]")
    return 0
