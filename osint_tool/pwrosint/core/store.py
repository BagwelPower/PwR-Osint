"""Kayıtlı raporlar ve dışa aktarma (JSON / tek dosyalık HTML)."""

from __future__ import annotations

import html
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import config_path
from .report import Item, Level, Report

MAX_SAVED = 200


def report_from_dict(d: dict) -> Report:
    r = Report(d.get("title", ""), d.get("target", ""))
    r.summary = d.get("summary")
    r.tool_id, r.action_id = d.get("tool"), d.get("action")
    r.elapsed = d.get("elapsed")
    for s in d.get("sections") or []:
        sec = r.section(s.get("title", ""), s.get("note"))
        for i in s.get("items") or []:
            sec.items.append(Item(i.get("label", ""), i.get("value", ""), i.get("url"),
                                  Level(i.get("level", "info"))))
    r.errors = list(d.get("errors") or [])
    r.notices = list(d.get("notices") or [])
    mk = d.get("missing_key")
    r.missing_key = tuple(mk) if mk else None
    r.sources = [(x.get("name", ""), bool(x.get("ok")), x.get("detail", "")) for x in d.get("sources") or []]
    return r


@dataclass
class Saved:
    id: str
    title: str
    target: str
    saved_at: float
    findings: int


class ReportStore:
    def __init__(self, root: Optional[Path] = None):
        self.root = root or config_path().with_name("reports")

    def save(self, report: Report) -> str:
        self.root.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", (report.target or report.title).lower())[:40].strip("-") or "rapor"
        rid = f"{time.strftime('%Y%m%d-%H%M%S')}-{slug}"
        data = report.to_dict()
        data["elapsed"] = report.elapsed
        data["saved_at"] = time.time()
        tmp = self.root / f"{rid}.tmp"
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.root / f"{rid}.json")
        self._prune()
        return rid

    def list(self) -> list[Saved]:
        out = []
        for p in sorted(self.root.glob("*.json"), reverse=True) if self.root.exists() else []:
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            out.append(Saved(p.stem, d.get("title", ""), d.get("target", ""), d.get("saved_at", p.stat().st_mtime),
                             len(d.get("highlights") or [])))
        return out

    def load(self, rid: str) -> Report:
        return report_from_dict(json.loads((self.root / f"{rid}.json").read_text(encoding="utf-8")))

    def delete(self, rid: str) -> None:
        try:
            (self.root / f"{rid}.json").unlink()
        except OSError:
            pass

    def _prune(self) -> None:
        files = sorted(self.root.glob("*.json"))
        for p in files[:-MAX_SAVED]:
            p.unlink(missing_ok=True)


# ---------------------------------------------------------------- HTML

_COLORS = {Level.OK: "#3FD68F", Level.WARN: "#FFC857", Level.BAD: "#FF5C7A", Level.MUTED: "#7A8899",
           Level.INFO: "#E6EDF3"}
_ICONS = {Level.OK: "✔", Level.WARN: "!", Level.BAD: "✖", Level.MUTED: "·", Level.INFO: "›"}


def _safe_url(url: Optional[str]) -> Optional[str]:
    return url if url and re.match(r"^(https?|tel|mailto):", url, re.I) else None


def to_html(report: Report, generator: str = "PwR Osint") -> str:
    e = html.escape
    parts = []
    hl = report.highlights(limit=20)
    if hl:
        rows = "".join(f'<li style="color:{_COLORS[i.level]}">{_ICONS[i.level]} <b>{e(i.label)}</b>'
                       f'{": " + e(i.value) if i.value else ""} <small>({e(t)})</small></li>' for t, i in hl)
        parts.append(f'<section class="hl"><h2>Önemli bulgular</h2><ul>{rows}</ul></section>')
    for n in report.notices:
        parts.append(f'<p class="note">ℹ {e(n)}</p>')
    for err in report.errors:
        parts.append(f'<p class="err">✖ {e(err)}</p>')
    for s in report.sections:
        rows = []
        for i in s.items:
            url = _safe_url(i.url)
            val = e(i.value or "")
            if url:
                val = f'<a href="{e(url)}" rel="noopener noreferrer">{val or e(url)}</a>'
            rows.append(f'<tr><td class="ic" style="color:{_COLORS[i.level]}">{_ICONS[i.level]}</td>'
                        f'<td class="k">{e(i.label)}</td><td style="color:{_COLORS[i.level]}">{val}</td></tr>')
        note = f'<p class="sn">{e(s.note)}</p>' if s.note else ""
        parts.append(f"<section><h2>{e(s.title)}</h2>{note}<table>{''.join(rows)}</table></section>")
    if report.sources:
        src = "".join(f"<li>{'✔' if ok else '·'} {e(n)}{' — ' + e(d) if d else ''}</li>" for n, ok, d in report.sources)
        parts.append(f'<section><h2>Kaynak durumu</h2><ul class="src">{src}</ul></section>')
    when = time.strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(report.title)} — {e(report.target)}</title>
<style>
body{{margin:0;background:#0A0E14;color:#E6EDF3;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:860px;margin:0 auto;padding:16px}}
h1{{font-size:20px;margin:8px 0 2px}} .meta{{color:#7A8899;font-size:13px;margin-bottom:16px}}
section{{background:#121821;border:1px solid #1C2533;border-radius:14px;padding:12px 14px;margin:12px 0}}
section.hl{{border-color:#FF5C7A66;background:#FF5C7A12}}
h2{{font-size:15px;margin:0 0 8px}} table{{width:100%;border-collapse:collapse}}
td{{padding:4px 6px;vertical-align:top;word-break:break-word}} td.k{{color:#7A8899;width:34%}}
td.ic{{width:14px}} a{{color:#00E5FF}} .sn,.note{{color:#7A8899;font-style:italic;font-size:13px}}
.err{{color:#FF5C7A}} ul{{margin:0;padding-left:18px}} .src{{color:#7A8899;font-size:13px}}
footer{{color:#7A8899;font-size:12px;margin:24px 0}}
</style></head><body><main>
<h1>{e(report.title)}</h1>
<div class="meta">Hedef: <b>{e(report.target)}</b> · {when}{' · ' + e(report.summary) if report.summary else ''}</div>
{''.join(parts)}
<footer>{e(generator)} ile oluşturuldu. Yalnızca yasal ve izinli araştırmalar için.</footer>
</main></body></html>"""
