"""Tam Domain Taraması: domain araçlarını sırayla çalıştırıp tek raporda birleştirir."""

from __future__ import annotations

from ..core import validate
from ..core.context import Context
from ..core.errors import Cancelled
from ..core.registry import Action, Field, Tool, get_tool, register
from ..core.report import Level, Report
from ..core.runner import run_action

STEPS = (
    ("host", "profile", "target", "Altyapı"),
    ("dns", "records", "domain", "DNS"),
    ("tls", "analyze", "domain", "TLS"),
    ("subdomain", "enumerate", "domain", "Subdomain"),
    ("site", "analyze", "url", "Site"),
    ("urlscan", "search", "domain", "urlscan"),
    ("wayback", "scan", "domain", "Arşiv"),
    ("phishing", "typosquat", "domain", "Taklit"),
)
SKIP_SECTIONS = {"Dış araçlar", "Dış kaynaklar", "Link", "Linkler", "Haritalar"}


def _fullscan(ctx: Context, rep: Report, v: dict) -> None:
    domain: str = v["domain"]
    done: list[str] = []
    for i, (tool_id, action_id, field, label) in enumerate(STEPS, 1):
        ctx.check_cancelled()
        rep.summary = f"{i}/{len(STEPS)} · {label} taranıyor… (tamamlanan: {', '.join(done) or '—'})"
        rep.changed()
        tool = get_tool(tool_id)
        value = f"https://{domain}/" if field == "url" else domain
        sub = run_action(ctx, tool, tool.action(action_id), {field: value})
        if ctx.cancel_event.is_set():
            raise Cancelled()
        for sec in sub.sections:
            if sec.title in SKIP_SECTIONS:
                continue
            merged = rep.section(f"{label} · {sec.title}", sec.note)
            merged.items.extend(sec.items)
        for name, ok, detail in sub.sources:
            rep.source(f"{label}: {name}", ok, detail)
        for n in sub.notices:
            rep.notice(f"{label}: {n}")
        for err in sub.errors:
            rep.source(f"{label} aracı", False, err)
        if sub.summary:
            rep.section(f"{label} · Özet").add(sub.summary)
        done.append(label)
        rep.changed()
    bad = sum(1 for s in rep.sections for it in s.items if it.level == Level.BAD)
    warn = sum(1 for s in rep.sections for it in s.items if it.level == Level.WARN)
    rep.summary = (f"{len(STEPS)} araç tamamlandı · {bad} kritik, {warn} dikkat gerektiren bulgu. "
                   "Ayrıntılar aşağıda araç adına göre gruplanmıştır.")


register(Tool("fullscan", "Tam Domain Taraması", "8 aracı tek seferde çalıştırır, tek raporda birleştirir",
              "TRACK_CHANGES", "Ağ & Domain", [
                  Action("scan", "Tara", (Field("domain", "Domain", "ornek.com", "url", validate.domain),),
                         _fullscan)]))
