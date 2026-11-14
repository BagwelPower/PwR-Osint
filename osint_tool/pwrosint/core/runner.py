"""Bir aracı çalıştırıp her durumda (hata, iptal) geçerli bir rapor döndürür."""

from __future__ import annotations

import logging
import time
from typing import Any, Optional
from collections.abc import Callable

from .context import Context
from .errors import Cancelled, MissingApiKey, OsintError
from .registry import Action, Tool
from .report import Report

log = logging.getLogger("pwrosint")


def run_action(ctx: Context, tool: Tool, action: Action, values: dict[str, Any],
               on_change: Optional[Callable[[Report], None]] = None) -> Report:
    target = " / ".join(_fmt(values[f.name]) for f in action.fields
                        if not f.is_sensitive and values.get(f.name) is not None)
    if len(target) > 80:
        target = target[:77] + "…"
    report = Report(f"{tool.title} · {action.title}", target, on_change)
    report.tool_id, report.action_id = tool.id, action.id
    started = time.monotonic()
    try:
        action.run(ctx, report, values)
    except MissingApiKey as e:
        report.missing_key = (e.service, e.setting)
    except Cancelled:
        report.error("Sorgu iptal edildi")
    except OsintError as e:
        report.error(str(e))
    except Exception as e:  # beklenmeyen hata: arayüz çökmesin, ama logla
        log.exception("%s/%s başarısız", tool.id, action.id)
        report.error(f"Beklenmeyen hata: {type(e).__name__}: {e}")
    report.elapsed = time.monotonic() - started
    report.changed()
    return report


def _fmt(v: Any) -> str:
    if isinstance(v, dict):  # ayrıştırılmış girdi (ör. plaka): kullanıcıya görünen biçimi
        return str(v.get("plate") or v.get("display") or next(iter(v.values()), ""))
    if isinstance(v, tuple):
        return ", ".join(str(x) for x in v)
    return str(v)
