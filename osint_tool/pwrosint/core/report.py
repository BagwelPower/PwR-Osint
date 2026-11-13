"""Modüllerin döndürdüğü yapılandırılmış sonuç modeli.

Modüller ekrana bir şey basmaz; bir ``Report`` doldurur. Aynı rapor terminalde
rich ile, telefonda Flet ile, ya da ``--json`` ile makine okunur biçimde
gösterilebilir.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Callable, Optional


class Level(str, Enum):
    """Bir bulgunun önemi; arayüzler bunu renge çevirir."""

    INFO = "info"
    OK = "ok"
    WARN = "warn"
    BAD = "bad"
    MUTED = "muted"


@dataclass
class Item:
    label: str
    value: str = ""
    url: Optional[str] = None
    level: Level = Level.INFO

    def to_dict(self) -> dict:
        d = asdict(self)
        d["level"] = self.level.value
        return d


@dataclass
class Section:
    title: str
    items: list[Item] = field(default_factory=list)
    note: Optional[str] = None

    def add(self, label: str, value: object = "", *, url: Optional[str] = None,
            level: Level = Level.INFO) -> "Section":
        self.items.append(Item(label, "" if value is None else str(value), url, level))
        return self

    def link(self, label: str, url: str) -> "Section":
        return self.add(label, url, url=url)


class Report:
    """Bir sorgunun sonucu. Bölümler eklendikçe dinleyiciler haberdar edilir,
    böylece arayüzler uzun sorgularda sonuçları canlı gösterebilir."""

    def __init__(self, title: str, target: str = "",
                 on_change: Optional[Callable[["Report"], None]] = None):
        self.title = title
        self.target = target
        self.sections: list[Section] = []
        self.errors: list[str] = []
        self.summary: Optional[str] = None
        self.elapsed: Optional[float] = None
        # Sorgulanan kaynakların durumu: (ad, başarılı mı, ayrıntı). Sonuçlardan ayrı
        # tutulur ki bir kaynağın limiti dolunca rapor "bozuk" görünmesin.
        self.sources: list[tuple[str, bool, str]] = []
        # Hata olmayan ama kullanıcının bilmesi gereken durumlar (ör. yedek kaynak kullanıldı).
        self.notices: list[str] = []
        # Eksik API anahtarı: (servis, ayar adı). Arayüz bunu hata değil, uyarı olarak gösterir.
        self.missing_key: Optional[tuple[str, str]] = None
        self._on_change = on_change
        self._lock = threading.Lock()

    # -- yazma ---------------------------------------------------------
    def section(self, title: str, note: Optional[str] = None) -> Section:
        sec = Section(title, note=note)
        with self._lock:
            self.sections.append(sec)
        return sec

    def source(self, name: str, ok: bool, detail: str = "") -> None:
        with self._lock:
            self.sources.append((name, ok, detail))

    def notice(self, message: str) -> None:
        with self._lock:
            if message not in self.notices:
                self.notices.append(message)

    def highlights(self, limit: int = 8) -> list[tuple[str, Item]]:
        """Rapordaki kritik (BAD) ve dikkat (WARN) bulgular, önem sırasıyla. Aynı etiketin birçok
        bölümde tekrarı (ör. her sızıntıdaki 'Sızan veriler') tek satırda toplanır."""
        out: list[tuple[str, Item]] = []
        for lvl in (Level.BAD, Level.WARN):
            groups: dict[str, list[tuple[str, Item]]] = {}
            for s in self.sections:
                for i in s.items:
                    if i.level == lvl:
                        groups.setdefault(i.label, []).append((s.title, i))
            for label, entries in groups.items():
                if len(entries) > 2:
                    titles = [t.split(" — ")[0] for t, _ in entries]
                    out.append((f"{len(entries)} bölümde", Item(
                        label, f"{len(entries)} kayıtta: " + ", ".join(titles[:6]) + (" …" if len(titles) > 6 else ""),
                        level=lvl)))
                else:
                    out.extend(entries)
        return out[:limit]

    def error(self, message: str) -> None:
        with self._lock:
            self.errors.append(message)
        self.changed()

    def changed(self) -> None:
        """Bir bölüm doldurulduktan sonra çağrılır."""
        if self._on_change:
            self._on_change(self)

    # -- okuma ---------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "target": self.target,
            "summary": self.summary,
            "sections": [
                {"title": s.title, "note": s.note, "items": [i.to_dict() for i in s.items]}
                for s in self.sections
            ],
            "errors": list(self.errors),
            "notices": list(self.notices),
            "missing_key": list(self.missing_key) if self.missing_key else None,
            "sources": [{"name": n, "ok": ok, "detail": d} for n, ok, d in self.sources],
            "highlights": [{"section": t, **i.to_dict()} for t, i in self.highlights()],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def to_text(self) -> str:
        """Panoya kopyalamak / paylaşmak için düz metin."""
        out = [f"# {self.title}" + (f" — {self.target}" if self.target else "")]
        if self.summary:
            out.append(self.summary)
        for n in self.notices:
            out.append(f"Not: {n}")
        hl = self.highlights()
        if hl:
            out.append("\n## Önemli bulgular")
            out.extend(f"  {'✖' if i.level == Level.BAD else '!'} {i.label}: {i.value}".rstrip(": ") for _, i in hl)
        for s in self.sections:
            out.append(f"\n## {s.title}")
            if s.note:
                out.append(s.note)
            width = max((len(i.label) for i in s.items if i.value), default=0)
            for i in s.items:
                out.append(f"  {i.label:<{width}}  {i.value}".rstrip() if i.value else f"  {i.label}")
        if self.missing_key:
            out.append(f"\n! {self.missing_key[0]} API anahtarı gerekli (Ayarlar → {self.missing_key[1]})")
        if self.sources:
            out.append("\n## Kaynak durumu")
            out.extend(f"  {'✔' if ok else '·'} {n}" + (f" — {d}" if d else "") for n, ok, d in self.sources)
        if self.errors:
            out.append("\n## Hatalar")
            out.extend(f"  ! {e}" for e in self.errors)
        return "\n".join(out)
