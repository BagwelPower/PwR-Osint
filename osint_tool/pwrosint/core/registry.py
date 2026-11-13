"""Araç tanımları. Arayüzler (terminal, Android) menülerini buradan üretir;
yeni bir araç eklemek için bir modülde ``@tool`` ile kaydetmek yeterlidir."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .context import Context
from .report import Report

Runner = Callable[[Context, Report, dict[str, Any]], None]


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    placeholder: str = ""
    kind: str = "text"  # text | email | phone | number | url | password | name
    parse: Callable[[str], Any] = str.strip
    optional: bool = False


@dataclass(frozen=True)
class Action:
    id: str
    title: str
    fields: tuple[Field, ...]
    run: Runner
    needs_key: Optional[str] = None  # ayar adı; arayüz uyarı gösterebilir


@dataclass
class Tool:
    id: str
    title: str
    subtitle: str
    icon: str  # Material ikon adı (ör. "DNS"); arayüz kendi ikon setine çevirir
    category: str
    actions: list[Action] = field(default_factory=list)

    def action(self, action_id: str) -> Action:
        for a in self.actions:
            if a.id == action_id:
                return a
        raise KeyError(action_id)


CATEGORIES = ["Kişi", "Ağ & Domain", "Tehdit İstihbaratı", "Diğer"]

_TOOLS: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    if tool.id in _TOOLS:
        raise ValueError(f"Araç zaten kayıtlı: {tool.id}")
    _TOOLS[tool.id] = tool
    return tool


def all_tools() -> list[Tool]:
    from .. import modules  # noqa: F401  — modüller içe aktarılınca kaydolur

    order = {c: i for i, c in enumerate(CATEGORIES)}
    return sorted(_TOOLS.values(), key=lambda t: order.get(t.category, 99))


def get_tool(tool_id: str) -> Tool:
    all_tools()
    return _TOOLS[tool_id]


def parse_inputs(action: Action, raw: dict[str, str]) -> dict[str, Any]:
    """Ham girdileri doğrular; hatalı alanları {alan: mesaj} olarak ValueError'a koyar."""
    values: dict[str, Any] = {}
    problems: dict[str, str] = {}
    for f in action.fields:
        text = (raw.get(f.name) or "").strip()
        if not text:
            if f.optional:
                values[f.name] = None
                continue
            problems[f.name] = "Bu alan gerekli"
            continue
        try:
            values[f.name] = f.parse(text)
        except ValueError as e:
            problems[f.name] = str(e)
    if problems:
        raise InputError(problems)
    return values


class InputError(ValueError):
    def __init__(self, problems: dict[str, str]):
        super().__init__("; ".join(problems.values()))
        self.problems = problems
