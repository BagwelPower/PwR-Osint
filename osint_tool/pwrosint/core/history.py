"""Son aramalar. Şifre alanları asla kaydedilmez."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import config_path
from .registry import Action

MAX_ENTRIES = 30


@dataclass
class Entry:
    tool: str
    action: str
    values: dict[str, str]
    when: float

    @property
    def label(self) -> str:
        return " / ".join(self.values.values())


class History:
    def __init__(self, path: Path | None = None):
        self.path = path or config_path().with_name("history.json")
        self.entries: list[Entry] = self._load()

    def _load(self) -> list[Entry]:
        try:
            with open(self.path, encoding="utf-8") as f:
                return [Entry(**e) for e in json.load(f)][:MAX_ENTRIES]
        except (OSError, ValueError, TypeError):
            return []

    def add(self, tool_id: str, action: Action, raw: dict[str, str]) -> None:
        values = {f.name: raw.get(f.name, "") for f in action.fields if not f.is_sensitive}
        if not any(values.values()):
            return
        self.entries = [e for e in self.entries
                        if not (e.tool == tool_id and e.action == action.id and e.values == values)]
        self.entries.insert(0, Entry(tool_id, action.id, values, time.time()))
        del self.entries[MAX_ENTRIES:]
        self._save()

    def clear(self) -> None:
        self.entries = []
        self._save()

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump([asdict(e) for e in self.entries], f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError:
            pass  # geçmiş kritik değil; yazılamazsa sessizce atla
