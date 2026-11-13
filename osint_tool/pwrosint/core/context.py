from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar
from collections.abc import Callable, Iterable

from .config import Settings
from .errors import Cancelled, MissingApiKey
from .http import Http

T = TypeVar("T")
R = TypeVar("R")


class Context:
    """Bir sorgu boyunca modüllere verilen ortam: ayarlar, HTTP ve iptal."""

    def __init__(self, settings: Settings, http: Http | None = None):
        self.settings = settings
        self.http = http or Http(settings.user_agent, settings.timeout)
        self.cancel_event = threading.Event()

    def check_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise Cancelled()

    def require(self, setting: str, service: str) -> str:
        value = getattr(self.settings, setting, "")
        if not value:
            raise MissingApiKey(service, setting)
        return value

    def parallel(self, fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
        """``fn``'i öğeler üzerinde paralel çalıştırır, sırayı korur, iptali dinler."""
        items = list(items)
        results: list[R] = [None] * len(items)  # type: ignore[list-item]
        with ThreadPoolExecutor(max_workers=self.settings.max_workers) as pool:
            futures = {pool.submit(fn, it): i for i, it in enumerate(items)}
            for fut, i in futures.items():
                if self.cancel_event.is_set():
                    for f in futures:
                        f.cancel()
                    raise Cancelled()
                results[i] = fut.result()
        return results
