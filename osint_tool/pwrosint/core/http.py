"""Tüm modüllerin kullandığı HTTP katmanı: ortak oturum, yeniden deneme,
zaman aşımı ve okunur hata mesajları."""

from __future__ import annotations

from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .errors import OsintError

BROWSER_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36"
)


class Http:
    def __init__(self, user_agent: str, timeout: int, pool_size: int = 32, retries: int = 2):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept-Language": "en-US,en;q=0.8"})
        retry = Retry(total=retries, connect=retries, read=retries, backoff_factor=0.5,
                      status_forcelist=(502, 503, 504), allowed_methods=("GET", "HEAD"), raise_on_status=False)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_size, pool_maxsize=pool_size)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def get(self, url: str, **kw: Any) -> requests.Response:
        kw.setdefault("timeout", self.timeout)
        try:
            return self.session.get(url, **kw)
        except requests.exceptions.SSLError as e:
            raise OsintError(f"{_host(url)}: SSL sertifikası doğrulanamadı") from e
        except requests.Timeout as e:
            raise OsintError(f"{_host(url)}: zaman aşımı ({kw['timeout']} sn)") from e
        except requests.ConnectionError as e:
            raise OsintError(f"{_host(url)}: bağlantı kurulamadı") from e
        except requests.RequestException as e:
            raise OsintError(f"{_host(url)}: {e}") from e

    def post(self, url: str, **kw: Any) -> requests.Response:
        kw.setdefault("timeout", self.timeout)
        try:
            return self.session.post(url, **kw)
        except requests.exceptions.SSLError as e:
            raise OsintError(f"{_host(url)}: SSL sertifikası doğrulanamadı") from e
        except requests.Timeout as e:
            raise OsintError(f"{_host(url)}: zaman aşımı ({kw['timeout']} sn)") from e
        except requests.RequestException as e:
            raise OsintError(f"{_host(url)}: bağlantı kurulamadı") from e

    def json(self, url: str, *, ok: tuple[int, ...] = (200,), expect: type = dict, **kw: Any) -> Any:
        """GET + JSON. ``ok`` dışındaki durum kodlarında, JSON olmayan ya da beklenen
        türde (``dict``/``list``) olmayan yanıtlarda OsintError fırlatır. Başarılı bir
        yanıtın gövdesi boşsa ``None`` döner."""
        resp = self.get(url, **kw)
        if resp.status_code not in ok:
            detail = ""
            if resp.status_code in (400, 422):  # istek reddedildi: sunucunun açıklaması tanıya yardımcı olur
                detail = " — " + " ".join(resp.text.split())[:120] if resp.text else ""
            raise OsintError(f"{_host(url)}: HTTP {resp.status_code}{_hint(resp.status_code)}{detail}")
        if resp.status_code == 204 or not resp.content:
            return None
        return parse_json(resp, expect)


def parse_json(resp: requests.Response, expect: type = dict) -> Any:
    host = _host(resp.url or "")
    try:
        data = resp.json()
    except ValueError as e:
        raise OsintError(f"{host}: geçersiz yanıt (JSON değil)") from e
    if not isinstance(data, expect):
        raise OsintError(f"{host}: beklenmeyen yanıt biçimi")
    return data


def _host(url: str) -> str:
    return url.split("/")[2] if "://" in url else url


def _hint(code: int) -> str:
    return {
        401: " (API anahtarı geçersiz)",
        403: " (erişim reddedildi)",
        404: " (bulunamadı)",
        429: " (istek limiti aşıldı, biraz bekleyin)",
    }.get(code, "")
