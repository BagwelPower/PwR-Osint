import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pwrosint.core.config import Settings  # noqa: E402
from pwrosint.core.context import Context  # noqa: E402
from pwrosint.core.errors import OsintError  # noqa: E402
from pwrosint.core.http import Http  # noqa: E402


class FakeHttp(Http):
    """URL öneki → yanıt eşlemesi. Eşleşmeyen istek testte hata sayılır."""

    def __init__(self):
        super().__init__("test", 5)
        self.routes: list[tuple[str, object]] = []
        self.calls: list[tuple[str, dict]] = []

    def add(self, prefix: str, body=None, status: int = 200, match_params: dict | None = None):
        self.routes.append((prefix, (status, body, match_params)))
        return self

    def get(self, url, **kw):
        self.calls.append((url, kw))
        params = kw.get("params") or {}
        # En uzun (en özel) önek kazanır; eşitlikte parametre koşulu olan ve sonra eklenen önce gelir.
        ranked = sorted(enumerate(self.routes), key=lambda r: (len(r[1][0]), bool(r[1][1][2]), r[0]), reverse=True)
        for _, (prefix, (status, body, want)) in ranked:
            if url.startswith(prefix) and all(str(params.get(k)) == str(v) for k, v in (want or {}).items()):
                if isinstance(body, Exception):
                    raise body
                resp = requests.Response()
                resp.status_code = status
                resp.url = url
                if isinstance(body, (dict, list)):
                    resp._content = json.dumps(body).encode()
                elif isinstance(body, bytes):
                    resp._content = body
                else:
                    resp._content = (body or "").encode()
                resp._content_consumed = True  # stream=True + iter_content da çalışsın
                resp.encoding = "utf-8"
                return resp
        raise OsintError(f"FakeHttp: beklenmeyen istek {url} {params}")


def doh(answers, status=0, rtype=None):
    """DNS-over-HTTPS JSON yanıtı üretir."""
    codes = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
    return {"Status": status, "Answer": [{"type": codes.get(rtype, 1), "data": a} for a in answers]}


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """Testler kullanıcının gerçek ayar/önbellek dizinine dokunmasın."""
    monkeypatch.setenv("PWR_OSINT_CONFIG", str(tmp_path / "config.json"))


@pytest.fixture
def http():
    return FakeHttp()


@pytest.fixture
def ctx(http):
    return Context(Settings(max_workers=4), http=http)


def add_dns(http: FakeHttp, name: str, rtype: str, answers, status=0):
    http.add("https://cloudflare-dns.com/dns-query", doh(answers, status, rtype),
             match_params={"name": name, "type": rtype})
