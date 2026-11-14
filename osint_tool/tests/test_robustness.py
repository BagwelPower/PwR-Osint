"""Hiçbir araç, ağ ne kadar kötü davranırsa davransın çökmemeli: her durumda
okunur bir hata mesajı veya geçerli bir rapor üretmeli."""

import pytest

from pwrosint.core.config import Settings
from pwrosint.core.context import Context
from pwrosint.core.errors import OsintError
from pwrosint.core.registry import all_tools, parse_inputs
from pwrosint.core.runner import run_action

from conftest import FakeHttp
from samples import SAMPLES

ALL_ACTIONS = [(t, a) for t in all_tools() for a in t.actions]
KEYS = dict(shodan_api_key="k", virustotal_api_key="k", hunter_api_key="k", haveibeenpwned_api_key="k",
            wigle_api_name="n", wigle_api_token="t", github_token="t")


def test_every_action_has_a_sample():
    missing = {(t.id, a.id) for t, a in ALL_ACTIONS} - set(SAMPLES)
    assert not missing, f"samples.py'ye ekleyin: {missing}"


def test_samples_pass_validation():
    for t, a in ALL_ACTIONS:
        parse_inputs(a, SAMPLES[(t.id, a.id)])


def _ctx(body, status=200):
    http = FakeHttp()
    http.add("http", body, status=status)
    return Context(Settings(max_workers=4, **KEYS), http=http)


SCENARIOS = {
    "ağ kopuk": (OsintError("bağlantı kurulamadı"), 200),
    "boş JSON": ({}, 200),
    "boş liste": ([], 200),
    "anlamsız metin": ("<html>bakım çalışması</html>", 200),
    "sunucu hatası": ("Internal Server Error", 500),
    "erişim reddedildi": ("Forbidden", 403),
}


@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("tool, action", ALL_ACTIONS, ids=[f"{t.id}-{a.id}" for t, a in ALL_ACTIONS])
def test_never_crashes(tool, action, scenario, monkeypatch):
    # TLS aracı ham soket açar; ağ yokmuş gibi davransın
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(OSError("ağ yok")))
    body, status = SCENARIOS[scenario]
    values = parse_inputs(action, SAMPLES[(tool.id, action.id)])
    report = run_action(_ctx(body, status), tool, action, values)
    unexpected = [e for e in report.errors if e.startswith("Beklenmeyen hata")]
    assert not unexpected, unexpected
    assert report.sections or report.errors  # kullanıcı boş ekranla kalmamalı
