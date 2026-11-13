"""Her aracın her işlemi gerçek servislere karşı: anahtarsız işlemler hatasız
gerçek veri döndürmeli; anahtarlı işlemler anahtar yokken net mesaj vermeli."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tests/samples.py

from pwrosint.core.config import Settings
from pwrosint.core.context import Context
from pwrosint.core.registry import all_tools, parse_inputs
from pwrosint.core.runner import run_action

from samples import NEEDS_KEY, SAMPLES

pytestmark = pytest.mark.skipif(os.environ.get("PWR_LIVE") != "1", reason="canlı testler kapalı")

ALL = [(t, a) for t in all_tools() for a in t.actions if (t.id, a.id) != ("image", "file")]  # yerel dosya: birim testi


@pytest.mark.parametrize("tool, action", ALL, ids=[f"{t.id}-{a.id}" for t, a in ALL])
def test_real_response(tool, action):
    values = parse_inputs(action, SAMPLES[(tool.id, action.id)])
    report = run_action(Context(Settings(timeout=25)), tool, action, values)
    print(report.to_text())
    assert not [e for e in report.errors if e.startswith("Beklenmeyen hata")]
    if (tool.id, action.id) in NEEDS_KEY:
        assert report.missing_key and not report.errors
        return
    assert not report.errors, report.errors
    assert sum(len(s.items) for s in report.sections) >= 2, "gerçek veri dönmedi"
