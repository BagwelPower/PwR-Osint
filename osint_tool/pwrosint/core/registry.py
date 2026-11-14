"""Araç tanımları. Arayüzler (terminal, Android) menülerini buradan üretir;
yeni bir araç eklemek için bir modülde ``@tool`` ile kaydetmek yeterlidir."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from collections.abc import Callable

from .context import Context
from .report import Report

Runner = Callable[[Context, Report, dict[str, Any]], None]


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    placeholder: str = ""
    kind: str = "text"  # text | email | phone | number | url | password | name | multiline | file
    parse: Callable[[str], Any] = str.strip
    optional: bool = False
    # Hassas alan: değeri geçmişe, rapor başlığına, kayıtlı raporlara ve dışa aktarmaya yazılmaz
    # (JWT, e-posta başlığı, şifre gibi). "password" türü her zaman hassastır.
    sensitive: bool = False
    # Dosya alanı için seçilebilecek uzantılar (boş: her tür dosya)
    accept: tuple[str, ...] = ()

    @property
    def is_sensitive(self) -> bool:
        return self.sensitive or self.kind == "password"


@dataclass(frozen=True)
class Action:
    id: str
    title: str
    fields: tuple[Field, ...]
    run: Runner
    needs_key: Optional[str] = None   # bu anahtar olmadan işlem hiç çalışmaz
    better_with: Optional[str] = None  # anahtar olmadan yedek kaynakla çalışır, anahtarla daha ayrıntılı
    # Aktif araç (hedefe doğrudan bağlantı açar): her çalıştırmadan önce kullanıcıya gösterilen onay metni.
    consent: Optional[str] = None


@dataclass
class Tool:
    id: str
    title: str
    subtitle: str
    icon: str  # Material ikon adı (ör. "DNS"); arayüz kendi ikon setine çevirir
    category: str
    actions: list[Action] = field(default_factory=list)
    description: str = ""          # aracın ne yaptığı, ne işe yaradığı
    sources: tuple[str, ...] = ()  # sorgulanan servisler
    limits: str = ""               # bilinmesi gereken sınırlar

    def action(self, action_id: str) -> Action:
        for a in self.actions:
            if a.id == action_id:
                return a
        raise KeyError(action_id)


CATEGORY_INFO = {
    "Kişi": "Kullanıcı adı, e-posta, telefon ve isimden kişinin dijital izini çıkarır.",
    "Sosyal Medya": "Platform hesaplarının ayrıntılı analizi: aktivite, bağlantılar, sızan bilgiler.",
    "Ağ & Domain": "Domain ve IP altyapısı: WHOIS, DNS, sertifika, alt alan adları, ağ sahibi.",
    "Web": "Web sitelerinin teknolojisi, iletişim bilgileri, gizli yolları ve geçmiş taramaları.",
    "Tehdit İstihbaratı": "Sızıntılar, zafiyetler (CVE), zararlı itibarı ve kara listeler.",
    "Dolandırıcılık & Oltalama": "Şüpheli SMS/linkler, sahte e-postalar, taklit domainler ve IBAN kontrolü.",
    "Ağ Araçları": "Sistem ve ağ yöneticisinin saha araçları: bağlantı, port, yerel ağ, ping, HTTP, hız.",
    "Dosya & Görsel": "Şüpheli dosyaların (PDF, Office, APK…) ve fotoğrafların gizli içeriği.",
    "Kripto": "Kripto para adreslerinin bakiye ve işlem geçmişi.",
    "Araç Kutusu": "Günlük işler için çevrimdışı araçlar: subnet, JWT, hash, kodlama, şifre, zaman.",
    "Konum & Araç": "Koordinat, Wi-Fi/MAC ve araç (VIN, plaka) sorguları.",
}
CATEGORIES = list(CATEGORY_INFO)

_TOOLS: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    if tool.id in _TOOLS:
        raise ValueError(f"Araç zaten kayıtlı: {tool.id}")
    _TOOLS[tool.id] = tool
    return tool


def all_tools() -> list[Tool]:
    from .. import modules  # noqa: F401  — modüller içe aktarılınca kaydolur
    from ..modules.docs import apply
    apply(_TOOLS.values())

    order = {c: i for i, c in enumerate(CATEGORIES)}
    featured = {"fullscan"}  # kategorisinin en kapsamlı aracı başta görünsün
    return sorted(_TOOLS.values(), key=lambda t: (order.get(t.category, 99), t.id not in featured))


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
