"""Ayarlar: API anahtarları ve ağ seçenekleri.

Konum önceliği:
1. ``PWR_OSINT_CONFIG`` ortam değişkeni (tam dosya yolu)
2. ``FLET_APP_STORAGE_DATA`` (Android/iOS uygulamasının yazılabilir dizini)
3. Çalışma dizinindeki ``config.json`` (eski sürümlerle uyum)
4. ``~/.pwr-osint/config.json``
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, fields
from pathlib import Path


@dataclass
class Settings:
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    hunter_api_key: str = ""
    haveibeenpwned_api_key: str = ""
    wigle_api_name: str = ""
    wigle_api_token: str = ""
    ipinfo_token: str = ""
    github_token: str = ""
    timeout: int = 10
    max_workers: int = 16
    user_agent: str = "PwR-Osint/2.1 (+https://github.com/BagwelPower/PwR-Osint)"
    disclaimer_accepted: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        known = {f.name: f for f in fields(cls)}
        clean = {}
        for key, value in data.items():
            if key not in known:
                continue
            default = known[key].default
            try:
                if isinstance(default, bool):
                    value = value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
                elif isinstance(default, int):
                    value = max(1, int(value))
                else:
                    value = "" if value is None else str(value).strip()
            except (TypeError, ValueError):
                continue
            clean[key] = value
        return cls(**clean)

    def to_dict(self) -> dict:
        return asdict(self)


API_KEY_FIELDS: list[tuple[str, str, str]] = [
    # (ayar adı, görünen ad, anahtarın alındığı adres)
    ("shodan_api_key", "Shodan", "https://account.shodan.io/"),
    ("virustotal_api_key", "VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    ("hunter_api_key", "Hunter.io", "https://hunter.io/api-keys"),
    ("haveibeenpwned_api_key", "Have I Been Pwned", "https://haveibeenpwned.com/API/Key"),
    ("ipinfo_token", "IPinfo (isteğe bağlı)", "https://ipinfo.io/account/token"),
    ("github_token", "GitHub token (isteğe bağlı)", "https://github.com/settings/tokens"),
    ("wigle_api_name", "WiGLE API Name", "https://wigle.net/account"),
    ("wigle_api_token", "WiGLE API Token", "https://wigle.net/account"),
]


def config_path() -> Path:
    if env := os.environ.get("PWR_OSINT_CONFIG"):
        return Path(env)
    if data_dir := os.environ.get("FLET_APP_STORAGE_DATA"):
        return Path(data_dir) / "config.json"
    legacy = Path.cwd() / "config.json"
    if legacy.exists():
        return legacy
    return Path.home() / ".pwr-osint" / "config.json"


_lock = threading.Lock()


def load_settings(path: Path | None = None) -> Settings:
    path = path or config_path()
    try:
        with open(path, encoding="utf-8") as f:
            return Settings.from_dict(json.load(f))
    except (OSError, ValueError):
        return Settings()


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    """Ayarları atomik olarak yazar; hata durumunda OSError fırlatır."""
    path = path or config_path()
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(settings.to_dict(), f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)  # API anahtarları: sadece sahibi okuyabilsin
        except OSError:
            pass
    return path
