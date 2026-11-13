import os
import json
from colorama import Fore, Style

# Android/iOS (Flet) üzerinde uygulama dizini salt okunurdur; yazılabilir
# veri dizini FLET_APP_STORAGE_DATA ile verilir. Masaüstünde eskisi gibi
# çalışma dizinindeki config.json kullanılır.
_DATA_DIR = os.environ.get("FLET_APP_STORAGE_DATA")
CONFIG_FILE = os.path.join(_DATA_DIR, "config.json") if _DATA_DIR else "config.json"

DEFAULT_CONFIG = {
    "shodan_api_key": "",
    "virustotal_api_key": "",
    "hunter_api_key": "",
    "securitytrails_api_key": "",
    "censys_api_id": "",
    "censys_api_secret": "",
    "whoisxml_api_key": "",
    "haveibeenpwned_api_key": "",
    "timeout": 10,
    "user_agent": "OSINT-Tool/1.0"
}

# Tüm modüller aynı sözlüğü paylaşır; böylece kaydedilen API anahtarları
# yeniden başlatmaya gerek kalmadan her modülde geçerli olur.
_CONFIG = {}

def load_config():
    if not _CONFIG:
        _CONFIG.update(DEFAULT_CONFIG)
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    _CONFIG.update(json.load(f))
            except Exception:
                pass
    return _CONFIG

def save_config(config):
    if config is not _CONFIG:
        _CONFIG.clear()
        _CONFIG.update(config)
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(_CONFIG, f, indent=2)
        return True
    except Exception:
        return False

def config_menu():
    config = load_config()
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.YELLOW + "====== API ANAHTAR YÖNETİMİ ======" + Style.RESET_ALL)
        for i, (key, value) in enumerate(config.items(), 1):
            value = str(value)
            masked = value[:4] + "****" + value[-4:] if value and len(value) > 8 else ("(boş)" if not value else value)
            print(Fore.GREEN + f" [{i}]" + Fore.WHITE + f" {key}: " + Fore.CYAN + masked)
        print(Fore.RED + " [0] Geri" + Style.RESET_ALL)

        choice = input(Fore.CYAN + "\nSeçim (güncellemek için numara): " + Style.RESET_ALL).strip()
        if choice == '0':
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(config):
                key = list(config.keys())[idx]
                new_val = input(Fore.CYAN + f"Yeni {key}: " + Style.RESET_ALL).strip()
                config[key] = int(new_val) if key == 'timeout' and new_val.isdigit() else new_val
                save_config(config)
                print(Fore.GREEN + "Kaydedildi!" + Style.RESET_ALL)
        except:
            print(Fore.RED + "Geçersiz seçim!" + Style.RESET_ALL)

if __name__ == "__main__":
    config_menu()