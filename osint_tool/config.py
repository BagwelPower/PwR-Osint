import os
import json
from colorama import Fore, Style

CONFIG_FILE = "config.json"

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

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        except:
            pass
    return DEFAULT_CONFIG

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False

def config_menu():
    config = load_config()
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Fore.YELLOW + "====== API ANAHTAR YÖNETİMİ ======" + Style.RESET_ALL)
        for i, (key, value) in enumerate(config.items(), 1):
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
                config[key] = new_val
                save_config(config)
                print(Fore.GREEN + "Kaydedildi!" + Style.RESET_ALL)
        except:
            print(Fore.RED + "Geçersiz seçim!" + Style.RESET_ALL)

if __name__ == "__main__":
    config_menu()