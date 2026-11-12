import requests
import hashlib
from colorama import Fore, Style
from config import load_config

config = load_config()

def hibp_check_email(email):
    print(Fore.CYAN + f"\n🔍 HIBP Sorgulaması: {email}\n" + Style.RESET_ALL)
    headers = {
        'User-Agent': config.get('user_agent', 'OSINT-Tool/1.0'),
        'hibp-api-key': config.get('haveibeenpwned_api_key', '')
    }
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        resp = requests.get(url, headers=headers, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            breaches = resp.json()
            print(Fore.RED + f"  ⚠️  {len(breaches)} SIZMA BULUNDU:\n")
            for b in breaches:
                name = b.get('Name', 'Bilinmiyor')
                date = b.get('BreachDate', 'Bilinmiyor')
                desc = b.get('Description', '')[:100]
                print(Fore.WHITE + f"  • {name} ({date})")
                print(Fore.YELLOW + f"    {desc}...")
        elif resp.status_code == 404:
            print(Fore.GREEN + "  ✅ Bu e-posta bilinen herhangi bir sızmada bulunamadı.")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def hibp_check_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = requests.get(url, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                h, count = line.split(':')
                if h == suffix:
                    print(Fore.RED + f"\n  ⚠️  Bu şifre {count} kez sızmış! KULLANMAYIN!")
                    return
            print(Fore.GREEN + "\n  ✅ Bu şifre bilinen sızmalarda bulunamadı.")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def hibp_menu():
    print(Fore.YELLOW + "\n─── HAVE I BEEN PWNED ───" + Style.RESET_ALL)
    print(" [1] E-posta Sızma Kontrolü")
    print(" [2] Şifre Sızma Kontrolü (K-anonimlik)")
    print(" [0] Geri")
    choice = input(Fore.CYAN + "\nSeçim: " + Style.RESET_ALL).strip()
    if choice == '1':
        email = input("E-posta: ").strip()
        hibp_check_email(email)
    elif choice == '2':
        pwd = input("Şifre (görünmez): ").strip()
        hibp_check_password(pwd)