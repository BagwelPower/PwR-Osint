import requests
from colorama import Fore, Style
from config import load_config

config = load_config()

def generate_permutations(first, last, domain):
    first = first.lower().strip()
    last = last.lower().strip()
    domain = domain.lower().strip()

    perms = [
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{first[0]}{last}@{domain}",
        f"{first[0]}.{last}@{domain}",
        f"{first}{last[0]}@{domain}",
        f"{first}.{last[0]}@{domain}",
        f"{last}{first}@{domain}",
        f"{last}.{first}@{domain}",
    ]
    return perms

def hunter_search(domain):
    api_key = config.get('hunter_api_key')
    if not api_key:
        print(Fore.RED + "HATA: Hunter.io API anahtarı ayarlanmamış!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 Hunter.io Araması: {domain}\n" + Style.RESET_ALL)
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        resp = requests.get(url, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            emails = data.get('emails', [])
            print(Fore.GREEN + f"  {len(emails)} e-posta bulundu.\n")
            for e in emails:
                val = e.get('value')
                typ = e.get('type')
                print(Fore.WHITE + f"  • {val:<30} | Tip: {typ}")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}: {resp.text}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def email_extra_menu():
    print(Fore.YELLOW + "\n─── EK E-POSTA ARAÇLARI ───" + Style.RESET_ALL)
    print(" [1] E-posta Permutator (Olasılık Oluşturucu)")
    print(" [2] Hunter.io Domain Sorgulama (API)")
    print(" [0] Geri")

    choice = input(Fore.CYAN + "\nSeçim: " + Style.RESET_ALL).strip()
    if choice == '1':
        first = input("Ad: ").strip()
        last = input("Soyad: ").strip()
        domain = input("Domain (örn: sirket.com): ").strip()
        perms = generate_permutations(first, last, domain)
        print(Fore.GREEN + f"\nOluşturulan {len(perms)} olasılık:")
        for p in perms:
            print(Fore.WHITE + f"  {p}")
    elif choice == '2':
        domain = input("Domain: ").strip()
        hunter_search(domain)
