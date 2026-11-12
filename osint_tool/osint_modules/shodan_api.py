import requests
from colorama import Fore, Style
from config import load_config

config = load_config()

def shodan_host(ip):
    api_key = config.get('shodan_api_key')
    if not api_key:
        print(Fore.RED + "HATA: Shodan API anahtarı ayarlanmamış!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 Shodan Host: {ip}\n" + Style.RESET_ALL)
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        resp = requests.get(url, timeout=config.get('timeout', 15))
        if resp.status_code == 200:
            data = resp.json()
            print(Fore.WHITE + f"  IP:        " + Fore.GREEN + data.get('ip_str', 'N/A'))
            print(Fore.WHITE + f"  Org:       " + Fore.CYAN + data.get('org', 'N/A'))
            print(Fore.WHITE + f"  ISP:       " + Fore.CYAN + data.get('isp', 'N/A'))
            print(Fore.WHITE + f"  Country:   " + Fore.CYAN + data.get('country_name', 'N/A'))
            print(Fore.WHITE + f"  City:      " + Fore.CYAN + data.get('city', 'N/A'))
            print(Fore.WHITE + f"  Ports:     " + Fore.YELLOW + str(data.get('ports', [])))

            print(Fore.YELLOW + "\n  Servisler:")
            for svc in data.get('data', [])[:5]:
                port = svc.get('port')
                prod = svc.get('product', 'Bilinmiyor')
                ver = svc.get('version', '')
                print(Fore.WHITE + f"    Port {port}: " + Fore.GREEN + f"{prod} {ver}".strip())
        elif resp.status_code == 404:
            print(Fore.YELLOW + "  Bu IP Shodan'da bulunamadı.")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}: {resp.text}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def shodan_search(query):
    api_key = config.get('shodan_api_key')
    if not api_key:
        print(Fore.RED + "HATA: Shodan API anahtarı ayarlanmamış!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 Shodan Arama: {query}\n" + Style.RESET_ALL)
    try:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
        resp = requests.get(url, timeout=config.get('timeout', 15))
        if resp.status_code == 200:
            data = resp.json()
            print(Fore.GREEN + f"  Toplam: {data.get('total', 0)} sonuç")
            for m in data.get('matches', [])[:10]:
                ip = m.get('ip_str')
                port = m.get('port')
                org = m.get('org', 'N/A')
                print(Fore.WHITE + f"  {ip}:{port} - " + Fore.CYAN + org)
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def shodan_menu():
    print(Fore.YELLOW + "\n─── SHODAN API ───" + Style.RESET_ALL)
    print(" [1] IP Sorgulama")
    print(" [2] Arama (query)")
    print(" [0] Geri")
    choice = input(Fore.CYAN + "\nSeçim: " + Style.RESET_ALL).strip()
    if choice == '1':
        ip = input("IP: ").strip()
        shodan_host(ip)
    elif choice == '2':
        q = input("Sorgu (örn: port:22 country:TR): ").strip()
        shodan_search(q)