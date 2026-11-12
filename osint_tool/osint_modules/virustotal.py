import requests
from colorama import Fore, Style
from config import load_config

config = load_config()

def vt_check_domain(domain):
    api_key = config.get('virustotal_api_key')
    if not api_key:
        print(Fore.RED + "HATA: VirusTotal API anahtarı ayarlanmamış!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 VirusTotal Domain: {domain}\n" + Style.RESET_ALL)
    headers = {'x-apikey': api_key}
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        resp = requests.get(url, headers=headers, timeout=config.get('timeout', 15))
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            print(Fore.WHITE + f"  Kategori:   " + Fore.CYAN + str(data.get('categories', {})))
            print(Fore.WHITE + f"  Reputation: " + (Fore.RED if data.get('reputation', 0) < 0 else Fore.GREEN) + str(data.get('reputation', 'N/A')))
            print(Fore.YELLOW + "\n  Analiz Sonuçları:")
            for k, v in stats.items():
                color = Fore.RED if k == 'malicious' else (Fore.YELLOW if k == 'suspicious' else Fore.GREEN)
                print(Fore.WHITE + f"    {k}: " + color + str(v))
        elif resp.status_code == 404:
            print(Fore.YELLOW + "  Bu domain VT'de bulunamadı.")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def vt_check_ip(ip):
    api_key = config.get('virustotal_api_key')
    if not api_key:
        print(Fore.RED + "HATA: VirusTotal API anahtarı ayarlanmamış!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 VirusTotal IP: {ip}\n" + Style.RESET_ALL)
    headers = {'x-apikey': api_key}
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        resp = requests.get(url, headers=headers, timeout=config.get('timeout', 15))
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            print(Fore.WHITE + f"  ASN:        " + Fore.CYAN + str(data.get('asn', 'N/A')))
            print(Fore.WHITE + f"  Country:    " + Fore.CYAN + str(data.get('country', 'N/A')))
            print(Fore.YELLOW + "\n  Analiz Sonuçları:")
            for k, v in stats.items():
                color = Fore.RED if k == 'malicious' else (Fore.YELLOW if k == 'suspicious' else Fore.GREEN)
                print(Fore.WHITE + f"    {k}: " + color + str(v))
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

def vt_menu():
    print(Fore.YELLOW + "\n─── VIRUSTOTAL API ───" + Style.RESET_ALL)
    print(" [1] Domain Sorgulama")
    print(" [2] IP Sorgulama")
    print(" [0] Geri")
    choice = input(Fore.CYAN + "\nSeçim: " + Style.RESET_ALL).strip()
    if choice == '1':
        d = input("Domain: ").strip()
        vt_check_domain(d)
    elif choice == '2':
        i = input("IP: ").strip()
        vt_check_ip(i)