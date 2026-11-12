import requests
import re
from colorama import Fore, Style
from config import load_config

config = load_config()

def enumerate_subdomains(domain):
    print(Fore.CYAN + f"\n🔍 Subdomain Enum: {domain}\n" + Style.RESET_ALL)
    found = set()

    # crt.sh - SSL sertifikalarından
    print(Fore.YELLOW + "─── crt.sh (SSL Sertifikaları) ───" + Style.RESET_ALL)
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '').strip()
                for n in name.split('\n'):
                    n = n.strip().lower()
                    if n.endswith(f'.{domain}') or n == domain:
                        found.add(n)
            print(Fore.GREEN + f"  {len(found)} subdomain bulundu (crt.sh)")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

    # DNSDumpster (HTML parse)
    print(Fore.YELLOW + "\n─── DNSDumpster ───" + Style.RESET_ALL)
    try:
        url = "https://dnsdumpster.com/"
        headers = {'User-Agent': config.get('user_agent', 'OSINT-Tool/1.0')}
        s = requests.Session()
        # CSRF token al
        r = s.get(url, headers=headers, timeout=config.get('timeout', 10))
        csrf = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text)
        if csrf:
            token = csrf.group(1)
            post_data = {
                'csrfmiddlewaretoken': token,
                'targetip': domain,
                'user': 'free'
            }
            h = {'Referer': url, 'User-Agent': config.get('user_agent', 'OSINT-Tool/1.0')}
            r = s.post(url, data=post_data, headers=h, timeout=config.get('timeout', 15))
            # Sonuçları parse et
            subdomains = re.findall(r'([a-zA-Z0-9\-]+\.' + re.escape(domain) + r')', r.text)
            for sd in subdomains:
                found.add(sd.lower())
            print(Fore.GREEN + f"  +{len(subdomains)} subdomain (DNSDumpster)")
        else:
            print(Fore.YELLOW + "  CSRF token alınamadı")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

    # HackerTarget API
    print(Fore.YELLOW + "\n─── HackerTarget API ───" + Style.RESET_ALL)
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=config.get('timeout', 10))
        if resp.status_code == 200 and 'error' not in resp.text.lower():
            for line in resp.text.strip().split('\n'):
                if line:
                    sd = line.split(',')[0].strip().lower()
                    found.add(sd)
            print(Fore.GREEN + f"  +{len(found)} toplam (HackerTarget)")
        else:
            print(Fore.YELLOW + "  Limit veya hata")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

    # Sonuçları göster
    if found:
        print(Fore.YELLOW + "\n─── BULUNAN SUBDOMAINLER ───" + Style.RESET_ALL)
        for sd in sorted(found):
            try:
                import socket
                ip = socket.gethostbyname(sd)
                print(Fore.WHITE + f"  {sd:<50} → " + Fore.CYAN + ip)
            except:
                print(Fore.WHITE + f"  {sd:<50} → " + Fore.RED + "Çözümlenemedi")
    else:
        print(Fore.RED + "\n  Hiç subdomain bulunamadı.")

    # Dış Linkler
    print(Fore.YELLOW + "\n─── Dış Araçlar ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  crt.sh:          " + Fore.CYAN + f"https://crt.sh/?q=%25.{domain}")
    print(Fore.WHITE + f"  DNSDumpster:     " + Fore.CYAN + f"https://dnsdumpster.com/#{domain}")
    print(Fore.WHITE + f"  SecurityTrails:  " + Fore.CYAN + f"https://securitytrails.com/domain/{domain}/subdomains")
    print(Fore.WHITE + f"  SubdomainFinder: " + Fore.CYAN + f"https://subdomainfinder.c99.nl/{domain}")
    print(Fore.WHITE + f"  Amass Online:    " + Fore.CYAN + f"https://amass.owasp.org/")