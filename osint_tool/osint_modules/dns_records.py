import socket
import requests
from colorama import Fore, Style
from config import load_config

config = load_config()

def get_dns_records(domain):
    print(Fore.CYAN + f"\n🔍 DNS Kayıtları: {domain}\n" + Style.RESET_ALL)

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for rtype in record_types:
        try:
            if rtype == 'A':
                answers = socket.getaddrinfo(domain, None, socket.AF_INET)
                ips = list(set(a[4][0] for a in answers))
                print(Fore.WHITE + f"  {rtype:6} → " + Fore.GREEN + ", ".join(ips))
            elif rtype == 'AAAA':
                try:
                    answers = socket.getaddrinfo(domain, None, socket.AF_INET6)
                    ips = list(set(a[4][0] for a in answers))
                    print(Fore.WHITE + f"  {rtype:6} → " + Fore.GREEN + ", ".join(ips))
                except:
                    print(Fore.WHITE + f"  {rtype:6} → " + Fore.RED + "Yok")
            else:
                # Diğer kayıtlar için basit çözüm - socket sınırlı
                print(Fore.WHITE + f"  {rtype:6} → " + Fore.YELLOW + "Manuel sorgulama gerekli")
        except Exception as e:
            print(Fore.WHITE + f"  {rtype:6} → " + Fore.RED + f"Hata: {e}")

    # DNS over HTTPS (Google) - TXT, MX vb. için
    print(Fore.YELLOW + "\n─── DoH (Google DNS) ile Detaylı Sorgulama ───" + Style.RESET_ALL)
    for rtype in ['MX', 'TXT', 'NS', 'CNAME', 'SOA']:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            resp = requests.get(url, timeout=config.get('timeout', 10))
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get('Answer', [])
                if answers:
                    for ans in answers:
                        print(Fore.WHITE + f"  {rtype:6} → " + Fore.GREEN + str(ans.get('data', '')))
                else:
                    print(Fore.WHITE + f"  {rtype:6} → " + Fore.RED + "Kayıt yok")
            else:
                print(Fore.WHITE + f"  {rtype:6} → " + Fore.RED + f"HTTP {resp.status_code}")
        except Exception as e:
            print(Fore.WHITE + f"  {rtype:6} → " + Fore.RED + f"Hata: {e}")

    # MXToolbox linki
    print(Fore.YELLOW + "\n─── Dış Araçlar ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  MXToolbox:     " + Fore.CYAN + f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}")
    print(Fore.WHITE + f"  DNSViz:        " + Fore.CYAN + f"https://dnsviz.net/d/{domain}/")
    print(Fore.WHITE + f"  IntoDNS:       " + Fore.CYAN + f"https://intodns.com/{domain}")