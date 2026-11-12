import re
import socket
from colorama import Fore, Style

PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
    ("169.254.0.0", "169.254.255.255"),
]

def ip_to_int(ip):
    parts = ip.split('.')
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))

def is_private_ip(ip):
    try:
        ip_int = ip_to_int(ip)
        for start, end in PRIVATE_RANGES:
            if ip_to_int(start) <= ip_int <= ip_to_int(end):
                return True
        return False
    except:
        return False

def is_valid_ip(target):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, target):
        return False
    parts = target.split('.')
    return all(0 <= int(p) <= 255 for p in parts)

def is_valid_domain(target):
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, target))

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def analyze_ip_domain(target):
    if not target:
        print(Fore.RED + "HATA: IP veya Domain boş olamaz!" + Style.RESET_ALL)
        return

    target = target.strip()
    print(Fore.CYAN + f"\n🔍 '{target}' analiz ediliyor...\n" + Style.RESET_ALL)

    is_ip = is_valid_ip(target)
    is_domain = is_valid_domain(target)

    if is_ip:
        ip = target
        domain = None
        print(Fore.YELLOW + "─── IP Analizi ───" + Style.RESET_ALL)
        print(Fore.WHITE + f"  IP Adresi:     " + Fore.GREEN + ip)
        print(Fore.WHITE + f"  Private IP:    " + (Fore.RED + "EVET (Yerel Ağ)" if is_private_ip(ip) else Fore.GREEN + "HAYIR (Public)"))
        try:
            rev_dns = socket.gethostbyaddr(ip)[0]
            print(Fore.WHITE + f"  Reverse DNS:  " + Fore.CYAN + rev_dns)
        except:
            print(Fore.WHITE + f"  Reverse DNS:  " + Fore.RED + "Bulunamadı")

    elif is_domain:
        domain = target
        ip = resolve_domain(domain)
        print(Fore.YELLOW + "─── Domain Analizi ───" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Domain:        " + Fore.GREEN + domain)
        if ip:
            print(Fore.WHITE + f"  Cozulenen IP: " + Fore.GREEN + ip)
        else:
            print(Fore.WHITE + f"  Cozulenen IP: " + Fore.RED + "Cozumlenemedi")

    else:
        print(Fore.RED + "  Gecersiz format! IP (1.2.3.4) veya Domain (example.com) girin.")
        return

    if ip and not is_private_ip(ip):
        print(Fore.YELLOW + "\n─── WHOIS / Geolocation (Linkler) ───" + Style.RESET_ALL)
        print(Fore.WHITE + f"  IPinfo.io:      " + Fore.CYAN + f"https://ipinfo.io/{ip}")
        print(Fore.WHITE + f"  Shodan:         " + Fore.CYAN + f"https://www.shodan.io/host/{ip}")
        print(Fore.WHITE + f"  AbuseIPDB:      " + Fore.CYAN + f"https://www.abuseipdb.com/check/{ip}")
        print(Fore.WHITE + f"  VirusTotal:     " + Fore.CYAN + f"https://www.virustotal.com/gui/ip-address/{ip}")
        print(Fore.WHITE + f"  Censys:         " + Fore.CYAN + f"https://search.censys.io/hosts/{ip}")
        print(Fore.WHITE + f"  MXToolbox:      " + Fore.CYAN + f"https://mxtoolbox.com/SuperTool.aspx?action=arin%3a{ip}")

    if domain:
        print(Fore.YELLOW + "\n─── Domain WHOIS / DNS (Linkler) ───" + Style.RESET_ALL)
        print(Fore.WHITE + f"  WHOIS (ICANN):  " + Fore.CYAN + f"https://lookup.icann.org/en/lookup?q={domain}")
        print(Fore.WHITE + f"  WHOIS (DomainTools): " + Fore.CYAN + f"https://whois.domaintools.com/{domain}")
        print(Fore.WHITE + f"  DNS Dumpster:   " + Fore.CYAN + f"https://dnsdumpster.com/#{domain}")
        print(Fore.WHITE + f"  SecurityTrails: " + Fore.CYAN + f"https://securitytrails.com/domain/{domain}")
        print(Fore.WHITE + f"  crt.sh (SSL):   " + Fore.CYAN + f"https://crt.sh/?q=%25.{domain}")
        print(Fore.WHITE + f"  ViewDNS.info:   " + Fore.CYAN + f"https://viewdns.info/dnsreport/?domain={domain}")

    print(Fore.YELLOW + "\n─── Port & Servis Tarama ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  Nmap Online:    " + Fore.CYAN + "https://nmap.online/")
    print(Fore.WHITE + f"  Shodan Portlar: " + Fore.CYAN + f"https://www.shodan.io/host/{ip if ip else 'domain'}")
    print(Fore.WHITE + f"  Censys Portlar: " + Fore.CYAN + f"https://search.censys.io/hosts/{ip if ip else 'domain'}")