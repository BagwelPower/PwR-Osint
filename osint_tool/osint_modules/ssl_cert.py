import ssl
import socket
import requests
from datetime import datetime
from colorama import Fore, Style
from config import load_config

config = load_config()

def analyze_ssl(domain, port=443):
    print(Fore.CYAN + f"\n🔍 SSL/TLS Analizi: {domain}:{port}\n" + Style.RESET_ALL)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=config.get('timeout', 10)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

        # Temel Bilgiler
        print(Fore.YELLOW + "─── Sertifika Bilgileri ───" + Style.RESET_ALL)
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))

        print(Fore.WHITE + f"  Subject CN:     " + Fore.GREEN + subject.get('commonName', 'Yok'))
        print(Fore.WHITE + f"  Issuer:         " + Fore.GREEN + issuer.get('commonName', 'Yok'))
        print(Fore.WHITE + f"  Version:        " + Fore.CYAN + version)
        print(Fore.WHITE + f"  Cipher:         " + Fore.CYAN + f"{cipher[0]} ({cipher[1]} bits)")

        # Geçerlilik
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()

        print(Fore.YELLOW + "\n─── Geçerlilik ───" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Başlangıç:      " + Fore.GREEN + str(not_before))
        print(Fore.WHITE + f"  Bitiş:          " + (Fore.RED if not_after < now else Fore.GREEN) + str(not_after))

        days_left = (not_after - now).days
        if days_left < 0:
            print(Fore.WHITE + f"  Kalan Gün:      " + Fore.RED + f"SÜRESİ DOLDU ({abs(days_left)} gün önce)")
        elif days_left < 30:
            print(Fore.WHITE + f"  Kalan Gün:      " + Fore.YELLOW + f"{days_left} gün (YAKIN!)")
        else:
            print(Fore.WHITE + f"  Kalan Gün:      " + Fore.GREEN + f"{days_left} gün")

        # SAN (Subject Alternative Names)
        san = cert.get('subjectAltName', [])
        if san:
            print(Fore.YELLOW + "\n─── SAN (Alternatif İsimler) ───" + Style.RESET_ALL)
            for typ, val in san:
                print(Fore.WHITE + f"  {typ}: " + Fore.CYAN + val)

        # Serial Number & Fingerprint
        print(Fore.YELLOW + "\n─── Parmak İzi / Seri No ───" + Style.RESET_ALL)
        print(Fore.WHITE + f"  Serial:         " + Fore.MAGENTA + cert.get('serialNumber', 'Yok'))

    except ssl.SSLError as e:
        print(Fore.RED + f"  SSL Hatası: {e}" + Style.RESET_ALL)
    except socket.timeout:
        print(Fore.RED + "  Bağlantı zaman aşımı!" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}" + Style.RESET_ALL)

    # Dış Linkler
    print(Fore.YELLOW + "\n─── Dış Araçlar ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  SSL Labs:       " + Fore.CYAN + f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}")
    print(Fore.WHITE + f"  crt.sh:         " + Fore.CYAN + f"https://crt.sh/?q=%25.{domain}")
    print(Fore.WHITE + f"  Censys Certs:   " + Fore.CYAN + f"https://search.censys.io/certificates?q={domain}")