import os
import sys
import time
from colorama import init, Fore, Style

# Colorama başlat
init(autoreset=True)

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + Style.BRIGHT + """
  ██████╗ ███████╗██╗███╗   ██╗████████╗  ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝ ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██║   ██║███████╗██║██╔██╗ ██║   ██║    ██║   ██║███████╗██║██╔██╗ ██║   ██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║    ██║   ██║╚════██║██║██║╚██╗██║   ██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║    ╚██████╔╝███████║██║██║ ╚████║   ██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝     ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
                        [ PwR Osint ]
                         Coded by BagwelPower
    """ + Style.RESET_ALL)

def main_menu():
    while True:
        banner()
        print(Fore.YELLOW + "====== ANA MENÜ ======" + Style.RESET_ALL)
        print(Fore.GREEN + " [1]" + Fore.WHITE + " Kullanıcı Adı (Username) Araştırması")
        print(Fore.GREEN + " [2]" + Fore.WHITE + " E-posta (E-mail) Analizi")
        print(Fore.GREEN + " [3]" + Fore.WHITE + " Telefon Numarası (Phone) Analizi")
        print(Fore.GREEN + " [4]" + Fore.WHITE + " İsim / Soyisim (Name) Araştırması")
        print(Fore.GREEN + " [5]" + Fore.WHITE + " IP & Domain Sorgulama")
        print(Fore.GREEN + " [6]" + Fore.WHITE + " Gelişmiş Araştırma (Konum, MAC, Arşiv)")
        print(Fore.GREEN + " [7]" + Fore.WHITE + " DNS Kayıtları Sorgulama")
        print(Fore.GREEN + " [8]" + Fore.WHITE + " SSL/TLS Sertifika Analizi")
        print(Fore.GREEN + " [9]" + Fore.WHITE + " Subdomain Enumeration")
        print(Fore.GREEN + " [10]" + Fore.WHITE + " Ek E-posta Araçları (Permutator, Hunter.io)")
        print(Fore.GREEN + " [11]" + Fore.WHITE + " Have I Been Pwned (Sızma Kontrolü)")
        print(Fore.GREEN + " [12]" + Fore.WHITE + " Shodan API")
        print(Fore.GREEN + " [13]" + Fore.WHITE + " VirusTotal API")
        print(Fore.GREEN + " [14]" + Fore.WHITE + " API Anahtar Yönetimi")
        print(Fore.RED + " [0]" + Fore.WHITE + " Çıkış")
        print(Fore.YELLOW + "======================" + Style.RESET_ALL)

        choice = input(Fore.CYAN + "\nSeçiminiz [0-14]: " + Style.RESET_ALL).strip()

        if choice == '1':
            username_search()
        elif choice == '2':
            email_search()
        elif choice == '3':
            phone_search()
        elif choice == '4':
            name_search()
        elif choice == '5':
            ip_domain_search()
        elif choice == '6':
            advanced_search()
        elif choice == '7':
            dns_records_search()
        elif choice == '8':
            ssl_cert_search()
        elif choice == '9':
            subdomain_search()
        elif choice == '10':
            email_extra_search()
        elif choice == '11':
            hibp_search()
        elif choice == '12':
            shodan_search_menu()
        elif choice == '13':
            virustotal_search_menu()
        elif choice == '14':
            config_menu()
        elif choice == '0':
            print(Fore.LIGHTRED_EX + "\nÇıkış yapılıyor... Görüşmek üzere!" + Style.RESET_ALL)
            sys.exit(0)
        else:
            print(Fore.RED + "\nGeçersiz seçim! Lütfen tekrar deneyin." + Style.RESET_ALL)
            time.sleep(1.5)

def username_search():
    banner()
    print(Fore.YELLOW + "--- KULLANICI ADI ARAŞTIRMASI ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Aranacak Kullanıcı Adı: " + Style.RESET_ALL).strip()
    if not target:
        return

    from osint_modules.username import search_username
    search_username(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def email_search():
    banner()
    print(Fore.YELLOW + "--- E-POSTA ANALİZİ ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Aranacak E-posta Adresi: " + Style.RESET_ALL).strip()
    if not target:
        return

    from osint_modules.email import analyze_email
    analyze_email(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def phone_search():
    banner()
    print(Fore.YELLOW + "--- TELEFON NUMARASI ANALİZİ ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Aranacak Telefon Numarası (+90...): " + Style.RESET_ALL).strip()
    if not target:
        return

    from osint_modules.phone import analyze_phone
    analyze_phone(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def name_search():
    banner()
    print(Fore.YELLOW + "--- İSİM / SOYİSİM ARAŞTIRMASI ---" + Style.RESET_ALL)
    name = input(Fore.CYAN + "Ad Soyad: " + Style.RESET_ALL).strip()
    if not name:
        return

    from osint_modules.name import search_name
    search_name(name)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def ip_domain_search():
    banner()
    print(Fore.YELLOW + "--- IP & DOMAIN ANALİZİ ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Aranacak IP veya Domain: " + Style.RESET_ALL).strip()
    if not target:
        return

    from osint_modules.ip_domain import analyze_ip_domain
    analyze_ip_domain(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def advanced_search():
    banner()
    from osint_modules.advanced import analyze_advanced
    analyze_advanced()

def dns_records_search():
    banner()
    print(Fore.YELLOW + "--- DNS KAYITLARI SORGULAMA ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Domain: " + Style.RESET_ALL).strip()
    if not target:
        return
    from osint_modules.dns_records import get_dns_records
    get_dns_records(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def ssl_cert_search():
    banner()
    print(Fore.YELLOW + "--- SSL/TLS SERTİFİKA ANALİZİ ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Domain: " + Style.RESET_ALL).strip()
    if not target:
        return
    from osint_modules.ssl_cert import analyze_ssl
    analyze_ssl(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def subdomain_search():
    banner()
    print(Fore.YELLOW + "--- SUBDOMAIN ENUMERATION ---" + Style.RESET_ALL)
    target = input(Fore.CYAN + "Domain: " + Style.RESET_ALL).strip()
    if not target:
        return
    from osint_modules.subdomain import enumerate_subdomains
    enumerate_subdomains(target)
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def email_extra_search():
    banner()
    from osint_modules.email_extra import email_extra_menu
    email_extra_menu()
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def hibp_search():
    banner()
    from osint_modules.hibp import hibp_menu
    hibp_menu()
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def shodan_search_menu():
    banner()
    from osint_modules.shodan_api import shodan_menu
    shodan_menu()
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def virustotal_search_menu():
    banner()
    from osint_modules.virustotal import vt_menu
    vt_menu()
    input(Fore.YELLOW + "\nDevam etmek için ENTER'a basın..." + Style.RESET_ALL)

def config_menu():
    banner()
    from config import config_menu as cfg_menu
    cfg_menu()

if __name__ == "__main__":
    main_menu()