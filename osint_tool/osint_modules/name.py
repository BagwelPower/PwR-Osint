from colorama import Fore, Style
from urllib.parse import quote

def search_name(name):
    """İsim / Soyisim araştırması yapar."""
    if not name or len(name) < 2:
        print(Fore.RED + "HATA: İsim en az 2 karakter olmalıdır!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 '{name}' için araştırma başlatılıyor...\n" + Style.RESET_ALL)

    encoded_name = quote(name)
    parts = name.strip().split()
    first_name = parts[0] if parts else ""
    last_name = parts[-1] if len(parts) > 1 else ""

    print(Fore.YELLOW + "─── Temel Analiz ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  👤 Aranan İsim: " + Fore.GREEN + name)
    print(Fore.WHITE + f"  🔤 Ad:           " + Fore.CYAN + first_name)
    print(Fore.WHITE + f"  🔤 Soyad:        " + Fore.CYAN + (last_name if last_name != first_name else "Belirtilmedi"))

    # Google Dorks & Search Queries
    print(Fore.YELLOW + "\n─── Google OSINT Dork'ları ───" + Style.RESET_ALL)
    dorks = [
        ("Genel Arama", f"https://www.google.com/search?q=\"{encoded_name}\""),
        ("PDF / Belge Araması", f"https://www.google.com/search?q=\"{encoded_name}\"+filetype:pdf"),
        ("Excel / Veri Araması", f"https://www.google.com/search?q=\"{encoded_name}\"+filetype:xlsx+OR+filetype:csv"),
        ("Sosyal Medya Arama", f"https://www.google.com/search?q=\"{encoded_name}\"+(site:linkedin.com+OR+site:facebook.com+OR+site:instagram.com+OR+site:twitter.com)"),
        ("Özgeçmiş / CV Araması", f"https://www.google.com/search?q=\"{encoded_name}\"+(cv+OR+resume+OR+ozgecmis)"),
        ("Haber Araması", f"https://www.google.com/search?q=\"{encoded_name}\"+site:gazete+OR+site:haber"),
        ("Görsel Arama", f"https://www.google.com/search?tbm=isch&q=\"{encoded_name}\""),
    ]
    for title, url in dorks:
        print(Fore.WHITE + f"  • {title:<22} → " + Fore.CYAN + url)

    # Sosyal Medya Doğrudan Arama Linkleri
    print(Fore.YELLOW + "\n─── Sosyal Medya Doğrudan Arama ───" + Style.RESET_ALL)
    social_searches = [
        ("LinkedIn Arama", f"https://www.linkedin.com/pub/dir?firstName={quote(first_name)}&lastName={quote(last_name)}"),
        ("Facebook Arama", f"https://www.facebook.com/search/top/?q={encoded_name}"),
        ("Twitter/X Arama", f"https://twitter.com/search?q={encoded_name}&f=user"),
        ("Instagram Arama", f"https://www.instagram.com/explore/tags/{quote(name.replace(' ', ''))}/"),
        ("GitHub Arama", f"https://github.com/search?type=users&q={encoded_name}"),
    ]
    for title, url in social_searches:
        print(Fore.WHITE + f"  • {title:<22} → " + Fore.CYAN + url)

    # Resmi / Kamu Açık Kaynak Arama Linkleri
    print(Fore.YELLOW + "\n─── Kamu / Açık Veri Linkleri ───" + Style.RESET_ALL)
    public_searches = [
        ("Google Akademik", f"https://scholar.google.com/scholar?q=\"{encoded_name}\""),
        ("DergiPark (Makale)", f"https://dergipark.org.tr/tr/search?q={encoded_name}&section=articles"),
        ("Resmi Gazete Arama", f"https://www.google.com/search?q=\"{encoded_name}\"+site:resmigazete.gov.tr"),
        ("YÖK Tez Araması", f"https://tez.yok.gov.tr/UlusalTezMerkezi/tezSorgu.jsp"),
    ]
    for title, url in public_searches:
        print(Fore.WHITE + f"  • {title:<22} → " + Fore.CYAN + url)
