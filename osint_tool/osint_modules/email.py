import re
import sys
import hashlib
from colorama import Fore, Style

def analyze_email(email):
    """E-posta adresini analiz eder."""
    if not email:
        print(Fore.RED + "HATA: E-posta boş olamaz!" + Style.RESET_ALL)
        return

    # Email validasyonu
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        print(Fore.RED + f"⚠️  '{email}' geçerli bir e-posta formatı değil!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 '{email}' analiz ediliyor...\n" + Style.RESET_ALL)

    # Domain extraction
    local_part, domain = email.split('@', 1)
    print(Fore.YELLOW + "─── Temel Bilgiler ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  📧 Local Part: " + Fore.GREEN + local_part)
    print(Fore.WHITE + f"  🌐 Domain:     " + Fore.GREEN + domain)
    print(Fore.WHITE + f"  🔢 Uzunluk:    " + Fore.CYAN + str(len(email)) + " karakter")

    # Domain tipi analizi
    print(Fore.YELLOW + "\n─── Domain Analizi ───" + Style.RESET_ALL)
    free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com',
                    'aol.com', 'protonmail.com', 'mail.com', 'gmx.com', 'yandex.com']
    disposable_domains = ['mailinator.com', 'guerrillamail.com', '10minutemail.com',
                          'tempmail.com', 'throwaway.email', 'yopmail.com']

    if domain.lower() in free_domains:
        print(Fore.YELLOW + f"  🏠 Ücretsiz E-posta Hizmeti: {domain}")
    if domain.lower() in disposable_domains:
        print(Fore.RED + f"  ⚠️  Geçici E-posta (Disposable): {domain} — Şüpheli!")

    # Domain TLD
    tld = domain.split('.')[-1]
    print(Fore.WHITE + f"  📌 TLD: " + Fore.CYAN + f".{tld}")

    # Gravatar / Hash
    print(Fore.YELLOW + "\n─── Gravatar / Avatar ───" + Style.RESET_ALL)
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?s=200&d=404"
    print(Fore.WHITE + f"  🔗 Gravatar URL: " + Fore.CYAN + gravatar_url)
    print(Fore.WHITE + f"  🔑 MD5 Hash:    " + Fore.MAGENTA + email_hash)

    # Breach check (simulated)
    print(Fore.YELLOW + "\n─── Breach / Sızma Kontrolü ───" + Style.RESET_ALL)
    known_breaches = ['linkedin.com', 'yahoo.com', 'adobe.com', 'facebook.com', 'myspace.com',
                      'twitter.com', 'tumblr.com', 'linkedin.com', 'dropbox.com']
    if domain.lower() in known_breaches:
        print(Fore.RED + f"  ⚠️  Dikkat: {domain} domaini bilinen breach veritabanlarında yer alıyor!")
        print(Fore.RED + "     Bu domain ile ilgili public breach verileri olabilir.")
    else:
        print(Fore.GREEN + f"  ✅ {domain} bilinen büyük breach'lerde bulunmadı.")

    # Social media profile check
    print(Fore.YELLOW + "\n─── Sosyal Medya Profil Taraması ───" + Style.RESET_ALL)
    sites = [
        ("GitHub", f"https://github.com/{local_part}"),
        ("Twitter/X", f"https://twitter.com/{local_part}"),
        ("Instagram", f"https://www.instagram.com/{local_part}"),
        ("LinkedIn", f"https://www.linkedin.com/in/{local_part}"),
        ("Reddit", f"https://www.reddit.com/user/{local_part}"),
        ("Pinterest", f"https://www.pinterest.com/{local_part}"),
        ("Spotify", f"https://open.spotify.com/user/{local_part}"),
        ("Medium", f"https://medium.com/@{local_part}"),
        ("TikTok", f"https://www.tiktok.com/@{local_part}"),
        ("Steam", f"https://steamcommunity.com/id/{local_part}"),
        ("Codeforces", f"https://codeforces.com/profile/{local_part}"),
        ("StackOverflow", f"https://stackoverflow.com/users/{local_part}"),
    ]
    for name, url in sites:
        print(Fore.WHITE + f"  • {name:<15} → " + Fore.CYAN + url)