import re
from colorama import Fore, Style

COUNTRY_CODES = {
    "+90": ("Türkiye", "TR"),
    "+1": ("ABD / Kanada", "US/CA"),
    "+44": ("Birleşik Krallık", "UK"),
    "+49": ("Almanya", "DE"),
    "+33": ("Fransa", "FR"),
    "+39": ("İtalya", "IT"),
    "+7": ("Rusya / Kazakistan", "RU/KZ"),
    "+81": ("Japonya", "JP"),
    "+86": ("Çin", "CN"),
    "+91": ("Hindistan", "IN"),
    "+31": ("Hollanda", "NL"),
    "+34": ("İspanya", "ES"),
    "+41": ("İsviçre", "CH"),
    "+46": ("İsveç", "SE"),
    "+47": ("Norveç", "NO"),
    "+48": ("Polonya", "PL"),
    "+30": ("Yunanistan", "GR"),
    "+351": ("Portekiz", "PT"),
    "+380": ("Ukrayna", "UA"),
    "+966": ("Suudi Arabistan", "SA"),
    "+971": ("BİRLEŞİK ARAP EMİRLİKLERİ", "AE"),
}

OPERATORS_TR = {
    "53": "Turkcell",
    "54": "Vodafone",
    "55": "Türk Telekom (Avea)",
    "50": "Türk Telekom",
    "51": "BİMcell / PTTcell / Vestelcell (Türk Telekom Altyapısı)",
    "56": "NetGSM / Diğer Sanal Operatörler",
}

def analyze_phone(phone):
    """Telefon numarasını analiz eder."""
    if not phone:
        print(Fore.RED + "HATA: Telefon numarası boş olamaz!" + Style.RESET_ALL)
        return

    # Sadece rakamlar ve + işaretini tut
    clean_phone = re.sub(r'[^\d+]', '', phone)

    if not clean_phone.startswith('+'):
        if clean_phone.startswith('0'):
            clean_phone = '+90' + clean_phone[1:]
        elif clean_phone.startswith('90'):
            clean_phone = '+' + clean_phone
        else:
            clean_phone = '+' + clean_phone

    print(Fore.CYAN + f"\n🔍 '{clean_phone}' analiz ediliyor...\n" + Style.RESET_ALL)

    print(Fore.YELLOW + "─── Temel Bilgiler ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  📱 Ham Veri:       " + Fore.GREEN + phone)
    print(Fore.WHITE + f"  🌐 Temizlenmiş:    " + Fore.GREEN + clean_phone)
    print(Fore.WHITE + f"  🔢 Karakter Sayısı: " + Fore.CYAN + str(len(clean_phone)))

    # Ülke tespiti
    country_name, country_code = "Bilinmeyen Ülke", "XX"
    for prefix, (c_name, c_code) in sorted(COUNTRY_CODES.items(), key=lambda x: len(x[0]), reverse=True):
        if clean_phone.startswith(prefix):
            country_name, country_code = c_name, c_code
            break

    print(Fore.YELLOW + "\n─── Ülke & Operatör Analizi ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  🏳️  Ülke:     " + Fore.GREEN + f"{country_name} ({country_code})")

    # Türkiye Operatör Tespiti
    if clean_phone.startswith('+90'):
        digits_only = clean_phone[3:]  # +90 çıkınca kalan
        if len(digits_only) >= 2:
            op_code = digits_only[:2]
            operator = OPERATORS_TR.get(op_code, "Bilinmeyen / Taşınmış Numara")
            print(Fore.WHITE + f"  📡 Operatör (Blok Tahmini): " + Fore.CYAN + operator)
            print(Fore.YELLOW + "  ℹ️  Not: Numara taşıma yapılmış olabilir, blok tahmini orijinal tahsistir.")

    # Format Kontrolü
    print(Fore.YELLOW + "\n─── Formatlar ───" + Style.RESET_ALL)
    print(Fore.WHITE + f"  E.164 Standardı: " + Fore.CYAN + clean_phone)
    if clean_phone.startswith('+90') and len(clean_phone) == 13:
        formatted_tr = f"+90 ({clean_phone[3:6]}) {clean_phone[6:9]} {clean_phone[9:11]} {clean_phone[11:13]}"
        print(Fore.WHITE + f"  Ulusal Format:   " + Fore.CYAN + formatted_tr)

    # OSINT Arama Linkleri
    print(Fore.YELLOW + "\n─── OSINT Arama Linkleri ───" + Style.RESET_ALL)
    raw_digits = clean_phone.replace('+', '')
    print(Fore.WHITE + f"  • Google Arama:   " + Fore.CYAN + f"https://www.google.com/search?q=\"{clean_phone}\"+OR+\"{raw_digits}\"")
    print(Fore.WHITE + f"  • WhatsApp Linki: " + Fore.CYAN + f"https://wa.me/{raw_digits}")
    print(Fore.WHITE + f"  • Telegram Linki: " + Fore.CYAN + f"https://t.me/+{raw_digits}")
    print(Fore.WHITE + f"  • Sync.ME:        " + Fore.CYAN + f"https://sync.me/search/?number={raw_digits}")
    print(Fore.WHITE + f"  • Truecaller:     " + Fore.CYAN + f"https://www.truecaller.com/search/tr/{raw_digits}")
