import requests
import re
from colorama import Fore, Style
from config import load_config

config = load_config()

# ---------- KOORDİNAT / REVERSE GEOCODING ----------
def reverse_geocode(lat, lon):
    print(Fore.CYAN + f"\n🔍 Reverse Geocoding: {lat}, {lon}\n" + Style.RESET_ALL)

    # Nominatim (OpenStreetMap) - Ücretsiz, rate limit var
    try:
        url = "https://nominatim.openstreetmap.org/reverse"
        params = {'lat': lat, 'lon': lon, 'format': 'json', 'addressdetails': 1}
        headers = {'User-Agent': config.get('user_agent', 'OSINT-Tool/1.0')}
        resp = requests.get(url, params=params, headers=headers, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            data = resp.json()
            addr = data.get('address', {})
            print(Fore.GREEN + "  Nominatim (OpenStreetMap):")
            print(Fore.WHITE + f"    Adres:     " + Fore.CYAN + data.get('display_name', 'N/A'))
            print(Fore.WHITE + f"    Mahalle:   " + Fore.CYAN + addr.get('neighbourhood', addr.get('suburb', 'N/A')))
            print(Fore.WHITE + f"    İlçe:      " + Fore.CYAN + addr.get('city_district', addr.get('county', 'N/A')))
            print(Fore.WHITE + f"    Şehir:     " + Fore.CYAN + addr.get('city', addr.get('town', addr.get('village', 'N/A'))))
            print(Fore.WHITE + f"    İl:        " + Fore.CYAN + addr.get('state', 'N/A'))
            print(Fore.WHITE + f"    Ülke:      " + Fore.CYAN + addr.get('country', 'N/A'))
            print(Fore.WHITE + f"    Posta Kodu:" + Fore.CYAN + addr.get('postcode', 'N/A'))
        else:
            print(Fore.RED + f"  Nominatim HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Nominatim Hata: {e}")

    # LocationIQ (Alternatif)
    print(Fore.YELLOW + "\n  Diğer servisler için linkler:")
    print(Fore.WHITE + f"    LocationIQ:   " + Fore.CYAN + f"https://locationiq.com/")
    print(Fore.WHITE + f"    Google Maps:  " + Fore.CYAN + f"https://maps.googleapis.com/maps/api/geocode/json?latlng={lat},{lon}")

# ---------- BSSID / MAC ADRESİ KONUM ----------
def bssid_location(bssid):
    clean_bssid = re.sub(r'[^a-fA-F0-9]', '', bssid).lower()
    if len(clean_bssid) != 12:
        print(Fore.RED + "  Geçersiz BSSID formatı! (12 hex karakter)")
        return

    formatted = ':'.join(clean_bssid[i:i+2] for i in range(0, 12, 2)).upper()
    print(Fore.CYAN + f"\n🔍 BSSID Konum Sorgulaması: {formatted}\n" + Style.RESET_ALL)

    # Wigle.net API (API key gerekli, public endpoint sınırlı)
    # Public JSON endpoint dene
    try:
        url = f"https://api.wigle.net/api/v2/network/search?netid={clean_bssid}"
        headers = {'User-Agent': config.get('user_agent', 'OSINT-Tool/1.0')}
        resp = requests.get(url, headers=headers, timeout=config.get('timeout', 15))
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('results', [])
            if results:
                r = results[0]
                print(Fore.GREEN + "  Wigle.net Sonucu:")
                print(Fore.WHITE + f"    SSID:       " + Fore.CYAN + r.get('ssid', 'N/A'))
                print(Fore.WHITE + f"    Latitude:   " + Fore.CYAN + str(r.get('trilat', 'N/A')))
                print(Fore.WHITE + f"    Longitude:  " + Fore.CYAN + str(r.get('trilong', 'N/A')))
                print(Fore.WHITE + f"    Adres:      " + Fore.CYAN + r.get('location', 'N/A'))
                print(Fore.WHITE + f"    Son Güncelleme:" + Fore.CYAN + r.get('lastupdt', 'N/A'))
            else:
                print(Fore.YELLOW + "  Wigle.net'te kayıt yok (veya API key gerekli)")
        elif resp.status_code == 401:
            print(Fore.YELLOW + "  Wigle.net API key gerektiriyor (https://wigle.net/account)")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

    # MAC Vendor Lookup (Ücretsiz)
    print(Fore.YELLOW + "\n  MAC Vendor (Üretici) Bilgisi:")
    try:
        url = f"https://api.macvendors.com/{formatted}"
        resp = requests.get(url, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            print(Fore.WHITE + f"    Üretici:    " + Fore.GREEN + resp.text)
        else:
            print(Fore.RED + f"    Bulunamadı")
    except Exception as e:
        print(Fore.RED + f"    Hata: {e}")

# ---------- ARAÇ PLAKA SORGULAMA (TÜRKİYE) ----------
def plate_lookup(plate):
    plate = plate.upper().strip().replace(' ', '')
    if not re.match(r'^\d{2}[A-Z]{1,3}\d{2,4}$', plate):
        print(Fore.RED + "  Geçersiz plaka formatı! (Örn: 34ABC123 veya 06XYZ1234)")
        return

    print(Fore.CYAN + f"\n🔍 Plaka Sorgulaması: {plate}\n" + Style.RESET_ALL)

    # 1. SBM (Sigorta Bilgi Merkezi) - Resmi, API key gerekir
    # Public endpoint yok, sadece link verelim

    # 2. Trafik Ceza Sorgulama (Resmi, T.C. kimlik no ile giriş gerekir)

    # 3. Plaka tanıma - İl kodu çıkar
    il_kodu = plate[:2]
    iller = {
        "01": "Adana", "02": "Adıyaman", "03": "Afyonkarahisar", "04": "Ağrı", "05": "Amasya",
        "06": "Ankara", "07": "Antalya", "08": "Artvin", "09": "Aydın", "10": "Balıkesir",
        "11": "Bilecik", "12": "Bingöl", "13": "Bitlis", "14": "Bolu", "15": "Burdur",
        "16": "Bursa", "17": "Çanakkale", "18": "Çankırı", "19": "Çorum", "20": "Denizli",
        "21": "Diyarbakır", "22": "Edirne", "23": "Elazığ", "24": "Erzincan", "25": "Erzurum",
        "26": "Eskişehir", "27": "Gaziantep", "28": "Giresun", "29": "Gümüşhane", "30": "Hakkari",
        "31": "Hatay", "32": "Isparta", "33": "Mersin", "34": "İstanbul", "35": "İzmir",
        "36": "Kars", "37": "Kastamonu", "38": "Kayseri", "39": "Kırklareli", "40": "Kırşehir",
        "41": "Kocaeli", "42": "Konya", "43": "Kütahya", "44": "Malatya", "45": "Manisa",
        "46": "Kahramanmaraş", "47": "Mardin", "48": "Muğla", "49": "Muş", "50": "Nevşehir",
        "51": "Niğde", "52": "Ordu", "53": "Rize", "54": "Sakarya", "55": "Samsun",
        "56": "Siirt", "57": "Sinop", "58": "Sivas", "59": "Tekirdağ", "60": "Tokat",
        "61": "Trabzon", "62": "Tunceli", "63": "Şanlıurfa", "64": "Uşak", "65": "Van",
        "66": "Yozgat", "67": "Zonguldak", "68": "Aksaray", "69": "Bayburt", "70": "Karaman",
        "71": "Kırıkkale", "72": "Batman", "73": "Şırnak", "74": "Bartın", "75": "Ardahan",
        "76": "Iğdır", "77": "Yalova", "78": "Karabük", "79": "Kilis", "80": "Osmaniye",
        "81": "Düzce"
    }

    print(Fore.YELLOW + "  Plaka Analizi:")
    print(Fore.WHITE + f"    İl Kodu:     " + Fore.CYAN + il_kodu)
    print(Fore.WHITE + f"    İl:          " + Fore.CYAN + iller.get(il_kodu, "Bilinmiyor"))

    # Plaka tipi
    letters = re.search(r'\d{2}([A-Z]+)', plate)
    if letters:
        l = letters.group(1)
        if len(l) == 1:
            print(Fore.WHITE + f"    Tip:         " + Fore.CYAN + "Resmi / Ticari (Eski sistem)")
        elif len(l) == 2:
            print(Fore.WHITE + f"    Tip:         " + Fore.CYAN + "Özel / Ticari")
        elif len(l) == 3:
            print(Fore.WHITE + f"    Tip:         " + Fore.CYAN + "Yeni sistem (3 harf)")

    print(Fore.YELLOW + "\n  Resmi Sorgulama Linkleri:")
    print(Fore.WHITE + f"    SBM (Sigorta):       " + Fore.CYAN + "https://www.sbm.org.tr/")
    print(Fore.WHITE + f"    Trafik Ceza:         " + Fore.CYAN + "https://trafikceza.com.tr/")
    print(Fore.WHITE + f"    NVI (Nüfus):         " + Fore.CYAN + "https://www.nvi.gov.tr/")
    print(Fore.WHITE + f"    Plaka Tanıma (YD):   " + Fore.CYAN + "https://yd.gib.gov.tr/")

# ---------- VIN / ŞASİ NO SORGULAMA ----------
def vin_lookup(vin):
    vin = vin.upper().strip()
    if len(vin) != 17:
        print(Fore.RED + "  VIN 17 karakter olmalıdır!")
        return

    print(Fore.CYAN + f"\n🔍 VIN/Şasi No Sorgulaması: {vin}\n" + Style.RESET_ALL)

    # WMI (World Manufacturer Identifier) - İlk 3 karakter
    wmi = vin[:3]
    print(Fore.YELLOW + "  WMI (Üretici Kodu): " + Fore.CYAN + wmi)

    # Basit WMI veritabanı
    wmi_db = {
        "WVW": "Volkswagen (Almanya)", "WBA": "BMW (Almanya)", "WDD": "Mercedes-Benz (Almanya)",
        "WPO": "Porsche (Almanya)", "WAU": "Audi (Almanya)", "WOL": "Opel (Almanya)",
        "VF1": "Renault (Fransa)", "VF3": "Peugeot (Fransa)", "VF7": "Citroën (Fransa)",
        "ZFA": "Fiat (İtalya)", "ZAR": "Alfa Romeo (İtalya)", "ZFF": "Ferrari (İtalya)",
        "JHM": "Honda (Japonya)", "JTD": "Toyota (Japonya)", "JN1": "Nissan (Japonya)",
        "JF1": "Subaru (Japonya)", "JS1": "Suzuki (Japonya)", "JM1": "Mazda (Japonya)",
        "KMH": "Hyundai (Kore)", "KNA": "Kia (Kore)", "KPT": "SsangYong (Kore)",
        "LGB": "Byd (Çin)", "LGW": "Great Wall (Çin)", "LHG": "Haval (Çin)",
        "1G": "General Motors (USA)", "1F": "Ford (USA)", "1C": "Chrysler (USA)",
        "2G": "General Motors (Kanada)", "2F": "Ford (Kanada)", "3G": "General Motors (Meksika)",
        "TMA": "Hyundai (Türkiye - Kocaeli)", "TMB": "Toyota (Türkiye - Sakarya)",
        "NM0": "Ford Otosan (Türkiye)", "NLH": "Honda (Türkiye)", "NMT": "Toyota (Türkiye)"
    }

    for prefix, maker in wmi_db.items():
        if wmi.startswith(prefix[:2]):  # İlk 2 karakter match
            print(Fore.WHITE + f"    Üretici:     " + Fore.GREEN + maker)
            break
    else:
        print(Fore.WHITE + f"    Üretici:     " + Fore.YELLOW + "Bilinmiyor (WMI veritabanı sınırlı)")

    # Model yılı (10. karakter)
    year_codes = {
        'A': '1980/2010', 'B': '1981/2011', 'C': '1982/2012', 'D': '1983/2013',
        'E': '1984/2014', 'F': '1985/2015', 'G': '1986/2016', 'H': '1987/2017',
        'J': '1988/2018', 'K': '1989/2019', 'L': '1990/2020', 'M': '1991/2021',
        'N': '1992/2022', 'P': '1993/2023', 'R': '1994/2024', 'S': '1995/2025',
        'T': '1996/2026', 'V': '1997/2027', 'W': '1998/2028', 'X': '1999/2029',
        'Y': '2000/2030', '1': '2001/2031', '2': '2002/2032', '3': '2003/2033',
        '4': '2004/2034', '5': '2005/2035', '6': '2006/2036', '7': '2007/2037',
        '8': '2008/2038', '9': '2009/2039'
    }
    year_char = vin[9]
    print(Fore.WHITE + f"    Model Yılı:  " + Fore.CYAN + year_codes.get(year_char, f"Bilinmiyor ({year_char})"))

    # Montaj yeri (11. karakter) - basit
    plant = vin[10]
    print(Fore.WHITE + f"    Montaj Kodu: " + Fore.CYAN + plant)

    print(Fore.YELLOW + "\n  Detaylı VIN Decoder Siteleri:")
    print(Fore.WHITE + f"    VINDecoder.net:   " + Fore.CYAN + f"https://www.vindecoder.net/check_vin/{vin}/")
    print(Fore.WHITE + f"    NHTSA (USA):      " + Fore.CYAN + f"https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/{vin}?format=json")
    print(Fore.WHITE + f"    AutoDNA (PL):     " + Fore.CYAN + f"https://autodna.com/vin/{vin}/")

# ---------- WAYBACK MACHINE / ARŞİV TARAMASI ----------
def wayback_scan(domain):
    print(Fore.CYAN + f"\n🔍 Wayback Machine Tarama: {domain}\n" + Style.RESET_ALL)

    try:
        # CDX API - Snapshot listesi
        url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'timestamp,original,statuscode,mimetype',
            'collapse': 'urlkey',
            'limit': 20
        }
        resp = requests.get(url, params=params, timeout=config.get('timeout', 15))
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:  # İlk satır header
                print(Fore.GREEN + f"  {len(data)-1} benzersiz snapshot bulundu:\n")
                for row in data[1:11]:  # İlk 10
                    ts, orig, status, mime = row
                    # Timestamp formatla
                    try:
                        formatted_ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}:{ts[12:14]}"
                    except:
                        formatted_ts = ts
                    status_color = Fore.GREEN if status == '200' else (Fore.YELLOW if status.startswith('3') else Fore.RED)
                    print(Fore.WHITE + f"  {formatted_ts} | " + status_color + f"{status} | " + Fore.CYAN + orig[:80])
                if len(data) > 11:
                    print(Fore.YELLOW + f"  ... ve {len(data)-11} sonuç daha.")
            else:
                print(Fore.YELLOW + "  Arşivde kayıt yok.")
        else:
            print(Fore.RED + f"  HTTP {resp.status_code}")
    except Exception as e:
        print(Fore.RED + f"  Hata: {e}")

    # Summary API
    try:
        url = f"https://web.archive.org/__wb/calendarcaptures?url={domain}"
        resp = requests.get(url, timeout=config.get('timeout', 10))
        if resp.status_code == 200:
            data = resp.json()
            years = list(data.keys())
            if years:
                print(Fore.YELLOW + f"\n  Yıllara göre snapshot sayısı:")
                for y in sorted(years, reverse=True)[:5]:
                    total = sum(data[y].values()) if isinstance(data[y], dict) else 0
                    print(Fore.WHITE + f"    {y}: " + Fore.CYAN + f"{total} capture")
    except:
        pass

    print(Fore.YELLOW + "\n  Linkler:")
    print(Fore.WHITE + f"    Wayback:    " + Fore.CYAN + f"https://web.archive.org/web/*/{domain}")
    print(Fore.WHITE + f"    Archive.is: " + Fore.CYAN + f"https://archive.is/{domain}")

# ---------- ANA MENÜ ----------
def analyze_advanced():
    while True:
        print(Fore.YELLOW + "\n─── GELİŞMİŞ ARAŞTIRMA (ÇALIŞIR) ───" + Style.RESET_ALL)
        print(" [1] Koordinat → Adres (Reverse Geocoding)")
        print(" [2] BSSID / MAC → Konum + Vendor")
        print(" [3] Plaka → İl + Tip Analizi")
        print(" [4] VIN/Şasi No → Üretici + Yıl")
        print(" [5] Domain → Wayback Machine Arşivi")
        print(" [0] Geri")

        choice = input(Fore.CYAN + "\nSeçim: " + Style.RESET_ALL).strip()

        if choice == '1':
            coords = input("Koordinat (lat,lon): ").strip()
            try:
                lat, lon = coords.split(',')
                reverse_geocode(lat.strip(), lon.strip())
            except:
                print(Fore.RED + "Format: 41.0082, 28.9784")
        elif choice == '2':
            bssid = input("BSSID/MAC (00:11:22:33:44:55): ").strip()
            bssid_location(bssid)
        elif choice == '3':
            plate = input("Plaka (34ABC123): ").strip()
            plate_lookup(plate)
        elif choice == '4':
            vin = input("VIN (17 karakter): ").strip()
            vin_lookup(vin)
        elif choice == '5':
            domain = input("Domain: ").strip()
            wayback_scan(domain)
        elif choice == '0':
            break
        else:
            print(Fore.RED + "Geçersiz!")

        input(Fore.YELLOW + "\nDevam için ENTER..." + Style.RESET_ALL)