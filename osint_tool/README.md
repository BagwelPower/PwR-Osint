# PwR Osint

**PwR Osint**, Python ile yazılmış açık kaynak bir OSINT (Open Source Intelligence) framework'üdür. Aynı çekirdek üç arayüzden kullanılır:

- 📱 **Android uygulaması**: kart tabanlı sonuçlar, akıllı arama, geçmiş, paylaşım
- 💻 **Etkileşimli terminal**: renkli menü, Windows / Linux / macOS
- ⚙️ **Komut satırı**: tek satırlık sorgular, `--json` çıktısı (betiklere bağlanabilir)

> **Coded by BagwelPower**

---

## 🎯 Araçlar

| Kategori | Araç | Ne yapar | API anahtarı |
|---|---|---|---|
| Kişi | **Kullanıcı Adı** | 24 sitede gerçek kontrol (resmî API'ler, "profil yok" metni tespiti) + giriş isteyen 10 site için manuel kontrol linkleri | — |
| | **E-posta** | MX / SPF / DMARC analizi, sağlayıcı tespiti, geçici e-posta tespiti, Gravatar · Permutator (Türkçe karakter desteği) · Hunter.io | Hunter (isteğe bağlı) |
| | **Telefon** | `phonenumbers` ile geçerlilik, tür (mobil/sabit/VoIP), operatör tahsisi, bölge, saat dilimi, formatlar | — |
| | **İsim / Soyisim** | Google dork'ları, platform aramaları, akademik/kamu kaynakları, kullanıcı adı adayları | — |
| Sosyal Medya | **GitHub** | Profil, diller, en popüler repolar, organizasyonlar, **commit'lerden sızan e-postalar**, aktif saatler | GitHub token (isteğe bağlı) |
| | **Reddit** | Hesap yaşı, karma, en çok yazdığı subreddit'ler, aktif saatlerden **saat dilimi tahmini** | — |
| | **Telegram** | Kullanıcı / kanal / grup ayrımı, abone sayısı, açıklama, fotoğraf | — |
| | **Mastodon** | Fediverse hesabı, biyografi, sunucunun doğruladığı linkler | — |
| Ağ & Domain | **IP & Domain** | RDAP WHOIS (kayıt/bitiş tarihi, yeni kayıt uyarısı), konum & ASN, abuse iletişimi, **Shodan InternetDB** ile açık port ve CVE'ler | — |
| | **DNS** | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA (DNS-over-HTTPS) + SPF/DMARC/CAA değerlendirmesi | — |
| | **SSL / TLS** | Sertifika doğrulama (bozuk sertifikada bile ayrıntı), kalan süre, SHA-256, protokol, SAN, HTTP güvenlik başlıkları | — |
| | **Subdomain** | crt.sh, HackerTarget, AlienVault OTX, Anubis + canlılık kontrolü | — |
| | **Web Arşivi** | Wayback Machine: ilk/son kayıt, ilginç dosyalar (.pdf, .sql, .env…), parametreli URL'ler | — |
| | **Reverse IP** | Aynı sunucuyu paylaşan diğer domainler | — |
| | **ASN / BGP** | Ağ sahibi, duyurulan IP blokları, üst sağlayıcılar (RIPEstat) | — |
| Web | **Site Analizi** | 60+ teknoloji imzası (TR e-ticaret altyapıları dahil), sayfadaki e-posta/telefon/sosyal hesaplar, **Analytics / AdSense / Pixel kimlikleri** (aynı sahibin diğer sitelerine giden iz), robots.txt, sitemap, security.txt | — |
| | **urlscan.io** | Domainin geçmiş taramaları, görülen IP'ler ve zararlı işaretleri | — |
| | **Google Dork** | Belgeler, açık dizinler, paneller, sızıntı siteleri, bulut depolama için 12 hazır dork | — |
| Tehdit | **Sızıntı Kontrolü** | Şifre sızıntısı (k-anonimlik: şifre cihazdan çıkmaz) · e-posta sızıntıları | HIBP (e-posta için) |
| | **Shodan** | Host detayı, servisler, zafiyetler · arama | Shodan |
| | **VirusTotal** | Domain, IP ve dosya hash'i itibarı, işaretleyen motorlar | VirusTotal |
| | **Oltalama & Taklit** | Domainin ~100+ benzer varyasyonunu üretip **kayıtlı olanları** bulur (MX'i olanlar kırmızı) · OpenPhish akışında arama | — |
| | **Kara Liste** | IP'nin 10 spam / DNSBL listesindeki durumu | — |
| Kripto | **Kripto Adres** | Bitcoin (Legacy/SegWit/Taproot, sağlama doğrulamalı) ve Ethereum: bakiye, USD/TL karşılığı, işlem geçmişi | — |
| Görsel & Dosya | **Görsel Analizi** | URL'den görsel: **EXIF (cihaz, çekim zamanı, seri no) ve GPS konumu**, boyut, hash'ler, Google Lens / Yandex / Bing / TinEye tersine arama | — |
| Diğer | **Konum** | Koordinat → adres (OpenStreetMap), harita/Street View linkleri · BSSID/MAC → üretici, rastgele MAC tespiti, WiGLE konumu | WiGLE (isteğe bağlı) |
| | **Araç** | VIN: yapı, kontrol hanesi, model yılı, NHTSA çözümleme · TR plaka: il ve format doğrulama | — |

Anahtarsız araçlar kurulumdan hemen sonra çalışır.

---

## 📱 Android

### APK'yı indir
Her push'ta GitHub Actions testleri çalıştırır ve APK'yı derler:
**Actions → CI & Android APK → son çalıştırma → Artifacts → `PwR-Osint-apk`** (zip içinde `.apk`).
`v2.0.0` gibi bir tag push'lanırsa APK doğrudan **Releases** sayfasına da eklenir.

Kurulum: APK'ya dokunun ve "bilinmeyen kaynaklardan yükleme" iznini bir kerelik verin.

### Özellikler
- **Akıllı arama**: e-posta, IP, domain, URL, görsel linki, telefon, hash, Bitcoin/Ethereum adresi, ASN, VIN, plaka, koordinat ya da kullanıcı adı yazın; uygulama türünü tanıyıp uygun aracı önerir ve çalıştırır.
- Sonuçlar renkli kartlarda gösterilir (yeşil = iyi, sarı = dikkat, kırmızı = risk). Linke dokunmak onu açar, satıra uzun basmak kopyalar.
- Rapor metin veya JSON olarak kopyalanabilir ya da paylaşılabilir. Uzun sorgular iptal edilebilir.
- Son 30 arama saklanır (şifreler asla saklanmaz).

---

## 💻 Terminal

```bash
git clone https://github.com/BagwelPower/PwR-Osint.git
cd PwR-Osint/osint_tool
python -m venv venv
# Windows: venv\Scripts\activate   ·   Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

```bash
python osint_tool.py                     # etkileşimli menü
python -m pwrosint --list                # tüm araçlar ve girdileri
python -m pwrosint dns ornek.com         # tek komut
python -m pwrosint email permutate Ahmet Yılmaz ornek.com
python -m pwrosint host 8.8.8.8 --json   # makine okunur çıktı
```

Sorgu sürerken `Ctrl+C` sorguyu iptal eder, programı kapatmaz.

---

## ⚙️ Yapılandırma

API anahtarları uygulamanın **Ayarlar** ekranından veya terminal menüsündeki **A** seçeneğinden girilir. Dosya konumu:

| Ortam | Konum |
|---|---|
| Android | Uygulamanın özel veri dizini |
| Terminal | `~/.pwr-osint/config.json` (çalışma dizininde `config.json` varsa o kullanılır) |
| Özel | `PWR_OSINT_CONFIG=/yol/config.json` |

Şablon için `config.json.example` dosyasına bakın. Dosya, sahibinden başka kimsenin okuyamayacağı izinlerle (`600`) yazılır.

| Servis | Anahtar adresi |
|---|---|
| Shodan | https://account.shodan.io/ |
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| Hunter.io | https://hunter.io/api-keys |
| Have I Been Pwned | https://haveibeenpwned.com/API/Key |
| WiGLE | https://wigle.net/account |
| GitHub (isteğe bağlı, limiti 60 → 5000/saat yapar) | https://github.com/settings/tokens |
| IPinfo (isteğe bağlı, limit artırır) | https://ipinfo.io/account/token |

---

## 🏗️ Mimari

```
osint_tool/
├── main.py                 # Android / mobil arayüz (Flet)
├── osint_tool.py           # Terminal başlatıcı (geriye dönük uyumluluk)
├── pwrosint/
│   ├── cli.py              # Terminal arayüzü (rich) + komut satırı
│   ├── core/
│   │   ├── report.py       # Yapılandırılmış sonuç modeli (Report → Section → Item)
│   │   ├── registry.py     # Araç / işlem / alan tanımları
│   │   ├── runner.py       # Çalıştırma, hata ve iptal yönetimi
│   │   ├── http.py         # Ortak HTTP oturumu, yeniden deneme, okunur hatalar
│   │   ├── dns.py          # DNS-over-HTTPS (Cloudflare → Google yedekli)
│   │   ├── validate.py     # Girdi doğrulama ve normalleştirme
│   │   ├── detect.py       # Akıllı arama
│   │   ├── history.py      # Son aramalar
│   │   └── config.py       # Ayarlar
│   └── modules/            # person, social, network, web, threat, crypto, media, misc
└── tests/                  # birim testleri (sahte HTTP) + tests/live (gerçek servisler)
```

Modüller ekrana hiçbir şey yazmaz, bir `Report` doldurur. Terminal, Android ve JSON çıktısı aynı raporu kendi biçiminde gösterir. Yeni bir araç eklemek için bir modülde `register(Tool(...))` çağırmak yeterlidir; menüler ve akıllı arama otomatik güncellenir.

### Testler
```bash
pip install -r requirements-dev.txt
python -m pytest                        # birim testleri, internet gerekmez
PWR_LIVE=1 python -m pytest tests/live  # gerçek servislere karşı duman testleri
```

---

## ⚠️ Yasal uyarı

Bu araç **yalnızca eğitim, araştırma ve kendi sistemlerinizdeki ya da yazılı izin aldığınız hedeflerdeki güvenlik testleri** için tasarlanmıştır.

- Başkalarının kişisel verilerini izinsiz toplamayın, saklamayın, paylaşmayın.
- Yerel yasalara uyun: Türkiye'de KVKK ve TCK 243–245, AB'de GDPR.
- Servislerin kullanım koşullarına ve istek limitlerine uyun.

**Sorumluluk tamamen kullanıcıya aittir.**

---

## 📜 Lisans

MIT. Ayrıntılar için `LICENSE` dosyasına bakın.
