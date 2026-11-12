# PwR Osint

**PwR Osint** — Python tabanlı, terminal menülü, kapsamlı OSINT (Open Source Intelligence) framework'ü. Kullanıcı adı, e-posta, telefon, isim, IP/domain, DNS, SSL, subdomain, BSSID, plaka, VIN, Wayback Machine ve daha fazlasını tek bir arayüzden sorgular.

> **Coded by BagwelPower**

---

## 🎯 Özellikler

| Modül | Açıklama |
|-------|----------|
| **1. Username** | 37 platformda (GitHub, Twitter, Instagram, LinkedIn, Reddit, vb.) kullanıcı adı varlığını kontrol eder |
| **2. E-posta** | Domain analizi, breach kontrolü, Gravatar, sosyal medya profilleri |
| **3. Telefon** | Ülke/operatör tespiti (TR için Turkcell/Vodafone/TT), E.164 format, OSINT linkleri (WhatsApp, Truecaller, Sync.me) |
| **4. İsim/Soyisim** | Google dork'ları, sosyal medya arama linkleri, akademik/kamu verisi kaynakları |
| **5. IP & Domain** | Public/private IP tespiti, reverse DNS, WHOIS/GeoIP/Shodan/Censys linkleri |
| **6. Gelişmiş** | Koordinat→Adres (Nominatim), BSSID→Konum+Vendor, Plaka→İl+Tip, VIN→Üretici+Yıl, Wayback Machine arşivi |
| **7. DNS Kayıtları** | A, AAAA, MX, NS, TXT, CNAME, SOA + DoH (Google DNS) |
| **8. SSL/TLS** | Sertifika detayları (SAN, geçerlilik, cipher, serial), SSL Labs linki |
| **9. Subdomain Enum** | crt.sh, DNSDumpster, HackerTarget API ile 200+ subdomain keşfi |
| **10. Ek E-posta** | Permutator (10 pattern), Hunter.io API entegrasyonu |
| **11. HIBP** | E-posta sızma kontrolü, şifre sızma kontrolü (k-anonimlik) |
| **12. Shodan** | Host sorgulama + arama (API key gerekli) |
| **13. VirusTotal** | Domain/IP reputation + analiz (API key gerekli) |
| **14. Config** | API anahtarları yönetimi (config.json) |

---

## 🚀 Kurulum

```bash
# 1. Repoyu klonla
git clone https://github.com/BagwelPower/PwR-Osint.git
cd PwR-Osint

# 2. Sanal ortam oluştur (önerilir)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 3. Bağımlılıkları yükle
pip install -r requirements.txt

# 4. (İsteğe bağlı) API keylerini ayarla
# Menüden [14] seçeneğiyle veya config.json dosyasını düzenleyerek
```

### requirements.txt
```text
colorama>=0.4.6
requests>=2.31.0
```

---

## ⚙️ Yapılandırma

İlk çalıştırmada `config.json` otomatik oluşturulur. API keyleri menüden **[14] API Anahtar Yönetimi** ile girilebilir veya dosyayı doğrudan düzenleyebilirsiniz.

```json
{
  "shodan_api_key": "",
  "virustotal_api_key": "",
  "hunter_api_key": "",
  "securitytrails_api_key": "",
  "censys_api_id": "",
  "censys_api_secret": "",
  "whoisxml_api_key": "",
  "haveibeenpwned_api_key": "",
  "timeout": 10,
  "user_agent": "PwR-Osint/1.0"
}
```

**API Key Sağlayıcılar:**
- **Shodan** → https://account.shodan.io/
- **VirusTotal** → https://www.virustotal.com/gui/my-apikey
- **Hunter.io** → https://hunter.io/api
- **Have I Been Pwned** → https://haveibeenpwned.com/API/Key
- **SecurityTrails** → https://securitytrails.com/app/api-keys
- **Censys** → https://censys.io/account/api
- **WhoisXML** → https://www.whoisxmlapi.com/

---

## 💻 Kullanım

```bash
python osint_tool.py
```

Menüden numara girerek ilgili modülü çalıştırın. Her modül sonunda `ENTER` ile ana menüye dönebilirsiniz.

---

## 📁 Proje Yapısı

```
PwR-Osint/
├── osint_tool.py          # Ana program (menü + routing)
├── config.py              # Config yükleme/kaydetme
├── config.json            # API keyler (gitignore'da)
├── config.json.example    # Şablon dosyası
├── requirements.txt       # Bağımlılıklar
├── README.md              # Bu dosya
├── LICENSE                # MIT Lisansı
├── .gitignore             # Git hariç tutmalar
└── osint_modules/
    ├── __init__.py
    ├── username.py
    ├── email.py
    ├── phone.py
    ├── name.py
    ├── ip_domain.py
    ├── advanced.py
    ├── dns_records.py
    ├── ssl_cert.py
    ├── subdomain.py
    ├── email_extra.py
    ├── hibp.py
    ├── shodan_api.py
    └── virustotal.py
```

---

## ⚠️ Yasal Uyarı

Bu araç **yalnızca eğitim, araştırma ve kendi sistemlerinizdeki güvenlik testleri** için tasarlanmıştır. Başkalarına ait sistemlere yetkisiz erişim, bilgi toplama veya herhangi bir saldırı **yasadışıdır** ve **etik değildir**.

- Sadece **kendi** ağlarınız, domainleriniz, hesaplarınız üzerinde kullanın.
- Başkalarının verilerini izinsiz toplamayın.
- Yerel yasalarınıza (Türkiye'de 5651 sayılı Kanun, TBK, KVKK; AB'de GDPR) uyun.

**Sorumluluk tamamen kullanıcıya aittir.**

---

## 🤝 Katkı

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/yeni-modul`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni modul: X'`)
4. Push yapın (`git push origin feature/yeni-modul`)
5. Pull Request açın

---

## 📜 Lisans

MIT License — detaylar için `LICENSE` dosyasına bakın.

---

## 👨‍💻 Yazar

**BagwelPower** — `Coded by BagwelPower`

---

⭐ Bu projeyi beğendiyseniz yıldızlamayı unutmayın!