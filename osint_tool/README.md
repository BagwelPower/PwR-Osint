# PwR Osint

**PwR Osint**, telefonda çalışan açık kaynak bir OSINT (açık kaynak istihbarat) ve siber güvenlik keşif aracıdır. Kişi, sosyal medya, domain, IP, web sitesi, sızıntı, kripto para ve fotoğraf için **28 araç ve 41 işlem** sunar. Çoğu API anahtarı gerektirmez.

Aynı çekirdek üç arayüzden kullanılır:

- 📱 **Android uygulaması**: akıllı arama, kart tabanlı sonuçlar, rapor kaydetme ve HTML dışa aktarma
- 💻 **Etkileşimli terminal**: Windows, Linux ve macOS
- ⚙️ **Komut satırı**: tek satırlık sorgular, `--json` ve `--html` çıktısı

> **Coded by BagwelPower**

| Ana ekran | Akıllı arama | Araç bilgisi | Sonuç |
|---|---|---|---|
| ![](../docs/screenshots/1-ana-ekran.png) | ![](../docs/screenshots/2-akilli-arama.png) | ![](../docs/screenshots/3-arac-bilgisi.png) | ![](../docs/screenshots/4-sonuc.png) |

---

## ✨ Öne çıkanlar

- **Akıllı arama.** Ne yazarsanız (e-posta, IP, domain, URL, telefon, hash, kripto adresi, ASN, VIN, plaka, koordinat, kullanıcı adı) türünü tanır ve ilgili araçları önerir.
- **Önemli bulgular.** Her raporun başında, bütün bölümlerden toplanmış kritik ve dikkat gerektiren bulgular yer alır: süresi dolan sertifika, internete açık veritabanı portu, sızmış şifre, GPS konumu, e-posta alabilen taklit domain gibi.
- **Anahtarsız çalışır.** Shodan, VirusTotal, Have I Been Pwned ve Hunter.io anahtarı yoksa ücretsiz yedek kaynaklar kullanılır ve raporda hangi kaynağın kullanıldığı yazılır.
- **Kaynak durumu.** Limiti dolan ya da yanıt vermeyen kaynaklar sonuçlara karışmaz; raporun altında ayrıca listelenir.
- **Pivot.** Sonuçtaki bir e-posta, IP ya da domain tek dokunuşla ilgili araçta açılır.
- **Tam Domain Taraması.** 8 araç tek raporda çalışır: altyapı, DNS, TLS, subdomain, site, urlscan, arşiv, taklit domainler.
- **Raporlar.** Raporlar cihazda saklanabilir, tek dosyalık HTML olarak dışa aktarılabilir, paylaşılabilir ya da JSON olarak kopyalanabilir.
- **Tanılama.** Ayarlar → Tanılama, bütün araçları cihazınızda çalıştırıp hangisinin çalıştığını gösterir.

---

## 🧰 Araçlar

| Kategori | Araç | Ne yapar | Anahtar |
|---|---|---|---|
| **Kişi** | Kullanıcı Adı | Hızlı tarama 23 sitede resmî API'lerle çalışır. Derin tarama, [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) veri setiyle **650'den fazla** sitede yaklaşık 15 saniye sürer. | — |
| | E-posta | MX, SPF ve DMARC; Gravatar profili ve doğrulanmış hesaplar; bilinen sızıntılar; kurumsal domainin yaşı. Ad soyaddan adres üretir, domainin sitesindeki adresleri toplar. | Hunter (isteğe bağlı) |
| | Telefon | Geçerlilik, tür, operatör tahsisi, bölge, saat dilimi, biçimler (libphonenumber). | — |
| | İsim / Soyisim | GitHub kullanıcıları, OpenAlex akademik yazarları, ORCID ve Wikidata kayıtları, hedefli Google dork'ları. | — |
| **Sosyal Medya** | GitHub | Profil, diller, popüler repolar, organizasyonlar, **commit'lerden sızan e-postalar**, aktif saatler. | Token (isteğe bağlı) |
| | Reddit | Hesap yaşı, karma, subreddit'ler, aktif saatlerden **saat dilimi tahmini**. Reddit erişimi engellerse herkese açık arşiv kullanılır. | — |
| | Telegram | Kullanıcı, kanal, grup ya da bot olduğu; abone sayısı, açıklama. | — |
| | Mastodon | Fediverse hesabı, sunucunun doğruladığı linkler. | — |
| **Ağ & Domain** | Tam Domain Taraması | Aşağıdaki 8 aracı tek raporda birleştirir. | — |
| | IP & Domain | RDAP WHOIS, konum ve ASN, abuse iletişimi, açık portlar ve **riskli servisler**, yazılımlar, CVE'ler. | — |
| | DNS | Bütün kayıt türleri ile SPF, DMARC ve CAA değerlendirmesi, kullanılan servisler. | — |
| | SSL / TLS | Sertifika doğrulama ve kalan süre, protokol, SAN, HTTP güvenlik başlıkları. | — |
| | Subdomain | 7 pasif kaynak (crt.sh, CertSpotter, HackerTarget, OTX, Anubis, urlscan, Wayback) ve canlılık kontrolü. | — |
| | Web Arşivi | Wayback Machine'deki ilk ve son kayıt, arşivlenmiş ilginç dosyalar ve parametreli URL'ler. | — |
| | Reverse IP | Aynı sunucudaki diğer siteler. | — |
| | ASN / BGP | Ağ sahibi, IP blokları, üst sağlayıcılar (RIPEstat). | — |
| **Web** | Site Analizi | yaklaşık 60 teknoloji imzası; sayfadaki e-posta, telefon ve sosyal hesaplar; **Analytics, AdSense ve Pixel kimlikleri**; robots.txt, sitemap, security.txt. | — |
| | urlscan.io | Geçmiş taramalar, görülen IP'ler, zararlı işaretleri. | — |
| | Google Dork | Belgeler, açık dizinler, paneller ve sızıntı siteleri için 12 hazır sorgu. | — |
| **Tehdit İstihbaratı** | Sızıntı Kontrolü | E-postanın bulunduğu sızıntılar, sızan veri türleri, şifre saklama riski. Şifre sızıntısı k-anonimlikle kontrol edilir, şifre cihazdan çıkmaz. Şifre gücünü de ölçer. | HIBP (isteğe bağlı) |
| | Shodan | Açık portlar, yazılımlar, CVE'ler. Banner bilgisi ve arama için anahtar gerekir. | Arama için |
| | Tehdit İtibarı | Domain, IP ya da dosya hash'i için AlienVault OTX tehdit raporları ve zararlı aileleri; anahtarla VirusTotal motorları. | VT (isteğe bağlı) |
| | Oltalama & Taklit | Domainin yüzlerce benzerini üretir, **kayıtlı ve e-posta alabilen** taklitleri bulur; OpenPhish akışında arar. | — |
| | Kara Liste | IP'nin 10 DNSBL listesindeki durumu. | — |
| **Kripto** | Kripto Adres | Bitcoin (Legacy, SegWit, Taproot; sağlama toplamı doğrulamalı) ve Ethereum: bakiye, USD ve TL karşılığı, işlemler. | — |
| **Görsel & Dosya** | Görsel Analizi | **Cihazdan ya da URL'den** fotoğrafın EXIF bilgisi (cihaz, tarih, seri no, düzenleme izi), **GPS konumu ve adresi**; tersine görsel arama. | — |
| **Diğer** | Konum | Koordinattan adres ve harita linkleri; MAC adresinden üretici, rastgele MAC tespiti, WiGLE konumu. | WiGLE (isteğe bağlı) |
| | Araç | VIN için yapı, kontrol hanesi ve NHTSA çözümlemesi; Türk plakası için il ve biçim doğrulaması. | — |

Her aracın uygulamadaki **"Bu araç ne yapar?"** kartında kaynakları ve sınırları ayrıca yazar.

---

## 📱 Android

**APK'yı indirmek için:** GitHub'da **Actions → CI & Android APK** sayfasında son başarılı çalıştırmayı açın, **Artifacts** bölümünden `PwR-Osint-apk` dosyasını indirin, zip'i açıp `.apk`'yı kurun. Kurulumda "bilinmeyen kaynaklardan yükleme" iznini bir kerelik vermeniz gerekir.

**İlk kurulumdan sonra:** **Ayarlar → Tanılama → Testi başlat** ile araçların cihazınızda çalıştığını kontrol edebilirsiniz. Bir sorun görürseniz sonucu kopyalayıp bir issue açın.

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
python osint_tool.py                                  # etkileşimli menü
python -m pwrosint --list                             # tüm araçlar ve girdileri
python -m pwrosint fullscan ornek.com --html rapor.html
python -m pwrosint username deep kullanici_adi
python -m pwrosint image file ~/foto.jpg
python -m pwrosint host 8.8.8.8 --json                # makine okunur çıktı
```

Sorgu sürerken `Ctrl+C` yalnızca sorguyu iptal eder, programı kapatmaz.

---

## ⚙️ API anahtarları (hepsi isteğe bağlı)

Anahtarlar uygulamada **Ayarlar** ekranından, terminalde ise menüdeki **A** seçeneğinden girilir. Yalnızca cihazınızda saklanır ve yalnızca ilgili servise gönderilir.

| Servis | Ne kazandırır | Adres |
|---|---|---|
| Shodan | Servis banner'ları, konum, Shodan araması | https://account.shodan.io/ |
| VirusTotal | 70'ten fazla antivirüs motorunun kararı | https://www.virustotal.com/gui/my-apikey |
| Have I Been Pwned | HIBP sızıntı veritabanı | https://haveibeenpwned.com/API/Key |
| Hunter.io | Domain için doğrulanmış e-posta adresleri | https://hunter.io/api-keys |
| GitHub | Saatte 60 yerine 5000 istek | https://github.com/settings/tokens |
| WiGLE | Wi-Fi ağlarının konumu | https://wigle.net/account |
| IPinfo | Daha yüksek istek limiti | https://ipinfo.io/account/token |

Ayar dosyası konumu: Android'de uygulamanın özel dizini; terminalde `~/.pwr-osint/config.json` (çalışma dizininde `config.json` varsa o kullanılır) ya da `PWR_OSINT_CONFIG` ile belirttiğiniz yol.

---

## 🏗️ Mimari

```
osint_tool/
├── main.py                 # Android / mobil arayüz (Flet)
├── osint_tool.py           # Terminal başlatıcı
├── pwrosint/
│   ├── cli.py              # Terminal arayüzü (rich) + komut satırı
│   ├── core/
│   │   ├── report.py       # Sonuç modeli: bölümler, önemli bulgular, kaynak durumu
│   │   ├── registry.py     # Araç / işlem / alan tanımları, kategoriler
│   │   ├── runner.py       # Çalıştırma, hata, iptal ve eksik anahtar yönetimi
│   │   ├── http.py         # Ortak HTTP: yeniden deneme, yanıt biçimi denetimi
│   │   ├── dns.py          # DNS-over-HTTPS (Cloudflare → Google)
│   │   ├── detect.py       # Akıllı arama
│   │   ├── store.py        # Kayıtlı raporlar, HTML dışa aktarma
│   │   ├── ports.py        # Riskli port sınıflandırması
│   │   └── validate.py, config.py, history.py, samples.py
│   └── modules/            # person, social, network, web, threat, crypto, media, misc, fullscan, docs
└── tests/                  # birim, sağlamlık ve canlı testler
```

Modüller ekrana bir şey yazmaz; bir `Report` doldurur. Terminal, Android, JSON ve HTML çıktısı aynı raporu kendi biçiminde gösterir. Yeni bir araç eklemek için bir modülde `register(Tool(...))` çağırmak ve `docs.py`'ye açıklamasını eklemek yeterlidir; menüler, akıllı arama ve tanılama otomatik olarak güncellenir.

### Kalite güvencesi

```bash
pip install -r requirements-dev.txt
python -m pytest                        # 380+ birim ve sağlamlık testi, internet gerekmez
PWR_LIVE=1 python -m pytest tests/live  # her işlem gerçek servislere karşı
```

- **Sağlamlık testi:** Her işlemi altı bozuk ağ senaryosunda çalıştırır (kopuk ağ, boş yanıt, HTML, 500, 403…). Hiçbir araç çökmemeli, kullanıcıya her zaman okunur bir mesaj vermelidir.
- **Canlı testler:** CI'da her push'ta, bütün işlemler gerçek servislere karşı çalıştırılır.
- **Statik analiz:** `ruff` ile yapılır. Testler geçmeden APK derlenmez.

---

## ⚠️ Yasal uyarı

Bu araç **yalnızca eğitim, araştırma, gazetecilik ve kendi sistemlerinizdeki ya da yazılı izin aldığınız hedeflerdeki güvenlik testleri** için tasarlanmıştır. Yalnızca herkese açık kaynakları sorgular; hedefe port taraması ya da saldırı niteliğinde istek göndermez.

- Başkalarının kişisel verilerini izinsiz toplamayın, saklamayın, paylaşmayın.
- Yerel yasalara uyun: Türkiye'de KVKK ve TCK 243–245, AB'de GDPR.
- Servislerin kullanım koşullarına ve istek limitlerine uyun.

**Sorumluluk tamamen kullanıcıya aittir.**

---

## 📜 Lisans ve teşekkür

MIT, ayrıntılar için `LICENSE` dosyasına bakın. Derin kullanıcı adı taramasının site listesi [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) projesinden gelir (CC BY-SA 4.0, Micah Hoffman ve katkıcılar). Telefon analizi Google'ın [libphonenumber](https://github.com/google/libphonenumber) verisini kullanır.
