"""Her aracın açıklaması, sorguladığı kaynaklar ve bilinmesi gereken sınırları.
Arayüzler bunu araç bilgi ekranında gösterir; test, hiçbir aracın açıklamasız
kalmamasını garanti eder."""

TOOL_DOCS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "username": (
        "Bir kullanıcı adının hangi platformlarda kayıtlı olduğunu bulur. Hızlı tarama 23 seçili sitede resmî "
        "API'lerle kontrol eder; derin tarama WhatsMyName veri setindeki 650+ sitenin her biri için "
        "'profil var' ve 'profil yok' imzalarını karşılaştırır.",
        ("Platform API'leri", "WhatsMyName", "Arctic Shift (Reddit yedeği)"),
        "Instagram, X, TikTok, LinkedIn gibi siteler giriş istediği için otomatik doğrulanamaz; bunlar manuel "
        "kontrol linki olarak verilir. Aynı kullanıcı adı farklı kişilere ait olabilir."),
    "email": (
        "E-posta adresinin geçerliliğini (MX), alan adının sahte gönderime karşı korumasını (SPF/DMARC), "
        "Gravatar profilini ve bağlı hesaplarını, bilinen sızıntılarını ve kurumsal domainin yaşını çıkarır. "
        "Permutator ad-soyaddan olası adresleri üretir; domain taraması sitede yayınlanan adresleri toplar.",
        ("DNS-over-HTTPS", "Gravatar", "XposedOrNot", "RDAP", "Hunter.io (anahtarla)"),
        "Bir adresin gerçekten var olduğu, posta kutusuna mesaj gönderilmeden kesin olarak bilinemez."),
    "phone": (
        "Numaranın geçerliliğini, türünü (mobil/sabit/VoIP), operatör tahsisini, bölgesini, saat dilimini ve "
        "tüm biçimlerini Google'ın libphonenumber veritabanıyla çıkarır; mesajlaşma ve arama linkleri verir.",
        ("libphonenumber (cihazda)",),
        "Operatör, numaranın ilk tahsis edildiği operatördür; numara taşınmış olabilir. Numaradan kişi "
        "bilgisine ulaşmak KVKK kapsamında kamuya açık değildir."),
    "name": (
        "Ad soyadla eşleşen gerçek kayıtları getirir: GitHub kullanıcıları, akademik yazarlar (kurum, yayın, "
        "atıf), ORCID kayıtları ve Wikidata'daki tanınmış kişiler; ardından hedefli Google dork'ları üretir.",
        ("GitHub", "OpenAlex", "ORCID", "Wikidata"),
        "Yaygın isimlerde sonuçlar farklı kişilere ait olabilir; kurum ve konum bilgisiyle eleyin."),
    "github": (
        "GitHub hesabının profilini, en popüler repolarını, kullandığı dilleri, organizasyonlarını, aktif "
        "saatlerini ve commit'lere yazılmış gerçek isim/e-posta adreslerini çıkarır.",
        ("GitHub API",),
        "Token olmadan saatte 60 istek; Ayarlar'dan token eklenirse 5000."),
    "reddit": (
        "Reddit hesabının yaşını, karmasını, en çok yazdığı subreddit'leri ve aktif saatlerinden tahmini saat "
        "dilimini çıkarır.",
        ("Reddit", "Arctic Shift arşivi"),
        "Reddit bazı ağlardan erişimi engeller; bu durumda veriler herkese açık arşivden gelir ve karma "
        "bilgisi gösterilemez."),
    "telegram": (
        "Telegram kullanıcı adının kullanıcı, kanal, grup ya da bot olduğunu; ad, açıklama, abone/üye sayısı "
        "ve profil fotoğrafını gösterir.",
        ("t.me",), "Gizli hesaplar ve telefon numarası bilgisi görünmez."),
    "fediverse": (
        "Mastodon ve diğer Fediverse sunucularındaki hesabın biyografisini, istatistiklerini ve sunucunun "
        "doğruladığı linkleri gösterir.",
        ("Mastodon API",), "Sunucu, hesabı kendi kurallarıyla gizleyebilir."),
    "host": (
        "Domain ya da IP için tam profil: DNS çözümleme, WHOIS (kayıt ve bitiş tarihi), konum ve ağ sahibi, "
        "abuse iletişimi, açık portlar, tespit edilen yazılımlar ve bilinen zafiyetler (CVE).",
        ("DNS-over-HTTPS", "RDAP", "ipinfo.io", "Shodan InternetDB"),
        "IP konumu ağ bloğunun kayıtlı yeridir, kişinin konumu değildir. .tr uzantıları RDAP sunmaz."),
    "dns": (
        "A, AAAA, CNAME, MX, NS, TXT, SOA, CAA kayıtlarını sorgular; SPF, DMARC ve CAA politikalarını "
        "değerlendirip domainin hangi servisleri kullandığını doğrulama kayıtlarından çıkarır.",
        ("Cloudflare DoH", "Google DoH"), ""),
    "tls": (
        "Sertifikanın geçerliliğini, sağlayıcısını, kalan süresini, parmak izini ve alternatif isimlerini; "
        "bağlantı protokolünü ve web sitesinin HTTP güvenlik başlıklarını (HSTS, CSP…) denetler.",
        ("Doğrudan TLS bağlantısı",), ""),
    "subdomain": (
        "Sertifika şeffaflık kayıtları, pasif DNS ve web arşivlerinden alt alan adlarını toplar, hangilerinin "
        "hâlâ bir IP'ye çözüldüğünü kontrol eder. Hedefe hiçbir tarama isteği gönderilmez.",
        ("crt.sh", "CertSpotter", "HackerTarget", "AlienVault OTX", "Anubis", "urlscan.io", "Wayback Machine"),
        "Ücretsiz kaynakların istek limitleri vardır; limitli kaynaklar 'Kaynak durumu'nda görünür."),
    "wayback": (
        "Domainin Wayback Machine'deki ilk ve son kaydını, arşivlenmiş ilginç dosyaları (.pdf, .sql, .env…) "
        "ve parametreli URL'leri listeler. Silinmiş sayfalar ve sızmış dosyalar için kullanılır.",
        ("Wayback Machine CDX",), ""),
    "reverseip": (
        "Aynı IP adresini paylaşan diğer domainleri bulur; bir sunucuda barındırılan diğer siteleri ve "
        "aynı sahibe ait olabilecek projeleri ortaya çıkarır.",
        ("HackerTarget", "urlscan.io"),
        "Paylaşımlı hosting ve CDN'lerde yüzlerce ilgisiz site aynı IP'de olabilir."),
    "asn": (
        "Ağın sahibini, duyurduğu IP bloklarını ve internet erişimini sağlayan üst sağlayıcıları BGP "
        "verisinden gösterir.",
        ("RIPEstat",), ""),
    "site": (
        "Sitenin kullandığı 60+ teknolojiyi, sayfadaki e-posta, telefon ve sosyal medya hesaplarını ve aynı "
        "sahibin diğer sitelerine giden Analytics/AdSense/Pixel kimliklerini çıkarır; robots.txt, sitemap ve "
        "security.txt dosyalarını okur.",
        ("Hedef site (tek sayfa isteği)",), ""),
    "urlscan": (
        "Domainin urlscan.io'daki geçmiş taramalarını, görülen IP'leri, sunucuları ve zararlı işaretlerini "
        "gösterir.", ("urlscan.io",), ""),
    "dorks": (
        "Domain için belgeler, açık dizinler, yönetim panelleri, sızıntı ve bulut depolama sitelerine yönelik "
        "hazır Google dork sorguları üretir.", (),
        "Sorgular tarayıcıda açılır; bulunanları izinsiz kullanmayın."),
    "hibp": (
        "Şifrenin sızıntılarda görülüp görülmediğini (şifre cihazdan çıkmadan) ve gücünü; e-posta adresinin "
        "bulunduğu sızıntıları, sızan veri türlerini ve şifre saklama riskini gösterir.",
        ("Pwned Passwords", "XposedOrNot", "Have I Been Pwned (anahtarla)"), ""),
    "shodan": (
        "IP'nin açık portlarını, yazılımlarını ve zafiyetlerini gösterir; anahtarla servis banner'ları, konum "
        "ve Shodan araması da kullanılabilir.",
        ("Shodan InternetDB", "Shodan API (anahtarla)"), "Arama işlemi yalnızca API anahtarıyla çalışır."),
    "virustotal": (
        "Domain, IP veya dosya hash'inin tehdit itibarını gösterir: hangi güvenlik motorlarının işaretlediği, "
        "hangi tehdit raporlarında ve zararlı ailelerinde geçtiği.",
        ("AlienVault OTX", "VirusTotal (anahtarla)"), ""),
    "phishing": (
        "Domainin yüzlerce benzerini (harf hatası, benzer karakter, farklı uzantı, oltalama ekleri) üretip "
        "hangilerinin kayıtlı olduğunu ve e-posta alabildiğini bulur; OpenPhish akışında arar.",
        ("DNS-over-HTTPS", "OpenPhish"), "Kayıtlı olması zararlı olduğu anlamına gelmez; inceleyin."),
    "blacklist": (
        "IP'nin 10 spam ve kötüye kullanım kara listesindeki (DNSBL) durumunu kontrol eder.",
        ("Spamhaus", "SpamCop", "Barracuda", "SORBS", "PSBL", "UCEPROTECT", "DroneBL", "s5h", "Mailspike",
         "Anonmails"),
        "Spamhaus genel DNS sunucularından gelen sorguları yanıtlamaz; bu liste 'Kaynak durumu'nda görünür."),
    "crypto": (
        "Bitcoin (Legacy, SegWit, Taproot) ve Ethereum adreslerinin bakiyesini, dolar/TL karşılığını ve işlem "
        "geçmişini gösterir; adres sağlama toplamını doğrular.",
        ("Blockstream", "BlockCypher", "CoinGecko"), "Ethereum'da yalnızca ETH bakiyesi; token'lar için Etherscan."),
    "image": (
        "Görseldeki gizli meta veriyi okur: cihaz, çekim zamanı, yazılım, seri numarası ve GPS konumu; "
        "boyut, hash ve tersine görsel arama linkleri verir.",
        ("Görsel adresi", "Google Lens / Yandex / Bing / TinEye"),
        "Sosyal medya siteleri yüklenen fotoğraflardaki EXIF verisini genellikle siler."),
    "geo": (
        "Koordinattan adres, harita ve sokak görünümü linkleri; MAC/BSSID adresinden üretici, rastgele MAC "
        "tespiti ve (WiGLE anahtarıyla) Wi-Fi ağının konumu.",
        ("OpenStreetMap Nominatim", "macvendors", "WiGLE (anahtarla)"), ""),
    "vehicle": (
        "VIN/şasi numarasının yapısını, kontrol hanesini, model yılını ve NHTSA veritabanındaki marka, model, "
        "motor ve fabrika bilgisini; Türk plakasının il ve biçim doğruluğunu gösterir.",
        ("NHTSA vPIC",),
        "Türkiye'de plakadan araç sahibine ulaşmak KVKK gereği kamuya açık değildir; bu araç bu sınırı aşmaz."),
}


def apply(tools) -> None:
    for t in tools:
        if t.id in TOOL_DOCS:
            t.description, t.sources, t.limits = TOOL_DOCS[t.id]
