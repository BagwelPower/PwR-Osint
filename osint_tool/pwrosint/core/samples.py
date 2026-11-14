"""Her işlem için gerçekçi örnek girdi. Testler ve uygulamadaki Tanılama ekranı kullanır."""

SAMPLES = {
    ("username", "scan"): {"username": "torvalds"},
    ("username", "deep"): {"username": "torvalds"},
    ("email", "analyze"): {"email": "test@gmail.com"},
    ("email", "permutate"): {"first": "Ahmet", "last": "Yılmaz", "domain": "github.com"},
    ("email", "hunter"): {"domain": "github.com"},
    ("phone", "analyze"): {"phone": "0532 123 45 67"},
    ("name", "search"): {"name": "Ahmet Yılmaz"},
    ("github", "profile"): {"username": "torvalds"},
    ("reddit", "profile"): {"username": "spez"},
    ("telegram", "profile"): {"username": "durov"},
    ("fediverse", "profile"): {"handle": "Gargron@mastodon.social"},
    ("host", "profile"): {"target": "github.com"},
    ("dns", "records"): {"domain": "github.com"},
    ("fullscan", "scan"): {"domain": "github.com"},
    ("tls", "analyze"): {"domain": "github.com"},
    ("subdomain", "enumerate"): {"domain": "example.com"},
    ("wayback", "scan"): {"domain": "example.com"},
    ("reverseip", "lookup"): {"target": "github.com"},
    ("asn", "lookup"): {"target": "AS9121"},
    ("site", "analyze"): {"url": "wordpress.org"},
    ("site", "files"): {"domain": "github.com"},
    ("urlscan", "search"): {"domain": "github.com"},
    ("dorks", "generate"): {"domain": "github.com"},
    ("hibp", "password"): {"password": "123456"},
    ("hibp", "email"): {"email": "test@gmail.com"},
    ("shodan", "host"): {"ip": "8.8.8.8"},
    ("shodan", "search"): {"query": "port:22 country:TR"},
    ("virustotal", "domain"): {"domain": "github.com"},
    ("virustotal", "ip"): {"ip": "8.8.8.8"},
    ("virustotal", "file"): {"hash": "44d88612fea8a8f36de82e1278abb02f"},
    ("phishing", "typosquat"): {"domain": "github.com"},
    ("phishing", "openphish"): {"domain": "github.com"},
    ("blacklist", "check"): {"ip": "8.8.8.8"},
    ("crypto", "btc"): {"address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
    ("crypto", "eth"): {"address": "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"},
    ("image", "file"): {"file": ""},  # testler örnek bir JPEG üretip yolunu buraya yazar
    ("image", "analyze"): {"url": "https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/gps/DSCN0010.jpg"},
    ("geo", "coords"): {"coords": "41.0082, 28.9784"},
    ("geo", "bssid"): {"mac": "00:1A:11:00:00:01"},
    ("vehicle", "vin"): {"vin": "1HGCM82633A004352"},
    ("vehicle", "plate"): {"plate": "34 ABC 123"},
}

SAMPLE_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaSBWZWxpIiwiaWF0IjoxNz"
              "AwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.c2lnbmF0dXJl")
SAMPLE_HEADERS = """Received: from mail.ornek.com (mail.ornek.com [93.184.216.34])
        by mx.google.com with ESMTPS id x1; Mon, 13 Jan 2025 10:00:05 +0000
Received: from [10.0.0.5] (unknown [203.0.113.7])
        by mail.ornek.com with ESMTPSA; Mon, 13 Jan 2025 10:00:01 +0000
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=ornek.com; dkim=pass header.d=ornek.com;
        dmarc=pass header.from=ornek.com
From: Ali Veli <ali@ornek.com>
To: ayse@example.org
Subject: Toplantı
Date: Mon, 13 Jan 2025 10:00:00 +0000
Message-ID: <abc123@ornek.com>"""

SAMPLES.update({
    ("emailheader", "analyze"): {"headers": SAMPLE_HEADERS},
    ("subnet", "calc"): {"net": "192.168.1.10/24"},
    ("decoder", "jwt"): {"token": SAMPLE_JWT},
    ("decoder", "auto"): {"text": "SGVsbG8gUHdSIE9zaW50IQ=="},
    ("decoder", "time"): {"time": "1700000000"},
    ("hash", "identify"): {"hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
    ("hash", "generate"): {"text": "parola"},
    ("password", "generate"): {"length": "20"},
    ("cve", "lookup"): {"cve": "CVE-2021-44228"},
    ("cve", "search"): {"query": "log4j"},
    ("netinfo", "show"): {},
    ("httpinspect", "inspect"): {"url": "http://github.com"},
    ("globalping", "ping"): {"target": "github.com", "location": ""},
    ("globalping", "traceroute"): {"target": "github.com", "location": "Europe"},
    ("globalping", "mtr"): {"target": "github.com", "location": "Europe"},
    ("globalping", "http"): {"target": "github.com", "location": ""},
    ("portscan", "scan"): {"target": "127.0.0.1"},  # asla üçüncü bir tarafa değil
    ("lan", "scan"): {},
    ("speedtest", "download"): {"mb": "5"},
    ("speedtest", "upload"): {},
})

# Bu işlemler API anahtarı ister; anahtar yoksa "anahtar gerekli" mesajı beklenen davranıştır.
NEEDS_KEY = {("shodan", "search")}
