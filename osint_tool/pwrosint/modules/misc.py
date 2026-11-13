"""Konum ve araç araçları: koordinat, BSSID/MAC, plaka, VIN."""

from __future__ import annotations

import re

from ..core import validate
from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

# ---------------------------------------------------------------- koordinat


def _coords(ctx: Context, rep: Report, v: dict) -> None:
    lat, lon = v["coords"]
    data = ctx.http.json("https://nominatim.openstreetmap.org/reverse",
                         params={"lat": lat, "lon": lon, "format": "jsonv2", "addressdetails": 1,
                                 "accept-language": "tr"},
                         headers={"User-Agent": ctx.settings.user_agent})
    sec = rep.section("Adres (OpenStreetMap)")
    if not data or "error" in data:
        sec.add("Sonuç", "Bu koordinatta adres bulunamadı (deniz / boş alan?)", level=Level.MUTED)
    else:
        sec.add("Tam adres", data.get("display_name", "—"))
        a = data.get("address", {})
        for label, keys in (("Mahalle", ("neighbourhood", "suburb", "quarter")),
                            ("İlçe", ("town", "city_district", "county", "district")),
                            ("İl", ("province", "state", "city")),
                            ("Posta kodu", ("postcode",)), ("Ülke", ("country",))):
            if val := next((a[k] for k in keys if a.get(k)), None):
                sec.add(label, val)
        if data.get("type"):
            sec.add("Yer türü", f"{data.get('category', '')}/{data['type']}")
    maps = rep.section("Haritalar")
    maps.link("OpenStreetMap", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}")
    maps.link("Google Maps", f"https://www.google.com/maps?q={lat},{lon}")
    maps.link("Google Street View", f"https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}")
    maps.link("Yandex Panorama", f"https://yandex.com.tr/maps/?panorama%5Bpoint%5D={lon}%2C{lat}&l=stv%2Csta")
    maps.link("Sentinel uydu", f"https://apps.sentinel-hub.com/eo-browser/?lat={lat}&lng={lon}&zoom=15")


# ---------------------------------------------------------------- BSSID / MAC

def _bssid(ctx: Context, rep: Report, v: dict) -> None:
    mac: str = v["mac"]
    first = int(mac[:2], 16)
    sec = rep.section("Adres")
    sec.add("MAC", mac)
    sec.add("OUI", mac[:8])
    if first & 0b10:
        sec.add("Tür", "Yerel yönetimli (rastgele/sanal MAC) — üretici tespit edilemez", level=Level.WARN)
    if first & 0b01:
        sec.add("Tür", "Multicast adres", level=Level.WARN)

    try:
        resp = ctx.http.get(f"https://api.macvendors.com/{mac[:8]}")
        vendor = resp.text.strip() if resp.status_code == 200 else None
    except OsintError:
        vendor = None
    sec.add("Üretici", vendor or "Bulunamadı", level=Level.OK if vendor else Level.MUTED)
    rep.changed()

    wifi = rep.section("Wi-Fi konumu (WiGLE)")
    name, token = ctx.settings.wigle_api_name, ctx.settings.wigle_api_token
    if not (name and token):
        wifi.add("WiGLE", "API anahtarı yok — Ayarlar'dan WiGLE bilgilerini girin", level=Level.MUTED)
        wifi.link("Manuel arama", "https://wigle.net/search")
        return
    data = ctx.http.json("https://api.wigle.net/api/v2/network/search", params={"netid": mac},
                         auth=(name, token)) or {}
    results = [r for r in data.get("results") or [] if isinstance(r, dict)]
    if not results:
        wifi.add("Sonuç", "Bu BSSID WiGLE veritabanında yok", level=Level.MUTED)
    for r in results[:5]:
        lat, lon = r.get("trilat"), r.get("trilong")
        wifi.add(r.get("ssid") or "(gizli SSID)", f"{lat}, {lon} · son görülme {str(r.get('lastupdt', ''))[:10]}",
                 url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}", level=Level.OK)


# ---------------------------------------------------------------- plaka (TR)

PROVINCES = (
    "Adana Adıyaman Afyonkarahisar Ağrı Amasya Ankara Antalya Artvin Aydın Balıkesir Bilecik Bingöl "
    "Bitlis Bolu Burdur Bursa Çanakkale Çankırı Çorum Denizli Diyarbakır Edirne Elazığ Erzincan "
    "Erzurum Eskişehir Gaziantep Giresun Gümüşhane Hakkâri Hatay Isparta Mersin İstanbul İzmir Kars "
    "Kastamonu Kayseri Kırklareli Kırşehir Kocaeli Konya Kütahya Malatya Manisa Kahramanmaraş Mardin "
    "Muğla Muş Nevşehir Niğde Ordu Rize Sakarya Samsun Siirt Sinop Sivas Tekirdağ Tokat Trabzon "
    "Tunceli Şanlıurfa Uşak Van Yozgat Zonguldak Aksaray Bayburt Karaman Kırıkkale Batman Şırnak "
    "Bartın Ardahan Iğdır Yalova Karabük Kilis Osmaniye Düzce"
).split()
_PLATE = re.compile(r"^(\d{2})([A-Z]{1,3})(\d{2,5})$")
# Harf sayısına göre izin verilen rakam sayıları (Karayolları Trafik Yönetmeliği)
_PLATE_DIGITS = {1: (4, 5), 2: (3, 4), 3: (2, 3)}


def parse_plate(value: str) -> dict:
    p = re.sub(r"[\s-]", "", value.upper().replace("İ", "I"))
    m = _PLATE.match(p)
    if not m:
        raise ValueError("Format: 34 ABC 123")
    il, letters, digits = m.groups()
    if not 1 <= int(il) <= 81:
        raise ValueError("İl kodu 01-81 arasında olmalı")
    if set(letters) & set("QWX"):
        raise ValueError("Türk plakalarında Q, W, X harfleri kullanılmaz")
    return {"plate": f"{il} {letters} {digits}", "il": il, "letters": letters, "digits": digits,
            "province": PROVINCES[int(il) - 1],
            "valid_format": len(digits) in _PLATE_DIGITS[len(letters)]}


def _plate(ctx: Context, rep: Report, v: dict) -> None:
    p = v["plate"]
    sec = rep.section("Plaka")
    sec.add("Plaka", p["plate"])
    sec.add("İl", f"{p['il']} — {p['province']}", level=Level.OK)
    sec.add("Harf/rakam düzeni", f"{len(p['letters'])} harf + {len(p['digits'])} rakam",
            level=Level.OK if p["valid_format"] else Level.WARN)
    if not p["valid_format"]:
        sec.note = "Bu harf/rakam kombinasyonu standart özel araç plakası düzenine uymuyor."
    info = rep.section("Sorgulama")
    info.note = ("Türkiye'de plakadan araç sahibine ulaşmak kamuya açık değildir (KVKK). "
                 "Hasar/ruhsat bilgileri yalnızca araç sahibinin onayıyla sorgulanabilir.")
    info.link("e-Devlet araç sorguları", "https://www.turkiye.gov.tr/arac-sorgulama")
    info.link("SBM hasar kaydı (SMS ile)", "https://www.sbm.org.tr/")
    info.link("Google'da ara", f"https://www.google.com/search?q=%22{p['plate'].replace(' ', '+')}%22")


# ---------------------------------------------------------------- VIN

_VIN_VALUES = dict(zip("ABCDEFGHJKLMNPRSTUVWXYZ", [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9, 2,
                                                   3, 4, 5, 6, 7, 8, 9]))
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
_YEAR_CODES = "ABCDEFGHJKLMNPRSTVWXY123456789"
_REGIONS = [("ABCDEFGH", "Afrika"), ("JKLMNPR", "Asya"), ("STUVWXYZ", "Avrupa"),
            ("12345", "Kuzey Amerika"), ("67", "Okyanusya"), ("89", "Güney Amerika")]


def parse_vin(value: str) -> str:
    v = re.sub(r"[\s-]", "", value.upper())
    if len(v) != 17:
        raise ValueError("VIN tam olarak 17 karakter olmalı")
    if re.search(r"[IOQ]", v):
        raise ValueError("VIN'de I, O, Q harfleri bulunmaz (1 ve 0 ile karışmasın diye)")
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", v):
        raise ValueError("VIN yalnızca harf ve rakam içerir")
    return v


def vin_check_digit(vin: str) -> str:
    total = sum((int(c) if c.isdigit() else _VIN_VALUES[c]) * w for c, w in zip(vin, _VIN_WEIGHTS))
    r = total % 11
    return "X" if r == 10 else str(r)


def vin_years(vin: str) -> list[int]:
    """10. karakter 30 yılda bir tekrar eder; olası yılları döndürür."""
    code = vin[9]
    if code not in _YEAR_CODES:
        return []
    base = 1980 + _YEAR_CODES.index(code)
    return [y for y in (base, base + 30) if y <= 2040]


def _vin(ctx: Context, rep: Report, v: dict) -> None:
    vin: str = v["vin"]
    sec = rep.section("Yapı")
    sec.add("WMI (üretici kodu)", vin[:3])
    sec.add("VDS (model)", vin[3:9])
    sec.add("VIS (seri)", vin[9:])
    region = next((name for chars, name in _REGIONS if vin[0] in chars), "?")
    sec.add("Üretim bölgesi", region)
    years = vin_years(vin)
    sec.add("Model yılı", " veya ".join(map(str, years)) if years else "Kodlanmamış")
    expected = vin_check_digit(vin)
    if vin[8] == expected:
        sec.add("Kontrol hanesi", f"{vin[8]} — doğru", level=Level.OK)
    else:
        sec.add("Kontrol hanesi", f"{vin[8]} (beklenen {expected})",
                level=Level.WARN if region != "Kuzey Amerika" else Level.BAD)
        sec.note = ("Kontrol hanesi Kuzey Amerika'da zorunludur; Avrupa/Asya araçlarında "
                    "kullanılmayabilir." if region != "Kuzey Amerika" else
                    "Kuzey Amerika aracında hatalı kontrol hanesi: VIN yanlış yazılmış veya sahte olabilir.")
    rep.changed()

    data = ctx.http.json(f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{vin}",
                         params={"format": "json"}, timeout=max(20, ctx.settings.timeout))
    results = (data or {}).get("Results") or [{}]
    r = results[0] if isinstance(results[0], dict) else {}
    dec = rep.section("Çözümleme (NHTSA vPIC)")
    labels = (("Make", "Marka"), ("Manufacturer", "Üretici"), ("Model", "Model"), ("ModelYear", "Yıl"),
              ("Trim", "Donanım"), ("BodyClass", "Kasa"), ("VehicleType", "Araç tipi"),
              ("FuelTypePrimary", "Yakıt"), ("DisplacementL", "Motor (L)"), ("EngineCylinders", "Silindir"),
              ("TransmissionStyle", "Şanzıman"), ("DriveType", "Çekiş"),
              ("PlantCountry", "Fabrika ülkesi"), ("PlantCity", "Fabrika şehri"))
    shown = 0
    for key, label in labels:
        if (val := (r.get(key) or "").strip()) and val != "Not Applicable":
            dec.add(label, val, level=Level.OK)
            shown += 1
    if not shown:
        dec.add("Sonuç", "NHTSA bu VIN için bilgi döndürmedi", level=Level.MUTED)
    if (err := r.get("ErrorText", "")) and not err.startswith("0 "):
        dec.note = "NHTSA notu: " + err.split(";")[0]
    links = rep.section("Linkler")
    links.link("NHTSA vPIC", f"https://vpic.nhtsa.dot.gov/decoder/Decoder?VIN={vin}")
    links.link("Google", f"https://www.google.com/search?q=%22{vin}%22")


# ---------------------------------------------------------------- kayıt

register(Tool("geo", "Konum", "Koordinat → adres, BSSID → üretici/konum", "TRAVEL_EXPLORE", "Diğer", [
    Action("coords", "Koordinat", (Field("coords", "Koordinat (enlem, boylam)", "41.0082, 28.9784",
                                         parse=validate.coordinates),), _coords),
    Action("bssid", "BSSID / MAC", (Field("mac", "BSSID / MAC", "00:11:22:33:44:55", parse=validate.mac),),
           _bssid)]))
register(Tool("vehicle", "Araç", "Plaka (TR) ve VIN / şasi no", "DIRECTIONS_CAR", "Diğer", [
    Action("vin", "VIN", (Field("vin", "VIN / şasi no (17 karakter)", "1HGCM82633A004352", parse=parse_vin),),
           _vin),
    Action("plate", "Plaka", (Field("plate", "Plaka", "34 ABC 123", parse=parse_plate),), _plate)]))
