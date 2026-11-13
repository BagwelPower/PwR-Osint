"""Görsel istihbaratı: EXIF (kamera, tarih, GPS), boyut, hash, tersine arama."""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report
from .web import parse_url

MAX_IMAGE = 25 * 1024 * 1024

# ---------------------------------------------------------------- EXIF (saf Python)

TAGS = {
    0x010F: "Make", 0x0110: "Model", 0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
    0x8298: "Copyright", 0x010E: "ImageDescription", 0x9003: "DateTimeOriginal", 0xA434: "LensModel",
    0xA431: "BodySerialNumber", 0x829A: "ExposureTime", 0x829D: "FNumber", 0x8827: "ISO",
    0x920A: "FocalLength", 0xA002: "PixelXDimension", 0xA003: "PixelYDimension", 0x9010: "OffsetTime",
}
GPS_TAGS = {1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude", 6: "GPSAltitude",
            7: "GPSTimeStamp", 29: "GPSDateStamp"}
_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _read_ifd(tiff: bytes, offset: int, endian: str, names: dict[int, str]) -> tuple[dict[str, Any], dict[int, int]]:
    out: dict[str, Any] = {}
    pointers: dict[int, int] = {}
    if offset + 2 > len(tiff):
        return out, pointers
    (count,) = struct.unpack_from(endian + "H", tiff, offset)
    for i in range(min(count, 512)):
        pos = offset + 2 + i * 12
        if pos + 12 > len(tiff):
            break
        tag, typ, n = struct.unpack_from(endian + "HHI", tiff, pos)
        size = _SIZES.get(typ, 1) * n
        data_pos = pos + 8 if size <= 4 else struct.unpack_from(endian + "I", tiff, pos + 8)[0]
        if tag in (0x8769, 0x8825):  # ExifIFD / GPSIFD işaretçisi
            pointers[tag] = struct.unpack_from(endian + "I", tiff, pos + 8)[0]
            continue
        if tag not in names or data_pos + size > len(tiff):
            continue
        raw = tiff[data_pos:data_pos + size]
        if typ == 2:
            val: Any = raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()
        elif typ == 3:
            val = struct.unpack(endian + "H" * n, raw)
        elif typ in (4, 9):
            val = struct.unpack(endian + ("I" if typ == 4 else "i") * n, raw)
        elif typ in (5, 10):
            nums = struct.unpack(endian + ("I" if typ == 5 else "i") * (2 * n), raw)
            val = tuple(nums[k] / nums[k + 1] if nums[k + 1] else 0.0 for k in range(0, len(nums), 2))
        else:
            val = raw
        if isinstance(val, tuple) and len(val) == 1:
            val = val[0]
        out[names[tag]] = val
    return out, pointers


def parse_exif(data: bytes) -> dict[str, Any]:
    """JPEG içindeki EXIF bloğunu okur. EXIF yoksa boş sözlük döner."""
    if data[:2] != b"\xff\xd8":
        return {}
    pos = 2
    while pos + 4 <= len(data):
        if data[pos] != 0xFF:
            return {}
        marker = data[pos + 1]
        if marker in (0xD9, 0xDA):  # görüntü verisi başladı
            return {}
        (length,) = struct.unpack_from(">H", data, pos + 2)
        if marker == 0xE1 and data[pos + 4:pos + 10] == b"Exif\0\0":
            tiff = data[pos + 10:pos + 2 + length]
            endian = "<" if tiff[:2] == b"II" else ">"
            (ifd0,) = struct.unpack_from(endian + "I", tiff, 4)
            out, ptr = _read_ifd(tiff, ifd0, endian, TAGS)
            if 0x8769 in ptr:
                out.update(_read_ifd(tiff, ptr[0x8769], endian, TAGS)[0])
            if 0x8825 in ptr:
                out.update(_read_ifd(tiff, ptr[0x8825], endian, GPS_TAGS)[0])
            return out
        pos += 2 + length
    return {}


def gps_coords(exif: dict[str, Any]) -> Optional[tuple[float, float]]:
    try:
        lat_d, lat_m, lat_s = exif["GPSLatitude"]
        lon_d, lon_m, lon_s = exif["GPSLongitude"]
    except (KeyError, ValueError, TypeError):
        return None
    lat = lat_d + lat_m / 60 + lat_s / 3600
    lon = lon_d + lon_m / 60 + lon_s / 3600
    if str(exif.get("GPSLatitudeRef", "N")).upper().startswith("S"):
        lat = -lat
    if str(exif.get("GPSLongitudeRef", "E")).upper().startswith("W"):
        lon = -lon
    if lat == 0 and lon == 0:
        return None
    return round(lat, 6), round(lon, 6)


def image_size(data: bytes) -> Optional[tuple[str, int, int]]:
    """(biçim, genişlik, yükseklik) — PNG, GIF, WebP, JPEG başlıklarından."""
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return "PNG", w, h
    if data[:6] in (b"GIF87a", b"GIF89a"):
        w, h = struct.unpack("<HH", data[6:10])
        return "GIF", w, h
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        chunk = data[12:16]
        if chunk == b"VP8X":
            return "WebP", 1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")
        if chunk == b"VP8 ":
            w, h = struct.unpack("<HH", data[26:30])
            return "WebP", w & 0x3FFF, h & 0x3FFF
        if chunk == b"VP8L":
            b = data[21:25]
            return "WebP", 1 + (((b[1] & 0x3F) << 8) | b[0]), 1 + (((b[3] & 0xF) << 10) | (b[2] << 2) | (b[1] >> 6))
    if data[:2] == b"\xff\xd8":
        pos = 2
        while pos + 9 < len(data):
            if data[pos] != 0xFF:
                break
            marker = data[pos + 1]
            (length,) = struct.unpack_from(">H", data, pos + 2)
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                h, w = struct.unpack_from(">HH", data, pos + 5)
                return "JPEG", w, h
            pos += 2 + length
        return "JPEG", 0, 0
    return None


# ---------------------------------------------------------------- araç

def _download(ctx: Context, url: str) -> tuple[bytes, dict]:
    resp = ctx.http.get(url, stream=True, allow_redirects=True)
    try:
        if resp.status_code != 200:
            raise OsintError(f"Görsel indirilemedi: HTTP {resp.status_code}")
        chunks, size = [], 0
        for chunk in resp.iter_content(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_IMAGE:
                raise OsintError("Dosya 25 MB'tan büyük")
    finally:
        resp.close()
    return b"".join(chunks), {k.lower(): v for k, v in resp.headers.items()}


def local_image(value: str) -> dict:
    """Cihazdaki görselin yolunu okur (uygulamada dosya seçici doldurur, terminalde elle yazılır)."""
    import os
    path = os.path.expanduser(value.strip().strip('"'))
    if not os.path.isfile(path):
        raise ValueError("Dosya bulunamadı")
    if os.path.getsize(path) > MAX_IMAGE:
        raise ValueError("Dosya 25 MB'tan büyük")
    with open(path, "rb") as f:
        data = f.read()
    if not image_size(data) and not data[4:12] in (b"ftypheic", b"ftypmif1", b"ftypheix"):
        raise ValueError("Desteklenen bir görsel değil (JPEG, PNG, GIF, WebP, HEIC)")
    return {"display": os.path.basename(path), "path": path, "bytes": data}


def _image(ctx: Context, rep: Report, v: dict) -> None:
    url: str = v["url"]
    data, headers = _download(ctx, url)
    analyze_bytes(ctx, rep, data, headers, url=url)


def _image_file(ctx: Context, rep: Report, v: dict) -> None:
    f = v["file"]
    analyze_bytes(ctx, rep, f["bytes"], {}, name=f["display"])


def analyze_bytes(ctx: Context, rep: Report, data: bytes, headers: dict, url: Optional[str] = None,
                  name: Optional[str] = None) -> None:
    info = rep.section("Dosya")
    if name:
        info.add("Dosya adı", name)
    dims = image_size(data)
    heic = data[4:12] in (b"ftypheic", b"ftypmif1", b"ftypheix")
    if dims:
        fmt, w, h = dims
        info.add("Biçim", fmt)
        if w:
            info.add("Boyut", f"{w} × {h} px ({w * h / 1e6:.1f} MP)")
    else:
        info.add("Biçim", "HEIC" if heic else headers.get("content-type", "bilinmiyor"),
                 level=Level.INFO if heic else Level.WARN)
    info.add("Dosya boyutu", f"{len(data) / 1024:,.1f} KB")
    for label, key in (("Son değişiklik", "last-modified"), ("Sunucu", "server")):
        if headers.get(key):
            info.add(label, headers[key])
    info.add("MD5", hashlib.md5(data).hexdigest())
    sha = hashlib.sha256(data).hexdigest()
    info.add("SHA-256", sha, url=f"https://www.virustotal.com/gui/file/{sha}")
    rep.changed()

    exif = parse_exif(data)
    ex = rep.section("EXIF meta verisi")
    if not exif:
        why = ("HEIC biçiminde EXIF okuma henüz desteklenmiyor; fotoğrafı JPEG olarak paylaşın" if heic else
               "EXIF yok" + (" — sosyal medya ve mesajlaşma uygulamaları genellikle siler" if dims and dims[0] == "JPEG"
                             else ""))
        ex.add("Durum", why, level=Level.MUTED)
    labels = (("Make", "Üretici"), ("Model", "Cihaz"), ("LensModel", "Lens"), ("BodySerialNumber", "Seri no"),
              ("Software", "Yazılım"), ("DateTimeOriginal", "Çekim zamanı"), ("OffsetTime", "Saat dilimi"),
              ("DateTime", "Değiştirilme"), ("Artist", "Sanatçı"), ("Copyright", "Telif"),
              ("ImageDescription", "Açıklama"))
    for key, label in labels:
        if exif.get(key):
            level = Level.WARN if key in ("BodySerialNumber", "Artist") else Level.OK
            ex.add(label, exif[key], level=level)
    if exif.get("Software") and any(k in str(exif["Software"]).lower()
                                    for k in ("photoshop", "gimp", "lightroom", "snapseed", "picsart", "canva")):
        ex.add("Düzenleme izi", f"Görsel bir düzenleme yazılımından geçmiş ({exif['Software']})", level=Level.WARN)
    if exif.get("ExposureTime"):
        exp = exif["ExposureTime"]
        ex.add("Pozlama", f"1/{round(1 / exp)} sn · f/{exif.get('FNumber', '?')} · ISO {exif.get('ISO', '?')}"
               if exp else "?")
    coords = gps_coords(exif)
    if coords:
        lat, lon = coords
        gps = rep.section("GPS konumu", note="Fotoğraf bu konumda çekilmiş. Konum çoğu zaman metre hassasiyetindedir.")
        gps.add("Koordinat", f"{lat}, {lon}", url=f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}",
                level=Level.BAD)
        if exif.get("GPSAltitude"):
            gps.add("Rakım", f"{exif['GPSAltitude']:.0f} m" if isinstance(exif["GPSAltitude"], float) else exif["GPSAltitude"])
        if exif.get("GPSDateStamp"):
            gps.add("GPS tarihi", exif["GPSDateStamp"])
        try:
            place = ctx.http.json("https://nominatim.openstreetmap.org/reverse",
                                  params={"lat": lat, "lon": lon, "format": "jsonv2", "accept-language": "tr"},
                                  headers={"User-Agent": ctx.settings.user_agent})
            if place and place.get("display_name"):
                gps.add("Adres", place["display_name"], level=Level.BAD)
            rep.source("OpenStreetMap", True)
        except OsintError as e:
            rep.source("OpenStreetMap", False, str(e).split(": ", 1)[-1])
        gps.link("Google Maps", f"https://www.google.com/maps?q={lat},{lon}")
    elif exif and not coords:
        ex.add("GPS", "Konum bilgisi yok", level=Level.MUTED)
    rep.changed()

    rev = rep.section("Tersine görsel arama")
    if url:
        enc = quote(url, safe="")
        rev.link("Google Lens", f"https://lens.google.com/uploadbyurl?url={enc}")
        rev.link("Yandex", f"https://yandex.com/images/search?rpt=imageview&url={enc}")
        rev.link("Bing", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}")
        rev.link("TinEye", f"https://tineye.com/search?url={enc}")
        rev.add("Kaynak site", urlsplit(url).hostname or "")
    else:
        rev.note = "Cihazdaki görsel için bu sitelere girip fotoğrafı yükleyin."
        rev.link("Google Lens", "https://lens.google.com/")
        rev.link("Yandex Görseller", "https://yandex.com/images/")
        rev.link("Bing Görsel Arama", "https://www.bing.com/visualsearch")
        rev.link("TinEye", "https://tineye.com/")


register(Tool("image", "Görsel Analizi", "Fotoğraftan cihaz, tarih, GPS konumu ve adres", "PHOTO_CAMERA", "Görsel & Dosya", [
    Action("file", "Cihazdan fotoğraf", (Field("file", "Fotoğraf", "Fotoğraf seçin", "file", local_image),),
           _image_file),
    Action("analyze", "URL'den", (Field("url", "Görsel adresi (URL)", "https://…/foto.jpg", "url", parse_url),),
           _image)]))
