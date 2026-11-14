"""Dosya Analizi: şüpheli dosyaların statik incelemesi (çevrimdışı).

Dosya hiçbir zaman çalıştırılmaz; yalnızca baytları okunur.
"""

from __future__ import annotations

import hashlib
import io
import math
import os
import re
import struct
import zipfile
from collections import Counter
from ..core.context import Context
from ..core.registry import Action, Field, Tool, register
from ..core.report import Item, Level, Report

MAX_FILE = 50 * 1024 * 1024
SCAN_BYTES = 8 * 1024 * 1024  # dize ve gösterge araması için okunan en fazla bayt

# (sihirli bayt, ofset, tür, beklenen uzantılar)
MAGIC: list[tuple[bytes, int, str, tuple[str, ...]]] = [
    (b"MZ", 0, "Windows çalıştırılabilir (EXE/DLL)", ("exe", "dll", "scr", "sys", "com", "cpl", "ocx")),
    (b"\x7fELF", 0, "Linux/Android çalıştırılabilir (ELF)", ("so", "elf", "bin", "")),
    (b"%PDF", 0, "PDF belgesi", ("pdf",)),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "OLE (eski Office: DOC/XLS/PPT, MSI)", ("doc", "xls", "ppt", "msi", "msg")),
    (b"PK\x03\x04", 0, "ZIP arşivi", ("zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "apk", "jar", "odt",
                                     "epub", "aab", "xapk")),
    (b"Rar!\x1a\x07", 0, "RAR arşivi", ("rar",)),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip arşivi", ("7z",)),
    (b"\x1f\x8b", 0, "GZIP", ("gz", "tgz")),
    (b"\xff\xd8\xff", 0, "JPEG görsel", ("jpg", "jpeg")),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG görsel", ("png",)),
    (b"GIF8", 0, "GIF görsel", ("gif",)),
    (b"dex\n", 0, "Android DEX bayt kodu", ("dex",)),
    (b"{\\rtf", 0, "RTF belgesi", ("rtf", "doc")),
    (b"#!", 0, "Betik (shebang)", ("sh", "py", "pl", "")),
    (b"\xca\xfe\xba\xbe", 0, "Java class / Mach-O (çoklu)", ("class", "")),
    (b"\xcf\xfa\xed\xfe", 0, "macOS çalıştırılabilir (Mach-O)", ("", "dylib")),
    (b"ID3", 0, "MP3 ses", ("mp3",)),
    (b"ftyp", 4, "MP4/MOV/HEIC", ("mp4", "mov", "m4a", "heic", "heif", "3gp")),
    (b"<?xml", 0, "XML", ("xml", "svg", "plist")),
    (b"<svg", 0, "SVG görsel", ("svg",)),
    (b"<!DOCTYPE html", 0, "HTML", ("html", "htm")),
    (b"<html", 0, "HTML", ("html", "htm")),
    (b"MSCF", 0, "Microsoft CAB", ("cab",)),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0, "Windows kısayolu (LNK)", ("lnk",)),
]
DANGEROUS_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "msi",
                 "ps1", "jar", "apk", "dll", "cpl", "iso", "img", "docm", "xlsm", "pptm"}


def local_file(value: str) -> dict:
    path = os.path.expanduser(value.strip().strip('"'))
    if not os.path.isfile(path):
        raise ValueError("Dosya bulunamadı")
    size = os.path.getsize(path)
    if size > MAX_FILE:
        raise ValueError("Dosya 50 MB'tan büyük")
    with open(path, "rb") as f:
        data = f.read()
    return {"display": os.path.basename(path), "path": path, "bytes": data}


def detect_type(data: bytes) -> tuple[str, tuple[str, ...]]:
    for magic, off, name, exts in MAGIC:
        if data[off:off + len(magic)] == magic:
            return name, exts
    sample = data[:4096]
    if sample and sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) > 0.95:
        return "Düz metin", ("txt", "csv", "log", "json", "js", "vbs", "ps1", "bat", "cmd", "sh", "py", "html", "")
    return "Bilinmeyen ikili veri", ()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data[:SCAN_BYTES])
    n = min(len(data), SCAN_BYTES)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def iocs(data: bytes) -> dict[str, list[str]]:
    blob = data[:SCAN_BYTES]
    texts = [blob.decode("latin-1")]
    try:  # UTF-16LE dizeler (Windows ikilileri, Office)
        texts.append(blob[: len(blob) - len(blob) % 2].decode("utf-16le", "ignore"))
    except UnicodeDecodeError:
        pass
    text = "\n".join(texts)
    urls = re.findall(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}", text)
    ips = [ip for ip in re.findall(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", text)
           if not ip.startswith(("0.", "127.", "255.")) and ip.count(".") == 3]
    emails = re.findall(r"[A-Za-z0-9._%+-]{2,64}@[A-Za-z0-9.-]{2,100}\.[A-Za-z]{2,12}", text)
    noise = ("schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org", "purl.org", "ns.adobe.com",
             "schemas.android.com", "www.apache.org/licenses")
    urls = [u for u in dict.fromkeys(u.rstrip(".,;)\"'") for u in urls) if not any(n in u for n in noise)]
    return {"URL": urls[:40], "IP": list(dict.fromkeys(ips))[:30], "E-posta": list(dict.fromkeys(emails))[:20]}


# ---------------------------------------------------------------- PDF

PDF_KEYS = {
    "/JS": ("JavaScript", Level.BAD), "/JavaScript": ("JavaScript", Level.BAD),
    "/OpenAction": ("Açılışta otomatik eylem", Level.WARN), "/AA": ("Otomatik eylem (AA)", Level.WARN),
    "/Launch": ("Program başlatma", Level.BAD), "/EmbeddedFile": ("Gömülü dosya", Level.WARN),
    "/RichMedia": ("Flash/zengin medya", Level.WARN), "/XFA": ("XFA formu", Level.WARN),
    "/AcroForm": ("Form", Level.INFO), "/URI": ("Link", Level.INFO), "/ObjStm": ("Nesne akışı (gizleme)", Level.INFO),
    "/Encrypt": ("Şifreli", Level.INFO),
}


def _pdf(rep: Report, data: bytes) -> int:
    sec = rep.section("PDF içeriği")
    risk = 0
    counts = {k: len(re.findall(re.escape(k).encode() + rb"[\s/<>\[(]", data)) for k in PDF_KEYS}
    seen = set()
    for key, (label, level) in PDF_KEYS.items():
        n = counts[key]
        if n and label not in seen:
            seen.add(label)
            sec.add(label, f"{n} adet ({key})", level=level)
            risk += 3 if level == Level.BAD else 1 if level == Level.WARN else 0
    if (counts["/JS"] or counts["/JavaScript"]) and (counts["/OpenAction"] or counts["/AA"]):
        sec.items.insert(0, Item("Açılışta JavaScript çalıştırır",
                                 "Kötü amaçlı PDF'lerin tipik imzası (otomatik eylem + JavaScript)", level=Level.BAD))
        risk += 3
    if not seen:
        sec.add("Etkin içerik", "JavaScript, otomatik eylem veya gömülü dosya bulunmadı", level=Level.OK)
    sec.note = "pdfid yöntemine benzer anahtar sayımı; gizlenmiş (hex kodlu) anahtarlar kaçabilir."
    return risk


# ---------------------------------------------------------------- Office / ZIP / APK

def _zip(rep: Report, data: bytes, ext: str) -> int:
    risk = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except zipfile.BadZipFile:
        rep.section("Arşiv").add("ZIP", "Bozuk ya da şifreli arşiv açılamadı", level=Level.WARN)
        return 1
    lower = [n.lower() for n in names]
    if "androidmanifest.xml" in lower or any(n.endswith(".dex") for n in lower):
        return _apk(rep, zf, names)
    if "[content_types].xml" in lower:  # OOXML (docx/xlsx/pptx)
        sec = rep.section("Office belgesi")
        vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
        if vba:
            sec.add("VBA makrosu", f"VAR ({', '.join(vba)}) — açarken makroları etkinleştirmeyin", level=Level.BAD)
            risk += 4
        else:
            sec.add("VBA makrosu", "Yok", level=Level.OK)
        external = []
        for n in names:
            if n.endswith(".rels"):
                try:
                    rels = zf.read(n).decode("utf-8", "ignore")
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    continue
                for target in re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', rels):
                    external.append((n, target))
        templ = [t for n, t in external if "attachedTemplate" in zf.read(n).decode("utf-8", "ignore") or
                 t.lower().endswith((".dotm", ".dotx", ".dot"))]
        if templ:
            sec.add("Dışarıdan şablon (template injection)", ", ".join(templ)[:200], level=Level.BAD)
            risk += 4
        if external:
            sec.add("Dış bağlantılar", f"{len(external)}: " + ", ".join(t for _, t in external[:5])[:200],
                    level=Level.WARN)
            risk += 1
        if any("activex" in n for n in lower):
            sec.add("ActiveX", "Belge ActiveX denetimi içeriyor", level=Level.WARN)
            risk += 1
        if any(n.endswith(".bin") and "oleobject" in n for n in lower):
            sec.add("Gömülü OLE nesnesi", "Belge içine gömülü dosya/nesne var", level=Level.WARN)
            risk += 1
        return risk
    sec = rep.section(f"Arşiv içeriği ({len(names)} dosya)")
    for n in names[:30]:
        e = n.rsplit(".", 1)[-1].lower() if "." in n else ""
        sec.add(n[:120], level=Level.BAD if e in DANGEROUS_EXT else Level.INFO)
        if e in DANGEROUS_EXT:
            risk += 2
    if any(zi.flag_bits & 0x1 for zi in zf.infolist()):
        sec.note = "Arşiv parola korumalı: içerik antivirüslerden gizlenmiş olabilir."
        risk += 1
    return risk


# Bankacılık truvaları ve casus yazılımlarda öne çıkan izinler
APK_DANGEROUS = {
    "READ_SMS": "SMS okuma (onay kodlarını çalabilir)", "RECEIVE_SMS": "Gelen SMS'leri yakalama",
    "SEND_SMS": "SMS gönderme", "BIND_ACCESSIBILITY_SERVICE": "Erişilebilirlik hizmeti (ekranı kontrol edebilir)",
    "SYSTEM_ALERT_WINDOW": "Diğer uygulamaların üstünde pencere (sahte giriş ekranı)",
    "REQUEST_INSTALL_PACKAGES": "Başka uygulama yükleme", "BIND_DEVICE_ADMIN": "Cihaz yöneticisi",
    "READ_CONTACTS": "Rehber okuma", "READ_CALL_LOG": "Arama kayıtları", "RECORD_AUDIO": "Mikrofon",
    "CAMERA": "Kamera", "ACCESS_FINE_LOCATION": "Hassas konum", "READ_PHONE_STATE": "Telefon kimliği/durumu",
    "CALL_PHONE": "Arama yapma", "QUERY_ALL_PACKAGES": "Tüm yüklü uygulamaları görme",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Bildirimleri okuma", "WRITE_SETTINGS": "Sistem ayarlarını değiştirme",
    "RECEIVE_BOOT_COMPLETED": "Açılışta otomatik başlama", "PACKAGE_USAGE_STATS": "Uygulama kullanım verisi",
    "MANAGE_EXTERNAL_STORAGE": "Tüm dosyalara erişim",
}


def axml_strings(data: bytes) -> list[str]:
    """İkili AndroidManifest.xml'in dize havuzu (RES_STRING_POOL_TYPE)."""
    if len(data) < 16 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("ikili XML değil")
    pos = struct.unpack_from("<H", data, 2)[0]  # ilk parça
    ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
    if ctype != 0x0001:
        raise ValueError("dize havuzu bulunamadı")
    count, _styles, flags, strings_start, _ = struct.unpack_from("<IIIII", data, pos + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, pos + hsize)
    base = pos + strings_start
    out = []
    for off in offsets[:5000]:
        p = base + off
        if utf8:
            n = data[p]
            p += 2 if n & 0x80 else 1
            blen = data[p]
            if blen & 0x80:
                blen = ((blen & 0x7F) << 8) | data[p + 1]
                p += 1
            p += 1
            out.append(data[p:p + blen].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, p)[0]
            p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                p += 2
            out.append(data[p:p + n * 2].decode("utf-16le", "replace"))
    return out


def _apk(rep: Report, zf: zipfile.ZipFile, names: list[str]) -> int:
    risk = 0
    sec = rep.section("Android uygulaması (APK)")
    dex = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
    sec.add("DEX dosyası", f"{len(dex)}" + (" (çoklu dex — büyük ya da paketlenmiş uygulama)" if len(dex) > 3 else ""))
    abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and n.count("/") >= 2})
    if abis:
        sec.add("Yerel kütüphaneler", ", ".join(abis))
    if any(n.startswith("assets/") and n.lower().endswith((".dex", ".jar", ".apk")) for n in names):
        sec.add("Gizli yük", "assets/ içinde ek kod (dex/jar/apk) — dropper davranışı olabilir", level=Level.BAD)
        risk += 3
    certs = [n for n in names if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
    sec.add("İmza", ", ".join(certs) if certs else "v1 imza dosyası yok (yalnızca v2/v3 imza olabilir)")
    try:
        strings = axml_strings(zf.read("AndroidManifest.xml"))
    except (KeyError, ValueError, struct.error, IndexError) as e:
        sec.add("Manifest", f"Okunamadı ({e})", level=Level.MUTED)
        return risk
    perms = sorted({s.rsplit(".", 1)[-1] for s in strings if ".permission." in s and s.split(".")[-1].isupper()})
    dangerous = [p for p in perms if p in APK_DANGEROUS]
    ps = rep.section(f"İzinler ({len(perms)})")
    for p in dangerous:
        ps.add(p, APK_DANGEROUS[p], level=Level.WARN)
    for p in perms:
        if p not in APK_DANGEROUS:
            ps.add(p, level=Level.MUTED)
    banker = {"READ_SMS", "RECEIVE_SMS"} & set(dangerous) and \
        {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"} & set(dangerous)
    if banker:
        ps.items.insert(0, Item("Bankacılık truvası kalıbı",
                                "SMS erişimi + erişilebilirlik/ekran üstü pencere birlikte istenmiş", level=Level.BAD))
        risk += 5
    risk += min(len(dangerous), 4)
    pkg = next((s for s in strings if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}", s)
                and not s.startswith(("android.", "com.android.", "androidx."))), None)
    if pkg:
        sec.add("Olası paket adı", pkg, url=f"https://play.google.com/store/apps/details?id={pkg}")
    rep.notice("APK manifest okuyucusu dize havuzunu çözümler; izinler güvenilirdir, paket adı tahminidir. "
               "Uygulama çalıştırılmadı.")
    return risk


def _ole_macros(rep: Report, data: bytes) -> int:
    markers = [m for m in (b"_VBA_PROJECT", b"VBA", b"Macros", b"AutoOpen", b"Document_Open", b"Workbook_Open",
                           b"Auto_Open", b"Shell", b"CreateObject", b"WScript") if m in data]
    sec = rep.section("Eski Office (OLE) belgesi")
    if b"_VBA_PROJECT" in data or b"Macros" in data:
        sec.add("VBA makrosu", "VAR (makro izleri bulundu)", level=Level.BAD)
        auto = [m.decode() for m in markers if m in (b"AutoOpen", b"Document_Open", b"Workbook_Open", b"Auto_Open")]
        if auto:
            sec.add("Otomatik çalışan makro", ", ".join(auto), level=Level.BAD)
        sec.note = "Bayt düzeyinde iz araması; tam ayrıştırma için olevba kullanın."
        return 5 if auto else 3
    sec.add("VBA makrosu", "İz bulunamadı", level=Level.OK)
    return 0


# ---------------------------------------------------------------- araç

def _filescan(ctx: Context, rep: Report, v: dict) -> None:
    f = v["file"]
    data: bytes = f["bytes"]
    name: str = f["display"]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    kind, exts = detect_type(data)
    risk = 0
    sec = rep.section("Dosya")
    sec.add("Ad", name)
    sec.add("Boyut", f"{len(data) / 1024:,.1f} KB")
    sec.add("Gerçek tür (içeriğe göre)", kind)
    if ext and exts and ext not in exts:
        sec.add("Uzantı yanıltıcı", f".{ext} uzantısı var ama içerik {kind}", level=Level.BAD)
        risk += 4
    if re.search(r"\.(pdf|doc|docx|jpg|png|txt|xls|xlsx)\.(exe|scr|js|vbs|bat|cmd|lnk|hta)$", name, re.I):
        sec.add("Çift uzantı", "Belge gibi görünen çalıştırılabilir dosya hilesi", level=Level.BAD)
        risk += 4
    if ext in DANGEROUS_EXT:
        sec.add("Riskli tür", f".{ext} çalıştırılabilir/etkin içerik taşıyabilir", level=Level.WARN)
        risk += 1
    ent = entropy(data)
    sec.add("Entropi", f"{ent:.2f} / 8" + (" — sıkıştırılmış/şifreli/paketlenmiş içerik" if ent > 7.5 else ""),
            level=Level.WARN if ent > 7.5 and kind.startswith(("Windows", "Linux")) else Level.INFO)
    md5, sha1, sha256 = (hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(),
                         hashlib.sha256(data).hexdigest())
    h = rep.section("Özetler")
    h.add("MD5", md5)
    h.add("SHA-1", sha1)
    h.add("SHA-256", sha256)
    h.note = "SHA-256'yı 'Tehdit İtibarı → Dosya hash' ile kontrol edebilirsiniz (yanındaki 🔍)."
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" in data[:256]:
        sec.add("EICAR", "Antivirüs test dosyası (zararsız)", level=Level.WARN)
    rep.changed()

    if kind == "PDF belgesi":
        risk += _pdf(rep, data)
    elif kind.startswith("ZIP"):
        risk += _zip(rep, data, ext)
    elif kind.startswith("OLE"):
        risk += _ole_macros(rep, data)
    elif kind.startswith("Windows"):
        pe = rep.section("Windows çalıştırılabilir")
        try:
            pe_off = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_off:pe_off + 4] == b"PE\0\0":
                machine, nsec, ts = struct.unpack_from("<HHI", data, pe_off + 4)
                from datetime import datetime, timezone
                pe.add("Mimari", {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64"}.get(machine, hex(machine)))
                pe.add("Bölüm sayısı", nsec)
                pe.add("Derleme zamanı", datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d") if ts else "—")
                names = [data[pe_off + 24 + struct.unpack_from("<H", data, pe_off + 20)[0] + i * 40:][:8]
                         .rstrip(b"\0").decode("latin-1") for i in range(min(nsec, 20))]
                packers = [n for n in names if n.upper().startswith(("UPX", ".ASPACK", ".MPRESS", ".THEMIDA", "PEC"))]
                pe.add("Bölümler", ", ".join(names))
                if packers:
                    pe.add("Paketleyici", ", ".join(packers), level=Level.WARN)
                    risk += 2
        except (struct.error, IndexError, ValueError, OverflowError, OSError):
            pe.add("PE başlığı", "Okunamadı", level=Level.MUTED)
        risk += 2

    found = iocs(data)
    if any(found.values()):
        io_sec = rep.section("Gömülü göstergeler (IOC)")
        for label, values in found.items():
            for val in values:
                io_sec.add(label, val)
        io_sec.note = "Dosya içinde geçen adresler; pivot için yanındaki 🔍 simgesini kullanın."

    verdict = ("YÜKSEK RİSK — açmayın" if risk >= 5 else "ŞÜPHELİ — dikkatli inceleyin" if risk >= 2
               else "Statik incelemede belirgin bir risk işareti yok")
    rep.summary = verdict
    rep.notice("Dosya çalıştırılmadı, yalnızca statik olarak okundu ve hiçbir yere gönderilmedi. Statik analiz "
               "zararlı yazılımı kesin olarak dışlayamaz.")


register(Tool("filescan", "Dosya Analizi", "PDF, Office, APK, EXE: gerçek tür, makro, izinler, IOC'ler",
              "FIND_IN_PAGE", "Dosya & Görsel", [
                  Action("analyze", "İncele", (Field("file", "Dosya", "Dosya seçin", "file", local_file),),
                         _filescan)]))
