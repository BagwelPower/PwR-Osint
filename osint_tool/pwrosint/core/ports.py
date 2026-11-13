"""İnternete açık olması risk taşıyan portlar. Port listesi tek başına bulgu
değildir (53/443 normaldir); bu tablo hangisinin dikkat gerektirdiğini söyler."""

from __future__ import annotations

from .report import Level

RISKY_PORTS: dict[int, tuple[str, Level]] = {
    21: ("FTP — şifreler düz metin", Level.WARN),
    23: ("Telnet — şifresiz uzaktan erişim", Level.BAD),
    25: ("SMTP — açık relay olabilir", Level.INFO),
    111: ("RPCbind", Level.WARN),
    135: ("Windows RPC", Level.BAD),
    139: ("NetBIOS", Level.BAD),
    445: ("SMB — fidye yazılımı hedefi", Level.BAD),
    1433: ("MS SQL Server veritabanı", Level.BAD),
    1521: ("Oracle veritabanı", Level.BAD),
    2049: ("NFS dosya paylaşımı", Level.BAD),
    2375: ("Docker API (şifresiz) — tam sunucu ele geçirme", Level.BAD),
    3306: ("MySQL veritabanı", Level.BAD),
    3389: ("RDP uzak masaüstü — kaba kuvvet hedefi", Level.BAD),
    5432: ("PostgreSQL veritabanı", Level.BAD),
    5601: ("Kibana paneli", Level.WARN),
    5900: ("VNC uzak masaüstü", Level.BAD),
    5984: ("CouchDB", Level.BAD),
    6379: ("Redis (çoğunlukla şifresiz)", Level.BAD),
    8086: ("InfluxDB", Level.WARN),
    9200: ("Elasticsearch (veri sızıntılarının bir numaralı kaynağı)", Level.BAD),
    11211: ("Memcached — DDoS amplifikasyonu", Level.BAD),
    27017: ("MongoDB veritabanı", Level.BAD),
}


def classify(ports: list[int]) -> list[tuple[int, str, Level]]:
    return [(p, *RISKY_PORTS[p]) for p in sorted(ports) if p in RISKY_PORTS]


def add_ports(sec, ports: list[int], label: str = "Açık portlar") -> None:
    sec.add(label, ", ".join(map(str, sorted(ports))) or "—")
    for port, desc, level in classify(ports):
        sec.add(f"Port {port} internete açık", desc, level=level)
