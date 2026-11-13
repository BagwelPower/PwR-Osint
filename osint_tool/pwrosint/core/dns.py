"""DNS-over-HTTPS çözümleyici. Android dahil her platformda çalışır; sistem
çözümleyicisinin desteklemediği MX/TXT/CAA gibi kayıtları da sorgular."""

from __future__ import annotations

from .context import Context
from .errors import OsintError

PROVIDERS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)
RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def query(ctx: Context, name: str, rtype: str) -> tuple[str, list[str]]:
    """(durum, [kayıtlar]) döndürür. Durum NOERROR, NXDOMAIN vb."""
    last_error: Exception | None = None
    for url in PROVIDERS:
        try:
            data = ctx.http.json(url, params={"name": name, "type": rtype},
                                 headers={"Accept": "application/dns-json"})
        except OsintError as e:
            last_error = e
            continue
        status = RCODES.get(data.get("Status", 2), str(data.get("Status")))
        want = _TYPE_CODES.get(rtype)
        answers = [a["data"] for a in data.get("Answer", []) or []
                   if want is None or a.get("type") == want]
        return status, answers
    raise OsintError(f"DNS sorgusu başarısız: {last_error}")


def resolve(ctx: Context, name: str, rtype: str = "A") -> list[str]:
    return query(ctx, name, rtype)[1]


def ptr_name(ip: str) -> str:
    import ipaddress
    return ipaddress.ip_address(ip).reverse_pointer


_TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
               "AAAA": 28, "SRV": 33, "CAA": 257}
