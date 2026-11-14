"""Kripto para adresi analizi (Bitcoin, Ethereum)."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from ..core.context import Context
from ..core.errors import OsintError
from ..core.registry import Action, Field, Tool, register
from ..core.report import Level, Report

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _base58check_ok(addr: str) -> bool:
    n = 0
    for ch in addr:
        if ch not in _B58:
            return False
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes(25, "big") if n.bit_length() <= 200 else b""
    if len(raw) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32_ok(addr: str) -> bool:
    addr = addr.lower()
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or len(data) < 6 or any(c not in _BECH32 for c in data):
        return False
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [_BECH32.index(c) for c in data]
    return _bech32_polymod(values) in (1, 0x2BC830A3)  # bech32 (v0) / bech32m (taproot)


def btc_address(value: str) -> str:
    v = value.strip()
    if v.lower().startswith("bc1"):
        if _bech32_ok(v):
            return v.lower()
    elif v[:1] in ("1", "3") and 26 <= len(v) <= 35 and _base58check_ok(v):
        return v
    raise ValueError("Geçersiz Bitcoin adresi (sağlama toplamı tutmuyor)")


def btc_kind(addr: str) -> str:
    if addr.startswith("1"):
        return "Legacy (P2PKH)"
    if addr.startswith("3"):
        return "Script (P2SH)"
    if addr.startswith("bc1p"):
        return "Taproot (P2TR)"
    return "SegWit (bech32)"


def eth_address(value: str) -> str:
    v = value.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
        raise ValueError("Ethereum adresi 0x ile başlayan 40 hex karakterdir")
    return v.lower()


def _prices(ctx: Context) -> dict:
    try:
        return ctx.http.json("https://api.coingecko.com/api/v3/simple/price",
                             params={"ids": "bitcoin,ethereum", "vs_currencies": "usd,try"}) or {}
    except OsintError:
        return {}


def _fiat(amount: float, price: dict) -> str:
    if not price:
        return ""
    return f"  ≈ ${amount * price.get('usd', 0):,.0f} · ₺{amount * price.get('try', 0):,.0f}"


def _btc(ctx: Context, rep: Report, v: dict) -> None:
    addr: str = v["address"]
    data = ctx.http.json(f"https://blockstream.info/api/address/{addr}") or {}
    chain, mem = data.get("chain_stats") or {}, data.get("mempool_stats") or {}
    received = chain.get("funded_txo_sum", 0) / 1e8
    sent = chain.get("spent_txo_sum", 0) / 1e8
    balance = received - sent
    price = _prices(ctx).get("bitcoin", {})
    sec = rep.section("Adres")
    sec.add("Tür", btc_kind(addr))
    sec.add("Bakiye", f"{balance:.8f} BTC{_fiat(balance, price)}", level=Level.OK if balance else Level.MUTED)
    sec.add("Toplam alınan", f"{received:.8f} BTC")
    sec.add("Toplam gönderilen", f"{sent:.8f} BTC")
    sec.add("İşlem sayısı", chain.get("tx_count", 0))
    if mem.get("tx_count"):
        sec.add("Onay bekleyen", f"{mem['tx_count']} işlem")
    rep.changed()

    txs = [t for t in ctx.http.json(f"https://blockstream.info/api/address/{addr}/txs", expect=list) or []
           if isinstance(t, dict) and t.get("txid")]
    if txs:
        t = rep.section(f"Son işlemler ({len(txs)})")
        for tx in txs[:25]:
            delta = (sum(o.get("value", 0) for o in tx.get("vout", []) if o.get("scriptpubkey_address") == addr)
                     - sum((i.get("prevout") or {}).get("value", 0) for i in tx.get("vin", [])
                           if (i.get("prevout") or {}).get("scriptpubkey_address") == addr)) / 1e8
            ts = (tx.get("status") or {}).get("block_time")
            when = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M") if ts else "onay bekliyor"
            t.add(when, f"{delta:+.8f} BTC", url=f"https://mempool.space/tx/{tx['txid']}",
                  level=Level.OK if delta > 0 else Level.WARN)
        times = [(tx.get("status") or {}).get("block_time") for tx in txs if (tx.get("status") or {}).get("block_time")]
        if times and chain.get("tx_count", 0) <= len(txs):
            sec.add("İlk görülme", datetime.fromtimestamp(min(times), timezone.utc).strftime("%Y-%m-%d"))
    links = rep.section("Blok gezginleri")
    links.link("mempool.space", f"https://mempool.space/address/{addr}")
    links.link("Blockchair", f"https://blockchair.com/bitcoin/address/{addr}")
    links.link("WalletExplorer (küme)", f"https://www.walletexplorer.com/address/{addr}")
    links.link("Google", f"https://www.google.com/search?q=%22{addr}%22")


def _eth(ctx: Context, rep: Report, v: dict) -> None:
    addr: str = v["address"]
    data = ctx.http.json(f"https://api.blockcypher.com/v1/eth/main/addrs/{addr[2:]}/balance") or {}
    bal = int(data.get("balance", 0)) / 1e18
    price = _prices(ctx).get("ethereum", {})
    sec = rep.section("Adres")
    sec.add("Bakiye", f"{bal:.6f} ETH{_fiat(bal, price)}", level=Level.OK if bal else Level.MUTED)
    sec.add("Toplam alınan", f"{int(data.get('total_received', 0)) / 1e18:.6f} ETH")
    sec.add("Toplam gönderilen", f"{int(data.get('total_sent', 0)) / 1e18:.6f} ETH")
    sec.add("İşlem sayısı", data.get("n_tx", 0))
    sec.note = "Bakiye yalnızca ETH'dir; token (USDT vb.) bakiyeleri için Etherscan'e bakın."
    links = rep.section("Gezginler")
    links.link("Etherscan", f"https://etherscan.io/address/{addr}")
    links.link("Etherscan token'lar", f"https://etherscan.io/tokenholdings?a={addr}")
    links.link("Arkham (etiketler)", f"https://intel.arkm.com/explorer/address/{addr}")
    links.link("DeBank (portföy)", f"https://debank.com/profile/{addr}")


register(Tool("crypto", "Kripto Adres", "Bitcoin / Ethereum bakiye ve işlemler", "CURRENCY_BITCOIN", "Kripto", [
    Action("btc", "Bitcoin", (Field("address", "Bitcoin adresi", "bc1q… / 1… / 3…", parse=btc_address),), _btc),
    Action("eth", "Ethereum", (Field("address", "Ethereum adresi", "0x…", parse=eth_address),), _eth)]))
