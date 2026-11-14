import socket
import threading

import pytest

from pwrosint.core.errors import OsintError
from pwrosint.core.report import Level
from pwrosint.modules import nettools

from test_modules import items, run

REAL_PROBE = nettools.probe_port


@pytest.fixture
def listener():
    """localhost'ta bir SSH benzeri servis: bağlanana banner gönderir."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.sendall(b"SSH-2.0-OpenSSH_9.6 Test\r\n")
                c.close()
            except OSError:
                continue
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    srv.close()


def test_probe_port_states(listener, monkeypatch):
    state, banner = REAL_PROBE("127.0.0.1", listener)
    assert state == "open" and banner.startswith("SSH-2.0-OpenSSH")
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    closed_port = free.getsockname()[1]
    free.close()
    assert REAL_PROBE("127.0.0.1", closed_port)[0] == "closed"  # reddedildi = host canlı


def test_portscan_report(ctx, listener, monkeypatch):
    monkeypatch.setattr(nettools, "TOP_PORTS", {listener: "Test-SSH", 3306: "MySQL", 1: "tcpmux"})
    open_set = {listener: ("open", "SSH-2.0-OpenSSH_9.6"), 3306: ("open", "")}
    monkeypatch.setattr(nettools, "probe_port", lambda h, p, **k: open_set.get(p, ("closed", "")))
    report = run(ctx, "portscan", target="127.0.0.1")
    sec = items(report, "Açık portlar")
    assert sec[f"{listener}/tcp"].value.startswith("Test-SSH · SSH-2.0-OpenSSH_9.6")
    assert sec["3306/tcp"].level == Level.BAD  # internete açık veritabanı
    assert items(report, "Tarama özeti")["Kapalı (yanıt: reddedildi)"].value == "1"


def test_scan_target_refuses_ranges():
    for bad in ("192.168.1.0/24", "10.0.0.1-20", "*.ornek.com"):
        with pytest.raises(ValueError):
            nettools.scan_target(bad)
    assert nettools.scan_target("192.168.1.1") == "192.168.1.1"


def test_portscan_requires_consent():
    from pwrosint.core.registry import get_tool
    for tid in ("portscan", "lan", "speedtest"):
        assert all(a.consent for a in get_tool(tid).actions), tid


@pytest.mark.parametrize("lip, ok", [("192.168.1.23", True), ("10.5.0.7", True), ("100.70.1.2", False),
                                     ("88.230.1.2", False), (None, False)])
def test_lan_only_private_wifi(lip, ok):
    if ok:
        assert str(nettools.lan_network(lip)).endswith("/24")
    else:
        with pytest.raises(OsintError):
            nettools.lan_network(lip)


def test_lan_discovery(ctx, monkeypatch):
    monkeypatch.setattr(nettools, "local_ip", lambda: "192.168.1.23")
    devices = {"192.168.1.1": {53: "open", 80: "open"}, "192.168.1.23": {}, "192.168.1.40": {9100: "open"},
               "192.168.1.50": {62078: "open"}, "192.168.1.60": {}}

    def probe(ip, port, **k):
        if ip not in devices:
            return "filtered", ""
        return devices[ip].get(port, "closed"), ""  # .60: hiç port açık değil ama reddediyor → canlı
    monkeypatch.setattr(nettools, "probe_port", probe)
    monkeypatch.setattr(socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError()))
    report = run(ctx, "lan")
    sec = items(report, "Cihazlar")
    assert set(sec) == {"192.168.1.1", "192.168.1.23 · BU CİHAZ", "192.168.1.40", "192.168.1.50", "192.168.1.60"}
    assert sec["192.168.1.1"].value.startswith("Router")
    assert sec["192.168.1.40"].value.startswith("Yazıcı")
    assert sec["192.168.1.50"].value.startswith("iPhone")


def test_lan_refuses_mobile_data(ctx, monkeypatch):
    monkeypatch.setattr(nettools, "local_ip", lambda: "100.80.1.2")
    report = run(ctx, "lan")
    assert "Wi-Fi" in report.errors[0]


def test_speedtest(ctx, http):
    http.add("https://speed.cloudflare.com/__down", "x" * 1000)
    report = run(ctx, "speedtest", "download", mb=5)
    sec = items(report, "Sonuç")
    assert "İndirme" in sec and sec["Kullanılan veri"].value.endswith("MB")
