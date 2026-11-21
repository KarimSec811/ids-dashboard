"""Generate small, deterministic PCAPs used by the tests and by the dashboard's
replay (demo) mode:

    python tests/make_pcaps.py            # writes ./test_pcaps/*.pcap

Everything uses private RFC1918 addresses and synthetic payloads.
Requires: pip install scapy
"""
from __future__ import annotations

import random
import sys
from pathlib import Path
from typing import List

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

T0 = 1_700_000_000.0
MAC_A, MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"


def _p(t: float, ip_layer, l4, payload: bytes = b""):
    pkt = Ether(src=MAC_A, dst=MAC_B) / ip_layer / l4
    if payload:
        pkt = pkt / Raw(payload)
    pkt.time = t
    return pkt


def tcp_session(t, client, sport, server, dport, request=b"", response=b"", rtt=0.002):
    """Complete, cleanly closed TCP connection (flag SF)."""
    c, s = IP(src=client, dst=server), IP(src=server, dst=client)
    pk = [
        _p(t, c, TCP(sport=sport, dport=dport, flags="S", seq=100)),
        _p(t + rtt, s, TCP(sport=dport, dport=sport, flags="SA", seq=500, ack=101)),
        _p(t + 2 * rtt, c, TCP(sport=sport, dport=dport, flags="A", seq=101, ack=501)),
    ]
    seq_c, seq_s, tt = 101, 501, t + 3 * rtt
    if request:
        pk.append(_p(tt, c, TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s), request))
        seq_c += len(request)
        tt += rtt
    if response:
        pk.append(_p(tt, s, TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c), response))
        seq_s += len(response)
        tt += rtt
    pk += [
        _p(tt, c, TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s)),
        _p(tt + rtt, s, TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1)),
        _p(tt + 2 * rtt, c, TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)),
    ]
    return pk


def normal_web(t0: float = T0, seed: int = 1) -> List:
    pk = []
    servers = ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    for i in range(24):
        t = t0 + i * 0.35
        client = f"10.0.0.{10 + i % 6}"
        # a "page load": 6 parallel connections to the same web server
        server = servers[i % 3]
        for k in range(6):
            pk += tcp_session(t + k * 0.01, client, 40000 + i * 10 + k, server, 80,
                              b"GET / HTTP/1.1\r\nHost: shop.example.test\r\n\r\n",
                              b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        pk.append(_p(t, IP(src=client, dst="10.0.0.53"), UDP(sport=50000 + i, dport=53) /
                     DNS(rd=1, qd=DNSQR(qname="shop.example.test"))))
    pk.sort(key=lambda x: float(x.time))
    return pk


def syn_flood(t0: float = T0, victim: str = "10.0.0.5", count: int = 600, seed: int = 2) -> List:
    rnd = random.Random(seed)
    pk = []
    for i in range(count):
        src = f"172.16.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
        pk.append(_p(t0 + i * (2.0 / count), IP(src=src, dst=victim),
                     TCP(sport=rnd.randint(1024, 65000), dport=80, flags="S", seq=rnd.randint(0, 2 ** 31))))
    return pk


def port_scan(t0: float = T0, attacker: str = "10.0.0.66", target: str = "10.0.0.5",
              ports=range(1, 61), open_ports=(22, 80)) -> List:
    pk = []
    a, v = IP(src=attacker, dst=target), IP(src=target, dst=attacker)
    for i, port in enumerate(ports):
        t = t0 + i * 0.05
        sport = 54000 + i
        pk.append(_p(t, a, TCP(sport=sport, dport=port, flags="S", seq=1000)))
        if port in open_ports:
            pk.append(_p(t + 0.001, v, TCP(sport=port, dport=sport, flags="SA", seq=7, ack=1001)))
            pk.append(_p(t + 0.002, a, TCP(sport=sport, dport=port, flags="R", seq=1001)))
        else:
            pk.append(_p(t + 0.001, v, TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1001)))
    return pk


def ip_sweep(t0: float = T0, attacker: str = "10.0.0.66", hosts=range(1, 41), port: int = 445,
             tail_seconds: float = 6.0) -> List:
    """SYNs to many hosts, nobody answers. A trailing packet well after the grace
    period lets the half-open probes mature (the sensor only sees time pass when
    packets arrive)."""
    pk = []
    for i, h in enumerate(hosts):
        pk.append(_p(t0 + i * 0.1, IP(src=attacker, dst=f"10.0.1.{h}"),
                     TCP(sport=55000 + i, dport=port, flags="S", seq=5)))
    pk.append(_p(t0 + tail_seconds + len(list(hosts)) * 0.1, IP(src=attacker, dst="10.0.1.250"),
                 TCP(sport=56000, dport=port, flags="S", seq=5)))
    return pk


def browsing(t0: float = T0, client: str = "10.0.0.20", hosts: int = 25) -> List:
    """One client opening short, successful connections to many different
    servers (normal browsing) -- must NOT look like an IP sweep."""
    pk = []
    for i in range(hosts):
        pk += tcp_session(t0 + i * 0.2, client, 41000 + i, f"203.0.113.{10 + i}", 443,
                          b"\x16\x03\x01\x02\x00", b"\x16\x03\x03\x00\x30")
    return pk


def write(path: Path, packets: List) -> None:
    packets = sorted(packets, key=lambda x: float(x.time))
    wrpcap(str(path), packets)
    print(f"  {path.name:22s} {len(packets):5d} packets")


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"Writing PCAPs to {out_dir}")
    write(out_dir / "normal_web.pcap", normal_web())
    write(out_dir / "syn_flood.pcap", syn_flood())
    write(out_dir / "port_scan.pcap", port_scan())
    write(out_dir / "ip_sweep.pcap", ip_sweep())
    write(out_dir / "browsing_many_hosts.pcap", browsing())
    # A demo that tells a story: normal traffic, then a sweep, a port scan and a flood.
    mixed = (normal_web(T0) + ip_sweep(T0 + 10, tail_seconds=3.0) +
             port_scan(T0 + 22) + syn_flood(T0 + 30))
    write(out_dir / "demo_mixed.pcap", mixed)


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "test_pcaps")
