"""Engine tests. They use lightweight fake packets, so they need neither
tshark nor root and run in about a second:   pytest tests/test_engine.py
"""
import json
import random
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ids.engine import (  # noqa: E402
    ConnState, NullSink, PacketAnalyzer, classify_detail, compile_signatures,
    get_service, keep_orientation,
)
from ids.intel import Enricher, IocList  # noqa: E402
from ids.settings import Settings  # noqa: E402
from ids.store import AlertStore, FlowStore  # noqa: E402

CONFIG = json.loads((ROOT / "tests" / "fixtures" / "config.json").read_text())
SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def tcp(ts, src, sport, dst, dport, flags, payload=b""):
    hexed = ":".join(f"{b:02x}" for b in payload)
    return SimpleNamespace(
        sniff_time=datetime.fromtimestamp(ts),
        ip=SimpleNamespace(src=src, dst=dst),
        tcp=SimpleNamespace(srcport=str(sport), dstport=str(dport), flags=f"0x{flags:04x}",
                            payload=hexed, urgent_pointer="0"))


def session(ts, client, sport, server, dport, payload_c=b"", payload_s=b"", rtt=0.002):
    """A complete, cleanly closed connection."""
    pk = [tcp(ts, client, sport, server, dport, SYN),
          tcp(ts + rtt, server, dport, client, sport, SYN | ACK),
          tcp(ts + 2 * rtt, client, sport, server, dport, ACK)]
    t = ts + 3 * rtt
    if payload_c:
        pk.append(tcp(t, client, sport, server, dport, PSH | ACK, payload_c))
        t += rtt
    if payload_s:
        pk.append(tcp(t, server, dport, client, sport, PSH | ACK, payload_s))
        t += rtt
    pk += [tcp(t, client, sport, server, dport, FIN | ACK),
           tcp(t + rtt, server, dport, client, sport, FIN | ACK),
           tcp(t + 2 * rtt, client, sport, server, dport, ACK)]
    return pk


class Collect(NullSink):
    def __init__(self):
        self.alerts, self.flows, self.closed = [], [], []

    def on_flow(self, p):
        self.flows.append(p)

    def on_flow_closed(self, r):
        self.closed.append(r)

    def on_alert(self, kind, alert):
        self.alerts.append((kind, alert))

    @property
    def new_alerts(self):
        return [a for k, a in self.alerts if k == "new"]


def run(packets, **detection):
    cfg = json.loads(json.dumps(CONFIG))
    cfg["detection"].update(detection)
    sink = Collect()
    analyzer = PacketAnalyzer(cfg, sink)
    for p in packets:
        analyzer.process_packet(p)
    return analyzer, sink


# --------------------------------------------------------------------------
# connection state & basic helpers
# --------------------------------------------------------------------------

def _state(*events):
    cs = ConnState()
    for ev in events:
        cs.observe(*ev)
    return cs


def test_connstate_flags():
    #                     is_orig syn   ack    fin    rst    payload
    assert _state((True, True, False, False, False, False)).flag == "S0"
    assert _state((True, True, False, False, False, False),
                  (False, False, False, False, True, False)).flag == "REJ"
    assert _state((True, True, False, False, False, False),
                  (True, False, False, False, True, False)).flag == "RSTOS0"
    assert _state((True, True, False, False, False, False),
                  (False, True, True, False, False, False)).flag == "S1"
    full = _state((True, True, False, False, False, False), (False, True, True, False, False, False),
                  (True, False, True, False, False, False), (True, False, True, True, False, False),
                  (False, False, True, True, False, False))
    assert full.flag == "SF" and full.closed
    assert _state((True, True, False, False, False, False), (True, False, False, True, False, False)).flag == "SH"


def test_half_open_means_handshake_never_completed():
    syn_synack = _state((True, True, False, False, False, False), (False, True, True, False, False, False))
    assert syn_synack.half_open                       # victim's SYN-ACK visible, no final ACK
    done = _state((True, True, False, False, False, False), (False, True, True, False, False, False),
                  (True, False, True, False, False, False))
    assert not done.half_open


def test_service_comes_from_responder_port_only():
    assert get_service(53, 4444, "TCP") == "other"        # nmap -g 53 must not look like DNS
    assert get_service(80, 4444, "TCP") == "other"
    assert get_service(54321, 80, "TCP") == "http"
    assert get_service(20, 50000, "TCP") == "ftp_data"    # active FTP data connection
    assert get_service(50000, 53, "UDP") == "domain_u"


def test_orientation():
    assert keep_orientation(40000, 80, "TCP", SYN)                    # SYN: sender is the client
    assert not keep_orientation(80, 40000, "TCP", SYN | ACK)          # SYN-ACK: sender is the server
    assert not keep_orientation(80, 40000, "TCP", PSH | ACK)          # mid-stream: well-known port = server
    assert keep_orientation(40000, 443, "TCP", ACK)


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def test_signatures_drop_conditions_that_cannot_fail():
    neptune = next(s for s in compile_signatures(CONFIG["thresholds"]) if s.name == "neptune")
    fields = {f for f, _, _ in neptune.ranges}
    assert "serror_rate" not in fields and "same_srv_rate" not in fields   # [0,1] rates
    assert "count" not in fields                                           # count >= 1 always true


def test_bigger_flood_is_not_scored_as_smaller():
    feats = {"protocol_type": "TCP", "service": "http", "flag": "S0", "half_open": 1, "duration": 0.0,
             "src_bytes": 0, "dst_bytes": 0, "count": 9000, "srv_count": 9000,
             "half_open_count": 9000, "half_open_rate": 1.0, "dst_host_count": 100,
             "dst_host_srv_count": 100, "dst_host_srv_diff_host_rate": 0.0}
    name, score, _ = classify_detail(feats, CONFIG["thresholds"], 0.95)
    assert name == "neptune" and score == 1.0


def test_single_refused_connection_is_just_a_closed_port():
    pk = [tcp(1000.0, "10.0.0.9", 40000, "10.0.0.5", 81, SYN),
          tcp(1000.0001, "10.0.0.5", 81, "10.0.0.9", 40000, RST | ACK)]
    _, sink = run(pk)
    assert sink.new_alerts == []


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------

def syn_flood(n=300, t0=1000.0, victim="10.0.0.5", seed=3):
    rnd = random.Random(seed)
    return [tcp(t0 + i * 0.004, f"172.16.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
                rnd.randint(1024, 65000), victim, 80, SYN) for i in range(n)]


def test_syn_flood_raises_one_aggregated_alert():
    analyzer, sink = run(syn_flood())
    analyzer.flush()                         # capture ended: pending alert updates are delivered
    alerts = sink.new_alerts
    assert [a["outcome"] for a in alerts] == ["neptune"]
    a = alerts[0]
    assert a["dst_ip"] == "10.0.0.5" and a["severity"] == "high" and a["id"]
    updates = [x for k, x in sink.alerts if k == "update"]
    assert updates, "aggregated alert should receive periodic updates"
    assert updates[-1]["count"] > 100 and updates[-1]["sources"] > 100
    assert analyzer.aggregator.created == 1


def test_syn_flood_with_visible_syn_acks_is_still_a_flood():
    pk = []
    for i, p in enumerate(syn_flood(200)):
        pk.append(p)
        src = p.ip.src
        pk.append(tcp(float(p.sniff_time.timestamp()) + 0.0005, "10.0.0.5", 80, src,
                      int(p.tcp.srcport), SYN | ACK))
    _, sink = run(pk)
    assert [a["outcome"] for a in sink.new_alerts] == ["neptune"]


def test_flood_from_a_real_host_whose_kernel_resets_each_syn_ack_is_still_a_flood():
    """hping3 from a real host: SYN, SYN-ACK, then the attacker's own kernel sends RST."""
    pk = []
    for i in range(300):
        t = 1000.0 + i * 0.001
        pk += [tcp(t, "10.0.0.66", 2000 + i, "10.0.0.5", 80, SYN),
               tcp(t + 0.00005, "10.0.0.5", 80, "10.0.0.66", 2000 + i, SYN | ACK),
               tcp(t + 0.00010, "10.0.0.66", 2000 + i, "10.0.0.5", 80, RST)]
    _, sink = run(pk)
    assert [a["outcome"] for a in sink.new_alerts] == ["neptune"]


def test_scan_of_many_open_ports_is_not_mistaken_for_a_flood():
    """Same SYN / SYN-ACK / RST pattern, but every probe goes to a different port."""
    pk = []
    for i in range(40):
        t = 1000.0 + i * 0.01
        pk += [tcp(t, "10.0.0.66", 54000 + i, "10.0.0.5", 5000 + i, SYN),
               tcp(t + 0.0005, "10.0.0.5", 5000 + i, "10.0.0.66", 54000 + i, SYN | ACK),
               tcp(t + 0.0010, "10.0.0.66", 54000 + i, "10.0.0.5", 5000 + i, RST)]
    _, sink = run(pk)
    assert [a["outcome"] for a in sink.new_alerts] == ["portsweep"]


def test_busy_web_server_is_not_a_flood():
    pk = []
    for i in range(120):                    # 60 new connections/second, all complete
        pk += session(1000.0 + i * 0.0166, f"10.0.0.{10 + i % 20}", 40000 + i, "10.0.0.5", 80,
                      b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n")
    pk.sort(key=lambda p: p.sniff_time)
    _, sink = run(pk)
    assert sink.new_alerts == []


def test_port_scan_detected_from_failed_probes():
    pk = []
    for i, port in enumerate(range(1, 41)):
        t = 1000.0 + i * 0.05
        pk += [tcp(t, "10.0.0.66", 54000 + i, "10.0.0.5", port, SYN),
               tcp(t + 0.001, "10.0.0.5", port, "10.0.0.66", 54000 + i, RST | ACK)]
    _, sink = run(pk)
    assert [(a["outcome"], a["src_ip"], a["dst_ip"]) for a in sink.new_alerts] == [
        ("portsweep", "10.0.0.66", "10.0.0.5")]


def test_client_using_several_ports_successfully_is_not_a_scan():
    pk = []
    for i, port in enumerate((22, 80, 443, 8080, 8443, 3306, 5432, 9000)):
        pk += session(1000.0 + i * 0.3, "10.0.0.20", 41000 + i, "10.0.0.5", port, b"x", b"y")
    pk.sort(key=lambda p: p.sniff_time)
    _, sink = run(pk)
    assert sink.new_alerts == []


def test_ip_sweep_matures_after_grace_period():
    pk = [tcp(1000.0 + i * 0.1, "10.0.0.66", 55000 + i, f"10.0.1.{i + 1}", 445, SYN) for i in range(30)]
    _, early = run(pk[:15])                          # 1.4 s of SYNs: nothing has outlived the grace period
    assert early.new_alerts == []
    _, sink = run(pk)                                # 2.9 s: the earliest probes have matured mid-sweep
    assert [a["outcome"] for a in sink.new_alerts] == ["ipsweep"]
    assert sink.new_alerts[0]["src_ip"] == "10.0.0.66"
    tail = pk + [tcp(1010.0, "10.0.0.66", 56000, "10.0.1.200", 445, SYN)]   # sweep ends, time moves on
    analyzer, sink = run(tail)
    assert [a["outcome"] for a in sink.new_alerts] == ["ipsweep"]


def test_browsing_many_hosts_is_not_an_ip_sweep():
    pk = []
    for i in range(30):
        pk += session(1000.0 + i * 0.2, "10.0.0.20", 41000 + i, f"203.0.113.{10 + i}", 443, b"hi", b"ho")
    pk.sort(key=lambda p: p.sniff_time)
    _, sink = run(pk)
    assert sink.new_alerts == []


def test_midstream_pickup_orients_flow_by_well_known_port():
    analyzer, _ = run([tcp(1000.0, "10.0.0.5", 80, "10.0.0.9", 40000, PSH | ACK, b"HTTP/1.1 200 OK\r\n\r\n")])
    flow = next(iter(analyzer.flows.values()))
    assert (flow.dst_ip, flow.dst_port, flow.service) == ("10.0.0.5", 80, "http")


# --------------------------------------------------------------------------
# resource bounds & robustness
# --------------------------------------------------------------------------

def test_state_stays_bounded_under_a_long_spoofed_flood():
    rnd = random.Random(7)
    analyzer = PacketAnalyzer(json.loads(json.dumps(CONFIG)), Collect())
    for i in range(30000):                 # 30k one-packet flows over ~10 minutes of packet time
        analyzer.process_packet(tcp(1000.0 + i * 0.02, f"{rnd.randint(11, 200)}.{rnd.randint(0, 255)}."
                                    f"{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
                                    rnd.randint(1024, 65000), "10.0.0.5", 80, SYN))
    assert analyzer.active_flows < 3000
    stats = analyzer.tracker.stats()
    assert stats["records"] < 6000 and stats["recon_sources"] < 6000 and stats["host_windows"] <= 2


def test_flow_sampling_is_per_connection_not_per_packet():
    pk = []
    for i in range(40):
        pk += session(1000.0 + i * 0.01, "10.0.0.20", 41000 + i, "10.0.0.5", 80, b"a", b"b")
    analyzer, sink = run(pk, sampling_rate=2)
    analyzer.flush()
    assert 0 < len(sink.closed) < 40
    assert all(rec["packets"] == 8 for rec in sink.closed)      # no flow is half-observed


def test_cleartext_shell_heuristics_do_not_fire_on_encrypted_ssh():
    ssh = [tcp(1000.0, "10.0.0.9", 40000, "10.0.0.5", 22, SYN)]
    ssh += session(1001.0, "10.0.0.9", 40001, "10.0.0.5", 22, b"\x8f# \x00 sudo ", b"\x01root@\x02")
    telnet = session(1002.0, "10.0.0.9", 40002, "10.0.0.5", 23, b"cat /bin/sh\r\n", b"root@host:~# ")
    analyzer, _ = run(ssh + telnet)
    by_port = {f.dst_port: f for f in analyzer.flows.values()}
    assert by_port[22].num_compromised == 0 and by_port[22].root_shell == 0
    assert by_port[23].num_compromised == 1


def test_ftp_failed_logins_counted_and_success_detected():
    cs = session(1000.0, "10.0.0.9", 40000, "10.0.0.21", 21, b"USER bob\r\n", b"530 Login incorrect.\r\n")
    analyzer, _ = run(cs)
    flow = next(iter(analyzer.flows.values()))
    assert flow.num_failed_logins == 1 and not flow.logged_in


def test_alert_ids_are_unique_and_acknowledgeable_fields_exist():
    _, sink = run(syn_flood(120, victim="10.0.0.5") + syn_flood(120, t0=1100.0, victim="10.0.0.6", seed=9))
    ids = [a["id"] for a in sink.new_alerts]
    assert len(ids) == 2 == len(set(ids))
    assert all(a["acknowledged"] is False and a["mitre"] for a in sink.new_alerts)


# --------------------------------------------------------------------------
# intel / settings / stores
# --------------------------------------------------------------------------

def test_ioc_domain_matching_respects_label_boundaries(tmp_path):
    f = tmp_path / "ioc.txt"
    f.write_text("# comment\n198.51.100.7\n203.0.113.0/24\nevil.example\n")
    ioc = IocList(f)
    assert ioc.load()
    assert ioc.match("198.51.100.7") == ["ip:198.51.100.7"]
    assert ioc.match("203.0.113.9") == ["cidr:203.0.113.0/24"]
    assert ioc.match(None, ["a.evil.example"]) == ["domain:evil.example"]
    assert ioc.match(None, ["notevil.example"]) == []
    assert ioc.match(None, ["EVIL.example."]) == ["domain:evil.example"]


def test_reverse_dns_defaults_to_internal_addresses_only():
    calls = []
    enr = Enricher(IocList(None), reverse_dns="private",
                   resolver=lambda ip: calls.append(ip) or f"host-{ip}.Example.")
    assert enr.rdns("8.8.8.8") is None and calls == []
    assert enr.rdns("10.0.0.5") == "host-10.0.0.5.example"
    assert enr.rdns("10.0.0.5") == "host-10.0.0.5.example" and len(calls) == 1      # cached
    enr.reverse_dns = "all"
    assert enr.rdns("8.8.8.8") == "host-8.8.8.8.example"


def test_settings_validation_blocks_evasion_and_garbage(tmp_path):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps(CONFIG))
    s = Settings(cfg)
    bad = s.apply_update({"capture_bpf": "not host 10.0.0.66; rm -rf /", "interface": "-w /tmp/x",
                          "match_threshold": 5, "sampling_rate": 100000, "reverse_dns": "sometimes"})
    assert not bad["ok"] and len(bad["errors"]) == 5
    assert s.get("capture_bpf") is None                      # nothing was written
    good = s.apply_update({"capture_bpf": "tcp and not port 22", "match_threshold": 0.9, "sampling_rate": 2,
                           "ioc_list": "1.2.3.4\n\n evil.test \n"})
    assert good["ok"] and "restart_required" in good and good["restart_required"]
    reread = json.loads(cfg.read_text())
    assert reread["capture_bpf"] == "tcp and not port 22" and reread["detection"]["match_threshold"] == 0.9
    assert (tmp_path / "data" / "ioc.txt").read_text() == "1.2.3.4\nevil.test"


def test_alert_store_roundtrip_and_ack_persistence(tmp_path):
    store = AlertStore(tmp_path / "a.db")
    store.init()
    alert = {"id": "abc123", "flow_id": "f1", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "outcome": "neptune",
             "severity": "high", "confidence": 1.0, "timestamp": "2026-01-01T00:00:00", "acknowledged": False}
    store.save_many([alert])
    alert.update(acknowledged=True, acknowledged_timestamp="2026-01-01T00:01:00Z", count=5)
    store.save_many([alert])                                     # upsert, not duplicate
    rows = store.history()
    assert len(rows) == 1 and rows[0]["acknowledged"] and rows[0]["count"] == 5
    assert store.find("f1")["id"] == "abc123" and store.find("abc123")["flow_id"] == "f1"
    assert store.history(outcome="smurf") == [] and len(store.history(acknowledged=True)) == 1
    assert store.prune() == 0


def test_alert_store_reads_databases_from_older_versions(tmp_path):
    import sqlite3
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE alerts (id TEXT PRIMARY KEY, flow_id TEXT, src_ip TEXT, dst_ip TEXT,
        outcome TEXT, severity TEXT, confidence REAL, timestamp TEXT, persisted_timestamp TEXT,
        acknowledged INTEGER DEFAULT 0, acknowledged_timestamp TEXT, investigated INTEGER DEFAULT 0,
        investigator_notes TEXT, alert_json TEXT)""")                      # no 'investigator' column
    conn.execute("INSERT INTO alerts (id, flow_id, outcome, persisted_timestamp, acknowledged, alert_json) "
                 "VALUES ('u-1','f','portsweep','2026-01-01T00:00:00Z',1,'{\"flow_id\":\"f\"}')")
    conn.commit()
    conn.close()
    store = AlertStore(db)
    store.init()
    row = store.history()[0]
    assert row["id"] == "u-1" and row["acknowledged"] is True


def test_flow_store_log_and_retention(tmp_path):
    store = FlowStore(tmp_path / "f.db", max_rows=5)
    store.init()
    rec = {c: None for c in FlowStore.COLUMNS}
    store.add_many([dict(rec, flow_id=f"f{i}", outcome="normal" if i % 2 else "neptune") for i in range(10)])
    store.prune()
    rows = store.recent(100)
    assert len(rows) == 5 and rows[0]["flow_id"] == "f9"
    assert all(r["outcome"] == "neptune" for r in store.recent(100, outcome="neptune"))


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
