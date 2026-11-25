"""Web-layer tests: HTTP API, Socket.IO events, persistence, auth and a full
PCAP replay through the real tshark/pyshark pipeline.

    python tests/make_pcaps.py        # once (needs scapy)
    pytest tests/test_app.py
"""
import importlib
import json
import shutil
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest  # type: ignore[reportMissingImports]
from jinja2 import DictLoader

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
needs_pcaps = pytest.mark.skipif(not (ROOT / "test_pcaps" / "demo_mixed.pcap").exists(),
                                 reason="run tests/make_pcaps.py first")

PAGES = {n: f"<html>{n}</html>" for n in ("index.html", "alerts.html", "flows.html", "export.html")}
PAGES["settings.html"] = "<html>{{ config.detection.match_threshold }}|{{ config.interface }}</html>"


@pytest.fixture(scope="module")
def ids(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ids")
    cfg = json.loads((ROOT / "tests" / "fixtures" / "config.json").read_text())
    cfg["replay_dir"] = str(ROOT / "test_pcaps")
    (tmp / "config.json").write_text(json.dumps(cfg))
    import os
    os.environ["IDS_CONFIG"] = str(tmp / "config.json")
    os.environ.pop("IDS_API_TOKEN", None)
    for name in [m for m in sys.modules if m == "app"]:
        del sys.modules[name]
    mod = importlib.import_module("app")
    mod.app.jinja_env.loader = DictLoader(PAGES)       # the real templates live in the user's repo
    mod.app.config["TESTING"] = True
    return mod


@pytest.fixture()
def http(ids):
    return ids.app.test_client()


def sio(ids, http):
    return ids.socketio.test_client(ids.app, flask_test_client=http)


def wait_for(cond, timeout=60.0, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(step)
    return False


# --------------------------------------------------------------------------
# basic HTTP
# --------------------------------------------------------------------------

def test_pages_render_and_settings_receive_effective_config(http):
    for path in ("/", "/alerts", "/flows", "/export"):
        assert http.get(path).status_code == 200
    body = http.get("/settings").get_data(as_text=True)
    assert "0.95|lo" in body


def test_security_headers(http):
    r = http.get("/api/status")
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"


def test_health_payload_keeps_the_keys_the_frontend_uses(http):
    data = http.get("/api/status").get_json()
    for key in ("cpu_percent", "memory_used_mb", "memory_total_mb", "queue_length", "active_flows",
                "active_alerts", "total_packets", "total_attacks", "packets_per_sec", "attacks_per_sec",
                "capture_status", "running", "detection_latency_ms", "uptime"):
        assert key in data, key
    assert data["capture_status"] == "STOPPED" and data["running"] is False


def test_sensor_resource_usage_aggregates_process_tree_and_normalizes_cpu(ids, monkeypatch):
    mb = 1024 * 1024

    class FakeProcess:
        def __init__(self, pid, rss_mb, cpu_samples):
            self.pid = pid
            self._rss = rss_mb * mb
            self._cpu_samples = iter(cpu_samples)
            self.cpu_calls = 0

        def create_time(self):
            return 1234.0

        def cpu_percent(self, interval=None):
            self.cpu_calls += 1
            return next(self._cpu_samples)

        def memory_info(self):
            return SimpleNamespace(rss=self._rss)

    # A new Process wrapper is returned on each tree scan. The sampler should
    # retain the original handles so psutil can calculate deltas between calls.
    root_first = FakeProcess(100, 60, [0.0, 60.0])
    child_first = FakeProcess(200, 20, [0.0, 20.0])
    root_next = FakeProcess(100, 60, [99.0])
    child_next = FakeProcess(200, 20, [99.0])
    snapshots = iter([
        [root_first, child_first],
        [root_next, child_next],
    ])

    monkeypatch.setattr(ids, "_sensor_processes", lambda: next(snapshots))
    monkeypatch.setattr(ids.psutil, "cpu_count", lambda logical=True: 4)
    monkeypatch.setattr(ids, "_sensor_cpu_process_handles", {})

    # First samples establish psutil's per-process baseline.
    assert ids._sensor_resource_usage() == (0.0, 80.0)
    # 80% summed across four logical CPUs = 20% of total machine capacity.
    assert ids._sensor_resource_usage() == (20.0, 80.0)
    assert root_first.cpu_calls == 2 and child_first.cpu_calls == 2
    assert root_next.cpu_calls == 0 and child_next.cpu_calls == 0


def test_settings_update_validates(http, ids):
    original = {
        "match_threshold": ids.config["detection"]["match_threshold"],
        "half_open_min_count": ids.config["detection"]["half_open_min_count"],
    }

    try:
        r = http.post(
            "/settings/update",
            json={"capture_bpf": "host 1.2.3.4; reboot", "match_threshold": 7},
        )
        assert r.status_code == 400
        assert len(r.get_json()["errors"]) == 2

        r = http.post(
            "/settings/update",
            json={"match_threshold": 0.9, "half_open_min_count": 12},
        )
        assert r.status_code == 200
        assert r.get_json()["ok"] is True

        assert ids.config["detection"]["match_threshold"] == 0.9
        assert ids.config["detection"]["half_open_min_count"] == 12

        assert http.post(
            "/settings/update",
            data="x",
            content_type="text/plain",
        ).status_code == 400

    finally:
        restored = http.post("/settings/update", json=original)
        assert restored.status_code == 200


def test_pcaps_listing_and_interfaces(http):
    names = [p["name"] for p in http.get("/api/pcaps").get_json()["pcaps"]]
    assert isinstance(names, list)
    assert "interfaces" in http.get("/api/interfaces").get_json()


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

def test_token_protects_telemetry_control_and_mutation(ids, http, monkeypatch):
    monkeypatch.setattr(ids, "API_TOKEN", "s3cret")
    client = None
    try:
        protected_gets = (
            "/api/interfaces", "/api/pcaps", "/api/status", "/api/flows",
            "/api/alerts", "/alerts/history", "/export/flows.csv", "/export/alerts.csv",
            "/export/alert_pcap?flow_id=x",
        )
        for path in protected_gets:
            assert http.get(path).status_code == 401
        assert http.post("/settings/update", json={"sampling_rate": 2}).status_code == 401
        ok = http.post("/settings/update", json={"sampling_rate": 2},
                       headers={"X-IDS-Token": "s3cret"})
        assert ok.status_code == 200

        unauth = ids.socketio.test_client(ids.app, flask_test_client=http)
        assert not unauth.is_connected()
        bad = ids.socketio.test_client(ids.app, flask_test_client=http, auth={"token": "wrong"})
        assert not bad.is_connected()
        client = ids.socketio.test_client(ids.app, flask_test_client=http, auth={"token": "s3cret"})
        assert client.is_connected()

        client.emit("start_ids", {"pcap": "../../etc/passwd", "speed": 0})
        events = client.get_received()
        status = [e for e in events if e["name"] == "status_update"][-1]["args"][0]
        assert status["color"] == "danger" and not ids.rt.running
    finally:
        # ALWAYS restore, even if an assertion above fails
        http.post("/settings/update", json={"sampling_rate": 1},
                  headers={"X-IDS-Token": "s3cret"})
        if client is not None and client.is_connected():
            client.disconnect()

        http.post("/settings/update", json={"sampling_rate": 1}, headers={"X-IDS-Token": "s3cret"})


def test_replay_names_cannot_escape_the_replay_directory(ids, http):
    client = sio(ids, http)
    client.get_received()
    for bad in ("../../etc/passwd", "/etc/passwd", "..\\x.pcap", "nope.pcap"):
        client.emit("start_ids", {"pcap": bad})
        status = [e for e in client.get_received() if e["name"] == "status_update"][-1]["args"][0]
        assert status["color"] == "danger" and not ids.rt.running
    client.disconnect()


# --------------------------------------------------------------------------
# full replay through tshark
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def replayed(ids):
    if shutil.which("tshark") is None or not (ROOT / "test_pcaps" / "demo_mixed.pcap").exists():
        pytest.skip("needs tshark and generated PCAPs")
    http = ids.app.test_client()
    client = sio(ids, http)
    client.get_received()
    client.emit("start_ids", {"pcap": "demo_mixed.pcap", "speed": 0})
    started = [e for e in client.get_received() if e["name"] == "status_update"][-1]["args"][0]
    assert started["running"] is True and started["mode"] == "replay"
    assert wait_for(lambda: not ids.rt.running, timeout=90), "replay did not finish"
    time.sleep(2.5)                                  # let the emitter / persistence threads catch up
    events = client.get_received()
    return {"client": client, "events": events, "http": http}


@needs_tshark
@needs_pcaps
def test_replay_emits_status_stats_and_exactly_the_three_attacks(replayed, ids):
    events = replayed["events"]
    names = {e["name"] for e in events}
    print("\n========== REPLAY DIAGNOSTICS ==========")

    print("\nDETECTION CONFIG:")
    print(ids.config.get("detection"))

    print("\nSOCKET EVENTS:")
    for event in events:
        print(event["name"], event.get("args"))

    print("\nALERT HISTORY:")
    history_response = replayed["http"].get("/alerts/history")
    print("Status:", history_response.status_code)
    print(history_response.get_json())

    print("\nALERT CSV:")
    csv_response = replayed["http"].get("/export/alerts.csv")
    print(csv_response.get_data(as_text=True))

    print("\n========================================")
    assert {"status_update", "alert_update", "stats_update", "flow_batch", "system_health"} <= names
    final = [e for e in events if e["name"] == "status_update"][-1]["args"][0]
    assert final["status"] == "Replay finished" and final["running"] is False
    alerts = {}
    for e in events:
        if e["name"] == "alert_update":
            for a in e["args"][0]["alerts"]:
                alerts[a["id"]] = a
    assert sorted(a["outcome"] for a in alerts.values()) == ["ipsweep", "neptune", "portsweep"]
    for a in alerts.values():
        assert a["id"] and a["severity"] and a["reasons"] and a["capture_source"] == "replay:demo_mixed.pcap"
    stats = [e["args"][0] for e in events if e["name"] == "stats_update"][-1]
    assert stats["total_packets"] > 1500 and len(stats["packets_history"]) == 60



@needs_tshark
@needs_pcaps
def test_alert_history_ack_and_persistence(replayed, ids):
    http = replayed["http"]
    assert wait_for(lambda: len(http.get("/alerts/history").get_json()) >= 3, timeout=10)
    rows = http.get("/alerts/history").get_json()
    victim = next(a for a in rows if a["outcome"] == "neptune")
    client = replayed["client"]
    client.get_received()
    client.emit("ack_alert", {"id": victim["id"]})
    updates = [a for e in client.get_received() if e["name"] == "alert_update" for a in e["args"][0]["alerts"]]
    assert updates and updates[0]["id"] == victim["id"] and updates[0]["acknowledged"] is True
    assert wait_for(lambda: ids.alert_store.find(victim["id"])["acknowledged"], timeout=10)
    # acknowledging by flow_id (what the existing front-end sends) works too
    other = next(a for a in rows if a["outcome"] == "portsweep")
    client.emit("ack_alert", {"flow_id": other["flow_id"]})
    assert wait_for(lambda: ids.alert_store.find(other["id"])["acknowledged"], timeout=10)
    client.emit("investigate_alert", {"id": other["id"], "note": "scanner is the pen-test box",
                                      "false_positive": True, "investigator": "kareem"})
    assert wait_for(lambda: ids.alert_store.find(other["id"]).get("investigated"), timeout=10)
    assert ids.alert_store.find(other["id"])["investigator_notes"][0]["false_positive"] is True
    assert len(http.get("/alerts/history?outcome=neptune").get_json()) == 1


@needs_tshark
@needs_pcaps
def test_flow_log_and_csv_exports(replayed, ids):
    http = replayed["http"]
    assert wait_for(lambda: len(http.get("/api/flows?source=db&limit=5000").get_json()) > 500, timeout=15)
    csv_text = http.get("/export/flows.csv?source=db&limit=50").get_data(as_text=True)
    assert csv_text.splitlines()[0].startswith("flow_id,timestamp,src_ip")
    alerts_csv = http.get("/export/alerts.csv").get_data(as_text=True)
    assert "neptune" in alerts_csv and "portsweep" in alerts_csv


@needs_tshark
@needs_pcaps
def test_evidence_pcap_for_replayed_alert_is_filtered_from_the_source(replayed, ids):
    http = replayed["http"]
    rows = http.get("/alerts/history?outcome=portsweep").get_json()
    r = http.get(f"/export/alert_pcap?id={rows[0]['id']}")
    assert r.status_code == 200 and r.headers["X-Export-Mode"] == "replay-filter"
    data = r.get_data()
    assert data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")                       # classic pcap magic
    assert 3000 < len(data) < 40000                                  # only the scanner<->target packets
    assert http.get("/export/alert_pcap?flow_id=does-not-exist").status_code == 404
    assert http.get("/export/alert_pcap").status_code == 400


def test_csv_cells_cannot_inject_formulas(ids):
    out = ids._csv_response([{"flow_id": "=HYPERLINK(\"http://evil\")", "names": ["@cmd", "ok"]}],
                            ["flow_id", "names"], "x.csv").get_data(as_text=True)
    assert "'=HYPERLINK" in out and "'@cmd,ok" in out


@needs_tshark
@needs_pcaps
def test_start_stop_while_replaying_is_clean(ids):
    http = ids.app.test_client()
    client = sio(ids, http)
    client.get_received()
    client.emit("start_ids", {"pcap": "demo_mixed.pcap", "speed": 1})      # paced: takes a while
    assert wait_for(lambda: ids.rt.running, timeout=5)
    time.sleep(1.0)
    client.emit("stop_ids")
    assert wait_for(lambda: not ids.rt.running, timeout=15), "stop did not take effect"
    last = [e for e in client.get_received() if e["name"] == "status_update"][-1]["args"][0]
    assert last["running"] is False
    client.emit("start_ids", {"pcap": "syn_flood.pcap", "speed": 0})        # can start again right away
    assert wait_for(lambda: ids.rt.running or ids.rt.last_totals["packets"] > 0, timeout=5)
    assert wait_for(lambda: not ids.rt.running, timeout=60)
    client.disconnect()


# --------------------------------------------------------------------------
# Phase 3: queue and persistence fault isolation
# --------------------------------------------------------------------------

def _clear_queue(q):
    while True:
        try:
            q.get_nowait()
        except ids_queue_empty:
            return


# Keep queue.Empty local to avoid depending on implementation details in app.py.
from queue import Empty as ids_queue_empty


def test_persist_alert_failure_does_not_block_flow_batch(ids, monkeypatch):
    class BrokenAlerts:
        def save_many(self, records):
            raise OSError("simulated alert database failure")

    class WorkingFlows:
        def __init__(self):
            self.saved = []

        def add_many(self, records):
            self.saved.extend(records)
            return len(records)

    _clear_queue(ids.alert_persist_queue)
    _clear_queue(ids.flow_log_queue)
    old_alert_store, old_flow_store = ids.alert_store, ids.flow_store
    flows = WorkingFlows()
    monkeypatch.setattr(ids, "alert_store", BrokenAlerts())
    monkeypatch.setattr(ids, "flow_store", flows)
    try:
        ids.alert_persist_queue.put_nowait({"id": "phase3-alert"})
        ids.flow_log_queue.put_nowait({"flow_id": "phase3-flow"})
        before = ids._pipeline_snapshot()
        ids._persist_once(time.time())
        after = ids._pipeline_snapshot()
        assert [r["flow_id"] for r in flows.saved] == ["phase3-flow"]
        assert after["pipeline"]["alert_persist_errors"] == before["pipeline"]["alert_persist_errors"] + 1
        assert after["dropped"]["alert_persist_errors"] == before["dropped"]["alert_persist_errors"] + 1
        assert ids.alert_persist_queue.empty() and ids.flow_log_queue.empty()
    finally:
        monkeypatch.setattr(ids, "alert_store", old_alert_store)
        monkeypatch.setattr(ids, "flow_store", old_flow_store)
        _clear_queue(ids.alert_persist_queue)
        _clear_queue(ids.flow_log_queue)


def test_persist_flow_failure_does_not_block_alert_batch(ids, monkeypatch):
    class WorkingAlerts:
        def __init__(self):
            self.saved = []

        def save_many(self, records):
            self.saved.extend(records)
            return len(self.saved)

    class BrokenFlows:
        def add_many(self, records):
            raise OSError("simulated flow database failure")

    _clear_queue(ids.alert_persist_queue)
    _clear_queue(ids.flow_log_queue)
    old_alert_store, old_flow_store = ids.alert_store, ids.flow_store
    alerts = WorkingAlerts()
    monkeypatch.setattr(ids, "alert_store", alerts)
    monkeypatch.setattr(ids, "flow_store", BrokenFlows())
    try:
        ids.alert_persist_queue.put_nowait({"id": "phase3-alert-ok"})
        ids.flow_log_queue.put_nowait({"flow_id": "phase3-flow-fail"})
        before = ids._pipeline_snapshot()
        ids._persist_once(time.time())
        after = ids._pipeline_snapshot()
        assert [a["id"] for a in alerts.saved] == ["phase3-alert-ok"]
        assert after["pipeline"]["flow_persist_errors"] == before["pipeline"]["flow_persist_errors"] + 1
        assert after["dropped"]["flow_persist_errors"] == before["dropped"]["flow_persist_errors"] + 1
    finally:
        monkeypatch.setattr(ids, "alert_store", old_alert_store)
        monkeypatch.setattr(ids, "flow_store", old_flow_store)
        _clear_queue(ids.alert_persist_queue)
        _clear_queue(ids.flow_log_queue)


def test_health_exposes_each_queue_and_pipeline_counters(ids, http):
    data = http.get("/api/status").get_json()
    assert set(data["queue_depths"]) == {"flow_events", "alert_events", "alert_persistence", "flow_log"}
    assert "alert_persist_errors" in data["pipeline_metrics"]["pipeline"]
    assert "flow_persist_errors" in data["pipeline_metrics"]["dropped"]
    assert "dropped_events" in data
