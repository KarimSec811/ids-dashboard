"""
Real-time Network IDS -- Flask-SocketIO backend (entry point).

    python app.py                       # http://127.0.0.1:5000

Layout
    app.py            web layer: routes, Socket.IO events, background services
    ids/engine.py     detection engine (flows, features, signatures, alerts)
    ids/capture.py    live capture / PCAP replay (pyshark)
    ids/intel.py      IOC matching, reverse DNS, GeoIP
    ids/store.py      SQLite persistence (alerts, flow log)
    ids/settings.py   config.json loading + validated updates

Runtime model: plain OS threads (Flask-SocketIO ``threading`` mode). There is
no monkey-patching, so pyshark's asyncio loop, SQLite and DNS lookups can never
stall the web server.

Environment
    IDS_CONFIG                path to config.json (default: next to app.py)
    IDS_HOST / IDS_PORT       bind address (default 127.0.0.1:5000)
    IDS_API_TOKEN             if set, required for control/mutating/export calls
    IDS_ALLOW_INSECURE=1      allow a non-loopback bind without a token
    CORS_ORIGINS              comma separated allowed origins (default: same-origin)
    FLASK_SECRET_KEY          session key (random per process if unset)
    LOG_LEVEL                 DEBUG/INFO/... (default INFO)
"""
from __future__ import annotations

import copy
import csv
import hmac
import io
import ipaddress
import logging
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
from flask import Flask, Response, jsonify, render_template, request, send_file
from flask_socketio import SocketIO, emit

from ids.capture import CaptureError, CaptureSession
from ids.engine import (  # noqa: F401  (re-exported for tests / scripts)
    ALERT_GROUPING, ALERT_UPDATE_FIELDS, ConnState, FlowFeatures, HostConnectionTracker, NullSink,
    PacketAnalyzer, classify, get_flow_id, get_service, score_attack,
)
from ids.intel import Enricher, IocList
from ids.settings import IFACE_RE, ConfigError, Settings
from ids.store import AlertStore, FlowStore

# --------------------------------------------------------------------------
# Logging / paths / configuration
# --------------------------------------------------------------------------

logging.basicConfig(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("ids-dashboard")

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.getenv("IDS_CONFIG") or (BASE_DIR / "config.json")).resolve()

try:
    settings = Settings(CONFIG_PATH)
except ConfigError as exc:
    logger.critical("%s", exc)
    raise

config = settings.data          # live reference (updated in place by Settings)

HOST = os.getenv("IDS_HOST", "127.0.0.1")
PORT = int(os.getenv("IDS_PORT", "5000"))
API_TOKEN = os.getenv("IDS_API_TOKEN") or None

REPLAY_DIR = settings.resolve("replay_dir", "test_pcaps")
EXPORT_DIR = BASE_DIR / "data" / "pcaps"
ALERT_HISTORY_LIMIT = int(settings.get("alert_history_limit", 100))
RECENT_FLOWS_LIMIT = int(settings.get("recent_flows_limit", 1000))
CHART_HISTORY_SECONDS = 60
PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")

psutil.cpu_percent(interval=None)       # warm-up: the first call has no baseline
_process_handle = psutil.Process(os.getpid())


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


# --------------------------------------------------------------------------
# Flask / Socket.IO
# --------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024      # settings bodies are tiny

_cors = os.getenv("CORS_ORIGINS")
if not _cors:
    _cors_allowed = None                    # same-origin only (safest default)
elif _cors.strip() == "*":
    _cors_allowed = "*"                     # string, not ['*']: a list is matched literally
else:
    _cors_allowed = [o.strip() for o in _cors.split(",") if o.strip()]

socketio = SocketIO(app, cors_allowed_origins=_cors_allowed, async_mode="threading",
                    ping_interval=20, ping_timeout=40, max_http_buffer_size=1_000_000)


@app.after_request
def _security_headers(resp: Response) -> Response:
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.path.startswith(("/api/", "/export", "/alerts/history", "/settings/update")):
        resp.headers["Cache-Control"] = "no-store"
    return resp


# --------------------------------------------------------------------------
# Authentication (optional shared token)
# --------------------------------------------------------------------------

def _token_ok(supplied: Optional[str]) -> bool:
    if not API_TOKEN:
        return True
    return bool(supplied) and hmac.compare_digest(str(supplied), API_TOKEN)


def _http_token() -> Optional[str]:
    header = request.headers.get("X-IDS-Token")
    if header:
        return header
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.args.get("token")        # allows plain <a href> downloads


def require_token(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not _token_ok(_http_token()):
            return jsonify({"error": "unauthorized", "auth_required": True}), 401
        return fn(*args, **kwargs)
    return wrapper


_authed_sids: set = set()


def _socket_authorized(data: Any = None) -> bool:
    if not API_TOKEN:
        return True
    if request.sid in _authed_sids:
        return True
    return isinstance(data, dict) and _token_ok(data.get("token"))


def _deny_socket() -> None:
    emit("auth_error", {"error": "unauthorized", "auth_required": True})
    emit("status_update", {"status": "Not authorized", "color": "danger",
                           "running": rt.running, "auth_required": True})


# --------------------------------------------------------------------------
# Thread-safe in-memory books
# --------------------------------------------------------------------------

def _utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class FlowBook:
    """Latest state of each recent flow (bounded, one entry per flow_id)."""

    def __init__(self, limit: int):
        self._limit = limit
        self._items: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.Lock()

    def add(self, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._items[payload["flow_id"]] = payload
            self._items.move_to_end(payload["flow_id"])
            while len(self._items) > self._limit:
                self._items.popitem(last=False)

    def recent(self, n: int = 500) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._items.values())[-n:]

    def find(self, flow_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._items.get(flow_id)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


class AlertBook:
    """Recent alerts, newest first when listed. Keyed by alert id."""

    def __init__(self, limit: int):
        self._limit = limit
        self._items: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._lock = threading.RLock()

    def add(self, alert: Dict[str, Any]) -> None:
        with self._lock:
            self._items[alert["id"]] = alert
            self._items.move_to_end(alert["id"])
            while len(self._items) > self._limit:
                self._items.popitem(last=False)

    def preload(self, alerts_newest_first: List[Dict[str, Any]]) -> None:
        with self._lock:
            for a in reversed(alerts_newest_first):
                if a.get("id") and a["id"] not in self._items:
                    self.add(a)

    def _find_locked(self, key: str) -> Optional[Dict[str, Any]]:
        if key in self._items:
            return self._items[key]
        for a in reversed(self._items.values()):
            if a.get("flow_id") == key:
                return a
        return None

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            a = self._find_locked(key)
            return copy.deepcopy(a) if a else None

    def mutate(self, key: str, fn) -> Optional[Dict[str, Any]]:
        """Apply ``fn(alert)`` under the lock; returns a copy, or None if absent."""
        with self._lock:
            a = self._find_locked(key)
            if a is None:
                return None
            fn(a)
            return copy.deepcopy(a)

    def merge_analyzer_update(self, update: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        def apply(a):
            for k in ALERT_UPDATE_FIELDS:
                if k in update:
                    a[k] = update[k]
            if update.get("names"):
                a["names"] = update["names"]
        return self.mutate(update["id"], apply)

    def list_newest_first(self, n: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(a) for a in list(reversed(self._items.values()))[:n]]

    def unacknowledged(self) -> int:
        with self._lock:
            return sum(1 for a in self._items.values() if not a.get("acknowledged"))

    def __len__(self) -> int:
        return len(self._items)


flow_book = FlowBook(RECENT_FLOWS_LIMIT)
alert_book = AlertBook(ALERT_HISTORY_LIMIT)

# Queues between the capture thread and the web/background threads.
flow_event_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=5000)
alert_event_queue: "queue.Queue[Tuple[str, Dict[str, Any]]]" = queue.Queue(maxsize=5000)
alert_persist_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=5000)
flow_log_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=20000)
dropped = {"flows": 0, "alerts": 0, "persist": 0, "flow_log": 0}

# --------------------------------------------------------------------------
# Persistence + intel services
# --------------------------------------------------------------------------

_alerts_path = settings.resolve("alerts_db_path", "data/alerts.db")
_flows_path = settings.resolve("flows_db_path", "data/flows.db")
alert_store: Optional[AlertStore] = (
    AlertStore(_alerts_path, retention_days=int(settings.get("alerts_retention_days", 30)))
    if _alerts_path else None)
flow_store: Optional[FlowStore] = (
    FlowStore(_flows_path, max_rows=int(settings.get("flows_max_rows", 500000)))
    if _flows_path else None)

ioc_list = IocList(settings.resolve("ioc_list_path", "data/ioc.txt"))
enricher = Enricher(ioc_list, reverse_dns=str(settings.get("reverse_dns", "private")),
                    geoip_db_path=settings.get("geoip_db_path"))


# --------------------------------------------------------------------------
# Runtime state (capture lifecycle)
# --------------------------------------------------------------------------

class Runtime:
    def __init__(self):
        self.lock = threading.RLock()
        self.running = False
        self.analyzer: Optional[PacketAnalyzer] = None
        self.session: Optional[CaptureSession] = None
        self.start_time: Optional[float] = None
        self.mode: Optional[str] = None
        self.source_label: Optional[str] = None
        self.error: Optional[str] = None
        self.last_totals = {"packets": 0, "attacks": 0}


rt = Runtime()


class DashboardSink(NullSink):
    """Called from the capture thread: must be fast and never block."""

    def on_flow(self, payload: Dict[str, Any]) -> None:
        flow_book.add(payload)
        try:
            flow_event_queue.put_nowait(payload)
        except queue.Full:
            dropped["flows"] += 1

    def on_flow_closed(self, record: Dict[str, Any]) -> None:
        if flow_store is None:
            return
        try:
            flow_log_queue.put_nowait(record)
        except queue.Full:
            dropped["flow_log"] += 1

    def on_alert(self, kind: str, alert: Dict[str, Any]) -> None:
        try:
            alert_event_queue.put_nowait((kind, alert))
        except queue.Full:
            dropped["alerts"] += 1
            logger.warning("Alert queue full; dropping an alert event")


def _status_payload(text: str, color: str, **extra) -> Dict[str, Any]:
    payload = {"status": text, "color": color, "running": rt.running,
               "mode": rt.mode, "source": rt.source_label, "error": rt.error}
    payload.update(extra)
    return payload


def broadcast_status(text: str, color: str, **extra) -> None:
    try:
        socketio.emit("status_update", _status_payload(text, color, **extra))
    except Exception:
        logger.debug("status emit failed", exc_info=True)


def _capture_worker(session: CaptureSession, analyzer: PacketAnalyzer) -> None:
    final = ("IDS Stopped", "info")
    try:
        session.run()
        if session.mode == "replay" and not session.stopping:
            final = ("Replay finished", "info")
    except CaptureError as exc:
        rt.error = str(exc)
        final = (f"Capture failed: {exc}", "danger")
        logger.error("Capture failed: %s", exc)
    except Exception as exc:
        rt.error = f"{type(exc).__name__}: {exc}"
        final = ("Capture crashed (see server log)", "danger")
        logger.exception("Capture crashed")
    finally:
        try:
            analyzer.flush()
        except Exception:
            logger.exception("Analyzer flush failed")
        with rt.lock:
            rt.last_totals = {"packets": analyzer.packets_processed,
                              "attacks": analyzer.aggregator.created}
            rt.running = False
            rt.start_time = None
        broadcast_status(*final)
        logger.info("Capture ended (%s)", final[0])


def start_capture(pcap_name: Optional[str] = None, speed: float = 0.0) -> Tuple[bool, str, str]:
    """Returns (ok, message, color)."""
    with rt.lock:
        if rt.running:
            return False, "IDS is already running", "warning"
        pcap_path = None
        if pcap_name:
            pcap_path = _resolve_replay(pcap_name)
            if pcap_path is None:
                return False, "Unknown replay file", "danger"
        else:
            iface = settings.get("interface")
            if not iface or not IFACE_RE.match(str(iface)) or str(iface).startswith("-"):
                return False, "No valid capture interface configured (Settings)", "danger"

        analyzer = PacketAnalyzer(settings.analyzer_config(), DashboardSink())
        session = CaptureSession(
            analyzer, interface=settings.get("interface"), bpf=settings.get("capture_bpf"),
            pcap_path=pcap_path, speed=speed)
        rt.analyzer, rt.session = analyzer, session
        rt.mode = session.mode
        rt.source_label = (f"replay:{pcap_path.name}" if pcap_path else f"live:{settings.get('interface')}")
        rt.error = None
        rt.running = True
        rt.start_time = time.time()
        flow_book.clear()
        socketio.start_background_task(_capture_worker, session, analyzer)
    logger.info("Capture started (%s)", rt.source_label)
    label = "Replay Started" if pcap_path else "IDS Started"
    return True, label, "success"


def stop_capture() -> bool:
    with rt.lock:
        session = rt.session
        if not rt.running or session is None:
            return False
    session.stop()
    return True


def _resolve_replay(name: str) -> Optional[Path]:
    """Only plain file names inside the replay directory are accepted."""
    if not REPLAY_DIR or not isinstance(name, str):
        return None
    if Path(name).name != name or not name.lower().endswith(PCAP_SUFFIXES):
        return None
    path = REPLAY_DIR / name
    return path if path.is_file() else None


# --------------------------------------------------------------------------
# Health / stats payloads
# --------------------------------------------------------------------------

def get_system_health() -> Dict[str, Any]:
    mem_info = _process_handle.memory_info()
    vm = psutil.virtual_memory()
    analyzer = rt.analyzer
    running = rt.running
    uptime = (time.time() - rt.start_time) if (running and rt.start_time) else 0
    hours, rem = divmod(int(uptime), 3600)
    minutes, seconds = divmod(rem, 60)
    pps, aps = analyzer.rates.per_second() if analyzer else (0.0, 0.0)
    totals = ({"packets": analyzer.packets_processed, "attacks": analyzer.aggregator.created}
              if analyzer else rt.last_totals)
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_used_mb": round(mem_info.rss / (1024 * 1024), 1),
        "memory_total_mb": round(vm.total / (1024 * 1024), 1),
        "queue_length": flow_event_queue.qsize(),
        "active_flows": analyzer.active_flows if analyzer else 0,
        "active_alerts": len(alert_book),
        "unacknowledged_alerts": alert_book.unacknowledged(),
        "total_packets": totals["packets"],
        "total_attacks": totals["attacks"],
        "packets_per_sec": pps if running else 0,
        "attacks_per_sec": aps if running else 0,
        "capture_status": "RUNNING" if running else "STOPPED",
        "running": running,
        "mode": rt.mode if running else None,
        "source": rt.source_label if running else None,
        "error": rt.error,
        "detection_latency_ms": analyzer.avg_detection_latency_ms if analyzer else 0.0,
        "uptime": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "dropped_events": sum(dropped.values()),
        "alerts_suppressed": analyzer.aggregator.suppressed if analyzer else 0,
        "tracker": analyzer.tracker.stats() if analyzer else {},
        "auth_required": bool(API_TOKEN),
    }


def get_stats_payload() -> Dict[str, Any]:
    analyzer = rt.analyzer
    running = rt.running
    pps, aps = analyzer.rates.per_second() if analyzer else (0.0, 0.0)
    pkt_hist, atk_hist = (analyzer.rates.series(CHART_HISTORY_SECONDS) if analyzer
                          else ([0] * CHART_HISTORY_SECONDS, [0] * CHART_HISTORY_SECONDS))
    totals = ({"packets": analyzer.packets_processed, "attacks": analyzer.aggregator.created}
              if analyzer else rt.last_totals)
    return {
        "packets_per_sec": pps if running else 0,
        "attacks_per_sec": aps if running else 0,
        "queue_length": flow_event_queue.qsize(),
        "active_flows": analyzer.active_flows if analyzer else 0,
        "capture_status": "RUNNING" if running else "STOPPED",
        "total_packets": totals["packets"],
        "total_attacks": totals["attacks"],
        "packets_history": pkt_hist,
        "attacks_history": atk_hist,
    }


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("index.html", page="dashboard")


@app.route("/alerts")
def alerts():
    return render_template("alerts.html", page="alerts")


@app.route("/flows")
def flows():
    return render_template("flows.html", page="flows")


@app.route("/export")
def export_page():
    return render_template("export.html", page="export")


@app.route("/settings", endpoint="settings")
def settings_page():
    return render_template("settings.html", page="settings", config=settings.effective())


@app.route("/health")
def health():
    return jsonify({"status": "ok", "running": rt.running})


# --------------------------------------------------------------------------
# Socket.IO events
# --------------------------------------------------------------------------

@socketio.on("connect")
def on_connect(auth=None):
    logger.info("Client connected")
    if isinstance(auth, dict) and _token_ok(auth.get("token")) and API_TOKEN:
        _authed_sids.add(request.sid)
    start_background_services()
    emit("status_update", _status_payload("IDS Started" if rt.running else "IDS Stopped",
                                          "success" if rt.running else "info"))


@socketio.on("disconnect")
def on_disconnect():
    _authed_sids.discard(request.sid)
    logger.info("Client disconnected")


@socketio.on("start_ids")
def on_start_ids(data=None):
    if not _socket_authorized(data):
        return _deny_socket()
    pcap = speed = None
    if isinstance(data, dict):
        pcap = data.get("pcap")
        try:
            speed = float(data.get("speed", 10.0))
        except (TypeError, ValueError):
            speed = 10.0
    ok, msg, color = start_capture(pcap, speed if speed is not None else 0.0)
    emit("status_update", _status_payload(msg, color, running=rt.running))


@socketio.on("stop_ids")
def on_stop_ids(data=None):
    if not _socket_authorized(data):
        return _deny_socket()
    if stop_capture():
        emit("status_update", _status_payload("IDS Stopping...", "warning", running=False))
        logger.info("IDS stop requested.")
    else:
        emit("status_update", _status_payload("IDS is not running", "info", running=False))


def _publish_alert(alert: Dict[str, Any], persist: bool = True) -> None:
    if persist and alert_store is not None:
        try:
            alert_persist_queue.put_nowait(copy.deepcopy(alert))
        except queue.Full:
            dropped["persist"] += 1
    socketio.emit("alert_update", {"alerts": [alert]})


def _mutate_alert(key: str, fn) -> Optional[Dict[str, Any]]:
    """Mutate an alert wherever it lives (memory first, then the database)."""
    updated = alert_book.mutate(key, fn)
    if updated is None and alert_store is not None:
        stored = alert_store.find(key)
        if stored is not None:
            fn(stored)
            alert_store.save_many([stored])
            socketio.emit("alert_update", {"alerts": [stored]})
            return stored
    if updated is not None:
        _publish_alert(updated)
    return updated


def _alert_keys(data: Any) -> List[str]:
    if not isinstance(data, dict):
        return []
    keys = []
    for field in ("id", "flow_id"):
        if isinstance(data.get(field), str) and data[field]:
            keys.append(data[field])
            break
    if isinstance(data.get("ids"), list):                  # bulk acknowledge
        keys.extend(str(i) for i in data["ids"][:200] if isinstance(i, (str, int)))
    return keys


@socketio.on("ack_alert")
def on_ack_alert(data=None):
    """Acknowledge by alert id or flow_id (single, or {'ids': [...]} in bulk)."""
    if not _socket_authorized(data):
        return _deny_socket()

    def ack(a):
        a["acknowledged"] = True
        a["acknowledged_timestamp"] = _utc_stamp()

    for key in _alert_keys(data):
        _mutate_alert(key, ack)


@socketio.on("investigate_alert")
def on_investigate_alert(data=None):
    if not _socket_authorized(data):
        return _deny_socket()
    if not isinstance(data, dict):
        return
    keys = _alert_keys(data)
    if not keys:
        return
    note = str(data.get("note") or "")[:2000]
    false_positive = bool(data.get("false_positive"))
    investigator = data.get("investigator")
    investigator = str(investigator)[:100] if investigator else None

    def investigate(a):
        a["acknowledged"] = True
        a["investigated"] = True
        a.setdefault("investigator_notes", []).append({
            "note": note or ("False positive" if false_positive else "Investigated"),
            "timestamp": _utc_stamp(),
            "false_positive": false_positive,
            "investigator": investigator,
        })
        if investigator:
            a["investigator"] = investigator

    _mutate_alert(keys[0], investigate)


@socketio.on("request_initial_data")
def on_request_initial_data(data=None):
    page = data.get("page") if isinstance(data, dict) else None
    if page == "flows":
        emit("flow_update", {"flows": flow_book.recent(500)})
    emit("alert_update", {"alerts": alert_book.list_newest_first(100)})
    emit("system_health", get_system_health())
    emit("stats_update", get_stats_payload())


@socketio.on("request_health")
def on_request_health():
    emit("system_health", get_system_health())


# --------------------------------------------------------------------------
# Background services
# --------------------------------------------------------------------------

_services_lock = threading.Lock()
_services_started = False


def start_background_services() -> None:
    """Idempotent. Called from __main__ and, for WSGI-style launches, on the
    first client connection."""
    global _services_started
    with _services_lock:
        if _services_started:
            return
        _services_started = True
    for store in (alert_store, flow_store):
        if store is not None:
            try:
                store.init()
            except Exception:
                logger.exception("Could not initialise %s", store.path)
    if alert_store is not None:
        try:
            alert_book.preload(alert_store.history(limit=ALERT_HISTORY_LIMIT))
        except Exception:
            logger.exception("Could not preload alert history")
    ioc_list.load(force=True)
    for target in (_emitter_loop, _alert_worker_loop, _health_loop, _persist_loop, _ioc_watcher_loop):
        socketio.start_background_task(target)
    logger.info("Background services started")


def _drain(q: "queue.Queue", limit: int) -> list:
    items = []
    for _ in range(limit):
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


def _emitter_loop() -> None:
    """Every 250 ms: push live flow deltas; every second: chart/stat counters."""
    last_stats = 0.0
    while True:
        try:
            batch = _drain(flow_event_queue, 1000)
            if batch:
                latest = OrderedDict((f["flow_id"], f) for f in batch)    # newest state per flow
                socketio.emit("flow_batch", {"flows": list(latest.values())[-300:]})
            now = time.time()
            if now - last_stats >= 1.0:
                last_stats = now
                socketio.emit("stats_update", get_stats_payload())
        except Exception:
            logger.exception("Emitter loop error")
        time.sleep(0.25)


def _alert_worker_loop() -> None:
    """Enrich (reverse DNS can be slow) and publish analyzer alert events."""
    while True:
        try:
            events = _drain(alert_event_queue, 100)
            if not events:
                time.sleep(0.1)
                continue
            for kind, alert in events:
                try:
                    _handle_alert_event(kind, alert)
                except Exception:
                    logger.exception("Alert handling failed")
        except Exception:
            logger.exception("Alert worker error")
            time.sleep(0.5)


def _handle_alert_event(kind: str, alert: Dict[str, Any]) -> None:
    if kind == "new":
        alert["capture_source"] = rt.source_label
        enricher.enrich(alert)
        alert_book.add(alert)
        _publish_alert(copy.deepcopy(alert))
        return
    updated = alert_book.merge_analyzer_update(alert)
    if updated is None:
        return
    iocs = enricher.ioc.match(updated.get("src_ip"), [updated.get("src_rdns")]) + \
        enricher.ioc.match(updated.get("dst_ip"), [updated.get("dst_rdns")] + list(updated.get("names") or []))
    iocs = list(dict.fromkeys(iocs))
    if iocs != updated.get("ioc_matches"):
        updated = alert_book.mutate(updated["id"], lambda a: a.__setitem__("ioc_matches", iocs)) or updated
    _publish_alert(updated)


def _health_loop() -> None:
    while True:
        try:
            socketio.emit("system_health", get_system_health())
        except Exception:
            logger.exception("Health emit error")
        time.sleep(3.0)


def _persist_loop() -> None:
    last_prune = time.time()
    while True:
        try:
            alerts_batch = _drain(alert_persist_queue, 500)
            flows_batch = _drain(flow_log_queue, 2000)
            if alert_store is not None and alerts_batch:
                latest = OrderedDict((a["id"], a) for a in alerts_batch if a.get("id"))   # coalesce
                alert_store.save_many(latest.values())
            if flow_store is not None and flows_batch:
                flow_store.add_many(flows_batch)
            if time.time() - last_prune > 3600:
                last_prune = time.time()
                if alert_store is not None:
                    alert_store.prune()
                if flow_store is not None:
                    flow_store.prune()
        except Exception:
            logger.exception("Persistence error")
        time.sleep(1.0)


def _ioc_watcher_loop() -> None:
    while True:
        try:
            ioc_list.load()
        except Exception:
            logger.debug("IOC reload failed", exc_info=True)
        time.sleep(5.0)


# --------------------------------------------------------------------------
# HTTP API
# --------------------------------------------------------------------------

_iface_cache: Dict[str, Any] = {"at": 0.0, "value": []}


def _tshark_interfaces() -> List[str]:
    """Interface names exactly as tshark/dumpcap know them (cached 60 s)."""
    if time.time() - _iface_cache["at"] < 60:
        return _iface_cache["value"]
    names: List[str] = []
    tool = shutil.which("tshark") or shutil.which("dumpcap")
    if tool:
        try:
            out = subprocess.run([tool, "-D"], capture_output=True, text=True, timeout=8).stdout
            for line in out.splitlines():
                m = re.match(r"^\d+\.\s+(\S+)(?:\s+\((.+)\))?\s*$", line.strip())
                if m:
                    names.append(m.group(2) or m.group(1))
        except Exception:
            logger.debug("tshark -D failed", exc_info=True)
    _iface_cache.update(at=time.time(), value=names)
    return names


@app.route("/api/interfaces")
def api_interfaces():
    out: List[str] = []
    try:
        out = list(psutil.net_if_addrs().keys())
    except Exception:
        iface = settings.get("interface")
        out = [iface] if iface else []
    return jsonify({"interfaces": out, "capture_interfaces": _tshark_interfaces(),
                    "current": settings.get("interface")})


@app.route("/api/pcaps")
def api_pcaps():
    files = []
    if REPLAY_DIR and REPLAY_DIR.is_dir():
        for p in sorted(REPLAY_DIR.iterdir()):
            if p.is_file() and p.name.lower().endswith(PCAP_SUFFIXES):
                files.append({"name": p.name, "size": p.stat().st_size})
    return jsonify({"pcaps": files})


@app.route("/api/status")
def api_status():
    return jsonify(get_system_health())


@app.route("/api/flows")
def api_flows():
    limit = _int_arg("limit", 500, 1, 20000)
    outcome = request.args.get("outcome")
    if request.args.get("source") == "db":
        if flow_store is None:
            return jsonify({"error": "flow database not configured"}), 404
        return jsonify(flow_store.recent(limit, outcome))
    rows = flow_book.recent(limit)
    if outcome:
        rows = [r for r in rows if r.get("outcome") == outcome]
    return jsonify(rows)


@app.route("/api/alerts")
def api_alerts():
    return _alerts_history_response()


@app.route("/alerts/history")
def alerts_history():
    return _alerts_history_response()


def _alerts_history_response():
    if alert_store is None:
        return jsonify({"error": "alerts DB not configured"}), 404
    ack = request.args.get("acknowledged")
    try:
        rows = alert_store.history(
            limit=_int_arg("limit", 500, 1, 5000), offset=_int_arg("offset", 0, 0, 10 ** 9),
            outcome=request.args.get("outcome"), severity=request.args.get("severity"),
            acknowledged=None if ack is None else ack.lower() in ("1", "true", "yes"))
        return jsonify(rows)
    except Exception:
        logger.exception("Failed reading alert history")
        return jsonify({"error": "read failed"}), 500


def _int_arg(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


@app.route("/settings/update", methods=["POST"])
@require_token
def settings_update():
    if not request.is_json:
        return jsonify({"error": "expected application/json"}), 400
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "invalid payload"}), 400
    try:
        result = settings.apply_update(body)
    except Exception:
        logger.exception("Failed updating settings")
        return jsonify({"error": "update failed"}), 500
    if not result["ok"]:
        return jsonify({"error": "validation failed", "errors": result["errors"], "ok": False}), 400
    analyzer = rt.analyzer
    if analyzer is not None:
        analyzer.configure(settings.analyzer_config())
    enricher.reverse_dns = str(settings.get("reverse_dns", "private"))
    ioc_list.load(force=True)
    return jsonify({"ok": True, "changed": result["changed"],
                    "restart_required": result["restart_required"] and rt.running})


# -- CSV exports --------------------------------------------------------------

def _csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection from attacker-controlled text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _csv_response(rows: List[Dict[str, Any]], columns: List[str], filename: str) -> Response:
    sio = io.StringIO()
    writer = csv.DictWriter(sio, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({k: _csv_cell(_flat(r.get(k, ""))) for k in columns})
    return Response(sio.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'})


def _flat(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    if isinstance(value, dict):
        return ";".join(f"{k}={v}" for k, v in value.items())
    return value


@app.route("/export/flows.csv")
def export_flows_csv():
    try:
        limit = _int_arg("limit", 500, 1, 20000)
        if request.args.get("source") == "db" and flow_store is not None:
            rows = flow_store.recent(limit)
        else:
            rows = flow_book.recent(limit)
        columns = ["flow_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                   "protocol_type", "outcome", "confidence", "src_bytes", "dst_bytes", "duration",
                   "service", "flag", "packets", "names", "first_seen", "last_seen"]
        return _csv_response(rows, columns, "flows.csv")
    except Exception:
        logger.exception("Failed to export flows")
        return Response("", status=500)


@app.route("/export/alerts.csv")
def export_alerts_csv():
    if alert_store is None:
        return jsonify({"error": "alerts DB not configured"}), 404
    try:
        rows = alert_store.history(limit=_int_arg("limit", 1000, 1, 5000))
        columns = ["id", "timestamp", "last_seen", "outcome", "severity", "confidence", "src_ip",
                   "dst_ip", "dst_port", "protocol_type", "service", "count", "flows", "sources",
                   "acknowledged", "investigated", "ioc_matches", "message"]
        return _csv_response(rows, columns, "alerts.csv")
    except Exception:
        logger.exception("Failed to export alerts")
        return Response("", status=500)


# -- Evidence PCAP export ----------------------------------------------------------

_export_lock = threading.Lock()


def _find_alert_or_flow(key: str) -> Optional[Dict[str, Any]]:
    obj = alert_book.get(key)
    if obj is None and alert_store is not None:
        obj = alert_store.find(key)
    return obj or flow_book.find(key)


def _filters_for(obj: Dict[str, Any]) -> Tuple[str, str]:
    """(BPF capture filter, tshark display filter) built only from validated
    IP addresses and integers -- never from raw request text. The scope follows
    how the alert was aggregated: a sweep covers every port/host the attacker
    touched, a flood covers everything aimed at the victim."""
    outcome = obj.get("outcome")
    grouping = ALERT_GROUPING.get(outcome, "pair")
    fields = {"src": ("src_ip",), "dst": ("dst_ip",)}.get(grouping, ("src_ip", "dst_ip"))
    bpf_parts, disp_parts = [], []
    for field in fields:
        try:
            ip = str(ipaddress.ip_address(obj.get(field)))
        except (ValueError, TypeError):
            continue
        bpf_parts.append(f"host {ip}")
        disp_parts.append(f"ip.addr == {ip}" if ":" not in ip else f"ipv6.addr == {ip}")
    proto = str(obj.get("protocol_type") or "").lower()
    port = obj.get("dst_port")
    wide_scope = outcome in ("portsweep", "ipsweep", "satan", "mscan")
    if not wide_scope and proto in ("tcp", "udp") and isinstance(port, int) and 0 < port < 65536:
        bpf_parts.append(f"{proto} port {port}")
        disp_parts.append(f"{proto}.port == {port}")
    elif not wide_scope and proto == "icmp":
        bpf_parts.append("icmp")
        disp_parts.append("icmp")
    return " and ".join(bpf_parts), " && ".join(disp_parts)


def _cleanup_exports(max_age: float = 86400.0) -> None:
    if EXPORT_DIR.is_dir():
        for p in EXPORT_DIR.glob("*.pcap"):
            try:
                if time.time() - p.stat().st_mtime > max_age:
                    p.unlink()
            except OSError:
                pass


@app.route("/export/alert_pcap")
@require_token
def export_alert_pcap():
    """Evidence PCAP for an alert.

    * Alerts raised from a replayed PCAP: matching packets are filtered out of
      that file (exact evidence).
    * Alerts from live capture: packets are not retained, so this records the
      next N packets of the same host pair ("forward capture"). The response
      header X-Export-Mode says which one you got.
    """
    key = request.args.get("flow_id") or request.args.get("id")
    if not key:
        return jsonify({"error": "flow_id required"}), 400
    obj = _find_alert_or_flow(key)
    if obj is None:
        return jsonify({"error": "flow not found"}), 404
    bpf, display = _filters_for(obj)
    if not bpf:
        return jsonify({"error": "alert has no usable addresses"}), 422
    if not _export_lock.acquire(blocking=False):
        return jsonify({"error": "another export is running"}), 429
    try:
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        _cleanup_exports()
        safe = re.sub(r"[^0-9a-zA-Z]", "", str(obj.get("id") or key))[:40] or secrets.token_hex(8)
        out_path = EXPORT_DIR / f"alert-{safe}.pcap"
        source = str(obj.get("capture_source") or "")
        if source.startswith("replay:"):
            return _export_from_replay(source[7:], display, out_path)
        return _export_forward_capture(bpf, out_path)
    except Exception:
        logger.exception("Failed creating pcap for flow")
        return jsonify({"error": "export failed"}), 500
    finally:
        _export_lock.release()


def _export_from_replay(name: str, display_filter: str, out_path: Path):
    src = _resolve_replay(name)
    tool = shutil.which("tshark")
    if src is None or tool is None:
        return jsonify({"error": "source capture or tshark not available"}), 500
    subprocess.run([tool, "-r", str(src), "-Y", display_filter, "-F", "pcap", "-w", str(out_path)],
                   check=False, timeout=60, capture_output=True)
    return _send_pcap(out_path, "replay-filter")


def _export_forward_capture(bpf: str, out_path: Path):
    count = _int_arg("count", int(settings.get("capture_packet_limit", 200)), 1, 5000)
    timeout = _int_arg("timeout", int(settings.get("capture_timeout_seconds", 10)), 1, 60)
    iface = settings.get("interface")
    if not iface or not IFACE_RE.match(str(iface)) or str(iface).startswith("-"):
        return jsonify({"error": "no valid capture interface configured"}), 500
    tool = shutil.which("dumpcap") or shutil.which("tshark")
    if not tool:
        return jsonify({"error": "tshark/dumpcap not found on host"}), 500
    cmd = [tool, "-i", str(iface), "-F", "pcap", "-w", str(out_path), "-f", bpf, "-c", str(count),
           "-a", f"duration:{timeout}"]
    logger.info("Running evidence capture: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=False, timeout=timeout + 5, capture_output=True)
    except subprocess.TimeoutExpired:
        logger.warning("PCAP capture timed out")
    return _send_pcap(out_path, "forward-capture")


def _send_pcap(path: Path, mode: str):
    if not path.exists() or path.stat().st_size == 0:
        return jsonify({"error": "no packets captured"}), 404
    resp = send_file(str(path), as_attachment=True, download_name=path.name,
                     mimetype="application/vnd.tcpdump.pcap")
    resp.headers["X-Export-Mode"] = mode
    return resp


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def _shutdown() -> None:
    try:
        stop_capture()
    except Exception:
        pass


def main() -> None:
    if not _is_loopback(HOST) and not API_TOKEN and os.getenv("IDS_ALLOW_INSECURE") != "1":
        logger.critical(
            "Refusing to bind %s without authentication: this dashboard can change IDS "
            "settings and start captures. Set IDS_API_TOKEN, bind to 127.0.0.1, or set "
            "IDS_ALLOW_INSECURE=1 to override.", HOST)
        sys.exit(2)
    import atexit
    atexit.register(_shutdown)
    start_background_services()
    logger.info("Starting IDS dashboard on http://%s:%s (auth %s)", HOST, PORT,
                "token required for control" if API_TOKEN else "off")
    socketio.run(app, host=HOST, port=PORT, debug=False, use_reloader=False,
                 allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
