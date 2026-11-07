"""Configuration loading, validation and atomic persistence.

The runtime-editable settings are an *allow-list with types and ranges*. This
matters for a security tool: an unvalidated settings endpoint is an IDS-evasion
primitive (set a BPF filter that hides the attacker, or sample 1-in-100000).
"""
from __future__ import annotations

import copy
import json
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REQUIRED_KEYS = ("interface", "thresholds")

DETECTION_DEFAULTS: Dict[str, Any] = {
    # TCP half-open: RFC 6298 starts the retransmission timer at 1 s, so 2 s means "unanswered even after
    # a retransmit", not "one lost SYN". Sources for every number: docs/TUNING.md.
    "half_open_grace_seconds": 2.0,
    "half_open_min_count": 10,            # half-open connections to ONE port, dominating the last 2 s
    "match_threshold": 0.95,
    # failed-probe sweeps (only refused/unanswered attempts count)
    "portsweep_port_threshold": 20,       # fast scanners: distinct ports on one host ...
    "ipsweep_host_threshold": 20,         # ... or hosts on one port ...
    "recon_window_seconds": 10.0,         # ... inside this window
    "slow_scan_window_seconds": 300.0,    # slow scanners: Zeek's scan.zeek defaults
    "slow_scan_port_threshold": 15,
    "slow_scan_host_threshold": 25,
    "alert_cooldown_seconds": 30.0,
    "alert_max_per_second": 20,
    "flow_idle_timeout_seconds": 120.0,
    "max_flows": 50000,
}

# key -> (type, minimum, maximum)
TOP_LEVEL_SCHEMA = {
    "sampling_rate": (int, 1, 1000),
    "capture_packet_limit": (int, 1, 5000),
    "capture_timeout_seconds": (int, 1, 120),
}
DETECTION_SCHEMA = {
    "match_threshold": (float, 0.5, 1.0),
    "half_open_grace_seconds": (float, 0.0, 60.0),
    "half_open_min_count": (int, 1, 100000),
    "alert_cooldown_seconds": (float, 0.0, 3600.0),
    "portsweep_port_threshold": (int, 2, 5000),
    "ipsweep_host_threshold": (int, 2, 5000),
    "recon_window_seconds": (float, 1.0, 600.0),
    "slow_scan_window_seconds": (float, 10.0, 3600.0),
    "slow_scan_port_threshold": (int, 2, 5000),
    "slow_scan_host_threshold": (int, 2, 5000),
}
REVERSE_DNS_MODES = ("off", "private", "all")

BPF_RE = re.compile(r"^[A-Za-z0-9_ .:/\-()\[\]&|!<>=+*%]{0,512}$")
IFACE_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
MAX_IOC_BYTES = 1_000_000
MAX_IOC_LINES = 20000


class ConfigError(RuntimeError):
    pass


def _coerce(name: str, value: Any, spec: Tuple[type, float, float]):
    typ, lo, hi = spec
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{name}: expected a number")
    try:
        num = typ(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name}: expected {typ.__name__}") from None
    if not (lo <= num <= hi):
        raise ValueError(f"{name}: must be between {lo} and {hi}")
    return num


class Settings:
    """Thread-safe wrapper around config.json."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.base_dir = self.path.parent
        self._lock = threading.RLock()
        self.data: Dict[str, Any] = self._load()

    # -- loading ----------------------------------------------------------
    def _load(self) -> Dict[str, Any]:
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except FileNotFoundError:
            raise ConfigError(f"Configuration file not found: {self.path}") from None
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Invalid JSON in {self.path}: {exc}") from None
        if not isinstance(cfg, dict):
            raise ConfigError("config.json must contain a JSON object")
        missing = [k for k in REQUIRED_KEYS if k not in cfg]
        if missing:
            raise ConfigError(f"config.json is missing required keys: {', '.join(missing)}")
        if not isinstance(cfg.get("thresholds"), dict):
            raise ConfigError("'thresholds' must be an object")
        if not isinstance(cfg.get("detection", {}), dict):
            raise ConfigError("'detection' must be an object")
        return cfg

    def resolve(self, key: str, default: Optional[str] = None) -> Optional[Path]:
        """Path-valued setting, relative paths resolved against the project dir.
        A key that is *present but null* disables the feature."""
        with self._lock:
            value = self.data[key] if key in self.data else default
        if not value:
            return None
        p = Path(str(value))
        return p if p.is_absolute() else self.base_dir / p

    # -- read access ------------------------------------------------------
    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self.data.get(key, default)

    def effective(self) -> Dict[str, Any]:
        """Deep copy with detection defaults filled in (for the settings page)."""
        with self._lock:
            cfg = copy.deepcopy(self.data)
        det = dict(DETECTION_DEFAULTS)
        for key in ("portsweep_port_threshold", "ipsweep_host_threshold"):
            if key in cfg:
                det[key] = cfg[key]
        det.update(cfg.get("detection") or {})
        cfg["detection"] = det
        cfg.setdefault("reverse_dns", "private")
        return cfg

    def analyzer_config(self) -> Dict[str, Any]:
        """What the PacketAnalyzer consumes (a snapshot, never mutated)."""
        return self.effective()

    # -- update -----------------------------------------------------------
    def validate_update(self, body: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any], Optional[str], List[str]]:
        top: Dict[str, Any] = {}
        det: Dict[str, Any] = {}
        errors: List[str] = []
        ioc_text: Optional[str] = None

        if "interface" in body:
            iface = body["interface"]
            if not isinstance(iface, str) or not IFACE_RE.match(iface) or iface.startswith("-"):
                errors.append("interface: invalid interface name")
            else:
                top["interface"] = iface
        if "capture_bpf" in body:
            bpf = body["capture_bpf"]
            if bpf in (None, ""):
                top["capture_bpf"] = None
            elif not isinstance(bpf, str) or not BPF_RE.match(bpf):
                errors.append("capture_bpf: contains characters that are not valid in a BPF filter")
            else:
                top["capture_bpf"] = bpf.strip()
        if "reverse_dns" in body:
            if body["reverse_dns"] not in REVERSE_DNS_MODES:
                errors.append(f"reverse_dns: must be one of {', '.join(REVERSE_DNS_MODES)}")
            else:
                top["reverse_dns"] = body["reverse_dns"]
        for key, spec in TOP_LEVEL_SCHEMA.items():
            if key in body:
                try:
                    top[key] = _coerce(key, body[key], spec)
                except ValueError as exc:
                    errors.append(str(exc))
        for key, spec in DETECTION_SCHEMA.items():
            if key in body:
                try:
                    det[key] = _coerce(key, body[key], spec)
                except ValueError as exc:
                    errors.append(str(exc))
        if "ioc_list" in body:
            text = body["ioc_list"]
            if not isinstance(text, str):
                errors.append("ioc_list: expected text")
            elif len(text.encode("utf-8")) > MAX_IOC_BYTES or text.count("\n") > MAX_IOC_LINES:
                errors.append("ioc_list: too large")
            else:
                ioc_text = "\n".join(line.strip() for line in text.splitlines() if line.strip())
        return top, det, ioc_text, errors

    def apply_update(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate + persist. Returns {'ok', 'changed', 'errors', 'restart_required'}."""
        top, det, ioc_text, errors = self.validate_update(body)
        if errors:
            return {"ok": False, "errors": errors, "changed": [], "restart_required": False}
        changed: List[str] = []
        with self._lock:
            cfg = copy.deepcopy(self.data)
            for key, value in top.items():
                if cfg.get(key) != value:
                    cfg[key] = value
                    changed.append(key)
            if det:
                section = dict(cfg.get("detection") or {})
                for key, value in det.items():
                    if section.get(key) != value:
                        section[key] = value
                        changed.append(f"detection.{key}")
                cfg["detection"] = section
            if changed:
                tmp = self.path.with_suffix(".tmp")
                with tmp.open("w", encoding="utf-8") as fh:
                    json.dump(cfg, fh, indent=2)
                os.replace(tmp, self.path)
                self.data.clear()
                self.data.update(cfg)       # in place: existing references stay valid
        if ioc_text is not None:
            path = self.resolve("ioc_list_path") or (self.base_dir / "data" / "ioc.txt")   # null means "default"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(ioc_text, encoding="utf-8")
            changed.append("ioc_list")
        needs_restart = any(k in ("interface", "capture_bpf") for k in changed)
        return {"ok": True, "errors": [], "changed": changed, "restart_required": needs_restart}
