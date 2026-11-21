#!/usr/bin/env python3
"""Static checks for config.json:  python eval/lint_config.py [config.json]   (exit code 1 on errors)

Catches the mistakes that make a signature silently useless or noisy: a field the engine never produces
(it reads as 0), a zero_fields entry that contradicts a range, a service name that cannot occur, a MITRE id
that does not match its name, thresholds below what TCP itself does on a healthy network.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ids.engine import (HostConnectionTracker, FlowFeatures, ICMP_TYPE_SERVICE_MAP, PORT_SERVICE_MAP,  # noqa: E402
                        UDP_SERVICE_OVERRIDES, compile_signatures)

KNOWN_FIELDS = set(FlowFeatures("x", "1.1.1.1", "2.2.2.2", 1, 2, "TCP").snapshot(HostConnectionTracker(), 0.0))
SERVICES = set(PORT_SERVICE_MAP.values()) | set(ICMP_TYPE_SERVICE_MAP.values()) | set(UDP_SERVICE_OVERRIDES.values()) | {"other", "ftp_data"}
FLAGS = {"SF", "S0", "S1", "S2", "S3", "REJ", "RSTO", "RSTR", "RSTOS0", "SH", "OTH"}
TOP_KEYS = {"interface", "capture_bpf", "sampling_rate", "capture_packet_limit", "capture_timeout_seconds", "thresholds",
            "detection", "threat_intel", "geoip_db_path", "ioc_list_path", "alerts_db_path", "flows_db_path", "reverse_dns",
            "replay_dir", "alerts_retention_days", "flows_max_rows", "recent_flows_limit", "alert_history_limit",
            "portsweep_port_threshold", "ipsweep_host_threshold"}
DETECTION_KEYS = {"match_threshold", "half_open_grace_seconds", "half_open_min_count", "portsweep_port_threshold",
                  "ipsweep_host_threshold", "recon_window_seconds", "slow_scan_window_seconds", "slow_scan_port_threshold",
                  "slow_scan_host_threshold", "alert_cooldown_seconds", "alert_max_per_second", "flow_idle_timeout_seconds",
                  "flow_closed_linger_seconds", "half_open_timeout_seconds", "max_flows", "flow_emit_interval_seconds",
                  "alert_update_interval_seconds", "sampling_rate"}
# ATT&CK names for the technique ids this project uses (verified against attack.mitre.org)
ATTACK_NAMES = {"T1499.001": "OS Exhaustion Flood", "T1499.002": "Service Exhaustion Flood",
                "T1499.003": "Application Exhaustion Flood", "T1499.004": "Application or System Exploitation",
                "T1498.001": "Direct Network Flood", "T1498.002": "Reflection Amplification",
                "T1046": "Network Service Discovery", "T1018": "Remote System Discovery",
                "T1595.001": "Scanning IP Blocks", "T1595.002": "Vulnerability Scanning",
                "T1110.001": "Password Guessing", "T1048.003": "Non-C2 Protocol"}


def lint(cfg):
    errors, warns = [], []
    err, warn = errors.append, warns.append
    for k in cfg:
        if k not in TOP_KEYS:
            warn(f"top-level key '{k}' is not read by anything")
    det = cfg.get("detection", {})
    for k in det:
        if k not in DETECTION_KEYS:
            warn(f"detection.{k} is not read by anything")
    th = cfg.get("thresholds", {})
    for name, s in th.items():
        tag = f"thresholds.{name}"
        ranges, zero = s.get("ranges", {}) or {}, s.get("zero_fields", []) or []
        for f in list(ranges) + list(zero):
            if f not in KNOWN_FIELDS:
                err(f"{tag}: field '{f}' is never produced by the engine (it would always read 0)")
        for f in zero:
            b = ranges.get(f)
            if b and b[0] > 0:
                err(f"{tag}: '{f}' must be 0 (zero_fields) AND in {b} (ranges): the signature can never fire")
        for f, b in ranges.items():
            if len(b) != 2 or b[0] > b[1]:
                err(f"{tag}: range for '{f}' is malformed: {b}")
        for sv in s.get("services", []) or []:
            if sv not in SERVICES:
                warn(f"{tag}: service '{sv}' cannot be produced by the engine's port map")
        for fl in s.get("flags", []) or []:
            if fl.upper() not in FLAGS:
                err(f"{tag}: unknown flag '{fl}'")
        if s.get("enabled", True):
            sig = next((x for x in compile_signatures({name: s}) if x.name == name), None)
            if sig is not None and not sig.ranges and not sig.zero_fields:
                warn(f"{tag}: enabled but has no informative condition besides protocol/service/flag")
            if "_validation" not in s:
                warn(f"{tag}: enabled without recorded validation numbers")
        intel = (cfg.get("threat_intel") or {}).get(name)
        if intel is None:
            warn(f"{tag}: no threat_intel entry (alerts will lack severity / MITRE)")
        else:
            m = intel.get("mitre") or {}
            tid, tname = m.get("technique_id", ""), m.get("technique_name", "")
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid or ""):
                err(f"threat_intel.{name}: malformed MITRE id '{tid}'")
            elif tid in ATTACK_NAMES and ATTACK_NAMES[tid].lower() not in tname.lower():
                err(f"threat_intel.{name}: {tid} is '{ATTACK_NAMES[tid]}' in ATT&CK but the config calls it '{tname}'")
    # thresholds against what TCP does on a healthy network
    g = det.get("half_open_grace_seconds", 2.0)
    if g < 1.0:
        warn(f"detection.half_open_grace_seconds={g} is below the 1 s initial SYN retransmission timer (RFC 6298): "
             "a single lost SYN would count as a failed probe")
    if det.get("half_open_min_count", 10) < 5:
        warn("detection.half_open_min_count < 5: a browser opening parallel connections can reach it")
    if det.get("portsweep_port_threshold", 20) < 10 or det.get("ipsweep_host_threshold", 20) < 10:
        warn("fast sweep thresholds < 10: failed connections to a handful of services is common on a normal network")
    if det.get("slow_scan_window_seconds", 300) < det.get("recon_window_seconds", 10):
        err("detection.slow_scan_window_seconds is shorter than recon_window_seconds")
    if not 0.5 <= det.get("match_threshold", 0.95) <= 1.0:
        err("detection.match_threshold must be between 0.5 and 1.0")
    return errors, warns


def main():
    path = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "config.json")
    errors, warns = lint(json.loads(path.read_text()))
    for e in errors:
        print("ERROR  ", e)
    for w in warns:
        print("warning", w)
    print(f"\n{path.name}: {len(errors)} error(s), {len(warns)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
