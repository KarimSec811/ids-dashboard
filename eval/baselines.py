#!/usr/bin/env python3
"""Run Zeek (with the misc/scan policy) and Suricata (default rules, e.g. ET Open) over every recorded PCAP
and store what they alert on:  python3 eval/baselines.py --results lab_results_vm

Writes <results>/baselines/<scenario>.json, which eval/evaluate.py turns into extra report columns.
Either tool may be missing; it is then simply left out.
"""
import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


def zeek_notices(pcap: Path):
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["zeek", "-C", "-r", str(pcap.resolve()), "local", "misc/scan"], cwd=tmp,
                       capture_output=True, timeout=300)
        log = Path(tmp) / "notice.log"
        if not log.exists():
            return []
        fields, notes = [], []
        for line in log.read_text(errors="replace").splitlines():
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#") and "note" in fields:
                notes.append(line.split("\t")[fields.index("note")])
        return notes


def suricata_alerts(pcap: Path):
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["suricata", "-r", str(pcap.resolve()), "-l", tmp, "-k", "none"],
                       capture_output=True, timeout=600)
        eve = Path(tmp) / "eve.json"
        if not eve.exists():
            return []
        alerts = []
        for line in eve.read_text(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("event_type") == "alert":
                alerts.append(ev.get("alert", {}).get("signature", "?"))
        return alerts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    args = ap.parse_args()
    results = Path(args.results)
    out = results / "baselines"
    out.mkdir(exist_ok=True)
    have = {t: shutil.which(t) for t in ("zeek", "suricata")}
    print("found:", {k: bool(v) for k, v in have.items()})
    for line in (results / "ground_truth.jsonl").read_text().splitlines():
        rec = json.loads(line)
        pcap, entry = results / rec["pcap"], {}
        if have["zeek"]:
            entry["zeek"] = {"notices": zeek_notices(pcap)}
        if have["suricata"]:
            entry["suricata"] = {"alerts": suricata_alerts(pcap)}
        (out / f"{rec['name']}.json").write_text(json.dumps(entry, indent=2))
        print(f"{rec['name']:28s} " + "  ".join(f"{k}={len(next(iter(v.values())))}" for k, v in entry.items()))


if __name__ == "__main__":
    main()
