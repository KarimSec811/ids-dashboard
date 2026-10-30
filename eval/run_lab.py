#!/usr/bin/env python3
"""Run the attack/benign scenarios from the attacker machine and record ground truth.

    sudo python3 eval/run_lab.py --victim 192.168.56.101 --iface eth0 \\
         --sweep-start 192.168.56.100 --sweep-end 192.168.56.199

For every scenario it captures a PCAP (tcpdump on the attacker side), runs the command, and
appends one line to <out>/ground_truth.jsonl (start/end time, command, expected detectors).
A 1 packet/s ping to the victim runs throughout: it stands in for the background traffic a real
network always has, which is what moves the sensor's packet-driven clock forward.
Only run this against machines you own. The default flood rate (1,000 pps, 8,000 packets) is gentle.
"""
import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from scenarios import SCENARIOS  # noqa: E402

DEAD_MAC = "02:de:ad:00:00:99"


def run(cmd, **kw):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


def run_group(cmd, timeout):
    """Run a shell command; on timeout kill the whole process group (a shell wrapper would
    otherwise leave the real tool running and the pipes open)."""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        return out, p.returncode
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return (out or "") + "\nTIMEOUT", -1


def tool_version(tool):
    if not shutil.which(tool):
        return None
    for flag in ("--version", "-V", "-v"):
        out = run([tool, flag], timeout=10)
        text = (out.stdout + out.stderr).strip().splitlines()
        if text and out.returncode in (0, 1):
            return text[0][:120]
    return "unknown"


def neighbor_mac(victim):
    run(["ping", "-c", "1", "-W", "1", victim])
    m = re.search(r"lladdr (\S+)", run(["ip", "neigh", "show", victim]).stdout)
    return m.group(1) if m else ""


def set_dead_neighbors(a, b, iface, add=True):
    lo, hi = int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b))
    for n in range(lo, hi + 1):
        ip = str(ipaddress.ip_address(n))
        if add:
            run(["ip", "neigh", "replace", ip, "lladdr", DEAD_MAC, "dev", iface, "nud", "permanent"])
        else:
            run(["ip", "neigh", "del", ip, "dev", iface])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--victim", required=True)
    ap.add_argument("--iface", required=True, help="attacker-side lab interface")
    ap.add_argument("--sweep-start", default=None, help="first address of a range with NO live hosts")
    ap.add_argument("--sweep-end", default=None)
    ap.add_argument("--out", default="lab_results")
    ap.add_argument("--only", default="", help="comma separated scenario names")
    ap.add_argument("--skip-slow", action="store_true")
    ap.add_argument("--tail", type=float, default=6.0, help="seconds to keep capturing after the attack")
    ap.add_argument("--router-mac", default="")
    ap.add_argument("--soak-minutes", type=float, default=0,
                    help="instead of scenarios: capture benign background traffic for N minutes -> soak.pcap")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if args.soak_minutes:
        pcap = out / "soak.pcap"
        print(f"capturing {args.soak_minutes} min of benign traffic on {args.iface} -> {pcap} (Ctrl+C to stop early)")
        proc = subprocess.Popen(["tcpdump", "-i", args.iface, "-n", "-U", "-w", str(pcap), "ip"],
                                stderr=subprocess.DEVNULL)
        try:
            time.sleep(args.soak_minutes * 60)
        except KeyboardInterrupt:
            pass
        proc.send_signal(signal.SIGINT)
        proc.wait()
        return

    mac = args.router_mac or neighbor_mac(args.victim)
    attacker_ip = re.search(r"inet (\S+?)/", run(["ip", "-4", "addr", "show", args.iface]).stdout)
    attacker_ip = attacker_ip.group(1) if attacker_ip else ""
    sweep = bool(args.sweep_start and args.sweep_end)
    base = ".".join(args.sweep_start.split(".")[:3]) if sweep else ""
    fill = dict(victim=args.victim, iface=args.iface, mac=mac, helpers=str(HERE / "helpers"),
                sweep_a=args.sweep_start or "", sweep_b=args.sweep_end or "",
                sweep_range=f"{base}.{args.sweep_start.split('.')[-1]}-{args.sweep_end.split('.')[-1]}" if sweep else "")

    (out / "lab_info.json").write_text(json.dumps({
        "date": datetime.now().isoformat(timespec="seconds"), "kernel": platform.platform(),
        "victim": args.victim, "attacker": attacker_ip, "iface": args.iface,
        "tools": {t: tool_version(t) for t in ("nmap", "masscan", "hping3", "fping", "tcpdump")},
    }, indent=2))
    truth = out / "ground_truth.jsonl"
    only = {s for s in args.only.split(",") if s}

    if sweep:
        set_dead_neighbors(args.sweep_start, args.sweep_end, args.iface)
    try:
        for sc in SCENARIOS:
            name = sc["name"]
            if only and name not in only:
                continue
            if args.skip_slow and sc.get("slow"):
                print(f"- {name}: skipped (slow)")
                continue
            if sc.get("sweep") and not sweep:
                print(f"- {name}: skipped (needs --sweep-start/--sweep-end)")
                continue
            if not shutil.which(sc["tool"]):
                print(f"- {name}: skipped ({sc['tool']} not installed)")
                continue
            cmd = sc["cmd"].format(**fill)
            pcap = out / f"{name}.pcap"
            print(f"* {name}: {cmd}")
            cap = subprocess.Popen(["tcpdump", "-i", args.iface, "-n", "-U", "-w", str(pcap), "ip"],
                                   stderr=subprocess.DEVNULL)
            beat = subprocess.Popen(["ping", "-i", "1", args.victim], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            time.sleep(1.5)
            t_start = time.time()
            log, rc = run_group(cmd, sc.get("timeout", 120))
            t_end = time.time()
            time.sleep(args.tail)
            beat.terminate()
            cap.send_signal(signal.SIGINT)
            cap.wait()
            (out / f"{name}.log").write_text(log[-4000:])
            rec = dict(name=name, kind=sc["kind"], tool=sc["tool"], cmd=cmd.replace(str(HERE), "eval"), expect=sc.get("expect", []),
                       known_limitation=sc.get("known_limitation"), t_start=t_start, t_end=t_end,
                       pcap=pcap.name, victim=args.victim, attacker=attacker_ip, returncode=rc)
            with truth.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
            print(f"    {t_end - t_start:.1f}s, {pcap.stat().st_size // 1024} KB")
    finally:
        if sweep:
            set_dead_neighbors(args.sweep_start, args.sweep_end, args.iface, add=False)
    print(f"\nDone. Copy {out}/ to the machine that has tshark and run: python eval/evaluate.py --results {out}")


if __name__ == "__main__":
    main()
