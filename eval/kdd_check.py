#!/usr/bin/env python3
"""Score the NSL-KDD signatures in config.json against the labelled NSL-KDD data.

    python eval/kdd_check.py --config config.json --data /path/to/dir   # dir holds KDDTrain+.txt and KDDTest+.txt

For every signature: how many records of its attack class it catches (recall), how many of the
records it fires on really are that class (precision), and how often it fires on NORMAL records.
It uses the same compiled signatures and scoring rules as the live engine (ids.engine), so what it
reports is what `classify_detail` would do on this data.

Caveat: NSL-KDD is 1998-era simulated traffic. This validates the signatures as KDD classifiers; it
says nothing about live networks.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ids.engine import compile_signatures  # noqa: E402

COLS = ("duration protocol_type service flag src_bytes dst_bytes land wrong_fragment urgent hot num_failed_logins "
        "logged_in num_compromised root_shell su_attempted num_root num_file_creations num_shells num_access_files "
        "num_outbound_cmds is_host_login is_guest_login count srv_count serror_rate srv_serror_rate rerror_rate "
        "srv_rerror_rate same_srv_rate diff_srv_rate srv_diff_host_rate dst_host_count dst_host_srv_count "
        "dst_host_same_srv_rate dst_host_diff_srv_rate dst_host_same_src_port_rate dst_host_srv_diff_host_rate "
        "dst_host_serror_rate dst_host_srv_serror_rate dst_host_rerror_rate dst_host_srv_rerror_rate label difficulty").split()


def load(path):
    df = pd.read_csv(path, header=None, names=COLS)
    df["protocol_type"] = df["protocol_type"].str.upper()
    df["flag"] = df["flag"].str.upper()
    df["service"] = df["service"].str.lower()
    return df


def signature_scores(df, sig):
    """Vectorised twin of ids.engine._evaluate: (gate_passed, score)."""
    gate = np.ones(len(df), dtype=bool)
    if sig.protocols:
        gate &= df["protocol_type"].isin(sig.protocols).values
    if sig.services:
        gate &= df["service"].isin(sig.services).values
    if sig.flags:
        gate &= df["flag"].isin(sig.flags).values
    for f in sig.zero_fields:
        gate &= (df[f].values == 0)
    if not sig.ranges:
        return gate, np.ones(len(df))
    hits = np.zeros(len(df))
    for f, lo, hi in sig.ranges:
        v = df[f].values
        hits += ((v >= lo) & (v <= hi))
    return gate, hits / len(sig.ranges)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "config.json"))
    ap.add_argument("--data", required=True)
    ap.add_argument("--threshold", type=float, default=None, help="override match_threshold")
    args = ap.parse_args()
    cfg = json.loads(Path(args.config).read_text())
    thr = args.threshold or (cfg.get("detection") or {}).get("match_threshold", 0.95)
    sigs = compile_signatures(cfg["thresholds"])
    for split in ("KDDTrain+.txt", "KDDTest+.txt"):
        df = load(Path(args.data) / split)
        normal = (df["label"] == "normal").values
        print(f"\n{split}: {len(df)} records, {normal.sum()} normal; match_threshold = {thr}")
        print(f"{'signature':13s} {'class n':>8s} {'recall':>7s} {'precision':>9s} {'fires on normal':>16s} {'fires total':>11s} {'informative ranges':>19s}")
        for sig in sigs:
            gate, score = signature_scores(df, sig)
            fire = gate & (score >= thr)
            is_cls = (df["label"] == sig.name).values
            n = int(is_cls.sum())
            tp = int((fire & is_cls).sum())
            rec = tp / n if n else float("nan")
            prec = tp / fire.sum() if fire.sum() else float("nan")
            fn_normal = int((fire & normal).sum())
            print(f"{sig.name:13s} {n:8d} {rec:7.1%} {prec:9.1%} {fn_normal:9d} ({fn_normal / normal.sum():.2%}) {int(fire.sum()):11d} {len(sig.ranges):19d}")


if __name__ == "__main__":
    main()
