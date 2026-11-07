#!/usr/bin/env python3
"""Re-derive the NSL-KDD signatures from the labelled data (reproducible, with a train/test split).

    python eval/kdd_fit.py --data /path/to/dir --base eval/config.original.json --out config.json

For each attack class a small *rule* is learned, in the format the engine already reads:
  1. categorical gates (protocol / service / flag) that cover >= 99% of the class;
  2. zero_fields: fields that are zero for >= 99.5% of the class AND remove a meaningful share of the
     still-matching non-class records;
  3. ranges: p0.5-p99.5 of the class, added greedily while each one removes >= 1% of the remaining
     false matches (max 8; every informative range must hold, so the rule is an AND).

Honesty rules baked in:
  * Only live-compatible fields are used. The dst_host_* family is excluded: its window (last 100
    connections) is defined differently from KDD's (last 100 to a host, capped at 255).
  * Classes with fewer than 200 training records (guess_passwd, mscan, processtable) are fitted on a
    random half of KDDTest+ and scored on the other half. All other classes are fitted on KDDTrain+ and
    scored on the whole of KDDTest+. Train/test shift in NSL-KDD is real; that is the point of the split.
  * Quality of each rule is written into the config next to it (_validation), so nobody has to take
    the thresholds on trust.
  * A signature ships enabled only if it validates on held-out data AND has a live trigger tested in the lab.
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))
from kdd_check import load, signature_scores  # noqa: E402
from ids.engine import DEFAULT_MITRE, compile_signatures  # noqa: E402
from ids.settings import DETECTION_DEFAULTS  # noqa: E402

FIELDS = ("duration src_bytes dst_bytes land wrong_fragment urgent hot num_failed_logins logged_in num_compromised "
          "root_shell su_attempted num_root num_file_creations num_shells num_access_files is_guest_login count "
          "srv_count serror_rate srv_serror_rate rerror_rate srv_rerror_rate same_srv_rate diff_srv_rate "
          "srv_diff_host_rate").split()
CLASSES = ["neptune", "portsweep", "satan", "ipsweep", "smurf", "back", "teardrop", "warezclient", "pod",
           "guess_passwd", "mscan", "processtable"]
SMALL = 200
MAX_RANGES = 8

# Dataset accuracy is necessary but not sufficient: a rule must also mean something on a live network.
# These guards encode that, by hand, and are applied after the fit (and re-scored, so the numbers stay honest).
LIVE_GUARDS = {
    "smurf": {"count": [10, 100000], "srv_count": [10, 100000]},   # an amplification attack is MANY replies, not one big ping
}
# Rules whose meaning the dataset cannot express. NSL-KDD never records 3+ failed logins on a guess_passwd
# connection, so a "3 failed logins" rule scores 0% on it: that number is reported, not hidden, and the rule
# is validated in the lab instead (eval scenarios ftp_guessing and benign_single_failed_login).
HANDWRITTEN = {
    "guess_passwd": {
        "protocol_types": ["tcp"],
        "services": ["ftp", "telnet", "pop_3", "pop_2", "imap4", "login", "shell"],   # cleartext logins the sensor can read
        "zero_fields": [],
        "ranges": {"num_failed_logins": [3, 100000]},          # one typo is not an attack; 3 is the usual lockout floor
        "_note": "hand-written: >= 3 server-confirmed failed logins on one connection of a cleartext login service",
    },
}
# Enabled only if it validates on held-out data AND has a live trigger that was tested in the lab.
LIVE_ENABLED = {"neptune", "smurf", "guess_passwd"}
MIN_PRECISION, MAX_NORMAL_FP = 0.90, 0.001
WHY_DISABLED = {
    "portsweep": "needs evidence across many connections; the failed-probe detectors do this properly",
    "ipsweep": "needs evidence across many connections; the failed-probe detectors do this properly",
    "satan": "needs evidence across many connections; the failed-probe detectors do this properly",
    "pod": "oversize/fragment heuristics cannot separate it from normal traffic; real detection needs IP reassembly",
    "teardrop": "overlapping-fragment attack; needs IP reassembly, which the sensor does not do",
    "warezclient": "absent from the held-out data, so it cannot be validated",
    "back": "reduces to 'an HTTP request of 17-55 KB', which a legitimate upload also is",
    "mscan": "occurs only in KDDTest+ and has no live equivalent that could be tested",
    "processtable": "occurs only in KDDTest+ and has no live equivalent that could be tested",
}
DEAD_KEYS = ("max_packets", "max_duration", "alerts_persist_path", "alerts_rotate_mb",
             "portsweep_port_threshold", "ipsweep_host_threshold")      # nothing reads these / moved into "detection"


def cover(series, share=0.99):
    vc = series.value_counts(normalize=True)
    keep, tot = [], 0.0
    for val, frac in vc.items():
        keep.append(val)
        tot += frac
        if tot >= share:
            break
    return sorted(keep)


def fit_class(df, cls):
    pos = df["label"] == cls
    P, N = df[pos], df[~pos]
    sig = {"protocol_types": [p.lower() for p in cover(P["protocol_type"])],
           "services": cover(P["service"]), "flags": cover(P["flag"])}
    live = N["protocol_type"].isin([p.upper() for p in sig["protocol_types"]]) & N["service"].isin(sig["services"]) \
        & N["flag"].isin(sig["flags"])
    cand = N[live]
    zero = []
    for f in FIELDS:                                  # 2. zero gates that earn their place
        if (P[f] == 0).mean() >= 0.995 and len(cand) and (cand[f] != 0).mean() >= 0.01:
            zero.append(f)
            cand = cand[cand[f] == 0]
    ranges, big = {}, len(P) >= SMALL
    for _ in range(MAX_RANGES):                       # 3. greedy ranges
        best = None
        for f in FIELDS:
            if f in zero or f in ranges:
                continue
            lo, hi = (P[f].quantile(0.005), P[f].quantile(0.995)) if big else (P[f].min(), P[f].max())
            kept = cand[(cand[f] >= lo) & (cand[f] <= hi)]
            gain = len(cand) - len(kept)
            if best is None or gain > best[0]:
                best = (gain, f, float(lo), float(hi), kept)
        if best is None or len(cand) == 0 or best[0] < 0.01 * len(cand):
            break
        ranges[best[1]] = [round(best[2], 4), round(best[3], 4)]
        cand = best[4]
    if len(sig["services"]) >= 20:                    # covers nearly every port: no signal, and a risk of missing unseen ports
        del sig["services"]
    sig.update(zero_fields=zero, ranges=ranges)
    return sig


def evaluate(df, thresholds, cls, thr):
    sigs = {s.name: s for s in compile_signatures(thresholds)}
    s = sigs[cls]
    gate, score = signature_scores(df, s)
    fire = gate & (score >= thr)
    is_cls = (df["label"] == cls).values
    normal = (df["label"] == "normal").values
    n, tp = int(is_cls.sum()), int((fire & is_cls).sum())
    return dict(n=n, recall=round(tp / n, 3) if n else None,
                precision=round(tp / fire.sum(), 3) if fire.sum() else None,
                fires_on_normal=int((fire & normal).sum()),
                normal_fp_rate=round((fire & normal).sum() / max(normal.sum(), 1), 5))


def finalize(base):
    """Everything in the config that is not a signature: evidence-based detection settings (see
    docs/TUNING.md for the source of each number), no dead keys, MITRE ids that match their names."""
    for k in DEAD_KEYS:
        base.pop(k, None)
    base["detection"] = {k: DETECTION_DEFAULTS[k] for k in (
        "match_threshold", "half_open_grace_seconds", "half_open_min_count", "portsweep_port_threshold",
        "ipsweep_host_threshold", "recon_window_seconds", "slow_scan_window_seconds", "slow_scan_port_threshold",
        "slow_scan_host_threshold", "alert_cooldown_seconds")}
    base.update(flows_db_path="data/flows.db", ioc_list_path="data/ioc.txt", reverse_dns="private")
    for name, intel in (base.get("threat_intel") or {}).items():
        if name in DEFAULT_MITRE and isinstance(intel, dict):
            intel["mitre"] = {**(intel.get("mitre") or {}), **DEFAULT_MITRE[name]}
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--base", required=True, help="config whose non-signature settings are kept")
    ap.add_argument("--out", required=True)
    ap.add_argument("--threshold", type=float, default=0.95)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    train, test = load(Path(args.data) / "KDDTrain+.txt"), load(Path(args.data) / "KDDTest+.txt")
    rng = np.random.RandomState(args.seed)
    half = rng.rand(len(test)) < 0.5
    test_a, test_b = test[half], test[~half]
    base = json.loads(Path(args.base).read_text())
    thresholds, report = {}, {}
    for cls in CLASSES:
        small = (train["label"] == cls).sum() < SMALL
        fit_df = test_a if small else train
        eval_df = test_b if small else test
        sig = dict(HANDWRITTEN[cls]) if cls in HANDWRITTEN else fit_class(fit_df, cls)
        sig["ranges"].update(LIVE_GUARDS.get(cls, {}))
        thresholds[cls] = sig
        cfg = {cls: sig}
        sig["_validation"] = {
            "fit_on": "random half of KDDTest+" if small else "KDDTrain+",
            "scored_on": "the other half of KDDTest+" if small else "KDDTest+ (held out)",
            "fit": evaluate(fit_df, cfg, cls, args.threshold),
            "held_out": evaluate(eval_df, cfg, cls, args.threshold),
        }
        h = sig["_validation"]["held_out"]
        ok = cls in HANDWRITTEN or ((h["precision"] or 0) >= MIN_PRECISION and h["normal_fp_rate"] <= MAX_NORMAL_FP)
        sig["enabled"] = bool(cls in LIVE_ENABLED and ok)
        if not sig["enabled"]:
            sig["_why_disabled"] = WHY_DISABLED.get(cls) or "did not meet the precision / false-positive bar on held-out data"
        report[cls] = sig["_validation"]
    base["thresholds"] = thresholds
    base = finalize(base)
    Path(args.out).write_text(json.dumps(base, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{'class':13s} {'fit on':8s} {'n(held)':>8s} {'recall':>7s} {'precision':>9s} {'FP on normal':>13s}  ranges")
    for cls, v in report.items():
        h = v["held_out"]
        print(f"{cls:13s} {'Test½' if 'half' in v['fit_on'] else 'Train':8s} {h['n']:8d} "
              f"{(h['recall'] if h['recall'] is not None else float('nan')):7.1%} "
              f"{(h['precision'] if h['precision'] is not None else float('nan')):9.1%} "
              f"{h['fires_on_normal']:6d} ({h['normal_fp_rate']:.2%})  {len(thresholds[cls]['ranges'])}+{len(thresholds[cls]['zero_fields'])}z  "
              f"{'ENABLED' if thresholds[cls]['enabled'] else 'disabled'}")


if __name__ == "__main__":
    main()
