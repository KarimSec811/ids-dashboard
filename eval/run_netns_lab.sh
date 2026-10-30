#!/usr/bin/env bash
# One command, no VMs: build the virtual lab, run every scenario with the real tools,
# evaluate, tear the lab down.   sudo eval/run_netns_lab.sh [--skip-slow] [--out DIR]
# Needs: Linux, root, iproute2, tcpdump, nmap, hping3, fping (masscan optional), tshark, the Python deps.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
OUT="${OUT:-$ROOT/eval/results/netns}"
"$HERE/netns_lab.sh" down >/dev/null 2>&1 || true
"$HERE/netns_lab.sh" up
trap '"$HERE/netns_lab.sh" down' EXIT
rm -rf "$OUT"
python3 "$HERE/run_lab.py" --victim 10.77.0.10 --iface veth-a --out "$OUT" \
    --sweep-start 10.77.0.100 --sweep-end 10.77.0.199 "$@"
"$HERE/netns_lab.sh" down >/dev/null 2>&1; trap - EXIT
python3 "$HERE/evaluate.py" --results "$OUT" --out "${EVAL_MD:-$ROOT/docs/EVALUATION.md}"
