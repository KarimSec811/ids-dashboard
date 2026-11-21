#!/usr/bin/env bash
# Virtual lab on one Linux box (needs root + iproute2):
#   this machine           = attacker ("Kali")           10.77.0.2   on veth-a
#   namespace "vic"        = victim ("Metasploitable")   10.77.0.10  on veth-v  (+ .11-.14 alive aliases)
# usage: sudo eval/netns_lab.sh up|down
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
case "${1:-}" in
  up)
    ip netns del vic 2>/dev/null || true; ip link del veth-a 2>/dev/null || true
    ip netns add vic
    ip link add veth-a type veth peer name veth-v
    ip link set veth-v netns vic
    ip addr add 10.77.0.2/24 dev veth-a && ip link set veth-a up
    ip netns exec vic bash -c 'ip link set lo up; ip addr add 10.77.0.10/24 dev veth-v
      for i in 11 12 13 14; do ip addr add 10.77.0.$i/24 dev veth-v; done
      ip link set veth-v up; ip route add default via 10.77.0.2'
    setsid nohup ip netns exec vic python3 "$HERE/helpers/fake_services.py" >/tmp/ids-lab-services.log 2>&1 </dev/null &
    echo $! > /tmp/ids-lab-services.pid
    sleep 1; cat /tmp/ids-lab-services.log
    echo "lab up: attacker 10.77.0.2 (veth-a) -> victim 10.77.0.10"
    ;;
  down)
    [ -f /tmp/ids-lab-services.pid ] && kill "$(cat /tmp/ids-lab-services.pid)" 2>/dev/null || true
    ip netns del vic 2>/dev/null || true
    ip link del veth-a 2>/dev/null || true
    rm -f /tmp/ids-lab-services.pid
    echo "lab down"
    ;;
  *) echo "usage: $0 up|down"; exit 1;;
esac
