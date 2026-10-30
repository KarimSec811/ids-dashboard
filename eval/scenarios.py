"""Lab scenarios. Placeholders filled in by run_lab.py:
   {victim} {iface} {mac} {sweep_range} {sweep_a} {sweep_b} {helpers}
Keys: expect = detectors that should fire; known_limitation = why a miss is expected (and documented);
      sweep = needs the dead-host range; slow = skipped with --skip-slow; tool = binary that must exist."""

ATTACK, BENIGN = "attack", "benign"

SCENARIOS = [
    # --- port scans ---------------------------------------------------------------
    dict(name="nmap_syn_t4", kind=ATTACK, tool="nmap", expect=["portsweep"],
         cmd="nmap -sS -T4 -p 1-1000 {victim}"),
    dict(name="nmap_syn_t2_polite", kind=ATTACK, tool="nmap", expect=["portsweep"], timeout=240,
         cmd="nmap -sS -T2 -p 1-100 {victim}"),
    dict(name="nmap_syn_t1_sneaky", kind=ATTACK, tool="nmap", expect=["portsweep"], timeout=400, slow=True,
         known_limitation="one probe every 15 s never accumulates inside the 10 s probe window",
         cmd="nmap -sS -T1 -p 1-8 {victim}"),
    dict(name="nmap_connect", kind=ATTACK, tool="nmap", expect=["portsweep"],
         cmd="nmap -sT -T4 -p 1-1000 {victim}"),
    dict(name="nmap_fin", kind=ATTACK, tool="nmap", expect=["portsweep"],
         cmd="nmap -sF -T4 -p 1-1000 {victim}"),
    dict(name="nmap_xmas", kind=ATTACK, tool="nmap", expect=["portsweep"],
         cmd="nmap -sX -T4 -p 1-1000 {victim}"),
    dict(name="nmap_udp", kind=ATTACK, tool="nmap", expect=["portsweep"], timeout=240,
         known_limitation="UDP probes and ICMP port-unreachable replies are not modelled as failed probes",
         cmd="nmap -sU -T4 --top-ports 20 {victim}"),
    dict(name="masscan_1000", kind=ATTACK, tool="masscan", expect=["portsweep"],
         cmd="timeout 20 masscan {victim} -p1-1000 --rate 1000 --wait 2 --router-mac {mac} -e {iface}"),
    # --- host sweeps (dead hosts get a static neighbour entry, see README) ----------
    dict(name="nmap_ping_sweep", kind=ATTACK, tool="nmap", expect=["ipsweep"], sweep=True,
         cmd="nmap -sn -PE --send-ip {sweep_range}"),
    dict(name="fping_sweep", kind=ATTACK, tool="fping", expect=["ipsweep"], sweep=True,
         cmd="fping -g {sweep_a} {sweep_b} -r 1 -q"),
    # --- SYN floods ------------------------------------------------------------------
    dict(name="hping3_syn_flood", kind=ATTACK, tool="hping3", expect=["neptune"], timeout=60,
         cmd="hping3 -S -p 80 -i u1000 -c 8000 {victim}"),
    dict(name="hping3_syn_flood_spoofed", kind=ATTACK, tool="hping3", expect=["neptune"], timeout=60,
         cmd="hping3 -S -p 80 -i u1000 -c 8000 --rand-source {victim}"),
    dict(name="hping3_flood_closed_port", kind=ATTACK, tool="hping3", expect=["neptune"], timeout=60,
         known_limitation="refused connections (RST) are a closed port, not reported as a SYN flood",
         cmd="hping3 -S -p 81 -i u1000 -c 8000 {victim}"),
    # --- credential guessing -----------------------------------------------------------
    dict(name="ftp_guessing", kind=ATTACK, tool="python3", expect=["guess_passwd"], timeout=90,
         cmd="python3 {helpers}/ftp_guess.py {victim} 21 45"),
    # --- benign (must stay silent) -------------------------------------------------------
    dict(name="benign_http_burst", kind=BENIGN, tool="curl",
         cmd="seq 300 | xargs -P 20 -I{{}} curl -s -o /dev/null http://{victim}/"),
    dict(name="benign_service_tour", kind=BENIGN, tool="python3",
         cmd="python3 {helpers}/service_tour.py {victim} 10"),
    dict(name="benign_admin_nmap", kind=BENIGN, tool="nmap",
         cmd="nmap -sT -p 22,80,3306 {victim}"),
    dict(name="benign_ping", kind=BENIGN, tool="ping",
         cmd="ping -c 20 -i 0.2 {victim}"),
]
