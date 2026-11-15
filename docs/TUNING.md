# Tuning guide: where every number in `config.json` comes from

There is no universal "perfect" threshold. The right value depends on the network: a busy server, a laptop and a
lab VM have different normal behaviour. What can be done is to start from numbers with a reason, measure false
positives on your own traffic, and move one setting at a time. This page gives the reason for each default and the
direction to move it. Every number below is checked by `python eval/lint_config.py` and exercised by the tests.

## Detection settings (`config.json` -> `detection`)

| Setting | Default | Why this value | Raise it if... / lower it if... |
|---|---|---|---|
| `half_open_grace_seconds` | **2.0** | TCP starts its retransmission timer at 1 s ([RFC 6298](https://www.rfc-editor.org/rfc/rfc6298): initial RTO = 1 s) and Linux retries a SYN after 1 s, then 3 s, 7 s... So an unanswered SYN at 2 s means "no answer even after a retransmit". Below 1 s, one lost SYN counts as a failed probe (the old config used 0.5 s). | Raise on lossy links (satellite, mobile). Do not go under 1.0. |
| `half_open_min_count` | **10** | A browser opens at most ~6 parallel connections to one host, and each completes its handshake within one RTT. 10 half-open connections to one port is not a page load. (The old value, 3, is.) | Raise on small hosts that see odd clients; lower only on isolated lab segments. |
| (fixed) half-open share >= 0.5, same-port share >= 0.8 | | A busy server always has some half-open connections in flight (2,000 new connections/s x 50 ms RTT = ~100). It is only a flood when they dominate recent traffic **and** hit one port. A scan of many open ports produces the same SYN, SYN-ACK, RST pattern but spreads across ports (found with a real `hping3` run, see `eval/NOTES.md`). | |
| `portsweep_port_threshold` | **20** | Distinct ports with **failed** attempts (refused, reset or unanswered) on one host within `recon_window_seconds`. Reference points: Zeek `scan.zeek` flags 15 ports in 5 min; Cisco's Snort-based presets need 60 to 120 ports in 60 to 600 s. Failed-only counting is what makes a low number safe: a client that merely uses 8 services successfully never counts. Real fast scanners (`nmap -T4`, masscan) probe 1,000 ports in under a second. | Lower to 10 on quiet networks for earlier warning; raise to 50 where NAT or proxies produce many failed connections. |
| `ipsweep_host_threshold` | **20** | Distinct hosts with failed attempts **on one port** (Zeek's definition of an address scan; it ignores peer-to-peer noise where every failure is on a different port). Cisco's ICMP host-sweep presets: 20 hosts (High), 30 (Medium), 50 (Low). Zeek: 25. | as above |
| `recon_window_seconds` | **10** | Fast tier. Short enough that a scan is reported within seconds, long enough for `nmap -T2` (one probe every 0.4 s) to reach the threshold. | |
| `slow_scan_window_seconds`, `slow_scan_port_threshold`, `slow_scan_host_threshold` | **300 s, 15, 25** | Slow tier: Zeek's `scan.zeek` defaults (a port scan is 15 ports with failed connections on one victim in 5 minutes; an address scan is 25 hosts on one port). Catches `nmap --scan-delay 5s` style scans the fast tier cannot see. A scan below these numbers (e.g. 8 ports at `-T1` pace) is missed on purpose; Zeek would miss it too. | Lower the slow thresholds to 10 for more sensitivity; expect more alerts from noisy hosts. |
| `match_threshold` | **0.95** | The shipped rules have at most 8 conditions, so 0.95 means every condition must hold. | Leave. Lowering it re-admits the loose matching that made the original `back` rule fire on 17-23% of normal records. |
| `alert_cooldown_seconds` | **30** | Repeated detections of one attack inside this window become one alert. | Raise to merge longer attacks; lower for finer-grained alerts. |

Cisco's presets for comparison (ports / hosts per window): Low 120 / 180 in 60 s, Medium 90 / 150 in 90 s, High 60 / 100 in 600 s;
ICMP host sweep 50 / 30 / 20 hosts. They count every port change, not only failures, which is why their numbers are higher.

## Suggested profiles (not measured: they follow the range the sources use)

| | fast ports / hosts | slow ports / hosts (300 s) | `half_open_min_count` |
|---|---|---|---|
| sensitive (lab, quiet network) | 10 / 10 | 10 / 15 | 6 |
| **balanced (default)** | **20 / 20** | **15 / 25** | **10** |
| conservative (busy campus, NAT, proxies) | 50 / 50 | 25 / 50 | 25 |

## How to tune on your own network (10 minutes per round)

1. Capture an hour of normal traffic (`eval/README.md`, step 7) and score it with `--soak`. The report prints alerts per hour and
   the reason for each.
2. For each alert decide: attack, or normal behaviour? Normal behaviour means raise that one threshold.
3. Change **one** setting, re-score the same capture, compare. Never tune on the attack run you will report.
4. Re-run the lab scenarios (`sudo eval/run_netns_lab.sh`) to confirm nothing you care about stopped being detected.

## Signatures (`config.json` -> `thresholds`)

The 12 NSL-KDD rules of the original config were bounding boxes (the min-max envelope of each attack class), so most of their
conditions could never fail and a few contradicted each other. They were re-derived with `python eval/kdd_fit.py`
(percentile ranges fitted on KDDTrain+, scored on the **held-out** KDDTest+; classes with <200 training records are fitted on a
random half of KDDTest+ and scored on the other half):

```
class         fit on    n(held)  recall precision  FP on normal  ranges
neptune       Train        4657   99.7%     95.0%      0 (0.00%)  5+3z  ENABLED
portsweep     Train         157   99.4%      3.7%     61 (0.63%)  5+1z  disabled
satan         Train         735   99.6%     12.8%    339 (3.49%)  4+2z  disabled
ipsweep       Train         141  100.0%     14.7%     83 (0.85%)  3+5z  disabled
smurf         Train         665   88.1%    100.0%      0 (0.00%)  3+1z  ENABLED
back          Train         359   98.9%     92.4%      5 (0.05%)  1+0z  disabled
teardrop      Train          12  100.0%     25.0%     36 (0.37%)  1+2z  disabled
warezclient   Train           0    nan%      0.0%     37 (0.38%)  6+2z  disabled
pod           Train          41  100.0%      7.0%     16 (0.17%)  2+0z  disabled
guess_passwd  Test½         621    0.0%      nan%      0 (0.00%)  1+0z  ENABLED
mscan         Test½         503   99.0%     51.3%      2 (0.04%)  3+3z  disabled
processtable  Test½         337  100.0%     99.4%      0 (0.00%)  3+4z  disabled
```

A signature ships **enabled** only if it validates on held-out data (precision >= 90%, <= 0.1% of normal records) **and** has a live
trigger that was tested in the lab. The others stay in the file with `"enabled": false` and a `_why_disabled` note:

* `portsweep`, `ipsweep`, `satan`: one connection cannot show a scan (held-out precision 4-15%). The failed-probe detectors do this
  properly across connections.
* `pod`, `teardrop`: need IP reassembly, which the sensor does not do (precision 7% / 25%).
* `back`: 92% precision on the dataset, but it reduces to "an HTTP request of 17-55 KB", which a legitimate upload also is.
* `warezclient`, `mscan`, `processtable`: absent from, or only present in, the held-out file; nothing live to test.
* `smurf` keeps its fitted rule **plus** a volume guard (`count` and `srv_count` >= 10): an amplification attack is many replies,
  not one large ping.
* `guess_passwd` is **hand-written** (a cleartext login service with >= 3 server-confirmed failed logins). NSL-KDD never records 3
  failed logins on one of its `guess_passwd` connections, so the dataset scores this rule at 0% and cannot validate it; that number is
  stored in the config next to the rule and the rule is validated in the lab instead.

Caveat: NSL-KDD is 1998-era simulated traffic. These numbers show the rules are internally sound, not that they transfer to your
network. That is what the lab and soak evaluations are for.

## MITRE ATT&CK mapping (checked against attack.mitre.org)

| Alert | Technique | Note |
|---|---|---|
| `neptune` (SYN flood) | T1499.001 OS Exhaustion Flood | ATT&CK's detection guidance for this technique is a burst of incomplete TCP handshakes; the old config used T1498.001 (volumetric floods) |
| `smurf` | T1498.002 Reflection Amplification | |
| `portsweep` | T1046 Network Service Discovery | |
| `ipsweep` | T1018 Remote System Discovery | from outside the network, T1595.001 (Scanning IP Blocks) is the reconnaissance equivalent |
| `satan`, `mscan` | T1595.002 Vulnerability Scanning | was the generic T1595 |
| `back` | T1499.003 Application Exhaustion Flood | the old config had the id T1499.004 with the name of T1499.003 |
| `teardrop`, `pod` | T1499.004 Application or System Exploitation | same id/name mismatch |
| `warezclient` | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | was T1567 (web services), but warezclient is FTP; confirm the id on attack.mitre.org if you change it |
| `guess_passwd` | T1110.001 Password Guessing | |

## Known limits that no threshold fixes

* Scans below the slow tier, scans spread across many source addresses, and UDP/ARP scans are not seen.
* A flood of SYNs to a **closed** port looks like refused connections, not half-open ones.
* An attacker who can send many spoofed sources can push a slow scanner's state out of the tracker (cap: 20,000 sources).
