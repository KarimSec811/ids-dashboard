# Tuning guide: where every number in `config.json` comes from

There is no universal "perfect" threshold. The right value depends on the network: a busy server, a laptop and a lab VM have
different normal behaviour. What can be done is to start from numbers with a reason, measure false positives on your own
traffic, and move one setting at a time. Every default below is checked by `python eval/lint_config.py` and exercised by the tests.

## Detection settings (`config.json` -> `detection`)

| Setting | Default | Why this value | Raise it if... / lower it if... |
|---|---|---|---|
| `half_open_grace_seconds` | **2.0** | TCP starts its retransmission timer at 1 s ([RFC 6298](https://www.rfc-editor.org/rfc/rfc6298): initial RTO 1 s), and Linux retries an unanswered SYN after 1 s, 3 s, 7 s... So "unanswered at 2 s" means no answer even after a retransmit. Under 1 s, one lost SYN counts as a failed probe (the old config used 0.5 s). | Raise on lossy links (mobile, satellite). Never below 1.0. |
| `half_open_min_count` | **10** | A browser opens about 6 parallel connections to a host and each completes its handshake in one RTT. 10 half-open connections to one port is not a page load. (The old value, 3, is.) | Raise for small hosts with odd clients; lower only on isolated lab segments. |
| fixed: half-open share >= 0.5 and same-port share >= 0.8 | | A busy server always has some handshakes in flight (2,000 new connections/s x 50 ms RTT = ~100). It is a flood only when they dominate recent traffic **and** hit one port. A scan of many open ports shows the same SYN, SYN-ACK, RST pattern but spreads across ports (found with a real `hping3` run, see `eval/NOTES.md`). | |
| `portsweep_port_threshold` | **20** | Distinct ports with **failed** attempts (refused, reset, or unanswered) on one host inside `recon_window_seconds`. Reference points: Zeek `scan.zeek` flags 15 ports per 5 min; Cisco's Snort-based presets need 60-120 ports per 60-600 s. Counting failures only is what makes a low number safe: a client using 8 services successfully never counts. | Lower to 10 on quiet networks; raise to 50 behind NAT or proxies. |
| `ipsweep_host_threshold` | **20** | Distinct hosts with failed attempts **on one port** (Zeek's definition of an address scan; it ignores peer-to-peer noise where every failure is on a different port). Cisco's ICMP host-sweep presets: 20 (High), 30 (Medium), 50 (Low). Zeek: 25. | as above |
| `recon_window_seconds` | **10** | Fast tier. Short enough to report within seconds, long enough for `nmap -T2` (a probe every 0.4 s) to reach the threshold. | |
| `slow_scan_window_seconds`, `slow_scan_port_threshold`, `slow_scan_host_threshold` | **300 s, 15, 25** | Slow tier: Zeek's `scan.zeek` defaults (15 ports on one victim, or 25 hosts on one port, in 5 minutes). Catches `nmap --scan-delay 5s` style scans the fast tier cannot see. A scan below these numbers (8 ports at `-T1` pace) is missed on purpose; Zeek would miss it too. | Lower to 10 for more sensitivity, expect more alerts from noisy hosts. |
| `match_threshold` | **0.95** | The shipped rules have at most 8 conditions, so 0.95 means every condition must hold. | Leave. Lowering it re-admits the loose matching that made the original `back` rule fire on 17-23% of normal records. |
| `alert_cooldown_seconds` | **30** | Repeated detections of one attack inside this window become one alert. | |

For comparison, Cisco's presets (ports / hosts per window): Low 120 / 180 per 60 s, Medium 90 / 150 per 90 s, High 60 / 100 per 600 s.
They count every port change, not only failures, which is why their numbers are higher. Cisco's documentation notes that Low
"might miss slow or filtered scans" and that busy NAT or proxy hosts cause false positives at Medium.

## Suggested profiles (not measured: they follow the range the sources use)

| | fast ports / hosts | slow ports / hosts (300 s) | `half_open_min_count` |
|---|---|---|---|
| sensitive (lab, quiet network) | 10 / 10 | 10 / 15 | 6 |
| **balanced (default)** | **20 / 20** | **15 / 25** | **10** |
| conservative (busy campus, NAT, proxies) | 50 / 50 | 25 / 50 | 25 |

## How to tune on your own network

1. Capture an hour of normal traffic (`eval/README.md`, step 7) and score it with `--soak`. The report prints alerts per hour and each alert's reason.
2. For each alert decide: attack, or normal behaviour? Normal behaviour means raise that one threshold.
3. Change **one** setting, re-score the same capture, compare. Never tune on the attack run you will report.
4. Re-run the lab scenarios (`sudo eval/run_netns_lab.sh`) to confirm nothing you care about stopped being detected.

## Signatures (`config.json` -> `thresholds`)

The 12 NSL-KDD rules of the original config were bounding boxes (the min-max envelope of each attack class). Most of their
conditions could never fail and a few contradicted each other. They were re-derived with `python eval/kdd_fit.py` (percentile
ranges fitted on KDDTrain+, scored on the **held-out** KDDTest+; classes with under 200 training records are fitted on half
of KDDTest+ and scored on the other half):

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

For comparison, the **original** rules scored on the same data (`python eval/kdd_check.py --config eval/config.original.json`,
threshold 0.85): `back` 3-14% precision and fires on 17-23% of normal records, `satan` ~20% precision and 6-14% of normal,
`pod` 7% precision, `ipsweep` 0% recall (it required `same_srv_rate` to be both 0 and 1), and `neptune` fires on 4.5% of normal records.

A signature ships **enabled** only if it validates on held-out data (precision >= 90%, <= 0.1% of normal records) **and** has a
live trigger tested in the lab. The rest stay in the file with `"enabled": false` and a `_why_disabled` note:

* `portsweep`, `ipsweep`, `satan`: one connection cannot show a scan (held-out precision 4-15%); the failed-probe detectors do this across connections.
* `pod`, `teardrop`: need IP reassembly, which the sensor does not do.
* `back`: 92% precision on the dataset, but it reduces to "an HTTP request of 17-55 KB", which a legitimate upload also is.
* `warezclient`, `mscan`, `processtable`: absent from, or only present in, the held-out file; nothing live to test.
* `smurf` keeps its fitted rule **plus** a volume guard (`count` and `srv_count` >= 10): an amplification attack is many replies, not one large ping.
* `guess_passwd` is **hand-written** (a cleartext login service with >= 3 server-confirmed failed logins; one typo is not an attack).
  NSL-KDD never records 3 failed logins on one of its `guess_passwd` connections, so the dataset scores this rule at 0% and cannot
  validate it. That number is stored next to the rule, and the rule is validated in the lab instead (`ftp_guessing`, `benign_single_failed_login`).

NSL-KDD is 1998-era simulated traffic. These numbers show the rules are internally sound, not that they transfer to your network.

## MITRE ATT&CK mapping (checked against attack.mitre.org)

| Alert | Technique | Note |
|---|---|---|
| `neptune` (SYN flood) | T1499.001 OS Exhaustion Flood | ATT&CK's detection guidance for it is "a burst of incomplete TCP handshakes". The old config used T1498.001 (volumetric floods) |
| `smurf` | T1498.002 Reflection Amplification | |
| `portsweep` | T1046 Network Service Discovery | |
| `ipsweep` | T1018 Remote System Discovery | from outside the network, T1595.001 (Scanning IP Blocks) is the reconnaissance equivalent |
| `satan`, `mscan` | T1595.002 Vulnerability Scanning | was the generic T1595 |
| `back` | T1499.003 Application Exhaustion Flood | the old config paired id T1499.004 with that name |
| `teardrop`, `pod` | T1499.004 Application or System Exploitation | same id/name mismatch |
| `warezclient` | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | was T1567 (web services); warezclient is FTP |
| `guess_passwd` | T1110.001 Password Guessing | |

## Limits no threshold fixes

* Scans below the slow tier, scans spread over many source addresses, and UDP/ARP scans are not seen.
* A flood of SYNs to a **closed** port looks like refused connections, not half-open ones.
* An attacker who can send many spoofed sources can push a slow scanner's state out of the tracker (cap: 20,000 sources).
