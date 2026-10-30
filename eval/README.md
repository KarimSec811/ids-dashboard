# Evaluation harness

Measures the sensor against **real attack tools** (nmap, masscan, hping3, fping) and against benign traffic, and
writes the results to `docs/EVALUATION.md`. Two ways to run it:

| | Where | Purpose |
|---|---|---|
| **Virtual lab** `eval/run_netns_lab.sh` | any Linux box, root, no VMs | reproducible; the *development* set |
| **VM lab** `eval/run_lab.py` | Kali -> Metasploitable | the **held-out test**: run once, never tune on it |

## A. Virtual lab (one command)

```bash
sudo apt install -y nmap masscan hping3 fping tcpdump iproute2 tshark
pip install -r requirements.txt
sudo eval/run_netns_lab.sh          # ~10 min; add --skip-slow to drop the 2-minute sneaky scan
```
It builds a network namespace with a Metasploitable-style victim (17 listening services, FTP that rejects every
password), runs every scenario in `eval/scenarios.py`, replays each capture through the sensor, writes
`docs/EVALUATION.md`, and tears the lab down. Results land in `eval/results/netns/`.

## B. VM lab: Windows 11 host, Kali attacker, Metasploitable victim

**1. Network (do this first).** Put Kali, Metasploitable, and any Ubuntu/Win10 guests on ONE isolated virtual network:
VirtualBox *Host-only Network* or *Internal Network*, VMware *Host-only (VMnet1)*. **Never bridged or NAT**: Metasploitable is
deliberately vulnerable and the scans must not leave the lab. Take a snapshot of every VM.

**2. Kali.** `sudo apt install -y nmap masscan hping3 fping tcpdump`. Copy the `eval/` folder over (only the Python
standard library is needed there). Find the lab interface with `ip -br addr` (e.g. `eth0`, address `192.168.56.x`) and the
victim's address with `ifconfig` on Metasploitable.

**3. Pick a sweep range that is completely unused** (used for the host-sweep scenarios; the script gives these addresses
a dead neighbour entry so probes become IP packets instead of stopping at ARP). VirtualBox's host-only DHCP hands out
`.101-.254`, so something like `.20-.80` is safe.

**4. Run on Kali** (about 8 minutes; `--skip-slow` saves two more):
```bash
sudo python3 eval/run_lab.py --victim 192.168.56.101 --iface eth0 \
     --sweep-start 192.168.56.20 --sweep-end 192.168.56.80 --out lab_results_vm
```
**5. Copy `lab_results_vm/` to the Windows host** (`scp -r kali@<ip>:~/lab_results_vm .` or a shared folder).

**6. Score it on Windows** (needs Wireshark installed so `tshark` is on PATH, plus `pip install -r requirements.txt`):
```powershell
python eval\evaluate.py --results lab_results_vm --config config.json --out docs\EVALUATION-VM.md
```
`--config config.json` scores your *deployed* configuration (default is the test fixture). Do not change thresholds
and re-run to improve the table: that turns the held-out test into a second development set.

**7. Benign soak (false positives per hour).** The Windows host sees all guest traffic on the host-only adapter. Use the guests
normally for an hour (browse from Win10, `apt update` on Ubuntu, SSH between guests), capturing on the host:
```powershell
tshark -D                                   # find the "VirtualBox Host-Only Network" adapter number
tshark -i 5 -a duration:3600 -w soak.pcap   # replace 5 with that number
python eval\evaluate.py --results lab_results_vm --out docs\EVALUATION-VM.md --soak soak.pcap
```

**8. Optional baselines.** On the Ubuntu guest install Zeek and Suricata (`suricata-update` fetches ET Open), copy the
results folder there and run `python3 eval/baselines.py --results lab_results_vm`. Copy `lab_results_vm/baselines/`
back and re-run step 6: the report gains Zeek and Suricata columns.

## How a scenario is judged
- *Detected*: at least one alert of an expected type during that scenario's capture. *First alert*: seconds from the
  command's start. *Alerts*: distinct alerts raised (1 is ideal; many means poor aggregation).
- *Benign* scenarios must produce no alert at all.
- Scenarios with a `known_limitation` are expected misses and are reported separately, not hidden.
- A 1 packet/s ping to the victim runs throughout as background traffic: the sensor's clock follows packets, so an
  unanswered probe is only declared failed once a later packet arrives.

## Adding a scenario
Append a dict to `SCENARIOS` in `eval/scenarios.py` (`cmd`, `expect`, `kind`, optional `known_limitation`). Placeholders:
`{victim} {iface} {mac} {sweep_range} {sweep_a} {sweep_b} {helpers}`.

Only run this against machines you own.
