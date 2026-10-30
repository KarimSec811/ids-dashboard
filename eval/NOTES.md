## Findings log (hand-written; appended to the report by evaluate.py)

**How to read the numbers.** The detectors were corrected while building this evaluation, so the virtual lab is a
*development set*. The unbiased test is the VM lab (Kali attacking Metasploitable), run once with these same scripts
and no tuning afterwards. Results from that run are the ones to quote.

1. **First run with real tools: 10 of 11 attacks detected, 4 of 4 benign clean.** One unexpected miss:
   `hping3_syn_flood` from a single real host. The packets show why: SYN, SYN-ACK, and then a RST sent by the
   attacker's *own kernel* (it never opened that socket). Every connection ended `RSTO`, so the half-open count never
   accumulated. The synthetic PCAPs had no reset in them, so the tests had never seen this.
   - *Fix:* a connection whose handshake the originator never completed counts as half-open even if the originator
     resets it. A reset from the *responder* (a closed port) still does not.
   - *Guard against a new false positive:* a scan of many open ports has the same SYN / SYN-ACK / RST pattern, so the
     half-open connections must also target one port (at least 80% of them) before the sensor calls it a flood.
   - *Regression tests:* `test_flood_from_a_real_host_whose_kernel_resets_each_syn_ack_is_still_a_flood` and
     `test_scan_of_many_open_ports_is_not_mistaken_for_a_flood`.
2. **Documented misses that are by design, not bugs:** a scan slower than the 10 s probe window, UDP scans, and a SYN
   flood against a closed port (the victim answers RST, which is indistinguishable from a closed-port probe burst).
3. **Sweeps on a flat Ethernet segment are invisible to any IP-level sensor:** probes to dead hosts stop at ARP and never
   become IP packets. The lab gives the dead range static neighbour entries so the packets exist, which is what a routed
   sweep looks like. Detecting ARP sweeps would need ARP analysis, which this sensor does not do.
4. **Time to first alert** is bounded below by the half-open grace period (2 s by default) for sweeps and slow scans, by design:
   the sensor waits to be sure an unanswered probe is really unanswered.
