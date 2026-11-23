# IDS v1.0.0 — Limitations and operational boundaries

This document describes the supported scope and known limitations of the v1.0.0 release. The sensor is intended for learning, controlled labs, development and small-scale monitoring where its visibility and performance constraints are understood. It is not a replacement for a production NDR, Zeek, Suricata or a managed SIEM.

## Detection coverage

The current engine provides stateful TCP connection tracking and cross-flow detection for selected behaviours:

- TCP port sweeps based on failed connection attempts.
- IP sweeps based on failed attempts to multiple hosts on a common port.
- SYN-flood-like activity when incomplete handshakes dominate traffic to one victim port.
- ICMP echo-reply amplification patterns classified as `smurf`.
- Repeated failed logins on supported cleartext login services, such as FTP and Telnet.

The shipped NSL-KDD-derived signatures are not all enabled. Rules that could not be validated with acceptable false-positive behaviour remain disabled. A rule being present in `config.json` does not mean the sensor detects that attack class.

## Known detection gaps

### UDP reconnaissance

UDP probes and ICMP port-unreachable responses are not modelled by the failed-probe tracking logic to the same extent as TCP. UDP port scans may therefore be missed.

### Distributed and low-and-slow reconnaissance

The scan detectors aggregate observations within configured time windows and around observed source/victim relationships. Activity distributed across many source addresses, or kept below the configured slow-scan thresholds, can evade these detectors. The documented virtual-lab evaluation missed an eight-port scan spread over approximately two minutes.

### ARP-level host discovery

On a flat Ethernet segment, a probe to an unused host may stop at ARP and never produce an IP packet visible to this sensor. ARP-only discovery is not detected by the IP-level sweep logic. Routed or otherwise IP-visible probes are required for the current detection path.

### SYN activity against closed ports

A SYN flood directed at a closed port that responds with TCP RST is not classified as the supported SYN-flood pattern. The detector is designed to identify sustained incomplete handshakes against a listening or otherwise non-resetting service, not every high-rate SYN stream.

### Encrypted application protocols

Payload heuristics are limited to supported cleartext protocols. Encryption prevents inspection of application credentials and content; metadata-only indicators may still be visible, but the current engine does not provide general encrypted-session threat detection.

### Packet-driven timeout behaviour

The analyzer's event-time progression is driven by observed packets. An unanswered probe is matured as failed when later traffic advances the event-time watermark or when the capture is flushed. On a completely silent link, alert timing can be delayed until more packets arrive or capture ends.

## Visibility and performance

### Capture throughput

The current PyShark/TShark capture path is parsing-bound. The README reports observed throughput in the range of a few hundred to approximately 1,500 packets per second in the tested environment. This is an empirical observation, not a guaranteed capacity or benchmark for other hardware, packet sizes or traffic mixes. The detection engine's isolated processing time does not represent end-to-end capture throughput.

### Capture point and packet loss

The sensor can only analyse traffic visible at its capture interface. Switch topology, SPAN/mirror configuration, interface drops, host scheduling and capture-buffer limits can all reduce visibility. A clean test result does not prove that every packet on a production network was observed.

### Evidence PCAP semantics

For alerts raised during PCAP replay, the evidence export can be filtered from the replay source. For live capture, the application does not retain a complete packet history for every alert; the evidence export may contain subsequent packets between the relevant hosts rather than the original triggering packets. Treat live evidence as supporting context, not a forensic full-fidelity recording.

## Deployment and operational constraints

- The dashboard is designed for a local or small controlled deployment. The documented runtime uses Flask-SocketIO threading mode and SQLite; it is not a horizontally scaled or high-availability architecture.
- The application does not automatically block traffic, isolate hosts, disable accounts or execute response actions. It is a monitoring and alerting tool; an analyst must validate alerts and take response actions separately.
- Live capture requires suitable operating-system privileges and a working Wireshark/TShark installation.
- The dashboard's default loopback binding is safer for local use. If it is exposed on a non-loopback interface, configure `IDS_API_TOKEN`; the explicit `IDS_ALLOW_INSECURE=1` override disables that protection and should not be used on an untrusted network.
- SQLite retention and bounded in-memory state are intended to constrain local resource use, not provide a tamper-proof or compliance-grade evidence archive.

## Evaluation boundaries

The published real-tool results are from a controlled virtual lab and are a development/regression set. The benign set is short and deliberately limited. These results do not establish production precision, recall, false-positive rate per hour, generalization to other operating systems, or resistance to adaptive evasion.

The synthetic PCAP tests are deterministic regression fixtures and share assumptions with the detector implementation. They demonstrate expected behaviour on known cases, not independent detection performance.

A separate VM-based held-out evaluation, longer benign soak, and comparison against established network-monitoring baselines remain future validation work. Do not describe the current lab metrics as independently validated production performance.

## Operator guidance

1. Deploy only where you are authorized to monitor traffic.
2. Confirm that the capture interface sees the traffic of interest.
3. Tune thresholds using representative benign traffic before relying on alerts.
4. Preserve original PCAPs and source logs separately when forensic retention is required.
5. Treat alerts as investigation leads; verify the evidence and consider missing telemetry before concluding that an incident occurred.
