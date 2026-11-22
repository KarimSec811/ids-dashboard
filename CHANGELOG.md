# Changelog

All notable changes to this project are documented here.

The project follows semantic versioning for published releases. This file starts with the first planned stable release; the v1.0.0 entry becomes authoritative only when the corresponding Git tag and GitHub Release are published.

## [Unreleased]

No changes recorded.

## [1.0.0] — 2026-11-22

First stable feature release candidate of the Network IDS Dashboard.

### Added
- Stateful TCP connection tracking and flow-oriented analysis.
- Cross-flow failed-probe tracking for TCP port-sweep and IP-sweep detection.
- SYN-flood detection using incomplete-handshake behaviour and traffic dominance checks.
- Selected ICMP amplification and cleartext login-failure detections.
- Alert aggregation, evidence fields, severity/confidence metadata and MITRE ATT&CK mappings.
- Flask and Socket.IO dashboard with alert investigation, acknowledgement, flow views and CSV exports.
- PCAP replay for repeatable demonstrations and regression testing.
- SQLite persistence for alert history and completed-flow records.
- Configuration validation and a configuration linter.
- Bounded queues/state, retention controls and pipeline health metrics.
- API token protection for control, telemetry and export surfaces when configured.
- Regression tests for engine behaviour, capture pacing, configuration validation, persistence failures and application integration.
- A real-tool virtual-lab evaluation harness and documented tuning methodology.

### Security and reliability
- Default loopback binding; non-loopback binding requires an API token unless the explicit insecure override is set.
- Validated settings updates and constrained PCAP replay file selection.
- CSV formula neutralization and safer rendering of network-derived strings.
- Isolated persistence error handling and queue/pipeline observability.

### Known limitations
- UDP scan coverage is incomplete.
- Distributed and sufficiently slow reconnaissance can evade current thresholds.
- ARP-only discovery of dead hosts is not visible to IP-level sweep detection.
- SYN floods against closed ports are not classified as the supported flood pattern.
- Payload heuristics are limited for encrypted protocols.
- Throughput is constrained by the PyShark/TShark capture path.
- Live evidence exports are not a complete historical packet capture.
- The virtual-lab evaluation is a development/regression set, not independent production validation.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md), [docs/EVALUATION.md](docs/EVALUATION.md), and [docs/TUNING.md](docs/TUNING.md) for scope, methodology and tuning details.
