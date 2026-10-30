# Backend contract (for the HTML / CSS / JS side)

Everything below is stable. Existing event names, routes and payload keys were
kept; additions are marked **new**.

Run: `python app.py` → http://127.0.0.1:5000 (needs Wireshark/tshark; live capture needs capture privileges).

## Socket.IO — client → server

| event | payload | notes |
|---|---|---|
| `start_ids` | `{}` or `{pcap: "demo_mixed.pcap", speed: 10, token?}` | **new:** `pcap` starts a *replay* of a file from `test_pcaps/` (demo mode, no privileges needed). `speed` = multiple of real time, `0` = as fast as possible |
| `stop_ids` | `{token?}` | takes effect immediately, even on a silent interface |
| `ack_alert` | `{id}` or `{flow_id}` or `{ids: [...]}` | **new:** `id` and bulk `ids`. Works for alerts that already left memory (updates the DB) |
| `investigate_alert` | `{id\|flow_id, note, false_positive, investigator}` | unchanged shape |
| `request_initial_data` | `{page: "flows"}` optional | replies with `alert_update`, `system_health`, **new** `stats_update`, and `flow_update` when `page == "flows"` |
| `request_health` | – | replies `system_health` |

`token` is only needed when the server runs with `IDS_API_TOKEN` (see Auth). You can also pass it once at connect: `io({auth: {token}})`.

## Socket.IO — server → client

| event | payload |
|---|---|
| `status_update` | `{status, color: success\|info\|warning\|danger, running, mode: live\|replay\|null, source, error}` (**new:** `mode`, `source`, `error`; `status` is e.g. `IDS Started`, `Replay Started`, `IDS Stopping...`, `IDS Stopped`, `Replay finished`, `Capture failed: …`) |
| `system_health` | every 3 s: `cpu_percent, memory_used_mb, memory_total_mb, queue_length, active_flows, active_alerts, total_packets, total_attacks, packets_per_sec, attacks_per_sec, capture_status, running, detection_latency_ms, uptime` + **new** `unacknowledged_alerts, dropped_events, alerts_suppressed, mode, source, error, tracker, auth_required` |
| `stats_update` | every 1 s: `packets_per_sec, attacks_per_sec, queue_length, active_flows, capture_status, total_packets, total_attacks` + **new** `packets_history`, `attacks_history` (60 integers, one per second, oldest first — feed charts directly). `packets_per_sec` is now a real per-second rate (it used to be capped at 60) |
| `alert_update` | `{alerts: [alert, …]}` — new alerts, aggregated updates (`count` grows), acknowledgements, investigations. **Upsert by `alert.id`** (or `flow_id`) |
| `flow_update` | `{flows: [flow, …]}` — full recent list; only sent in reply to `request_initial_data {page:"flows"}`. Now one entry per flow (latest state), up to 500 |
| `flow_batch` | **new.** `{flows: [flow, …]}` — live deltas ≈4×/s (latest state of each changed flow). Upsert by `flow_id` |
| `auth_error` | **new.** `{error, auth_required}` — a control event was refused |

Alerts are **aggregated**: one alert per attacker→victim pair (scans), per victim (SYN flood, smurf, pod, teardrop) or per attacker (ipsweep) within a cooldown (default 30 s). Expect many `alert_update`s for the *same* `id` with a growing `count`.

## Alert object

```
id, flow_id, src_ip, dst_ip, src_port, dst_port, protocol_type, service,
outcome            neptune | portsweep | ipsweep | smurf | satan | back | teardrop | warezclient | guess_passwd | mscan | processtable | pod
confidence 0–1, severity high|medium|low, message, timestamp (first seen), first_seen, last_seen,
count (flagged packets), flows (distinct flows), sources (distinct source IPs),
reasons [str]      human-readable "why" — show it in the inspector
evidence {flag, service, count, srv_count, serror_rate, rerror_rate, dst_host_count, src_bytes, dst_bytes, duration, …}
mitre {tactic, techniques[]}     description?   names [DNS/SNI/Host names seen]
capture_source     "live:<iface>" | "replay:<file>"
src_rdns, dst_rdns, src_geo?, dst_geo?, enrichment_summary?, ioc_matches [ "ip:…" | "cidr:…" | "domain:…" ]
acknowledged, acknowledged_timestamp?, investigated?, investigator?, investigator_notes [{note,timestamp,false_positive,investigator}]
```
Treat every string as untrusted (reverse DNS, SNI and DNS names come from the attacker): render with `textContent`, never `innerHTML`.

## Flow object (`flow_update` / `flow_batch`)

All NSL-KDD features (`duration, protocol_type, service, flag, src_bytes, dst_bytes, count, srv_count, serror_rate, …, dst_host_*`) plus
`flow_id, src_ip, src_port, dst_ip, dst_port, outcome, confidence, level (0 normal / 1 flagged), timestamp, packets`, **new** `half_open`, `half_open_count`, `half_open_rate`, `half_open_same_port_rate`, `names`.
`src` is the connection *originator* (SYN sender) even if capture started mid-connection.

## HTTP

| route | notes |
|---|---|
| `GET /`, `/alerts`, `/flows`, `/export`, `/settings` | pages (templates unchanged; `/settings` gets `config` with `detection` defaults filled in) |
| `GET /health` | **new** `{status:"ok", running}` |
| `GET /api/status` | **new** same payload as `system_health` |
| `GET /api/interfaces` | `{interfaces, capture_interfaces (tshark names), current}` |
| `GET /api/pcaps` | **new** `{pcaps: [{name,size}]}` — files available for replay |
| `GET /api/flows?limit=&outcome=&source=memory\|db` | **new** JSON; `source=db` = completed-flow log |
| `GET /alerts/history` · `/api/alerts` | `?limit=&offset=&outcome=&severity=&acknowledged=true\|false` (filters are new) |
| `GET /export/flows.csv` | `?limit=&source=db` (more columns; formula-injection safe) |
| `GET /export/alerts.csv` | **new** |
| `GET /export/alert_pcap?id=<alert id>` (or `flow_id`) | evidence PCAP. Header `X-Export-Mode`: `replay-filter` (exact packets from the replayed file) or `forward-capture` (live packets are not stored, so it records the *next* N packets of the same hosts; `?count=&timeout=` are capped). **Requires token if one is configured** |
| `POST /settings/update` (JSON) | allow-listed + validated: `interface, capture_bpf, sampling_rate, capture_packet_limit, capture_timeout_seconds, portsweep_port_threshold, ipsweep_host_threshold, match_threshold, half_open_grace_seconds, half_open_min_count, alert_cooldown_seconds, reverse_dns (off\|private\|all), ioc_list (text)`. `200 {ok, changed[], restart_required}` or `400 {error, errors[]}` — show `errors` next to the fields. `restart_required` = capture is running and `interface`/`capture_bpf` changed |

## Auth (optional)

`IDS_API_TOKEN=…` makes these require the token: `POST /settings/update`, `/export/alert_pcap`, and the socket events `start_ids, stop_ids, ack_alert, investigate_alert`. Send it as header `X-IDS-Token` (or `Authorization: Bearer …`, or `?token=` for plain download links), and in socket payloads / `auth`. Viewing pages and data stays open. Without a token the server only binds to 127.0.0.1 (set `IDS_HOST` to change; a non-loopback bind without a token is refused unless `IDS_ALLOW_INSECURE=1`).

## Optional `config.json` keys (all have defaults)

```
"reverse_dns": "private",            // off | private (internal IPs only) | all
"geoip_db_path": null,               // MaxMind GeoLite2-City.mmdb (+ pip install geoip2)
"alerts_db_path": "data/alerts.db",  // set null to disable persistence
"flows_db_path": "data/flows.db",    // completed-flow log; null to disable
"alerts_retention_days": 30, "flows_max_rows": 500000,
"replay_dir": "test_pcaps", "ioc_list_path": "data/ioc.txt",
"recent_flows_limit": 1000, "alert_history_limit": 100,
"detection": {
  "match_threshold": 0.95, "half_open_grace_seconds": 2.0, "half_open_min_count": 10,
  "portsweep_port_threshold": 10, "ipsweep_host_threshold": 10, "recon_window_seconds": 10,
  "alert_cooldown_seconds": 30, "alert_max_per_second": 20,
  "flow_idle_timeout_seconds": 120, "max_flows": 50000
}
```
