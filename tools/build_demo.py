#!/usr/bin/env python3
"""Build the static GitHub Pages demo into docs/demo/.

    python tools/build_demo.py      # needs tshark + scapy (it replays a real PCAP through the real backend)

It records the live Socket.IO event stream of a replay, renders the real templates to
static HTML, and copies the real front-end JS/CSS. Re-run it after changing templates or JS.
"""
import json
import os
import shutil
import sys
import tempfile
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo"
PCAP = "demo_mixed.pcap"
PAGES = {"/": "index.html", "/alerts": "alerts.html", "/flows": "flows.html",
         "/export": "export.html", "/settings": "settings.html"}
KEEP = {"status_update", "stats_update", "system_health", "alert_update", "flow_batch"}


def record(speed: float = 2.5):
    tmp = Path(tempfile.mkdtemp())
    cfg = json.loads((ROOT / "tests/fixtures/config.json").read_text())
    cfg.update(interface="eth0", replay_dir=str(ROOT / "test_pcaps"))
    (tmp / "config.json").write_text(json.dumps(cfg))
    os.environ["IDS_CONFIG"] = str(tmp / "config.json")
    sys.path.insert(0, str(ROOT))
    if not (ROOT / "test_pcaps" / PCAP).exists():
        sys.path.insert(0, str(ROOT / "tests"))
        import make_pcaps
        make_pcaps.main(ROOT / "test_pcaps")
    import app as A

    client = A.socketio.test_client(A.app)
    client.get_received()
    events, t0 = [], time.time()

    def drain():
        for e in client.get_received():
            if e["name"] in KEEP:
                events.append({"t": int((time.time() - t0) * 1000), "name": e["name"],
                               "data": e["args"][0] if e["args"] else None})

    client.emit("start_ids", {"pcap": PCAP, "speed": speed})
    while time.time() - t0 < 180:
        drain()
        if not A.rt.running and A.rt.last_totals["packets"]:
            break
        time.sleep(0.05)
    time.sleep(1.5)
    drain()
    return A, events


def rewrite(html: str) -> str:
    html = html.replace('href="/static/', 'href="static/').replace('src="/static/', 'src="static/')
    for path, name in PAGES.items():
        html = html.replace(f'href="{path}"', f'href="{name}"')
    return html.replace('<script src="static/js/vendor/socket.io.min.js"></script>',
                        '<script src="demo-shim.js"></script>')


def main():
    A, events = record()
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    http = A.app.test_client()
    for path, name in PAGES.items():
        (OUT / name).write_text(rewrite(http.get(path).get_data(as_text=True)), encoding="utf-8")
    shutil.copytree(ROOT / "static", OUT / "static", ignore=shutil.ignore_patterns("vendor"))
    shutil.copy(ROOT / "tools" / "demo-shim.js", OUT / "demo-shim.js")
    (OUT / "events.json").write_text(json.dumps(events, separators=(",", ":"), default=str))
    (ROOT / "docs" / "index.html").write_text(
        '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=demo/">'
        '<a href="demo/">Open the live demo</a>')
    alerts = {a["id"]: a["outcome"] for e in events if e["name"] == "alert_update" for a in e["data"]["alerts"]}
    print(f"events: {len(events)} over {events[-1]['t'] / 1000:.1f}s; alerts: {sorted(alerts.values())}")
    print(f"wrote {OUT} ({sum(f.stat().st_size for f in OUT.rglob('*') if f.is_file()) // 1024} KB)")


if __name__ == "__main__":
    main()
