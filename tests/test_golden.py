"""Golden regression: each labelled PCAP must raise exactly the expected alerts.

Runs the real pyshark/tshark replay path. If a detector change alters one of these,
the test fails -- update the expectation deliberately, never silently.
"""
import shutil
import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from ids.capture import CaptureSession  # noqa: E402
from ids.engine import NullSink, PacketAnalyzer  # noqa: E402
from ids.settings import Settings  # noqa: E402

GOLDEN = {
    "normal_web.pcap": [],                      # page loads: 6 parallel connections per server
    "browsing_many_hosts.pcap": [],             # one client, 25 different servers, all successful
    "syn_flood.pcap": ["neptune"],              # 600 SYNs from spoofed sources, one victim
    "port_scan.pcap": ["portsweep"],            # 60 ports on one host, closed ports answer RST
    "ip_sweep.pcap": ["ipsweep"],               # SYN to 40 hosts, nobody answers
    "demo_mixed.pcap": ["ipsweep", "neptune", "portsweep"],
}


class _Sink(NullSink):
    def __init__(self):
        self.new = []

    def on_alert(self, kind, alert):
        if kind == "new":
            self.new.append(alert["outcome"])


@pytest.fixture(scope="module", autouse=True)
def pcaps():
    import make_pcaps
    make_pcaps.main(ROOT / "test_pcaps")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_pcap_raises_expected_alerts(name):
    warnings.filterwarnings("ignore")
    analyzer = PacketAnalyzer(Settings(ROOT / "tests" / "fixtures" / "config.json").analyzer_config(), sink := _Sink())
    CaptureSession(analyzer, pcap_path=ROOT / "test_pcaps" / name).run()
    analyzer.flush()
    assert sorted(sink.new) == GOLDEN[name]
