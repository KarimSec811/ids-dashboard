from types import SimpleNamespace

from ids.capture import CaptureSession


class RecordingEvent:
    def __init__(self, result=False):
        self.timeouts = []
        self.result = result

    def wait(self, timeout=None):
        self.timeouts.append(timeout)
        return self.result

    def is_set(self):
        return self.result


def packet(ts):
    return SimpleNamespace(sniff_time=SimpleNamespace(timestamp=lambda: ts))


def test_pace_preserves_intervals_longer_than_250ms():
    session = CaptureSession(analyzer=None, pcap_path="capture.pcap", speed=1.0)
    event = RecordingEvent()
    session._stop = event

    assert session._pace(packet(105.0), 100.0) == 105.0
    assert event.timeouts == [5.0]


def test_pace_applies_speed_multiplier():
    session = CaptureSession(analyzer=None, pcap_path="capture.pcap", speed=2.0)
    event = RecordingEvent()
    session._stop = event

    session._pace(packet(104.0), 100.0)
    assert event.timeouts == [2.0]


def test_pace_does_not_wait_for_non_monotonic_timestamp():
    session = CaptureSession(analyzer=None, pcap_path="capture.pcap", speed=1.0)
    event = RecordingEvent()
    session._stop = event

    assert session._pace(packet(99.0), 100.0) == 99.0
    assert event.timeouts == []


def test_pace_leaves_previous_timestamp_when_timestamp_is_unavailable():
    session = CaptureSession(analyzer=None, pcap_path="capture.pcap", speed=1.0)
    event = RecordingEvent()
    session._stop = event
    bad_packet = SimpleNamespace(sniff_time=None)

    assert session._pace(bad_packet, 100.0) == 100.0
    assert event.timeouts == []


def test_pace_wait_is_interruptible():
    session = CaptureSession(analyzer=None, pcap_path="capture.pcap", speed=1.0)
    event = RecordingEvent(result=True)
    session._stop = event

    session._pace(packet(110.0), 100.0)
    assert event.timeouts == [10.0]
    assert session.stopping is True
