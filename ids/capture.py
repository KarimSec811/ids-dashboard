"""Packet sources: live capture (pyshark/tshark) and PCAP replay.

Runs in a plain OS thread, so pyshark's asyncio machinery gets its own event
loop and nothing here can block the web server.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("ids.capture")


class CaptureError(RuntimeError):
    """Raised for problems the operator can fix (tshark missing, bad interface...)."""


class CaptureSession:
    """One capture run. ``run()`` blocks until the source ends or ``stop()``."""

    def __init__(self, analyzer, *, interface: Optional[str] = None, bpf: Optional[str] = None,
                 pcap_path: Optional[Path] = None, speed: float = 0.0,
                 on_packet: Optional[Callable[[int], None]] = None):
        self.analyzer = analyzer
        self.interface = interface
        self.bpf = bpf or None
        self.pcap_path = Path(pcap_path) if pcap_path else None
        self.speed = float(speed or 0.0)          # replay only: 0 = as fast as possible
        self.on_packet = on_packet
        self.packets = 0
        self._stop = threading.Event()
        self._capture = None

    @property
    def mode(self) -> str:
        return 'replay' if self.pcap_path else 'live'

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # -- control ----------------------------------------------------------
    def stop(self) -> None:
        """Ask the capture to end. For live capture the generator would stay
        blocked until the next packet arrives, so the tshark child is
        terminated explicitly; the packet loop then sees EOF immediately."""
        self._stop.set()
        cap = self._capture
        if cap is None:
            return
        for proc in list(getattr(cap, '_running_processes', ()) or ()):
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    # -- main loop --------------------------------------------------------
    def run(self) -> None:
        try:
            import pyshark
        except ImportError as exc:
            raise CaptureError("pyshark is not installed (pip install pyshark)") from exc

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            if self.pcap_path:
                if not self.pcap_path.is_file():
                    raise CaptureError(f"PCAP not found: {self.pcap_path.name}")
                cap = pyshark.FileCapture(str(self.pcap_path), keep_packets=False, eventloop=loop)
                source = iter(cap)
            else:
                if not self.interface:
                    raise CaptureError("No capture interface configured")
                cap = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf,
                                          eventloop=loop)
                source = cap.sniff_continuously()
            self._capture = cap
            prev_ts = None
            try:
                for packet in source:
                    if self._stop.is_set():
                        break
                    if self.speed > 0:
                        prev_ts = self._pace(packet, prev_ts)
                    self.analyzer.process_packet(packet)
                    self.packets += 1
                    if self.on_packet is not None and self.packets % 200 == 0:
                        self.on_packet(self.packets)
            except Exception as exc:
                # Terminating tshark on purpose makes pyshark complain; that is not an error.
                if not self._stop.is_set():
                    raise self._translate(exc) from exc
        finally:
            self._close(loop)

    def _pace(self, packet, prev_ts):
        try:
            ts = float(packet.sniff_time.timestamp())
        except Exception:
            return prev_ts
        if prev_ts is not None and ts > prev_ts:
            self._stop.wait(min((ts - prev_ts) / self.speed, 0.25))
        return ts

    def _translate(self, exc: Exception) -> Exception:
        name = type(exc).__name__
        text = str(exc)
        if name == 'TSharkNotFoundException' or 'tshark' in text.lower() and 'not' in text.lower():
            return CaptureError("tshark was not found. Install Wireshark/tshark and make sure it is on PATH.")
        if 'dumpcap' in text.lower() and ('crash' in text.lower() or name == 'TSharkCrashException'):
            target = f" '{self.interface}'" if getattr(self, 'interface', None) else ''
            return CaptureError(f"Capture could not start on interface{target}: dumpcap exited immediately. "
                                "Check the interface name (tshark -D) and that you have capture privileges.")
        if 'permission' in text.lower() or 'privilege' in text.lower():
            return CaptureError("Not permitted to capture. Run with capture privileges "
                                "(Administrator / root / CAP_NET_RAW) or fix the dumpcap permissions.")
        if 'no such device' in text.lower() or "doesn't exist" in text.lower() or 'does not exist' in text.lower():
            return CaptureError(f"Capture interface not found: {text.strip()[:160]}")
        return CaptureError(f"{name}: {text.strip()[:200]}")

    def _close(self, loop) -> None:
        cap, self._capture = self._capture, None
        if cap is not None:
            try:
                cap.close()
            except Exception:
                logger.debug("capture close failed", exc_info=True)
        try:
            loop.close()
        except Exception:
            pass
