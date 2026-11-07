"""Detection engine: connection tracking, NSL-KDD-style features, scoring, alerts.

This module is deliberately free of Flask / Socket.IO / pyshark imports. It only
needs objects that look like pyshark packets, so it can be unit-tested with fake
packets and reused behind any front-end.

Design notes (what changed compared with the first rewrite):

* Services are derived from the *responder's* port (the originator's ephemeral
  or spoofed source port never decides the service).
* The cross-flow tracker works on a 2-second *start-time* window kept in
  per-host / per-service deques, so a lookup costs O(window), not O(all flows),
  and every structure is pruned (no unbounded dicts).
* Port/host sweeps are counted from *failed probes only* (refused, reset or
  unanswered attempts), so ordinary browsing never looks like a sweep.
* Scoring ignores range conditions that can never fail (e.g. a rate in [0, 1])
  and treats volume counters as lower-bounded only, so a *bigger* flood is never
  scored as *less* of a flood.
* Alerts are aggregated (one alert per attacker/victim pair or per victim for
  DoS-style attacks) instead of one alert per packet.
"""
from __future__ import annotations

import logging
import math
import re
import time
import uuid
import zlib
from collections import Counter, OrderedDict, deque
from datetime import datetime
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("ids.engine")

# --------------------------------------------------------------------------
# Constants / lookup tables
# --------------------------------------------------------------------------

SERROR_FLAGS = {"S0", "S1", "S2", "S3"}
REJ_FLAG = "REJ"

# Connection states that describe a connection that has not (yet) done anything
# useful: still half-open, refused, or reset before any data moved.
UNANSWERED_FLAGS = {"S0", "S1", "S2", "S3", "SH", "REJ", "RSTO", "RSTOS0"}
TRANSIENT_FLAGS = {"S0", "S1", "S2", "S3", "SH"}

# Cleartext services where payload keyword heuristics are meaningful. Encrypted
# protocols (ssh, rdp, tls) are excluded on purpose: random ciphertext matches
# short keyword patterns by chance.
LOGIN_SERVICES = {"ftp", "telnet", "pop_3", "pop_2", "imap4", "smtp", "login",
                  "shell", "exec", "klogin", "kshell"}
SHELL_SERVICES = {"telnet", "shell", "login", "exec", "klogin", "kshell"}
HTTP_SERVICES = {"http", "http_443", "http_2784", "http_8001"}

FAILED_LOGIN_RE = re.compile(
    rb"login incorrect|access denied|authentication failed|permission denied"
    rb"|login failed|incorrect password|^530[ -]|^-ERR[^\r\n]*(auth|login|password)",
    re.IGNORECASE | re.MULTILINE,
)
SUCCESS_LOGIN_RE: Dict[str, "re.Pattern[bytes]"] = {
    "ftp": re.compile(rb"^230[ -]", re.MULTILINE),
    "telnet": re.compile(rb"welcome|last login|login successful", re.IGNORECASE),
    "pop_3": re.compile(rb"^\+OK[^\r\n]*(logged|maildrop|authenticated)", re.IGNORECASE | re.MULTILINE),
    "imap4": re.compile(rb"^\S+ OK[^\r\n]*(logged in|authenticated)", re.IGNORECASE | re.MULTILINE),
}
HTTP_RESPONSE_RE = re.compile(rb"^HTTP/1\.[01] \d{3}", re.MULTILINE)
SHELL_COMMAND_PATTERNS = (b"/bin/sh", b"/bin/bash", b"cmd.exe", b"root@", b"sudo ")
FILE_OP_KEYWORDS = (b"retr ", b"stor ", b"download", b"upload")
GUEST_KEYWORDS = (b"anonymous", b"guest")
CONTENT_SCAN_BYTES = 4096          # never regex-scan more than this per packet

# NSL-KDD 'service' feature: mapped mostly by well-known port number.
PORT_SERVICE_MAP = {
    7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime', 19: 'chargen', 20: 'ftp_data',
    21: 'ftp', 22: 'ssh', 23: 'telnet', 24: 'mtp', 25: 'smtp', 37: 'time', 42: 'name',
    43: 'whois', 49: 'login', 53: 'domain', 67: 'csnet_ns', 68: 'csnet_ns', 69: 'tftp_u',
    70: 'gopher', 79: 'finger', 80: 'http', 87: 'link', 95: 'supdup', 101: 'hostname',
    102: 'iso_tsap', 105: 'csnet_ns', 106: 'pop_2', 109: 'pop_2', 110: 'pop_3',
    111: 'sunrpc', 119: 'nntp', 123: 'ntp_u', 137: 'netbios_ns', 138: 'netbios_dgm',
    139: 'netbios_ssn', 143: 'imap4', 150: 'sql_net', 152: 'bftp', 161: 'pm_dump',
    162: 'pm_dump', 170: 'print-srv', 177: 'X11', 179: 'bgp', 389: 'ldap', 443: 'http_443',
    445: 'private', 512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 520: 'rje',
    522: 'supdup', 525: 'tim_i', 526: 'tempo', 530: 'courier', 532: 'netnews',
    540: 'uucp', 543: 'klogin', 544: 'kshell', 546: 'eco_i', 547: 'eco_i', 554: 'rtsp',
    561: 'efc', 600: 'ipcserver', 631: 'printer', 993: 'imap4', 995: 'pop_3',
    1080: 'socks', 1433: 'sql_net', 1434: 'sql_net', 1521: 'sql_net', 1701: 'mtp',
    1720: 'h323', 1723: 'pptp', 2049: 'nfs', 2784: 'http_2784', 3306: 'sql_net',
    3389: 'vmnet', 5000: 'other', 5432: 'postgres', 6000: 'X11', 6379: 'redis',
    6667: 'IRC', 7000: 'afs', 8001: 'http_8001', 8080: 'http', 8081: 'http',
    8888: 'http', 8889: 'http', 9999: 'Z39_50', 27017: 'mongodb', 27018: 'other',
    31337: 'red_i',
}
UDP_SERVICE_OVERRIDES = {53: 'domain_u'}
ICMP_TYPE_SERVICE_MAP = {
    0: 'ecr_i', 8: 'ecr_i',      # echo reply / echo request
    13: 'tim_i', 14: 'tim_i',    # timestamp request / reply
    3: 'urp_i',                  # destination unreachable
}

# Fields that are bounded to [0, 1] -- a [0, 1] range on them can never fail.
RATE_FIELDS = frozenset({
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
})
BINARY_FIELDS = frozenset({'logged_in', 'is_guest_login', 'is_host_login', 'land',
                           'root_shell', 'su_attempted'})
# Volume counters from the 2-second window. Only their lower bound is meaningful.
OPEN_ENDED_FIELDS = frozenset({'count', 'srv_count'})
HOST_WINDOW_FIELDS = frozenset({'dst_host_count', 'dst_host_srv_count'})  # capped by the 100-conn window


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def get_service(src_port: Optional[int], dst_port: Optional[int], protocol_type: str = 'TCP') -> str:
    """NSL-KDD service name.

    ``src_port`` is the originator's port and ``dst_port`` the responder's. Only
    the responder port decides the service, so a scanner that fixes its source
    port to 53 or 80 (``nmap -g``) is not mislabelled. The one exception is
    active-mode FTP, where the *server* originates the data connection from
    port 20.
    """
    if protocol_type == 'TCP' and src_port == 20:
        return 'ftp_data'
    if protocol_type == 'UDP' and dst_port in UDP_SERVICE_OVERRIDES:
        return UDP_SERVICE_OVERRIDES[dst_port]
    return PORT_SERVICE_MAP.get(dst_port, 'other')


def get_icmp_service(icmp_type: Optional[int]) -> str:
    return ICMP_TYPE_SERVICE_MAP.get(icmp_type, 'other')


def to_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def compute_entropy(values: Iterable[Any]) -> float:
    values = list(values)
    if not values:
        return 0.0
    counts = Counter(values)
    total = sum(counts.values())
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c)


def iso(ts: float) -> str:
    """Naive local ISO timestamp (same format the dashboard has always used)."""
    return datetime.fromtimestamp(ts).isoformat()


def _as_list(value) -> List[str]:
    return value if isinstance(value, list) else [value]


def get_layer_payload_bytes(layer) -> bytes:
    """pyshark exposes a segment's data as a colon-separated hex string
    ('47:45:54:20'). It must be hex-decoded, not utf-8 encoded."""
    raw = (getattr(layer, 'payload', None) or getattr(layer, 'segment_data', None)
           or getattr(layer, 'data', None))
    if raw is None:
        return b''
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    try:
        return bytes.fromhex(str(raw).replace(':', ''))
    except ValueError:
        return b''


def get_packet_payload(packet) -> bytes:
    for proto_name in ('tcp', 'udp'):
        layer = getattr(packet, proto_name, None)
        if layer is not None:
            payload = get_layer_payload_bytes(layer)
            if payload:
                return payload
    # ICMP payload is a nested sub-layer (packet.icmp.data).
    for proto_name in ('icmp', 'icmpv6'):
        icmp_layer = getattr(packet, proto_name, None)
        if icmp_layer is not None:
            data_sublayer = getattr(icmp_layer, 'data', None)
            if data_sublayer is not None:
                payload = get_layer_payload_bytes(data_sublayer)
                if payload:
                    return payload
    return b''


def clean_text(value: Any, limit: int = 253) -> str:
    """Printable-ASCII-ish, length-capped copy of an attacker-controlled string
    (reverse DNS, SNI, DNS query names...). Defence in depth: the UI must still
    escape it, but control characters never need to reach the UI at all."""
    text = str(value)
    return ''.join(ch for ch in text if ch.isprintable())[:limit]


# --------------------------------------------------------------------------
# TCP connection state -> KDD/Zeek-style 'flag'
# --------------------------------------------------------------------------

class ConnState:
    """Tracks one connection's TCP lifecycle to derive a KDD/Zeek-style state:
    SF, S0, S1, S2, S3, REJ, RSTO, RSTR, RSTOS0, SH, OTH. It describes the
    outcome of the WHOLE connection, not any one packet."""

    __slots__ = ('syn_seen', 'synack_seen', 'established', 'fin_orig',
                 'fin_resp', 'rst_orig', 'rst_resp', 'any_data', 'ack_after_synack')

    def __init__(self):
        self.syn_seen = False
        self.synack_seen = False
        self.established = False
        self.fin_orig = False
        self.fin_resp = False
        self.rst_orig = False
        self.rst_resp = False
        self.any_data = False
        self.ack_after_synack = False   # originator completed the 3-way handshake

    def observe(self, is_orig: bool, syn: bool, ack: bool, fin: bool, rst: bool, has_payload: bool) -> None:
        if rst:
            if is_orig:
                self.rst_orig = True
            else:
                self.rst_resp = True
            return
        if syn and not ack:
            if is_orig:
                self.syn_seen = True
        elif syn and ack:
            if not is_orig:
                self.synack_seen = True
        if fin:
            if is_orig:
                self.fin_orig = True
            else:
                self.fin_resp = True
        if has_payload:
            self.any_data = True
        if is_orig and ack and not syn and self.synack_seen:
            self.ack_after_synack = True
        if self.synack_seen:
            # Zeek semantics: once the responder answered the SYN the
            # connection counts as established (S1) until torn down.
            self.established = True

    @property
    def flag(self) -> str:
        if self.rst_orig:
            return 'RSTO' if (self.established or self.synack_seen) else 'RSTOS0'
        if self.rst_resp:
            return 'RSTR' if (self.established or self.synack_seen) else 'REJ'
        if self.syn_seen and not self.synack_seen:
            return 'SH' if self.fin_orig else 'S0'
        if self.established or self.any_data:
            if self.fin_orig and self.fin_resp:
                return 'SF'
            if self.fin_orig:
                return 'S2'
            if self.fin_resp:
                return 'S3'
            return 'S1'
        return 'OTH'

    @property
    def closed(self) -> bool:
        return self.rst_orig or self.rst_resp or (self.fin_orig and self.fin_resp)

    @property
    def half_open(self) -> bool:
        """SYN seen but the handshake was never completed by the originator.
        True for a classic SYN flood whether or not the SYN-ACK is visible to this
        sensor, and also when the attacker's own kernel answers each SYN-ACK with a
        RST (what hping3 does from a real host). A RST from the *responder* is a
        refusal (closed port), not a half-open connection."""
        return self.syn_seen and not self.ack_after_synack and not self.rst_resp


# --------------------------------------------------------------------------
# Cross-flow aggregation (count / srv_count / *error_rate / dst_host_* / sweeps)
# --------------------------------------------------------------------------

class ConnRecord:
    __slots__ = ('flow_id', 'start_ts', 'timestamp', 'src_ip', 'src_port', 'dst_ip',
                 'dst_port', 'service', 'protocol_type', 'flag', 'total_bytes',
                 'answered', 'counted', 'pending', 'half_open')

    def __init__(self, flow_id, timestamp, src_ip, src_port, dst_ip, dst_port,
                 service, protocol_type, flag):
        self.flow_id = flow_id
        self.start_ts = timestamp
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.service = service
        self.protocol_type = protocol_type
        self.flag = flag
        self.total_bytes = 0
        self.answered = True
        self.counted = False   # already counted as a failed probe
        self.pending = False   # waiting in the half-open grace queue
        self.half_open = False  # handshake not completed (SYN flood signal)


class _ReconWindow:
    """Failed probes of ONE source inside ONE time window (bounded)."""
    __slots__ = ('events', 'ports', 'hosts_by_port')

    def __init__(self):
        self.events: Deque[Tuple[float, str, int]] = deque()
        self.ports: Dict[str, Dict[int, int]] = {}             # victim -> {port: attempts}
        self.hosts_by_port: Dict[int, Dict[str, int]] = {}     # port -> {victim: attempts}

    def add(self, now: float, dst: str, port: int, cap: int) -> None:
        self.events.append((now, dst, port))
        p = self.ports.setdefault(dst, {})
        p[port] = p.get(port, 0) + 1
        h = self.hosts_by_port.setdefault(port, {})
        h[dst] = h.get(dst, 0) + 1
        if len(self.events) > cap:
            self.drop_oldest()

    def drop_oldest(self) -> None:
        _, dst, port = self.events.popleft()
        p = self.ports.get(dst)
        if p is not None:
            n = p.get(port, 0) - 1
            if n <= 0:
                p.pop(port, None)
            else:
                p[port] = n
            if not p:
                del self.ports[dst]
        h = self.hosts_by_port.get(port)
        if h is not None:
            n = h.get(dst, 0) - 1
            if n <= 0:
                h.pop(dst, None)
            else:
                h[dst] = n
            if not h:
                del self.hosts_by_port[port]

    def prune(self, now: float, seconds: float) -> None:
        while self.events and now - self.events[0][0] > seconds:
            self.drop_oldest()

    def distinct_ports(self, dst: str) -> int:
        return len(self.ports.get(dst, ()))

    def max_hosts(self) -> int:
        """Most distinct victims probed on any ONE port (Zeek's definition of an address scan)."""
        return max((len(h) for h in self.hosts_by_port.values()), default=0)


class _SrcRecon:
    """Failed-probe history of one source address: a fast and a slow window, plus half-open probes
    that have not yet outlived the grace period."""
    __slots__ = ('fast', 'slow', 'pending', 'last_ts')

    def __init__(self):
        self.fast = _ReconWindow()
        self.slow = _ReconWindow()
        self.pending: Deque[ConnRecord] = deque()
        self.last_ts = 0.0


def _frac(records, predicate, total: int) -> float:
    if not total:
        return 0.0
    return sum(1 for r in records if predicate(r)) / total


class HostConnectionTracker:
    """Holds the two windows NSL-KDD defines over *other* recent connections:

    * 'traffic' features (count, srv_count, *error_rate, same/diff_srv_rate):
      connections *started* in the last 2 seconds.
    * 'host' features (dst_host_*): the last 100 connections to the same host.

    It also keeps a bounded failed-probe history per source for the
    deterministic portsweep / ipsweep detectors.
    """

    TIME_WINDOW_SECONDS = 2.0
    HOST_WINDOW_SIZE = 100
    STALE_RECORD_SECONDS = 120.0
    MAX_WINDOW_RECORDS = 5000        # per host / per service window
    MAX_RECON_EVENTS = 4096          # per source
    MAX_TRACKED_SOURCES = 20000
    MAX_RECORDS = 200000

    def __init__(self, portsweep_port_threshold: int = 20, ipsweep_host_threshold: int = 20,
                 recon_window_seconds: float = 10.0, probe_grace_seconds: float = 2.0,
                 slow_window_seconds: float = 300.0, slow_port_threshold: int = 15,
                 slow_host_threshold: int = 25):
        self.portsweep_port_threshold = int(portsweep_port_threshold)
        self.ipsweep_host_threshold = int(ipsweep_host_threshold)
        self.recon_window_seconds = float(recon_window_seconds)
        self.probe_grace_seconds = float(probe_grace_seconds)
        self.slow_window_seconds = float(slow_window_seconds)
        self.slow_port_threshold = int(slow_port_threshold)
        self.slow_host_threshold = int(slow_host_threshold)
        self._records: Dict[str, ConnRecord] = {}
        self._win_dst: Dict[str, Deque[ConnRecord]] = {}
        self._win_srv: Dict[str, Deque[ConnRecord]] = {}
        self._host_order: Dict[str, Deque[ConnRecord]] = {}
        self._recon: Dict[str, _SrcRecon] = {}
        self._new_probes: List[ConnRecord] = []
        self._ops = 0

    # -- bookkeeping ----------------------------------------------------
    def update(self, flow_id: str, timestamp: float, src_ip: str, src_port: int,
               dst_ip: str, dst_port: int, service: str, protocol_type: str,
               flag: str, *, total_bytes: int = 0, answered: bool = True,
               half_open: bool = False) -> None:
        rec = self._records.get(flow_id)
        if rec is None:
            rec = ConnRecord(flow_id, timestamp, src_ip, src_port, dst_ip, dst_port,
                             service, protocol_type, flag)
            self._records[flow_id] = rec
            self._push(self._win_dst, dst_ip, rec)
            self._push(self._win_srv, service, rec)
            hq = self._host_order.get(dst_ip)
            if hq is None:
                hq = self._host_order[dst_ip] = deque(maxlen=self.HOST_WINDOW_SIZE)
            hq.append(rec)
        else:
            rec.timestamp = timestamp
            rec.flag = flag
            rec.service = service
        rec.total_bytes = total_bytes
        rec.answered = answered
        rec.half_open = half_open
        self._track_probe(rec, timestamp)
        self._ops += 1
        if self._ops % 2000 == 0 or len(self._records) > self.MAX_RECORDS:
            self.expire(timestamp)

    def _push(self, table: Dict[str, Deque[ConnRecord]], key: str, rec: ConnRecord) -> None:
        dq = table.get(key)
        if dq is None:
            dq = table[key] = deque(maxlen=self.MAX_WINDOW_RECORDS)
        dq.append(rec)

    def _window(self, table: Dict[str, Deque[ConnRecord]], key: str, now: float):
        dq = table.get(key)
        if not dq:
            return ()
        limit = self.TIME_WINDOW_SECONDS
        while dq and now - dq[0].start_ts > limit:
            dq.popleft()
        if not dq:
            del table[key]
            return ()
        return dq

    def forget(self, flow_id: str) -> None:
        self._records.pop(flow_id, None)

    def is_probe(self, flow_id: str) -> bool:
        rec = self._records.get(flow_id)
        return bool(rec and rec.counted)

    def stats(self) -> Dict[str, int]:
        return {
            'records': len(self._records),
            'dst_windows': len(self._win_dst),
            'srv_windows': len(self._win_srv),
            'host_windows': len(self._host_order),
            'recon_sources': len(self._recon),
        }

    # -- NSL-KDD features -----------------------------------------------
    def time_based_features(self, dst_ip: str, service: str, now: float,
                            dst_port: Optional[int] = None) -> Dict[str, float]:
        same_host = self._window(self._win_dst, dst_ip, now)
        same_srv = self._window(self._win_srv, service, now)
        count = len(same_host)
        srv_count = len(same_srv)
        h_serr = h_rerr = h_same = h_half = h_half_port = 0
        for r in same_host:
            if r.half_open:
                h_half += 1
                if dst_port is None or r.dst_port == dst_port:
                    h_half_port += 1
            if r.flag in SERROR_FLAGS:
                h_serr += 1
            elif r.flag == REJ_FLAG:
                h_rerr += 1
            if r.service == service:
                h_same += 1
        s_serr = s_rerr = s_diff_host = 0
        for r in same_srv:
            if r.flag in SERROR_FLAGS:
                s_serr += 1
            elif r.flag == REJ_FLAG:
                s_rerr += 1
            if r.dst_ip != dst_ip:
                s_diff_host += 1
        return {
            'count': count,
            'srv_count': srv_count,
            'half_open_count': h_half,
            'half_open_rate': h_half / count if count else 0.0,
            # a flood hammers ONE port; a scan of open ports touches many
            'half_open_same_port_rate': h_half_port / h_half if h_half else 0.0,
            'serror_rate': h_serr / count if count else 0.0,
            'rerror_rate': h_rerr / count if count else 0.0,
            'same_srv_rate': h_same / count if count else 0.0,
            'diff_srv_rate': (count - h_same) / count if count else 0.0,
            'srv_serror_rate': s_serr / srv_count if srv_count else 0.0,
            'srv_rerror_rate': s_rerr / srv_count if srv_count else 0.0,
            'srv_diff_host_rate': s_diff_host / srv_count if srv_count else 0.0,
        }

    def host_based_features(self, src_ip: str, src_port: int, dst_ip: str, service: str) -> Dict[str, float]:
        window = list(self._host_order.get(dst_ip, ()))
        n = len(window)
        same_srv = [r for r in window if r.service == service]
        m = len(same_srv)
        return {
            'dst_host_count': n,
            'dst_host_srv_count': m,
            'dst_host_same_srv_rate': m / n if n else 0.0,
            'dst_host_diff_srv_rate': (n - m) / n if n else 0.0,
            'dst_host_same_src_port_rate': _frac(window, lambda r: r.src_port == src_port, n),
            # Source-diversity proxy for the original feature.
            'dst_host_srv_diff_host_rate': _frac(same_srv, lambda r: r.src_ip != src_ip, m),
            'dst_host_serror_rate': _frac(window, lambda r: r.flag in SERROR_FLAGS, n),
            'dst_host_srv_serror_rate': _frac(same_srv, lambda r: r.flag in SERROR_FLAGS, m),
            'dst_host_rerror_rate': _frac(window, lambda r: r.flag == REJ_FLAG, n),
            'dst_host_srv_rerror_rate': _frac(same_srv, lambda r: r.flag == REJ_FLAG, m),
        }

    # -- failed-probe tracking (portsweep / ipsweep) ----------------------
    def _probe_state(self, rec: ConnRecord, now: float) -> Optional[bool]:
        """True: counts as a failed probe now. False: definitely not a probe.
        None: undecided (half-open, still inside the grace period)."""
        flag = rec.flag
        if flag in ('REJ', 'RSTOS0'):
            return True
        if flag in ('S0', 'SH'):
            return True if now - rec.start_ts >= self.probe_grace_seconds else None
        if flag == 'RSTO' and rec.total_bytes == 0:
            return True                      # connect()-then-RST scan
        if rec.protocol_type == 'ICMP' and not rec.answered:
            return True if now - rec.start_ts >= self.probe_grace_seconds else None
        return False

    def _track_probe(self, rec: ConnRecord, now: float) -> None:
        r = self._recon.get(rec.src_ip)
        if not rec.counted:
            state = self._probe_state(rec, now)
            if state is True:
                r = r or self._new_recon(rec.src_ip)
                self._count_probe(r, rec, now)
            elif state is None and not rec.pending:
                r = r or self._new_recon(rec.src_ip)
                rec.pending = True
                r.pending.append(rec)
        if r is not None:
            r.last_ts = now
            self._resolve_pending(r, now)
            self._prune_recon(r, now)

    def _new_recon(self, src_ip: str) -> _SrcRecon:
        r = self._recon[src_ip] = _SrcRecon()
        return r

    def _resolve_pending(self, r: _SrcRecon, now: float) -> None:
        grace = self.probe_grace_seconds
        while r.pending and now - r.pending[0].start_ts >= grace:
            rec = r.pending.popleft()
            rec.pending = False
            if not rec.counted and self._probe_state(rec, now) is True:
                self._count_probe(r, rec, now)

    def drain_new_probes(self) -> List[ConnRecord]:
        """Probes counted since the last call. Probes can mature long after their last packet
        (half-open grace), so sweep verdicts are driven by this queue, not only by the packet
        being processed."""
        out, self._new_probes = self._new_probes, []
        return out

    def _count_probe(self, r: _SrcRecon, rec: ConnRecord, now: float) -> None:
        rec.counted = True
        if len(self._new_probes) < 5000:
            self._new_probes.append(rec)
        r.fast.add(now, rec.dst_ip, rec.dst_port, self.MAX_RECON_EVENTS)
        r.slow.add(now, rec.dst_ip, rec.dst_port, self.MAX_RECON_EVENTS)

    def _prune_recon(self, r: _SrcRecon, now: float) -> None:
        r.fast.prune(now, self.recon_window_seconds)
        r.slow.prune(now, max(self.slow_window_seconds, self.recon_window_seconds))

    def recon_verdict(self, src_ip: str, dst_ip: str, now: Optional[float] = None
                      ) -> Optional[Tuple[str, int, float]]:
        """('portsweep'|'ipsweep', distinct count, window seconds) or None.

        Two windows, as in production tools: a short one that catches fast scanners and a long one
        (Zeek's default: 15 ports / 25 hosts in 5 minutes) that catches slow ones. Only FAILED
        attempts count, and an address scan means many hosts on ONE port."""
        r = self._recon.get(src_ip)
        if r is None:
            return None
        if now is not None:
            self._prune_recon(r, now)
        for win, secs, port_thr, host_thr in (
                (r.fast, self.recon_window_seconds, self.portsweep_port_threshold, self.ipsweep_host_threshold),
                (r.slow, self.slow_window_seconds, self.slow_port_threshold, self.slow_host_threshold)):
            ports = win.distinct_ports(dst_ip)
            if ports >= port_thr:
                return 'portsweep', ports, secs
            hosts = win.max_hosts()
            if hosts >= host_thr:
                return 'ipsweep', hosts, secs
        return None

    def check_portsweep(self, src_ip: str, dst_ip: str, now: Optional[float] = None) -> Tuple[bool, int]:
        r = self._recon.get(src_ip)
        if r is None:
            return False, 0
        if now is not None:
            self._prune_recon(r, now)
        fast, slow = r.fast.distinct_ports(dst_ip), r.slow.distinct_ports(dst_ip)
        return (fast >= self.portsweep_port_threshold or slow >= self.slow_port_threshold), max(fast, slow)

    def check_ipsweep(self, src_ip: str, now: Optional[float] = None) -> Tuple[bool, int]:
        r = self._recon.get(src_ip)
        if r is None:
            return False, 0
        if now is not None:
            self._prune_recon(r, now)
        fast, slow = r.fast.max_hosts(), r.slow.max_hosts()
        return (fast >= self.ipsweep_host_threshold or slow >= self.slow_host_threshold), max(fast, slow)

    # -- garbage collection ----------------------------------------------
    def expire(self, now: float) -> None:
        cutoff = now - self.STALE_RECORD_SECONDS
        for fid in [fid for fid, rec in self._records.items() if rec.timestamp < cutoff]:
            del self._records[fid]
        if len(self._records) > self.MAX_RECORDS:          # hard cap: drop the oldest
            for fid in sorted(self._records, key=lambda k: self._records[k].timestamp)[
                    :len(self._records) - self.MAX_RECORDS]:
                del self._records[fid]
        for table in (self._win_dst, self._win_srv):
            for key in list(table):
                self._window(table, key, now)
        for host in list(self._host_order):
            dq = self._host_order[host]
            if not dq or dq[-1].timestamp < cutoff:
                del self._host_order[host]
        for src in list(self._recon):
            r = self._recon[src]
            self._resolve_pending(r, now)
            self._prune_recon(r, now)
            if not r.fast.events and not r.slow.events and not r.pending:
                del self._recon[src]                 # nothing left to remember about this source
        if len(self._recon) > self.MAX_TRACKED_SOURCES:
            for src in sorted(self._recon, key=lambda k: self._recon[k].last_ts)[
                    :len(self._recon) - self.MAX_TRACKED_SOURCES]:
                del self._recon[src]


# --------------------------------------------------------------------------
# Per-flow feature extraction
# --------------------------------------------------------------------------

class FlowFeatures:
    """One connection (both directions). ``src`` is the *originator* and ``dst``
    the *responder* -- the analyzer orients flows before creating them."""

    NAME_SCAN_PACKETS = 12     # only look for DNS/SNI/Host names in the first packets

    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, src_port: int,
                 dst_port: int, protocol_type: str, cfg: Optional[dict] = None):
        cfg = cfg or {}
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol_type = protocol_type
        self.service = get_service(src_port, dst_port, protocol_type)
        self.config = cfg
        self.monitored_ip = cfg.get('monitored_ip', dst_ip)

        self.start_time: Optional[float] = None
        self.last_time: Optional[float] = None
        self.duration = 0.0
        self.src_bytes = 0
        self.dst_bytes = 0
        self.packet_count = 0
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.wrong_fragment = 0
        self.urgent = 0
        self.land = int(src_ip == dst_ip and src_port == dst_port)

        self.conn_state = ConnState() if protocol_type == 'TCP' else None
        self.flag = 'SF' if protocol_type == 'UDP' else 'OTH'

        # Content / heuristic features: best-effort payload keyword matching on
        # cleartext protocols only. Indicative, not authoritative.
        self.hot = 0
        self.num_failed_logins = 0
        self.logged_in = False
        self.num_compromised = 0
        self.root_shell = 0
        self.su_attempted = 0
        self.num_root = 0
        self.num_file_creations = 0
        self.num_shells = 0
        self.num_access_files = 0
        self.num_outbound_cmds = 0
        self.is_host_login = False
        self.is_guest_login = 0
        self._guest_user = False

        self.names: List[str] = []          # DNS / SNI / HTTP Host names seen
        self.outcome = 'normal'
        self.confidence = 0.0
        self.level = 0
        self.last_emit_ts = 0.0
        self.last_emit_flag: Optional[str] = None
        self.last_emit_outcome: Optional[str] = None

    # -- derived --------------------------------------------------------
    @property
    def answered(self) -> bool:
        return self.bwd_packets > 0

    @property
    def closed(self) -> bool:
        return bool(self.conn_state and self.conn_state.closed)

    @property
    def half_open(self) -> bool:
        return bool(self.conn_state and self.conn_state.half_open)

    # -- observation ----------------------------------------------------
    def observe(self, packet, timestamp: float, direction: str) -> None:
        is_orig = (direction == 'fwd')
        if self.start_time is None:
            self.start_time = timestamp
        self.last_time = timestamp
        self.duration = max(0.0, self.last_time - self.start_time)
        self.packet_count += 1

        payload = get_packet_payload(packet)
        payload_len = len(payload)

        ip_layer = getattr(packet, 'ip', None)
        if ip_layer is not None:
            self._observe_fragmentation(ip_layer)

        tcp_layer = getattr(packet, 'tcp', None)
        udp_layer = getattr(packet, 'udp', None)
        icmp_layer = getattr(packet, 'icmp', None)
        if tcp_layer is not None:
            self._observe_tcp(tcp_layer, is_orig, payload_len > 0)
        elif udp_layer is not None:
            self.flag = 'SF'
        elif icmp_layer is not None:
            self._observe_icmp(icmp_layer)

        if is_orig:
            self.src_bytes += payload_len
            self.fwd_packets += 1
        else:
            self.dst_bytes += payload_len
            self.bwd_packets += 1

        self._observe_content(payload, is_orig)
        if self.packet_count <= self.NAME_SCAN_PACKETS and len(self.names) < 8:
            self._observe_names(packet)

    def _observe_fragmentation(self, ip_layer) -> None:
        try:
            frag_offset = int(getattr(ip_layer, 'frag_offset', 0) or 0)
        except (TypeError, ValueError):
            frag_offset = 0
        more_fragments = False
        mf = getattr(ip_layer, 'flags_mf', None)
        if mf is not None:
            more_fragments = str(mf).strip().lower() in ('1', 'true')
        else:
            try:
                more_fragments = bool(int(str(getattr(ip_layer, 'flags', '0x00')), 16) & 0x1)
            except (TypeError, ValueError):
                pass
        if more_fragments or frag_offset > 0:
            self.wrong_fragment += 1

    def _observe_tcp(self, tcp_layer, is_orig: bool, has_payload: bool) -> None:
        raw_flags = parse_tcp_flags(tcp_layer)
        syn = bool(raw_flags & 0x02)
        ack = bool(raw_flags & 0x10)
        fin = bool(raw_flags & 0x01)
        rst = bool(raw_flags & 0x04)
        if raw_flags & 0x20:
            self.urgent += 1
        else:
            urg_ptr = getattr(tcp_layer, 'urgent_pointer', None)
            try:
                if urg_ptr is not None and int(urg_ptr) > 0:
                    self.urgent += 1
            except (TypeError, ValueError):
                pass
        if self.conn_state is None:
            self.conn_state = ConnState()
        self.conn_state.observe(is_orig, syn, ack, fin, rst, has_payload)
        self.flag = self.conn_state.flag

    def _observe_icmp(self, icmp_layer) -> None:
        try:
            icmp_type = int(getattr(icmp_layer, 'type', -1))
        except (TypeError, ValueError):
            icmp_type = -1
        self.service = get_icmp_service(icmp_type)
        self.flag = 'REJ' if icmp_type == 3 else 'SF'

    def _observe_content(self, payload: bytes, is_orig: bool) -> None:
        if not payload:
            return
        service_l = (self.service or '').lower()
        chunk = payload[:CONTENT_SCAN_BYTES]
        lower = chunk.lower()

        if service_l in LOGIN_SERVICES:
            if FAILED_LOGIN_RE.search(chunk):
                self.num_failed_logins += 1
            if is_orig and any(k in lower for k in GUEST_KEYWORDS):
                self._guest_user = True
        if not self.logged_in and not is_orig:
            pattern = SUCCESS_LOGIN_RE.get(service_l)
            if pattern is not None and pattern.search(chunk):
                self.logged_in = True
            elif service_l in HTTP_SERVICES and HTTP_RESPONSE_RE.search(chunk):
                self.logged_in = True          # server answered the request
            if self.logged_in and self._guest_user:
                self.is_guest_login = 1
        if self.logged_in and is_orig and service_l in ('ftp', 'tftp_u'):
            if any(k in lower for k in FILE_OP_KEYWORDS):
                self.num_access_files += 1
            if b'stor ' in lower:
                self.num_file_creations += 1
        if service_l in SHELL_SERVICES and any(cmd in lower for cmd in SHELL_COMMAND_PATTERNS):
            self.num_compromised = 1
            self.num_shells += 1
            if b'root@' in lower or b'sudo ' in lower:
                self.root_shell = 1
                self.su_attempted = 1
        self.hot = int(self.num_failed_logins > 3 or self.num_access_files > 5 or self.root_shell == 1)

    def _observe_names(self, packet) -> None:
        for layer_name, attrs in (('dns', ('qry_name',)),
                                  ('tls', ('handshake_extensions_server_name',)),
                                  ('ssl', ('handshake_extensions_server_name',)),
                                  ('http', ('host',))):
            layer = getattr(packet, layer_name, None)
            if layer is None:
                continue
            for attr in attrs:
                value = getattr(layer, attr, None)
                if value:
                    name = clean_text(value).lower().rstrip('.')
                    if name and name not in self.names and len(self.names) < 8:
                        self.names.append(name)

    # -- output ---------------------------------------------------------
    def snapshot(self, tracker: HostConnectionTracker, now: float) -> Dict[str, Any]:
        """This flow's own features merged with the tracker's cross-flow
        features: one flat dict used for classification AND the dashboard."""
        time_feats = tracker.time_based_features(self.dst_ip, self.service, now, self.dst_port)
        host_feats = tracker.host_based_features(self.src_ip, self.src_port, self.dst_ip, self.service)
        features: Dict[str, Any] = {
            'duration': round(self.duration, 3),
            'protocol_type': self.protocol_type,
            'service': self.service or 'other',
            'flag': self.flag,
            'half_open': int(self.half_open),
            'src_bytes': self.src_bytes,
            'dst_bytes': self.dst_bytes,
            'land': self.land,
            'wrong_fragment': self.wrong_fragment,
            'urgent': self.urgent,
            'hot': self.hot,
            'num_failed_logins': self.num_failed_logins,
            'logged_in': int(self.logged_in),
            'num_compromised': self.num_compromised,
            'root_shell': self.root_shell,
            'su_attempted': self.su_attempted,
            'num_root': self.num_root,
            'num_file_creations': self.num_file_creations,
            'num_shells': self.num_shells,
            'num_access_files': self.num_access_files,
            'num_outbound_cmds': self.num_outbound_cmds,
            'is_host_login': int(self.is_host_login),
            'is_guest_login': self.is_guest_login,
        }
        features.update(time_feats)
        features.update(host_feats)
        for key in RATE_FIELDS:
            features[key] = round(float(features.get(key, 0.0)), 3)
        return features

    def to_record(self) -> Dict[str, Any]:
        """Compact flow-log row written when the flow ends."""
        return {
            'flow_id': self.flow_id,
            'first_seen': iso(self.start_time or 0.0),
            'last_seen': iso(self.last_time or 0.0),
            'src_ip': self.src_ip, 'src_port': self.src_port,
            'dst_ip': self.dst_ip, 'dst_port': self.dst_port,
            'protocol_type': self.protocol_type, 'service': self.service,
            'flag': self.flag, 'src_bytes': self.src_bytes, 'dst_bytes': self.dst_bytes,
            'packets': self.packet_count, 'duration': round(self.duration, 3),
            'outcome': self.outcome, 'confidence': round(self.confidence, 3),
            'names': ','.join(self.names),
        }


def parse_tcp_flags(tcp_layer) -> int:
    try:
        return int(str(tcp_layer.flags), 16)
    except (TypeError, ValueError, AttributeError):
        return 0


# --------------------------------------------------------------------------
# Signature scoring
# --------------------------------------------------------------------------

class _Signature:
    __slots__ = ('name', 'protocols', 'services', 'flags', 'zero_fields', 'ranges')

    def __init__(self, name, protocols, services, flags, zero_fields, ranges):
        self.name = name
        self.protocols = protocols
        self.services = services
        self.flags = flags
        self.zero_fields = zero_fields
        self.ranges = ranges


def _range_is_trivial(field: str, lo: float, hi: float) -> bool:
    """A condition that cannot fail (given how the feature is computed) carries
    no information; counting it only inflates the score."""
    if field in RATE_FIELDS or field in BINARY_FIELDS:
        return lo <= 0.0 and hi >= 1.0
    if field in OPEN_ENDED_FIELDS:
        return lo <= 1            # 'count' includes the current connection
    if field in HOST_WINDOW_FIELDS:
        return lo <= 1 and hi >= HostConnectionTracker.HOST_WINDOW_SIZE
    return False


def _compile_signature(name: str, cfg: Dict[str, Any]) -> _Signature:
    protocols = {p.upper() for p in _as_list(cfg['protocol_types'])} if cfg.get('protocol_types') else None
    services = {s.lower() for s in _as_list(cfg['services'])} if cfg.get('services') else None
    flags = {f.upper() for f in _as_list(cfg['flags'])} if cfg.get('flags') else None
    zero_fields = tuple(cfg.get('zero_fields', []) or [])
    ranges = []
    for field, bounds in (cfg.get('ranges', {}) or {}).items():
        lo, hi = float(bounds[0]), float(bounds[1])
        if field in OPEN_ENDED_FIELDS:
            hi = math.inf           # a bigger flood must not score as a smaller one
        if _range_is_trivial(field, lo, hi):
            continue
        ranges.append((field, lo, hi))
    return _Signature(name, protocols, services, flags, zero_fields, tuple(ranges))


_SIG_CACHE: Dict[int, Tuple[Any, List[_Signature]]] = {}


def compile_signatures(thresholds: Dict[str, Any]) -> List[_Signature]:
    cached = _SIG_CACHE.get(id(thresholds))
    if cached is not None and cached[0] is thresholds:
        return cached[1]
    sigs = [_compile_signature(name, cfg) for name, cfg in thresholds.items()
            if isinstance(cfg, dict) and cfg.get('enabled', True)]
    if len(_SIG_CACHE) > 8:
        _SIG_CACHE.clear()
    _SIG_CACHE[id(thresholds)] = (thresholds, sigs)
    return sigs


def _evaluate(sig: _Signature, features: Dict[str, Any],
              flag: Optional[str] = None) -> Tuple[bool, float, List[str]]:
    if sig.protocols and str(features.get('protocol_type', '')).upper() not in sig.protocols:
        return False, 0.0, []
    if sig.services and str(features.get('service', '')).lower() not in sig.services:
        return False, 0.0, []
    flag = flag if flag is not None else features.get('flag', '')
    if sig.flags and str(flag).upper() not in sig.flags:
        return False, 0.0, []
    for field_name in sig.zero_fields:
        if to_number(features.get(field_name, 0)) != 0:
            return False, 0.0, []
    if not sig.ranges:
        return True, 1.0, []
    hits = 0
    failed: List[str] = []
    for field_name, lo, hi in sig.ranges:
        if lo <= to_number(features.get(field_name, 0)) <= hi:
            hits += 1
        else:
            failed.append(field_name)
    return True, hits / len(sig.ranges), failed


def score_attack(features: Dict[str, Any], attack_cfg: Dict[str, Any]) -> Tuple[bool, float]:
    """Hard-gate on protocol/service/flag/zero_fields, then score the fraction
    of *informative* range conditions satisfied."""
    ok, score, _ = _evaluate(_compile_signature('?', attack_cfg), features)
    return ok, score


def classify_detail(features: Dict[str, Any], thresholds: Dict[str, Any],
                    match_threshold: float, half_open_grace_seconds: float = 2.0,
                    half_open_min_count: int = 10) -> Tuple[str, float, List[str]]:
    """Highest-scoring signature that clears its hard gates and the confidence
    threshold. Returns (name, score, failed_range_fields).

    A connection that is half-open, refused or reset *without moving any data*
    is only evaluated when there is corroboration (several such connections to
    the same host in the 2-second window, which is what a SYN flood looks like
    from its first packets) or the connection has stayed half-open past the
    grace period. One refused connection is simply a closed port."""
    flag = features.get('flag')
    no_payload = not features.get('src_bytes') and not features.get('dst_bytes')
    # A sensor that sees the victim's SYN-ACKs reports a never-completed
    # handshake as S1 ('established'); for signature purposes it is half-open.
    eff_flag = 'S0' if (flag in ('S1', 'RSTO') and features.get('half_open') and no_payload) else flag
    if no_payload and eff_flag in UNANSWERED_FLAGS:
        # Corroboration = many *half-open* connections to this host right now AND
        # they dominate the recent traffic to it. A busy server legitimately
        # sees many new connections, but each has completed its handshake by
        # the time the next SYN arrives; a SYN flood has not. Refused (REJ)
        # connections are a closed port, not a flood -- port scans are handled
        # by the failed-probe sweep detectors.
        ho_count = features.get('half_open_count', features.get('count', 0))
        ho_rate = features.get('half_open_rate', 1.0)
        same_port = features.get('half_open_same_port_rate', 1.0)
        corroborated = ho_count >= half_open_min_count and ho_rate >= 0.5 and same_port >= 0.8
        settled = eff_flag in TRANSIENT_FLAGS and features.get('duration', 0.0) >= half_open_grace_seconds
        if not corroborated and not settled:
            return 'normal', 0.0, []
    best = ('normal', 0.0, [])
    for sig in compile_signatures(thresholds):
        ok, score, failed = _evaluate(sig, features, eff_flag)
        if ok and score >= match_threshold and score > best[1]:
            best = (sig.name, score, failed)
    return best


def classify(features: Dict[str, Any], thresholds: Dict[str, Any], match_threshold: float,
             half_open_grace_seconds: float = 2.0, half_open_min_count: int = 10) -> Tuple[str, float]:
    name, score, _ = classify_detail(features, thresholds, match_threshold,
                                     half_open_grace_seconds, half_open_min_count)
    return name, score


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

DEFAULT_SEVERITY = {
    'neptune': 'high', 'smurf': 'high', 'pod': 'high', 'teardrop': 'high', 'back': 'high',
    'guess_passwd': 'high', 'processtable': 'high',
    'warezclient': 'medium', 'satan': 'medium', 'portsweep': 'medium', 'ipsweep': 'medium',
    'mscan': 'medium',
}
DEFAULT_MITRE = {   # same shape as config.json threat_intel[...]['mitre']; verified against attack.mitre.org
    'neptune': {'technique_id': 'T1499.001', 'technique_name': 'Endpoint Denial of Service: OS Exhaustion Flood', 'tactic': 'Impact'},
    'smurf': {'technique_id': 'T1498.002', 'technique_name': 'Network Denial of Service: Reflection Amplification', 'tactic': 'Impact'},
    'portsweep': {'technique_id': 'T1046', 'technique_name': 'Network Service Discovery', 'tactic': 'Discovery'},
    'ipsweep': {'technique_id': 'T1018', 'technique_name': 'Remote System Discovery', 'tactic': 'Discovery'},
    'satan': {'technique_id': 'T1595.002', 'technique_name': 'Active Scanning: Vulnerability Scanning', 'tactic': 'Reconnaissance'},
    'mscan': {'technique_id': 'T1595.002', 'technique_name': 'Active Scanning: Vulnerability Scanning', 'tactic': 'Reconnaissance'},
    'back': {'technique_id': 'T1499.003', 'technique_name': 'Endpoint Denial of Service: Application Exhaustion Flood', 'tactic': 'Impact'},
    'teardrop': {'technique_id': 'T1499.004', 'technique_name': 'Endpoint Denial of Service: Application or System Exploitation', 'tactic': 'Impact'},
    'pod': {'technique_id': 'T1499.004', 'technique_name': 'Endpoint Denial of Service: Application or System Exploitation', 'tactic': 'Impact'},
    'warezclient': {'technique_id': 'T1048.003', 'technique_name': 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol', 'tactic': 'Exfiltration'},
    'guess_passwd': {'technique_id': 'T1110.001', 'technique_name': 'Brute Force: Password Guessing', 'tactic': 'Credential Access'},
    'processtable': {'technique_id': 'T1499.001', 'technique_name': 'Endpoint Denial of Service: OS Exhaustion Flood', 'tactic': 'Impact'},
}
# How events of one attack type are grouped into a single alert:
# 'dst' = one alert per victim (DoS from many/spoofed sources),
# 'src' = one alert per attacker, 'pair' = one alert per attacker->victim pair.
ALERT_GROUPING = {'neptune': 'dst', 'smurf': 'dst', 'pod': 'dst', 'teardrop': 'dst',
                  'ipsweep': 'src', 'mscan': 'src'}
EVIDENCE_FIELDS = ('flag', 'service', 'count', 'srv_count', 'serror_rate', 'rerror_rate',
                   'dst_host_count', 'dst_host_srv_diff_host_rate', 'src_bytes', 'dst_bytes',
                   'duration', 'wrong_fragment', 'num_failed_logins')
# Fields the analyzer owns and refreshes on aggregated alerts.
ALERT_UPDATE_FIELDS = ('count', 'flows', 'sources', 'last_seen', 'confidence', 'evidence', 'reasons')


class _AlertState:
    __slots__ = ('alert', 'srcs', 'flow_ids', 'last_event', 'last_emit', 'dirty', 'features')

    def __init__(self, alert, now):
        self.alert = alert
        self.srcs = set()
        self.flow_ids = set()
        self.last_event = now
        self.last_emit = now
        self.dirty = False
        self.features: Dict[str, Any] = {}


class AlertAggregator:
    """Turns a stream of per-packet detections into a small number of alerts."""

    MAX_TRACKED_IDS = 5000

    def __init__(self, cooldown: float = 30.0, max_new_per_second: int = 20,
                 update_interval: float = 2.0, threat_intel: Optional[dict] = None):
        self.cooldown = float(cooldown)
        self.max_new_per_second = int(max_new_per_second)
        self.update_interval = float(update_interval)
        self.threat_intel = threat_intel or {}
        self._active: Dict[Tuple, _AlertState] = {}
        self._recent_new: Deque[float] = deque()
        self.suppressed = 0
        self.created = 0
        self._ops = 0

    @staticmethod
    def _key(outcome: str, flow: FlowFeatures) -> Tuple:
        mode = ALERT_GROUPING.get(outcome, 'pair')
        if mode == 'dst':
            return (outcome, flow.dst_ip)
        if mode == 'src':
            return (outcome, flow.src_ip)
        return (outcome, flow.src_ip, flow.dst_ip)

    def observe(self, now: float, outcome: str, score: float, flow: FlowFeatures,
                features: Dict[str, Any], reasons: List[str]) -> List[Tuple[str, Dict[str, Any]]]:
        key = self._key(outcome, flow)
        st = self._active.get(key)
        if st is not None and now - st.last_event > self.cooldown:
            del self._active[key]
            st = None
        events: List[Tuple[str, Dict[str, Any]]] = []
        if st is None:
            while self._recent_new and now - self._recent_new[0] > 1.0:
                self._recent_new.popleft()
            if len(self._recent_new) >= self.max_new_per_second:
                self.suppressed += 1
                return events
            st = _AlertState(self._build(now, outcome, score, flow), now)
            self._active[key] = st
            self._recent_new.append(now)
            self.created += 1
            self._merge(st, now, score, flow, features, reasons)
            events.append(('new', self._snapshot(st)))
            st.last_emit = now
        else:
            self._merge(st, now, score, flow, features, reasons)
            st.dirty = True
            if now - st.last_emit >= self.update_interval:
                events.append(('update', self._snapshot(st)))
                st.last_emit, st.dirty = now, False
        self._ops += 1
        if self._ops % 500 == 0:
            self._gc(now)
        return events

    def flush(self) -> List[Tuple[str, Dict[str, Any]]]:
        """Pending (dirty) alert updates, e.g. when capture stops."""
        out = []
        for st in self._active.values():
            if st.dirty:
                out.append(('update', self._snapshot(st)))
                st.dirty = False
        return out

    def _build(self, now: float, outcome: str, score: float, flow: FlowFeatures) -> Dict[str, Any]:
        intel = self.threat_intel.get(outcome, {}) if isinstance(self.threat_intel, dict) else {}
        intel = intel if isinstance(intel, dict) else {}
        alert = {
            'id': uuid.uuid4().hex,
            'flow_id': flow.flow_id,
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol_type': flow.protocol_type,
            'service': flow.service,
            'outcome': outcome,
            'confidence': round(score, 3),
            'timestamp': iso(now),
            'first_seen': iso(now),
            'last_seen': iso(now),
            'severity': intel.get('severity') or DEFAULT_SEVERITY.get(outcome, 'medium'),
            'message': f"Suspicious activity detected: {outcome}",
            'acknowledged': False,
            'count': 0,
            'flows': 0,
            'sources': 0,
            'mitre': intel.get('mitre') or DEFAULT_MITRE.get(outcome),
            'reasons': [],
            'evidence': {},
        }
        for key in ('description', 'display_name', 'recommendation'):
            if intel.get(key):
                alert[key] = intel[key]
        if flow.names:
            alert['names'] = list(flow.names)
        return alert

    def _merge(self, st: _AlertState, now: float, score: float, flow: FlowFeatures,
               features: Dict[str, Any], reasons: List[str]) -> None:
        a = st.alert
        a['count'] += 1
        a['last_seen'] = iso(now)
        a['confidence'] = max(a['confidence'], round(score, 3))
        st.last_event = now
        if len(st.srcs) < self.MAX_TRACKED_IDS:
            st.srcs.add(flow.src_ip)
        if len(st.flow_ids) < self.MAX_TRACKED_IDS:
            st.flow_ids.add(flow.flow_id)
        a['sources'] = len(st.srcs)
        a['flows'] = len(st.flow_ids)
        st.features = features
        a['reasons'] = reasons
        a['evidence'] = {k: features[k] for k in EVIDENCE_FIELDS if k in features}
        if flow.names:
            known = a.setdefault('names', [])
            for n in flow.names:
                if n not in known and len(known) < 8:
                    known.append(n)

    @staticmethod
    def _snapshot(st: _AlertState) -> Dict[str, Any]:
        snap = dict(st.alert)
        snap['reasons'] = list(snap.get('reasons') or [])
        snap['evidence'] = dict(snap.get('evidence') or {})
        if 'names' in snap:
            snap['names'] = list(snap['names'])
        return snap

    def _gc(self, now: float) -> None:
        for key in [k for k, st in self._active.items() if now - st.last_event > self.cooldown]:
            del self._active[key]


# --------------------------------------------------------------------------
# Rate buckets (real per-second counters for the dashboard charts)
# --------------------------------------------------------------------------

class RateBuckets:
    def __init__(self, keep_seconds: int = 120):
        import threading
        self._lock = threading.Lock()
        self._buckets: Dict[int, List[int]] = {}
        self._keep = keep_seconds

    def add(self, packets: int = 1, flagged: int = 0, now: Optional[float] = None) -> None:
        sec = int(now if now is not None else time.time())
        with self._lock:
            b = self._buckets.get(sec)
            if b is None:
                b = self._buckets[sec] = [0, 0]
                if len(self._buckets) > self._keep:
                    for old in sorted(self._buckets)[:len(self._buckets) - self._keep]:
                        del self._buckets[old]
            b[0] += packets
            b[1] += flagged

    def series(self, seconds: int = 60, now: Optional[float] = None) -> Tuple[List[int], List[int]]:
        """Per-second packet / flagged-packet counts, oldest first, ending now."""
        end = int(now if now is not None else time.time())
        with self._lock:
            rows = [self._buckets.get(s, (0, 0)) for s in range(end - seconds + 1, end + 1)]
        return [r[0] for r in rows], [r[1] for r in rows]

    def per_second(self, window: int = 5, now: Optional[float] = None) -> Tuple[float, float]:
        """Average rate over the last ``window`` *completed* seconds."""
        end = int(now if now is not None else time.time())
        with self._lock:
            rows = [self._buckets.get(s, (0, 0)) for s in range(end - window, end)]
        return (round(sum(r[0] for r in rows) / window, 1),
                round(sum(r[1] for r in rows) / window, 1))


# --------------------------------------------------------------------------
# Packet analyzer
# --------------------------------------------------------------------------

class NullSink:
    """Receives the analyzer's output. Subclass / duck-type to consume it."""

    def on_flow(self, payload: Dict[str, Any]) -> None: ...
    def on_flow_closed(self, record: Dict[str, Any]) -> None: ...
    def on_alert(self, kind: str, alert: Dict[str, Any]) -> None: ...


def get_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol_type: str) -> str:
    """Canonical, direction-independent id: both directions map to one flow."""
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{protocol_type}:{lo[0]}:{lo[1]}-{hi[0]}:{hi[1]}"


def keep_orientation(sport: int, dport: int, protocol_type: str, tcp_flags: Optional[int]) -> bool:
    """True if the first packet seen came from the originator.

    A bare SYN is the originator; a SYN-ACK means we joined mid-handshake and
    the sender is the responder. For anything else (mid-stream pickup, UDP) the
    side with the well-known port is taken as the server."""
    if protocol_type == 'TCP' and tcp_flags is not None:
        syn, ack = bool(tcp_flags & 0x02), bool(tcp_flags & 0x10)
        if syn and not ack:
            return True
        if syn and ack:
            return False
    s_known, d_known = sport in PORT_SERVICE_MAP, dport in PORT_SERVICE_MAP
    if s_known != d_known:
        return d_known
    if sport and dport and (sport < 1024) != (dport < 1024):
        return dport < 1024
    return True


def _num(config: dict, section: str, key: str, default, cast=float):
    """Look a setting up in config[section][key], then config[key], else default."""
    for source in ((config.get(section) or {}), config):
        if isinstance(source, dict) and source.get(key) is not None:
            try:
                return cast(source[key])
            except (TypeError, ValueError):
                break
    return default


class PacketAnalyzer:
    """Turns packets into flows, features, classifications and alerts.

    It is single-threaded by design: call ``process_packet`` from one thread
    (the capture thread). Output goes to ``sink``.
    """

    def __init__(self, config: dict, sink: Optional[NullSink] = None):
        self.sink = sink or NullSink()
        self.flows: "OrderedDict[str, FlowFeatures]" = OrderedDict()
        self.tracker = HostConnectionTracker()
        self.aggregator = AlertAggregator()
        self.rates = RateBuckets()
        self.running = True
        self.packets_seen = 0
        self.packets_processed = 0
        self.packets_flagged = 0
        self.flows_closed = 0
        self._processing_times: Deque[float] = deque(maxlen=200)
        self._next_maintenance = 0.0
        self.first_packet_ts = 0.0
        self.last_packet_ts = 0.0
        self.config: dict = {}
        self.configure(config)

    # -- configuration --------------------------------------------------
    def configure(self, config: dict) -> None:
        """(Re)read tunables. Safe to call while running."""
        self.config = config
        self.thresholds = config.get('thresholds', {}) or {}
        self.match_threshold = _num(config, 'detection', 'match_threshold', 0.95)
        self.half_open_grace_seconds = _num(config, 'detection', 'half_open_grace_seconds', 2.0)
        self.half_open_min_count = _num(config, 'detection', 'half_open_min_count', 10, int)
        self.sampling_rate = max(1, _num(config, 'detection', 'sampling_rate', 1, int))
        self.flow_idle_timeout = _num(config, 'detection', 'flow_idle_timeout_seconds', 120.0)
        self.flow_closed_linger = _num(config, 'detection', 'flow_closed_linger_seconds', 10.0)
        self.half_open_timeout = _num(config, 'detection', 'half_open_timeout_seconds', 30.0)
        self.max_flows = _num(config, 'detection', 'max_flows', 50000, int)
        self.flow_emit_interval = _num(config, 'detection', 'flow_emit_interval_seconds', 0.5)

        scale = self.sampling_rate
        t = self.tracker
        for attr, key, default in (('portsweep_port_threshold', 'portsweep_port_threshold', 20),
                                   ('ipsweep_host_threshold', 'ipsweep_host_threshold', 20),
                                   ('slow_port_threshold', 'slow_scan_port_threshold', 15),
                                   ('slow_host_threshold', 'slow_scan_host_threshold', 25)):
            setattr(t, attr, max(2, math.ceil(_num(config, 'detection', key, default, int) / scale)))
        t.recon_window_seconds = _num(config, 'detection', 'recon_window_seconds', 10.0)
        t.slow_window_seconds = _num(config, 'detection', 'slow_scan_window_seconds', 300.0)
        t.probe_grace_seconds = self.half_open_grace_seconds

        agg = self.aggregator
        agg.cooldown = _num(config, 'detection', 'alert_cooldown_seconds', 30.0)
        agg.max_new_per_second = _num(config, 'detection', 'alert_max_per_second', 20, int)
        agg.update_interval = _num(config, 'detection', 'alert_update_interval_seconds', 2.0)
        agg.threat_intel = config.get('threat_intel', {}) or {}

    @property
    def avg_detection_latency_ms(self) -> float:
        if not self._processing_times:
            return 0.0
        return round(sum(self._processing_times) / len(self._processing_times) * 1000, 2)

    @property
    def active_flows(self) -> int:
        return len(self.flows)

    # -- packet adaptation ----------------------------------------------
    @staticmethod
    def determine_protocol(packet) -> str:
        if hasattr(packet, 'tcp'):
            return 'TCP'
        if hasattr(packet, 'udp'):
            return 'UDP'
        if hasattr(packet, 'icmp') or hasattr(packet, 'icmpv6'):
            return 'ICMP'
        return 'OTHER'

    @staticmethod
    def extract_ports(packet, protocol_type: str) -> Tuple[int, int]:
        try:
            if protocol_type == 'TCP' and hasattr(packet, 'tcp'):
                return int(packet.tcp.srcport), int(packet.tcp.dstport)
            if protocol_type == 'UDP' and hasattr(packet, 'udp'):
                return int(packet.udp.srcport), int(packet.udp.dstport)
        except (AttributeError, ValueError):
            pass
        return 0, 0

    @staticmethod
    def get_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol_type: str) -> str:
        return get_flow_id(src_ip, src_port, dst_ip, dst_port, protocol_type)

    # -- main entry -----------------------------------------------------
    def process_packet(self, packet) -> Optional[Tuple[str, float]]:
        """Analyze one packet. Returns (outcome, score) or None if skipped."""
        start = time.perf_counter()
        try:
            ip_layer = getattr(packet, 'ip', None)
            if ip_layer is None:
                ip_layer = getattr(packet, 'ipv6', None)
            if ip_layer is None:
                return None
            src_ip, dst_ip = getattr(ip_layer, 'src', None), getattr(ip_layer, 'dst', None)
            if src_ip is None or dst_ip is None:
                return None
            protocol_type = self.determine_protocol(packet)
            src_port, dst_port = self.extract_ports(packet, protocol_type)
            timestamp = float(packet.sniff_time.timestamp())
            self.packets_seen += 1
            self.first_packet_ts = self.first_packet_ts or timestamp
            self.last_packet_ts = timestamp

            flow_id = get_flow_id(src_ip, src_port, dst_ip, dst_port, protocol_type)
            flow = self.flows.get(flow_id)
            if flow is None:
                # Connection-level (not packet-level) sampling keeps every
                # flow's TCP state machine intact.
                if self.sampling_rate > 1 and zlib.crc32(flow_id.encode()) % self.sampling_rate:
                    return None
                tcp_flags = parse_tcp_flags(packet.tcp) if protocol_type == 'TCP' else None
                if keep_orientation(src_port, dst_port, protocol_type, tcp_flags):
                    o_ip, o_port, r_ip, r_port = src_ip, src_port, dst_ip, dst_port
                else:
                    o_ip, o_port, r_ip, r_port = dst_ip, dst_port, src_ip, src_port
                flow = FlowFeatures(flow_id, o_ip, r_ip, o_port, r_port, protocol_type, self.config)
                self.flows[flow_id] = flow
            else:
                self.flows.move_to_end(flow_id)
            if timestamp >= self._next_maintenance:
                self.maintenance(timestamp)
                self._next_maintenance = timestamp + 5.0

            direction = 'fwd' if (src_ip == flow.src_ip and src_port == flow.src_port) else 'bwd'
            flow.observe(packet, timestamp, direction)

            # Host-level tracking BEFORE classification so the current
            # connection is reflected in cross-flow features and recon checks.
            self.tracker.update(flow_id, timestamp, flow.src_ip, flow.src_port,
                                flow.dst_ip, flow.dst_port, flow.service,
                                flow.protocol_type, flow.flag,
                                total_bytes=flow.src_bytes + flow.dst_bytes,
                                answered=flow.answered, half_open=flow.half_open)
            features = flow.snapshot(self.tracker, timestamp)
            if self.sampling_rate > 1:      # estimate the unsampled volume
                for key in OPEN_ENDED_FIELDS:
                    features[key] = int(features[key] * self.sampling_rate)

            outcome, score, failed = classify_detail(
                features, self.thresholds, self.match_threshold,
                self.half_open_grace_seconds, self.half_open_min_count)
            reasons = self._explain(outcome, flow, features, score, failed)

            if self.tracker.is_probe(flow_id):
                recon = self._check_recon_heuristics(flow.src_ip, flow.dst_ip, timestamp)
                if recon:
                    outcome, score = recon[0], max(score, 0.99)
                    reasons = [recon[1]]

            flow.outcome, flow.confidence = outcome, score
            flow.level = 0 if outcome == 'normal' else 1

            if (flow.last_emit_ts == 0.0 or flow.flag != flow.last_emit_flag
                    or outcome != flow.last_emit_outcome
                    or timestamp - flow.last_emit_ts >= self.flow_emit_interval):
                flow.last_emit_ts, flow.last_emit_flag, flow.last_emit_outcome = timestamp, flow.flag, outcome
                self.sink.on_flow(self._build_dashboard_payload(flow, features, outcome, score, timestamp))

            self._handle_new_probes(timestamp, skip_flow_id=flow_id)
            flagged = outcome != 'normal'
            if flagged:
                self.packets_flagged += 1
                for kind, alert in self.aggregator.observe(timestamp, outcome, score, flow, features, reasons):
                    self.sink.on_alert(kind, alert)
            self.packets_processed += 1
            self.rates.add(1, 1 if flagged else 0)
            return outcome, score
        except Exception:
            logger.exception("Error processing packet")
            return None
        finally:
            self._processing_times.append(time.perf_counter() - start)

    # -- recon / explanation ----------------------------------------------
    def _check_recon_heuristics(self, src_ip: str, dst_ip: str,
                                now: Optional[float] = None) -> Optional[Tuple[str, str]]:
        """Deterministic cross-flow detectors for portsweep / ipsweep, driven
        by FAILED probes only. Returns (outcome, human readable reason)."""
        v = self.tracker.recon_verdict(src_ip, dst_ip, now)
        if v is None:
            return None
        outcome, n, secs = v
        what = (f"distinct ports probed on {dst_ip}" if outcome == 'portsweep'
                else f"distinct hosts probed on a single port by {src_ip}")
        return outcome, f"{n} {what} in {secs:g}s (failed/unanswered attempts)"

    def _handle_new_probes(self, now: float, skip_flow_id: Optional[str] = None) -> None:
        """Raise sweep alerts for probes that matured since the last packet
        (e.g. unanswered SYNs that outlived the half-open grace period) and
        relabel those flows in the dashboard."""
        for rec in self.tracker.drain_new_probes():
            verdict = self._check_recon_heuristics(rec.src_ip, rec.dst_ip, now)
            if not verdict or rec.flow_id == skip_flow_id:
                continue
            flow = self.flows.get(rec.flow_id)
            if flow is None:
                continue
            outcome, reason = verdict
            flow.outcome, flow.confidence, flow.level = outcome, 0.99, 1
            features = flow.snapshot(self.tracker, now)
            self.sink.on_flow(self._build_dashboard_payload(flow, features, outcome, 0.99, now))
            self.packets_flagged += 1
            for kind, alert in self.aggregator.observe(now, outcome, 0.99, flow, features, [reason]):
                self.sink.on_alert(kind, alert)

    def _explain(self, outcome: str, flow: FlowFeatures, features: Dict[str, Any],
                 score: float, failed: List[str]) -> List[str]:
        if outcome == 'normal':
            return []
        reasons = []
        if outcome in ('neptune', 'smurf', 'pod'):
            reasons.append(f"{features.get('count', 0)} connections to {flow.dst_ip} in "
                           f"{HostConnectionTracker.TIME_WINDOW_SECONDS:g}s, "
                           f"{features.get('half_open_count', 0)} half-open "
                           f"({features.get('half_open_rate', 0):.0%}), "
                           f"{features.get('rerror_rate', 0):.0%} refused")
        reasons.append(f"matched '{outcome}' signature (score {score:.2f}, flag {features.get('flag')}, "
                       f"service {features.get('service')})")
        if failed:
            reasons.append("out-of-range: " + ", ".join(failed[:6]))
        return reasons

    # -- dashboard payloads -------------------------------------------------
    @staticmethod
    def _build_dashboard_payload(flow: FlowFeatures, features: Dict[str, Any],
                                 outcome: str, score: float, timestamp: float) -> Dict[str, Any]:
        data = dict(features)
        data.update({
            'flow_id': flow.flow_id,
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'outcome': outcome,
            'confidence': round(score, 3),
            'level': flow.level,
            'timestamp': iso(timestamp),
            'packets': flow.packet_count,
        })
        if flow.names:
            data['names'] = list(flow.names)
        return data

    # -- lifecycle ------------------------------------------------------
    def maintenance(self, now: float) -> None:
        """Expire finished / idle flows and prune the tracker."""
        self.tracker.expire(now)
        self._handle_new_probes(now)
        expired = []
        for fid, f in self.flows.items():          # least-recently-touched first
            age = now - (f.last_time or now)
            if age <= self.flow_closed_linger:
                break
            if f.closed:
                limit = self.flow_closed_linger
            elif f.flag in UNANSWERED_FLAGS and not (f.src_bytes or f.dst_bytes):
                limit = self.half_open_timeout
            else:
                limit = self.flow_idle_timeout
            if age > limit:
                expired.append(fid)
        for fid in expired:
            self._close_flow(fid)
        while len(self.flows) > self.max_flows:
            self._close_flow(next(iter(self.flows)))

    def _close_flow(self, flow_id: str) -> None:
        flow = self.flows.pop(flow_id, None)
        if flow is None:
            return
        self.tracker.forget(flow_id)
        self.flows_closed += 1
        try:
            self.sink.on_flow_closed(flow.to_record())
        except Exception:
            logger.exception("Flow sink failed")

    def flush(self) -> None:
        """Close every flow and emit pending alert updates (capture stopped)."""
        self._handle_new_probes(self.last_packet_ts)
        for kind, alert in self.aggregator.flush():
            self.sink.on_alert(kind, alert)
        for fid in list(self.flows):
            self._close_flow(fid)
