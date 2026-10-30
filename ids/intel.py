"""Alert enrichment: IOC matching, reverse DNS, GeoIP.

Everything here is framework-free and failure-tolerant: an enrichment failure
must never lose or delay an alert.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .engine import clean_text

logger = logging.getLogger("ids.intel")


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


# --------------------------------------------------------------------------
# IOC list
# --------------------------------------------------------------------------

class IocList:
    """Newline list of IPs, CIDRs and domains ('#' starts a comment). Reloaded
    when the file's mtime changes."""

    def __init__(self, path: Optional[Path]):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._ips: set = set()
        self._cidrs: list = []
        self._domains: set = set()
        self._mtime: Optional[float] = None

    @property
    def counts(self) -> Dict[str, int]:
        return {'ips': len(self._ips), 'cidrs': len(self._cidrs), 'domains': len(self._domains)}

    def load(self, force: bool = False) -> bool:
        """Returns True if the list was (re)loaded."""
        if self.path is None or not self.path.exists():
            return False
        try:
            mtime = self.path.stat().st_mtime
            if not force and self._mtime == mtime:
                return False
            ips, cidrs, domains = set(), [], set()
            for raw in self.path.read_text(encoding='utf-8').splitlines():
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if '/' in line:
                    try:
                        cidrs.append(ipaddress.ip_network(line, strict=False))
                        continue
                    except ValueError:
                        pass
                try:
                    ips.add(str(ipaddress.ip_address(line)))
                    continue
                except ValueError:
                    pass
                domains.add(line.lower().rstrip('.'))
            with self._lock:
                self._ips, self._cidrs, self._domains, self._mtime = ips, cidrs, domains, mtime
            logger.info('Loaded IOC list: %d IPs, %d CIDRs, %d domains', len(ips), len(cidrs), len(domains))
            return True
        except Exception:
            logger.exception('Failed loading IOC list')
            return False

    def match(self, ip: Optional[str] = None, names: Sequence[Optional[str]] = ()) -> List[str]:
        """IOC hits for an address and/or hostnames (reverse DNS, DNS query
        names, TLS SNI, HTTP Host). Domains match on label boundaries:
        'evil.com' matches 'a.evil.com' but not 'notevil.com'."""
        matches: List[str] = []
        with self._lock:
            ips, cidrs, domains = self._ips, self._cidrs, self._domains
        if ip:
            if ip in ips:
                matches.append(f"ip:{ip}")
            try:
                addr = ipaddress.ip_address(ip)
                matches.extend(f"cidr:{net}" for net in cidrs if addr in net)
            except ValueError:
                pass
        for name in names:
            if not name:
                continue
            host = str(name).lower().rstrip('.')
            for d in domains:
                if host == d or host.endswith('.' + d):
                    entry = f"domain:{d}"
                    if entry not in matches:
                        matches.append(entry)
        return matches


# --------------------------------------------------------------------------
# Enricher
# --------------------------------------------------------------------------

class _TtlCache:
    def __init__(self, max_items: int = 4096):
        self._data: Dict[str, tuple] = {}
        self._lock = threading.Lock()
        self._max = max_items

    def get(self, key: str):
        with self._lock:
            hit = self._data.get(key)
            if hit and hit[0] > time.time():
                return True, hit[1]
        return False, None

    def put(self, key: str, value: Any, ttl: float) -> None:
        with self._lock:
            if len(self._data) >= self._max:
                now = time.time()
                for k in [k for k, v in self._data.items() if v[0] <= now] or list(self._data)[:self._max // 4]:
                    self._data.pop(k, None)
            self._data[key] = (time.time() + ttl, value)


def _default_resolver(ip: str) -> Optional[str]:
    return socket.gethostbyaddr(ip)[0]


class Enricher:
    """Adds reverse DNS, GeoIP and IOC matches to an alert.

    reverse_dns modes:
      'off'     never resolve
      'private' resolve internal addresses only (default). Resolving a public
                attacker address is an *active* lookup that the attacker's
                reverse-zone server can observe, and the answer is
                attacker-controlled text.
      'all'     resolve everything
    """

    def __init__(self, ioc: IocList, reverse_dns: str = 'private',
                 geoip_db_path: Optional[str] = None,
                 resolver: Callable[[str], Optional[str]] = _default_resolver):
        self.ioc = ioc
        self.reverse_dns = reverse_dns
        self._resolver = resolver
        self._rdns_cache = _TtlCache()
        self._geo_cache = _TtlCache()
        self._geo_reader = None
        self._geo_warned = False
        self._geo_path = geoip_db_path

    # -- reverse DNS ------------------------------------------------------
    def rdns(self, ip: Optional[str]) -> Optional[str]:
        if not ip or self.reverse_dns == 'off':
            return None
        if self.reverse_dns == 'private' and not is_internal(ip):
            return None
        found, value = self._rdns_cache.get(ip)
        if found:
            return value
        try:
            name = self._resolver(ip)
            value = clean_text(name).lower().rstrip('.') if name else None
            self._rdns_cache.put(ip, value, 3600)
        except Exception:
            value = None
            self._rdns_cache.put(ip, None, 300)      # negative cache
        return value

    # -- GeoIP --------------------------------------------------------------
    def _reader(self):
        if self._geo_reader is None and self._geo_path:
            try:
                import geoip2.database          # optional dependency
                self._geo_reader = geoip2.database.Reader(self._geo_path)
            except Exception as exc:
                if not self._geo_warned:
                    logger.warning('GeoIP disabled (%s). pip install geoip2 and check geoip_db_path.', exc)
                    self._geo_warned = True
        return self._geo_reader

    def geo(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        if not ip or not self._geo_path or is_internal(ip):
            return None
        found, value = self._geo_cache.get(ip)
        if found:
            return value
        value = None
        reader = self._reader()
        if reader is not None:
            try:
                r = reader.city(ip)
                value = {
                    'city': r.city.name, 'country': r.country.name,
                    'country_code': r.country.iso_code,
                    'latitude': r.location.latitude, 'longitude': r.location.longitude,
                }
            except Exception:
                value = None
        self._geo_cache.put(ip, value, 86400)
        return value

    # -- alert --------------------------------------------------------------
    def enrich(self, alert: Dict[str, Any]) -> None:
        """In-place enrichment. Each step is independent and non-fatal."""
        src, dst = alert.get('src_ip'), alert.get('dst_ip')
        alert['src_rdns'] = self._safe(self.rdns, src)
        alert['dst_rdns'] = self._safe(self.rdns, dst)
        for side, ip in (('src', src), ('dst', dst)):
            g = self._safe(self.geo, ip)
            if g:
                alert[f'{side}_geo'] = g
        parts = []
        for side in ('src', 'dst'):
            g = alert.get(f'{side}_geo')
            if isinstance(g, dict) and (g.get('city') or g.get('country')):
                place = ', '.join(x for x in (g.get('city'), g.get('country')) if x)
                parts.append(f"{side}:{place}")
        if parts:
            alert['enrichment_summary'] = ' | '.join(parts)

        iocs: List[str] = []
        iocs += self._safe(self.ioc.match, src, [alert.get('src_rdns')]) or []
        iocs += self._safe(self.ioc.match, dst, [alert.get('dst_rdns')] + list(alert.get('names') or [])) or []
        alert['ioc_matches'] = list(dict.fromkeys(iocs))

    @staticmethod
    def _safe(fn, *args):
        try:
            return fn(*args)
        except Exception:
            logger.debug('enrichment step failed', exc_info=True)
            return None
