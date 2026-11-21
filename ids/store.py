"""SQLite persistence.

* One short-lived connection per operation (cheap in SQLite, and safe to use
  from any thread). WAL mode lets the dashboard read while the writer commits.
* The ``alerts`` table is schema-compatible with databases created by earlier
  versions of this project.
* Retention is enforced so a long-running sensor cannot fill the disk.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("ids.store")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


class AlertStore:
    def __init__(self, path: Path, retention_days: int = 30, max_rows: int = 100000):
        self.path = Path(path)
        self.retention_days = retention_days
        self.max_rows = max_rows

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(_connect(self.path)) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY, flow_id TEXT, src_ip TEXT, dst_ip TEXT,
                    outcome TEXT, severity TEXT, confidence REAL, timestamp TEXT,
                    persisted_timestamp TEXT, acknowledged INTEGER DEFAULT 0,
                    acknowledged_timestamp TEXT, investigated INTEGER DEFAULT 0,
                    investigator_notes TEXT, investigator TEXT, alert_json TEXT)''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_flow_id ON alerts(flow_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alerts_persisted ON alerts(persisted_timestamp)')
            cols = [r[1] for r in conn.execute("PRAGMA table_info(alerts)")]
            if 'investigator' not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN investigator TEXT")
            conn.commit()
        logger.info("Alert database ready: %s", self.path)

    # -- writes -----------------------------------------------------------
    def save_many(self, alerts: Iterable[Dict[str, Any]]) -> int:
        """Upsert a batch of alert dicts (each must carry an 'id')."""
        rows = []
        persisted = _utc_now()
        for a in alerts:
            if not a.get('id'):
                continue
            rows.append((
                a['id'], a.get('flow_id'), a.get('src_ip'), a.get('dst_ip'), a.get('outcome'),
                a.get('severity'), float(a.get('confidence') or 0.0), a.get('timestamp'), persisted,
                1 if a.get('acknowledged') else 0, a.get('acknowledged_timestamp'),
                1 if a.get('investigated') else 0, json.dumps(a.get('investigator_notes') or []),
                a.get('investigator'), json.dumps(a, ensure_ascii=False, default=str)))
        if not rows:
            return 0
        with closing(_connect(self.path)) as conn:
            conn.executemany('''
                INSERT INTO alerts (id, flow_id, src_ip, dst_ip, outcome, severity, confidence,
                    timestamp, persisted_timestamp, acknowledged, acknowledged_timestamp,
                    investigated, investigator_notes, investigator, alert_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    src_ip=excluded.src_ip, dst_ip=excluded.dst_ip, outcome=excluded.outcome,
                    severity=excluded.severity, confidence=excluded.confidence,
                    persisted_timestamp=excluded.persisted_timestamp,
                    acknowledged=excluded.acknowledged,
                    acknowledged_timestamp=excluded.acknowledged_timestamp,
                    investigated=excluded.investigated,
                    investigator_notes=excluded.investigator_notes,
                    investigator=excluded.investigator, alert_json=excluded.alert_json''', rows)
            conn.commit()
        return len(rows)

    def prune(self) -> int:
        with closing(_connect(self.path)) as conn:
            cur = conn.execute(
                "DELETE FROM alerts WHERE persisted_timestamp < datetime('now', ?)",
                (f'-{int(self.retention_days)} days',))
            removed = cur.rowcount or 0
            conn.execute("DELETE FROM alerts WHERE rowid <= (SELECT MAX(rowid) FROM alerts) - ?",
                         (int(self.max_rows),))
            conn.commit()
        return removed

    # -- reads ------------------------------------------------------------
    @staticmethod
    def _decode(row_id: str, alert_json: str, acknowledged: int, ack_ts: Optional[str]) -> Dict[str, Any]:
        try:
            alert = json.loads(alert_json)
        except (TypeError, ValueError):
            alert = {'_raw': str(alert_json)}
        alert.setdefault('id', row_id)
        if acknowledged:
            alert['acknowledged'] = True
            if ack_ts:
                alert.setdefault('acknowledged_timestamp', ack_ts)
        return alert

    def history(self, limit: int = 500, offset: int = 0, outcome: Optional[str] = None,
                severity: Optional[str] = None, acknowledged: Optional[bool] = None) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        where, params = [], []
        if outcome:
            where.append('outcome = ?')
            params.append(outcome)
        if severity:
            where.append('severity = ?')
            params.append(severity)
        if acknowledged is not None:
            where.append('acknowledged = ?')
            params.append(1 if acknowledged else 0)
        sql = 'SELECT id, alert_json, acknowledged, acknowledged_timestamp FROM alerts'
        if where:
            sql += ' WHERE ' + ' AND '.join(where)
        sql += ' ORDER BY persisted_timestamp DESC, rowid DESC LIMIT ? OFFSET ?'
        params += [max(1, min(int(limit), 5000)), max(0, int(offset))]
        with closing(_connect(self.path)) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._decode(*r) for r in rows]

    def find(self, key: str) -> Optional[Dict[str, Any]]:
        """Look an alert up by id or flow_id."""
        if not key or not self.path.exists():
            return None
        with closing(_connect(self.path)) as conn:
            row = conn.execute(
                'SELECT id, alert_json, acknowledged, acknowledged_timestamp FROM alerts '
                'WHERE id = ? OR flow_id = ? ORDER BY persisted_timestamp DESC LIMIT 1',
                (key, key)).fetchone()
        return self._decode(*row) if row else None


class FlowStore:
    """Completed-flow log (like Zeek's conn.log) so the Flows page and CSV
    export are not limited to whatever is still in memory."""

    COLUMNS = ('flow_id', 'first_seen', 'last_seen', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
               'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'packets',
               'duration', 'outcome', 'confidence', 'names')

    def __init__(self, path: Path, max_rows: int = 500000):
        self.path = Path(path)
        self.max_rows = max_rows

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(_connect(self.path)) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS flows (
                    flow_id TEXT, first_seen TEXT, last_seen TEXT, src_ip TEXT, src_port INTEGER,
                    dst_ip TEXT, dst_port INTEGER, protocol_type TEXT, service TEXT, flag TEXT,
                    src_bytes INTEGER, dst_bytes INTEGER, packets INTEGER, duration REAL,
                    outcome TEXT, confidence REAL, names TEXT)''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_flows_outcome ON flows(outcome)')
            conn.commit()
        logger.info("Flow database ready: %s", self.path)

    def add_many(self, records: Iterable[Dict[str, Any]]) -> int:
        rows = [tuple(r.get(c) for c in self.COLUMNS) for r in records]
        if not rows:
            return 0
        marks = ','.join('?' * len(self.COLUMNS))
        with closing(_connect(self.path)) as conn:
            conn.executemany(f'INSERT INTO flows ({",".join(self.COLUMNS)}) VALUES ({marks})', rows)
            conn.commit()
        return len(rows)

    def recent(self, limit: int = 500, outcome: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        sql = f'SELECT {",".join(self.COLUMNS)} FROM flows'
        params: list = []
        if outcome:
            sql += ' WHERE outcome = ?'
            params.append(outcome)
        sql += ' ORDER BY rowid DESC LIMIT ?'
        params.append(max(1, min(int(limit), 20000)))
        with closing(_connect(self.path)) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(zip(self.COLUMNS, r)) for r in rows]

    def prune(self) -> None:
        with closing(_connect(self.path)) as conn:
            conn.execute("DELETE FROM flows WHERE rowid <= (SELECT MAX(rowid) FROM flows) - ?",
                         (int(self.max_rows),))
            conn.commit()
