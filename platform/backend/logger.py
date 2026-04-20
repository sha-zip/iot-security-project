"""
logger.py — Journal d'Audit Sécurisé
=====================================
Enregistre tous les événements de sécurité dans une base SQLite.
Utilisé par le backend pour alimenter le moteur IA.
"""

import os
import json
import time
import sqlite3
import threading
import logging
from typing import List, Dict, Any, Optional

log = logging.getLogger("audit_logger")


class AuditLogger:
    """
    Journal d'audit thread-safe pour tous les événements de sécurité.
    """

    def __init__(self, db_path: str = "/app/monitoring/logs.db"):
        self._db_path = db_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type  TEXT NOT NULL,
                    device_id   TEXT,
                    timestamp   REAL NOT NULL,
                    details     TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_audit_device
                    ON audit_log(device_id, timestamp);

                CREATE INDEX IF NOT EXISTS idx_audit_event
                    ON audit_log(event_type, timestamp);
            """)

    def log_event(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Enregistre un événement d'audit."""
        device_id = (details or {}).get("device_id")
        details_str = json.dumps(details or {})
        now = time.time()

        with self._lock, self._get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_log (event_type, device_id, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                (event_type, device_id, now, details_str)
            )
        log.debug("[AUDIT] %s | device=%s", event_type, device_id)

    def get_recent_events(
        self,
        device_id: str,
        limit: int = 100,
        window_seconds: Optional[float] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retourne les événements récents pour un device."""
        query = "SELECT * FROM audit_log WHERE device_id = ?"
        params: list = [device_id]

        if window_seconds is not None:
            since = time.time() - window_seconds
            query += " AND timestamp >= ?"
            params.append(since)

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def get_event_count(
        self,
        device_id: str,
        window_seconds: float = 60.0,
        event_type: Optional[str] = None,
    ) -> int:
        """Compte les événements dans une fenêtre temporelle."""
        since = time.time() - window_seconds
        query = ("SELECT COUNT(*) as cnt FROM audit_log "
                 "WHERE device_id = ? AND timestamp >= ?")
        params: list = [device_id, since]

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        with self._lock, self._get_conn() as conn:
            row = conn.execute(query, params).fetchone()
        return row["cnt"] if row else 0
