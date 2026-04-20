"""
device_registry.py — Registre des Devices IoT
===============================================
Gère la liste des devices autorisés, leurs certificats, statuts et droits.
Stockage en SQLite avec accès thread-safe.
"""

import os
import sqlite3
import threading
import time
import logging
from typing import Optional, List, Dict, Any

log = logging.getLogger("device_registry")


class DeviceStatus:
    PENDING  = "pending"    # Enrôlement en cours
    ACTIVE   = "active"     # Autorisé et actif
    MONITORED = "monitored" # Sous surveillance renforcée
    BLOCKED  = "blocked"    # Bloqué / révoqué


class DeviceRegistry:
    """
    Registre thread-safe des devices IoT.
    Chaque device est identifié par son device_id et son fingerprint de clé.
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
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id       TEXT PRIMARY KEY,
                    fingerprint     TEXT NOT NULL,
                    certificate_pem TEXT,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    registered_at   REAL NOT NULL,
                    last_seen       REAL,
                    metadata        TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_devices_status
                    ON devices(status);

                CREATE INDEX IF NOT EXISTS idx_devices_fingerprint
                    ON devices(fingerprint);
            """)
        log.info("Base de données du registre initialisée : %s", self._db_path)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register_device(
        self,
        device_id: str,
        fingerprint: str,
        certificate_pem: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> None:
        """Enregistre ou met à jour un device."""
        import json as _json
        now = time.time()
        meta_str = _json.dumps(metadata or {})

        with self._lock, self._get_conn() as conn:
            conn.execute("""
                INSERT INTO devices
                    (device_id, fingerprint, certificate_pem, status, registered_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    fingerprint     = excluded.fingerprint,
                    certificate_pem = excluded.certificate_pem,
                    status          = CASE
                                        WHEN status = 'blocked' THEN 'blocked'
                                        ELSE 'active'
                                      END,
                    metadata        = excluded.metadata
            """, (device_id, fingerprint, certificate_pem,
                  DeviceStatus.ACTIVE, now, meta_str))
        log.info("[REGISTRE] Device enregistré/mis à jour : %s", device_id)

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Retourne les infos d'un device ou None."""
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_devices(self) -> List[Dict[str, Any]]:
        """Liste tous les devices (sans les certificats pour alléger)."""
        with self._lock, self._get_conn() as conn:
            rows = conn.execute("""
                SELECT device_id, fingerprint, status, registered_at, last_seen
                FROM devices ORDER BY registered_at DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def update_device_status(self, device_id: str, status: str) -> bool:
        """Met à jour le statut d'un device."""
        if status not in (
            DeviceStatus.PENDING, DeviceStatus.ACTIVE,
            DeviceStatus.MONITORED, DeviceStatus.BLOCKED
        ):
            log.warning("Statut invalide : %s", status)
            return False

        with self._lock, self._get_conn() as conn:
            cursor = conn.execute(
                "UPDATE devices SET status = ? WHERE device_id = ?",
                (status, device_id)
            )
            updated = cursor.rowcount > 0

        if updated:
            log.info("[REGISTRE] Statut mis à jour : device=%s status=%s",
                     device_id, status)
        return updated

    def update_last_seen(self, device_id: str) -> None:
        """Met à jour la date du dernier message reçu."""
        with self._lock, self._get_conn() as conn:
            conn.execute(
                "UPDATE devices SET last_seen = ? WHERE device_id = ?",
                (time.time(), device_id)
            )

    def delete_device(self, device_id: str) -> bool:
        """Supprime un device du registre (admin uniquement)."""
        with self._lock, self._get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM devices WHERE device_id = ?", (device_id,)
            )
        return cursor.rowcount > 0

    def get_active_device_count(self) -> int:
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM devices WHERE status = 'active'"
            ).fetchone()
        return row["cnt"] if row else 0
