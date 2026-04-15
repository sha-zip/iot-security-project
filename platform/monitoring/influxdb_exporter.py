"""
InfluxDB Exporter - Envoie les métriques de risk score vers InfluxDB.
"""

import os
import logging
from datetime import datetime

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

logger = logging.getLogger(__name__)

# Configuration via variables d'environnement
INFLUXDB_URL = os.environ.get("INFLUXDB_URL", "http://localhost:8086")
INFLUXDB_TOKEN = os.environ.get("INFLUXDB_TOKEN", "mytoken1234")
INFLUXDB_ORG = os.environ.get("INFLUXDB_ORG", "iot_org")
INFLUXDB_BUCKET = os.environ.get("INFLUXDB_BUCKET", "iot_bucket")


class InfluxDBExporter:
    """Client InfluxDB pour écrire les métriques de risk score."""

    def __init__(self, url=None, token=None, org=None, bucket=None):
        self.url = url or INFLUXDB_URL
        self.token = token or INFLUXDB_TOKEN
        self.org = org or INFLUXDB_ORG
        self.bucket = bucket or INFLUXDB_BUCKET
        self.client = InfluxDBClient(
            url=self.url, token=self.token, org=self.org
        )
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)
        logger.info(
            "InfluxDB exporter initialisé: %s (org=%s, bucket=%s)",
            self.url, self.org, self.bucket,
        )

    def write_risk_score(self, risk_data):
        """
        Écrit un risk score dans InfluxDB.

        Args:
            risk_data: dict avec score, level, reason, event_type, device_id
        """
        try:
            point = (
                Point("risk_score")
                .tag("device_id", risk_data.get("device_id", "unknown"))
                .tag("event_type", risk_data.get("event_type", "unknown"))
                .tag("risk_level", risk_data.get("level", "LOW"))
                .field("score", int(risk_data.get("score", 0)))
                .field("risk_reason", str(risk_data.get("reason", "")))
                .time(datetime.utcnow(), WritePrecision.NS)
            )
            self.write_api.write(
                bucket=self.bucket, org=self.org, record=point
            )
            logger.debug(
                "Risk score exporté: device=%s score=%s level=%s",
                risk_data.get("device_id"),
                risk_data.get("score"),
                risk_data.get("level"),
            )
        except Exception:
            logger.exception("Erreur lors de l'export vers InfluxDB")

    def write_log(self, log):
        """
        Écrit un log IoT complet dans InfluxDB (compatible avec l'existant).

        Args:
            log: dict avec les champs du log IoT
        """
        try:
            point = (
                Point("iot_logs")
                .tag("device_id", log.get("device_id", "unknown"))
                .tag("event_type", log.get("event_type", "unknown"))
                .tag("auth_method", log.get("auth_method", "unknown"))
                .field("latency_ms", float(log.get("latency_ms", 0)))
                .field(
                    "failed_attempts_24h",
                    int(log.get("failed_attempts_24h", 0)),
                )
                .field("risk_score", int(log.get("risk_score", 0)))
                .time(datetime.utcnow(), WritePrecision.NS)
            )
            self.write_api.write(
                bucket=self.bucket, org=self.org, record=point
            )
        except Exception:
            logger.exception("Erreur lors de l'export du log vers InfluxDB")

    def close(self):
        """Ferme la connexion InfluxDB."""
        if self.client:
            self.client.close()
