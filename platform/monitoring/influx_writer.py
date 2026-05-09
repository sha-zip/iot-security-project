"""
influx_writer.py — Écriture InfluxDB
======================================
Remplace logger.py (SQLite audit) — tous les événements de sécurité
sont maintenant écrits dans InfluxDB et visibles dans Grafana.
 
Mesures :
  - iot_predictions  : résultats pipeline IA (risk, action, confidence...)
  - iot_events       : événements sécurité (enroll, cert_issued, blocked...)
"""

import json
import logging
from datetime import datetime, timezone

from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS
 
log = logging.getLogger("influx_writer")
#config
url = "http://influxdb:8086"
token = "mytoken1234"
org = "iot_org"
bucket = "iot_bucket"

client = InfluxDBClient(url=url, token=token, org=org)
write_api = client.write_api(write_options=SYNCHRONOUS)

def write_log(log):
    point = (
     Point("iot_logs")
     .tag("device_id", log["device_id"])
     .tag("event_type", log["event_type"])
     .tag("auth_method", log["auth_method"])
     .field("latency_ms", log["latency_ms"])
     .field("failed_attempts_24h", log["failed_attempts_24h"])
     .field("risk_score", int(log["risk_score"]))
     .time(datetime.utcnow(), WritePrecision.NS)
   )
    write_api.write(bucket=bucket, org=org, record=point)

# ---------------------------------------------------------------------------
# Mesure 1 : Prédictions IA  →  iot_predictions
# ---------------------------------------------------------------------------
def write_prediction(device_id, action, risk_score, explanation, data, level="LOW RISK", confidence=0.0, predicted_attack: str = "None") -> None:
    """
    Écrit le résultat du pipeline IA dans InfluxDB.
    Affiché dans Grafana : courbes risk_score, actions, confidence...
    """
    
    auth = data.get("auth", data)
    import json
    point = (
     Point("iot_predictions")
     .tag("device_id", device_id)
     .tag("action", action)
     .tag("level",  level)
     .tag("predicted_attack", predicted_attack)
     #riskscore converti en 0-100 pour faciliter dans grafana
     .field("risk_score",          int(risk_score))
     .field("confidence",          float(confidence))
     .field("latency_ms",          float(auth.get("tls_latency_ms", auth.get("latency_ms", 0.0))))
     .field("failed_attempts_24h", int(auth.get("failed_attempts_24h", 0)))
     .field("secure_element_used",  int(bool(auth.get("secure_element_used", False))))
     .field("explanation",         json.dumps(explanation))
     .time(datetime.utcnow(), WritePrecision.NS)
)
    write_api.write(bucket=bucket, org=org, record=point)
    try:
     write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
     log.debug("[INFLUX] iot_predictions écrit : device=%s action=%s score=%d",
       device_id, action, risk_score)
    except Exception as exc:
     log.error("[INFLUX] Erreur écriture iot_predictions : %s", exc)

# ---------------------------------------------------------------------------
# Mesure 2 : Événements sécurité  →  iot_events
# ---------------------------------------------------------------------------
 
def write_device_event(
    event_type: str,
    device_id:  str,
    details:    dict = None,
) -> None:
    """
    Remplace audit.log_event() de logger.py.
    Écrit un événement de sécurité dans InfluxDB → visible dans Grafana.
 
    event_type exemples :
      enroll_attempt, csr_rejected, cert_issued, cert_failed,
      device_blocked, enhanced_monitoring, cert_revoked,
      unknown_device, auth_failure, data_received
    """
    details = details or {}
 
    point = (
        Point("iot_events")
        .tag("device_id",  device_id or details.get("device_id", "unknown"))
        .tag("event_type", event_type)
        # Champs optionnels selon l'événement
        .field("risk_score",  int(details.get("risk_score",  0)))
        .field("ip",          str(details.get("ip",          "")))
        .field("reason",      str(details.get("reason",      "")))
        .field("fingerprint", str(details.get("fingerprint", ""))[:32])  # tronqué
        .field("details",     json.dumps(details))
        .time(datetime.now(timezone.utc), WritePrecision.NS)
    )
 
    try:
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        log.debug("[INFLUX] iot_events écrit : event=%s device=%s",
                  event_type, device_id)
    except Exception as exc:
        log.error("[INFLUX] Erreur écriture iot_events : %s", exc)
 
 
# ---------------------------------------------------------------------------
# Mesure 3 : Statut device  →  iot_device_status
# ---------------------------------------------------------------------------
 
def write_device_status(device_id: str, status: str) -> None:
    """
    Écrit le changement de statut d'un device (active/blocked/monitored).
    Permet à Grafana d'afficher l'historique des statuts.
    """
    status_map = {
        "active":    1,
        "monitored": 2,
        "blocked":   3,
        "pending":   0,
    }
 
    point = (
        Point("iot_device_status")
        .tag("device_id", device_id)
        .tag("status",    status)
        .field("status_code", status_map.get(status, 0))
        .time(datetime.now(timezone.utc), WritePrecision.NS)
    )
 
    try:
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
        log.debug("[INFLUX] iot_device_status écrit : device=%s status=%s",
                  device_id, status)
    except Exception as exc:
        log.error("[INFLUX] Erreur écriture iot_device_status : %s", exc)
 



