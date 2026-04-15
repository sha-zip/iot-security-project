import csv
import time
import json
import random
import sys
import os
import logging

# Ajouter le répertoire alerting au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "alerting"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "alerting"))

from influxdb_exporter import InfluxDBExporter
from risk_score_manager import RiskScoreManager
from alert_dispatcher import AlertDispatcher

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CSV_FILE = "data.csv"

def simulate_logs():
    # Initialiser les composants
    exporter = InfluxDBExporter()
    risk_manager = RiskScoreManager()
    dispatcher = AlertDispatcher()

    with open(CSV_FILE, newline='') as csvfile:
     reader = csv.DictReader(csvfile)

     for row in reader:
      log = {
             "timestamp": row["timestamp"],
             "device_id": row["device_id"],
             "auth_method": row["auth_method"],
             "secure_element_used": row["secure_element_used"] == "TRUE",
             "attack_type": row["attack_type"],
             "auth_result": row["auth_result"],
             "latency_ms": float(row["latency_ms"]),
             "failed_attempts_24h": int(row["failed_attempts_24h"]),
             "risk_score": int(row["risk_score"])
        }
      #determiner type d evenement
      if log["auth_result"] == "Failure":
       event_type = "auth_failure"
      elif log["attack_type"] != "None":
       event_type = "attack_detected"
      elif log["failed_attempts_24h"] > 10:
       event_type = "brute_force"
      elif log["latency_ms"] > 200:
       event_type = "latency_anomaly"
      else:
       event_type = "normal_activity"
      log["event_type"] = event_type

     #simulation anomalies
      if random.random() < 0.1:
       log["event_type"] = "suspicious_behavior"
       log["risk_score"] = min(log["risk_score"]+ 20, 100)

      # Calculer le risk score avec le manager
      risk_data = risk_manager.compute_risk(log)

      # Exporter le log IoT et le risk score vers InfluxDB
      exporter.write_log(log)
      exporter.write_risk_score(risk_data)

      # Dispatcher les alertes si nécessaire
      dispatcher.dispatch(risk_data)

      logger.info(
       "Device=%s | Score=%d | Level=%s | Type=%s | Reason=%s",
       risk_data["device_id"],
       risk_data["score"],
       risk_data["level"],
       risk_data["event_type"],
       risk_data["reason"],
      )

      #simulation temp reel
      time.sleep(random.uniform(1, 3))

    exporter.close()

if __name__ == "__main__":
    simulate_logs()

