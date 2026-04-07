import csv
import time
import json
import random
from influx_writer import write_log

CSV_FILE = "data.csv"

def simulate_logs():
    with open(CSV_FILE, newline='') as csvfile:
     reader = csv.DictReader(csvfile)

     for row in reader:
      log = {
             "timestamp": row["timestamp"],
             "device_id": row["device_id"],
             "auth_method": row["device_id"],
             "secure_element_used": row["secure_element_used"] == "TRUE",
             "attack_type": row["attack_type"],
             "auth_result": row["auth_result"],
             "latency_ms": float(row["latency_ms"]),
             "failed_attempts_24h": int(row["failed_attempts_24h"]),
             "risk_score": int(row["risk_score"])
        }
      #deter;iner type d evenement
      if log["auth_result"] == "Failure":
       event_type = "auth_failure"
      elif log["attack_type"] != "None":
       event_type = "attack_detected"
      else:
       event_type = "normal_activity"
      log["event_type"] = event_type

     #simulation anomalies
      if random.random() < 0.1:
       log["event_type"] = "suspicious_behavior"
       log["risk_score"] = min(log["risk_score"]+ 20, 100)

      #afficher log
      write_log(log)

      #simulation temp reel
      time.sleep(random.uniform(1, 3))

if __name__ == "__main__":
    simulate_logs()

