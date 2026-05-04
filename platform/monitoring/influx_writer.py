from influxdb_client import InfluxDBClient, Point, WritePrecision
from datetime import datetime

#config
url = "http://influxdb:8086"
token = "mytoken1234"
org = "iot_org"
bucket = "iot_bucket"

client = InfluxDBClient(url=url, token=token, org=org)
write_api = client.write_api()

def write_log(log):
    point = (
     Point("iot_logs")
     .tag("device_id", log["device_id"])
     .tag("event_type", log["event_type"])
     .tag("auth_method", log["auth_method"])
     .field("latency_ms", log["latency_ms"])
     .field("failed_attempts_24h", log["failed_attempts_24h"])
     .field("risk_score", log["risk_score"])
     .time(datetime.utcnow(), WritePrecision.NS)
   )
    write_api.write(bucket=bucket, org=org, record=point)

def write_prediction(device_id, action, risk_score, explanation, data, level="LOW RISK", confidence=0.0):
    import json
    point = (
     Point("iot_predictions")
     .tag("device_id", device_id)
     .tag("action", action)
     .tag("level",  level)
     #riskscore converti en 0-100 pour faciliter dans grafana
     .field("risk_score",          int(risk_score * 100))
     .field("confidence",          float(confidence))
     .field("latency_ms",          float(data.get("latency_ms", 0.0)))
     .field("failed_attempts_24h", int(data.get("failed_attempts_24h", 0)))
     .field("explanation",         json.dumps(explanation))
     .time(datetime.utcnow(), WritePrecision.NS)
)
    write_api.write(bucket=bucket, org=org, record=point)
