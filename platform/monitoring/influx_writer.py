from influxdb_client import InfluxDBClient, Point, WritePrecision
from datetime import datetime

#config
url = "http://localhost:8086"
token = "mytoken123"
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

