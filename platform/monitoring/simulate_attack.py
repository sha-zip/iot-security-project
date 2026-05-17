"""
simulate_attack.py
==================
Script de simulation d'attaque par force brute sur un objet IoT.
Emplacement : platform/monitoring/simulate_attack.py

Utilisation :
    python3 simulate_attack.py
"""
import json
import ssl
import queue
import requests
import time
import urllib3
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration — chemins des certificats
# ---------------------------------------------------------------------------

DEVICE_ID   = "iot-device-001"
MQTT_BROKER = "localhost"
MQTT_PORT   = 8883
NB_REQUETES = 15
DELAI       = 0.5
RESPONSE_WAIT = 3.0

# Certificats PKI du projet
CERT_FILE = "/home/nad/iot-security-project/pki/device001.crt"
KEY_FILE  = "/home/nad/iot-security-project/pki/device001.key"
CA_FILE   = "/home/nad/iot-security-project/pki/ca.crt"

DATA_TOPIC = f"iot/{DEVICE_ID}/data"
CMD_TOPIC = f"iot/{DEVICE_ID}/cmd"
responses = queue.Queue()
#--------------------------------------------
#MQTT callbqcks
#--------------------------------------------
def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
     client.subscribe(CMD_TOPIC, qos=1)
    else:
     print(f"[MQTT] connexion refusee (code={reason_code})")
def on_message(client, userdata, msg):
    try:
     payload = json.loads(msg.payload.decode("utf-8"))
     responses.put(payload)
    except Exception as exec:
     responses.put({"action": "unknown", "risk_score": 0, "reason": f"payload invalid: {exec}"})
#-------------------------------------------------
#tls helper
#---------------------------------------------------
def build_tls_dict():
    return {
     "ca_certs": CA_FILE,
     "certfile": CERT_FILE,
     "keyfile": KEY_FILE,
     "cert_reqs": ssl.CERT_REQUIRED,
     "tls_version": ssl.PROTOCOL_TLS_CLIENT,
     "insecure": True,
    }
# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------
def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,client_id=f"simulator-{DEVICE_ID}", protocol=mqtt.MQTTv5)
    client.on_connect = on_connect
    client.on_message = on_message

    print("=" * 62)
    print("  SIMULATION ATTAQUE PAR FORCE BRUTE")
    print("=" * 62)
    print(f"  Cible       : {DEVICE_ID}")
    print(f"  Broker      : {MQTT_BROKER}: {MQTT_PORT}")
    print(f"  Topic data  : {DATA_TOPIC}")
    print(f"  Topic cmd   : {CMD_TOPIC}")
    print(f"  Nb requetes : {NB_REQUETES}")
    print("=" * 62)
    print()

    try:
     client.tls_set(
      ca_certs=CA_FILE,
      certfile=CERT_FILE,
      keyfile=KEY_FILE,
      cert_reqs=ssl.CERT_REQUIRED,
      tls_version=ssl.PROTOCOL_TLS_CLIENT,
     )
     client.tls_insecure_set(True)
     client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
     client.loop_start()
     time.sleep(1.0)
    except Exception as exc:
     print(f"[ERREUR] impossible de se connecter au broker mqtt : type={type(exc).__name__} repr={exc!r}")
     return

    for i in range(1, NB_REQUETES + 1):
     payload = {
      "device_id"           : DEVICE_ID,
      "timestamp"           : time.time(),
      "auth": {
       "auth_result"         : "Failure",
       "failed_attempts_24h" : 10 + i,
       "tls_latency_ms"          : 320.0,
       "attack_type"         : "Bruteforce",
       "secure_element"      : "FALSE",
       "auth_method"         : "mTLS_Software",
      }
     }

     try:
      while not responses.empty():
       responses.get_nowait()
      #publish.single(
      # DATA_TOPIC,
      # payload=json.dumps(payload),
       #qos=1,
       #hostname=MQTT_BROKER,
       #port=MQTT_PORT,
       #tls=build_tls_dict(),
       #transport="tcp",
      #)
      client.publish(DATA_TOPIC, json.dumps(payload), qos=1)
      try:
       data       = responses.get(timeout=RESPONSE_WAIT)
       action     = data.get("action", "unknown")
       risk_score = data.get("risk_score", 0.0)
       attack_type = data.get("attack_type", data.get("predicted_attack", "unknown"))
       risk_level  = data.get("risk_level", data.get("level", "unknown"))

       if action == "block":
        status = "[BLOQUE]"
       else:
        status = "[AUTORISE]"

       print(f"  [{i:02d}/{NB_REQUETES}]  "
              f"failed_attempts={10 + i:>3}  |  "
              f"risk_score={risk_score:>5.1f}  |  "
              f"attack={attack_type:<12}      |   "
              f"level={risk_level:<11}         |  "
              f"action={action:<18}  {status}")

      except queue.Empty:
       print(f"  [{i:02d}/{NB_REQUETES}]  Aucune reponse recue sur: {CMD_TOPIC}")
     except Exception as exc:
      print(f"  [{i:02d}/{NB_REQUETES}]  Erreur MQTT : {exc}")

     time.sleep(DELAI)
    client.loop_stop()
    client.disconnect()
    print()
    print("=" * 62)
    print("  Simulation terminee.")
    print("=" * 62)
if __name__ == "__main__":
    main()
