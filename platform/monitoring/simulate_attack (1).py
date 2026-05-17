"""
simulate_attack.py
==================
Script de simulation d'attaque par force brute sur un objet IoT.
Emplacement : platform/monitoring/simulate_attack.py

Utilisation :
    python3 simulate_attack.py
"""

import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration — chemins des certificats
# ---------------------------------------------------------------------------

BACKEND_URL = "https://localhost:8443/api/v1/data"
DEVICE_ID   = "iot-device-001"
NB_REQUETES = 15
DELAI       = 0.5

# Certificats PKI du projet
CERT_FILE = "/home/nad/iot-security-project/pki/device001.crt"
KEY_FILE  = "/home/nad/iot-security-project/pki/device001.key"
CA_FILE   = "/home/nad/iot-security-project/pki/ca.crt"

# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

print("=" * 62)
print("  SIMULATION ATTAQUE PAR FORCE BRUTE")
print("=" * 62)
print(f"  Cible       : {DEVICE_ID}")
print(f"  Endpoint    : {BACKEND_URL}")
print(f"  Nb requetes : {NB_REQUETES}")
print("=" * 62)
print()

for i in range(1, NB_REQUETES + 1):

    payload = {
        "device_id"           : DEVICE_ID,
        "timestamp"           : time.time(),
        "auth_result"         : "Failure",
        "failed_attempts_24h" : 10 + i,
        "latency_ms"          : 320.0,
        "attack_type"         : "Bruteforce",
        "secure_element"      : "FALSE",
        "auth_method"         : "mTLS_Software",
        "temperature"         : 25.0
    }

    try:
        response = requests.post(
            BACKEND_URL,
            json=payload,
            cert=(CERT_FILE, KEY_FILE),
            verify=CA_FILE,
            timeout=5
        )

        data       = response.json()
        action     = data.get("action", "unknown")
        risk_score = data.get("risk_score", 0.0)

        if action == "block":
            status = "[BLOQUE]"
        elif action == "enhanced_monitoring":
            status = "[SURVEILLANCE]"
        else:
            status = "[AUTORISE]"

        print(f"  [{i:02d}/{NB_REQUETES}]  "
              f"failed_attempts={10 + i:>3}  |  "
              f"risk_score={risk_score:>5.1f}  |  "
              f"action={action:<22}  {status}")

    except requests.exceptions.SSLError as e:
        # Si mTLS echoue, retenter sans certificat client
        try:
            response = requests.post(
                BACKEND_URL,
                json=payload,
                verify=False,
                timeout=5
            )
            data       = response.json()
            action     = data.get("action", "unknown")
            risk_score = data.get("risk_score", 0.0)

            if action == "block":
                status = "[BLOQUE]"
            elif action == "enhanced_monitoring":
                status = "[SURVEILLANCE]"
            else:
                status = "[AUTORISE]"

            print(f"  [{i:02d}/{NB_REQUETES}]  "
                  f"failed_attempts={10 + i:>3}  |  "
                  f"risk_score={risk_score:>5.1f}  |  "
                  f"action={action:<22}  {status}")

        except Exception as e2:
            print(f"  [{i:02d}/{NB_REQUETES}]  Erreur SSL : {e2}")

    except requests.exceptions.ConnectionError:
        print(f"  [{i:02d}/{NB_REQUETES}]  Connexion refusee.")
        break

    except Exception as e:
        print(f"  [{i:02d}/{NB_REQUETES}]  Erreur : {e}")

    time.sleep(DELAI)

print()
print("=" * 62)
print("  Simulation terminee.")
print("=" * 62)
