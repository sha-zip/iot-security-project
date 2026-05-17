"""
simulate_attack.py
==================
Script de simulation d'attaque par force brute sur un objet IoT.

Emplacement : platform/monitoring/simulate_attack.py

Objectif :
    Envoyer au backend une série de requêtes POST vers /api/v1/data
    en injectant des données caractéristiques d'une attaque par force brute :
      - auth_result         = Failure
      - failed_attempts_24h = valeur croissante (> 10)
      - latency_ms          = 320 ms (anormalement élevée)
      - attack_type         = Bruteforce
      - secure_element      = FALSE (absence de SE)

Utilisation :
    python3 simulate_attack.py

Prérequis :
    pip install requests
    Le backend doit être démarré sur localhost:8443
"""

import requests
import time
import json
import urllib3

# Désactiver les warnings SSL en mode développement (HTTP)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BACKEND_URL  = "http://localhost:8443/api/v1/data"   # adapter si HTTPS
DEVICE_ID    = "iot-device-001"
NB_REQUETES  = 15
DELAI        = 0.5   # secondes entre chaque requête

# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

print("=" * 60)
print("  SIMULATION ATTAQUE PAR FORCE BRUTE")
print("=" * 60)
print(f"  Cible       : {DEVICE_ID}")
print(f"  Endpoint    : {BACKEND_URL}")
print(f"  Nb requêtes : {NB_REQUETES}")
print("=" * 60)
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
            verify=False,   # désactiver vérif SSL en dev
            timeout=5
        )
        data = response.json()

        action     = data.get("action", "unknown")
        risk_score = data.get("risk_score", 0.0)

        # Affichage coloré selon le niveau de risque
        if action == "block":
            status = "🔴 BLOQUE"
        elif action == "enhanced_monitoring":
            status = "🟠 SURVEILLANCE"
        else:
            status = "🟢 AUTORISE"

        print(f"  [{i:02d}/{NB_REQUETES}]  "
              f"failed_attempts={10 + i:>3}  |  "
              f"risk_score={risk_score:>5.1f}  |  "
              f"action={action:<22}  {status}")

    except requests.exceptions.ConnectionError:
        print(f"  [{i:02d}/{NB_REQUETES}]  ❌ Impossible de contacter le backend "
              f"— vérifier que le serveur est démarré.")
        break

    except Exception as e:
        print(f"  [{i:02d}/{NB_REQUETES}]  ❌ Erreur inattendue : {e}")

    time.sleep(DELAI)

print()
print("=" * 60)
print("  Simulation terminée.")
print("=" * 60)
