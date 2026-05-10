#!/usr/bin/env bash
# entrypoint.sh — Init SoftHSM + stunnel + agent
# Flux : SoftHSM ← PKCS#11 → stunnel → mTLS → Mosquitto:8883
#        agent.py → localhost:11883 (loopback stunnel client)
set -euo pipefail

TOKEN_LABEL="${SE_TOKEN_LABEL:-iot-token}"
USER_PIN="${SE_USER_PIN:-1234}"
SO_PIN="so${USER_PIN}"
KEY_LABEL="${SE_KEY_LABEL:-iot-device-key}"
PKCS11_LIB="${PKCS11_LIB:-/usr/lib/softhsm/libsofthsm2.so}"
DEVICE_ID="${DEVICE_ID:-iot-device-001}"
CERT_STORE="/tmp/device_certs"
MQTT_BROKER="${MQTT_BROKER:-mqtt}"
MQTT_PORT="${MQTT_PORT:-8883}"
CA_CERT="${CA_CERT:-/app/pki/ca.crt}"

# Port local stunnel (différent de 1883 pour éviter le conflit avec Mosquitto)
STUNNEL_LOCAL_PORT=11883

mkdir -p "${CERT_STORE}"
mkdir -p /etc/stunnel
mkdir -p /var/log/stunnel

# ── 1. Initialiser le token SoftHSM si absent ────────────────────────────
echo "[INIT] Vérification token SoftHSM : ${TOKEN_LABEL}"
TOKEN_EXISTS=$(softhsm2-util --show-slots 2>/dev/null | grep -c "${TOKEN_LABEL}" || true)

if [ "${TOKEN_EXISTS}" -eq 0 ]; then
    echo "[INIT] Token absent — initialisation..."
    softhsm2-util --init-token \
        --free \
        --label  "${TOKEN_LABEL}" \
        --so-pin "${SO_PIN}" \
        --pin    "${USER_PIN}"
    echo "[INIT] Token initialisé."
else
    echo "[INIT] Token '${TOKEN_LABEL}' déjà présent."
fi

# ── 2. Vérifier/générer la clé RSA dans le token ────────────────────────
echo "[INIT] Vérification clé RSA dans le token..."

python3 - << PYEOF
import os, sys, pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType

try:
    lib = pkcs11.lib("${PKCS11_LIB}")
    tokens = list(lib.get_tokens(token_label="${TOKEN_LABEL}"))
    if not tokens:
        print("[INIT] ERREUR : Token introuvable depuis Python")
        sys.exit(1)

    session = tokens[0].open(user_pin="${USER_PIN}", rw=True)
    keys = list(session.get_objects({
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: "${KEY_LABEL}",
    }))
    session.close()

    if keys:
        print("[INIT] Clé '${KEY_LABEL}' déjà présente dans le token.")
    else:
        print("[INIT] Clé absente — génération RSA-2048...")
        session = tokens[0].open(user_pin="${USER_PIN}", rw=True)
        pub, priv = session.generate_keypair(
            KeyType.RSA, 2048, store=True, label="${KEY_LABEL}",
            public_template={
                Attribute.TOKEN: True,
                Attribute.VERIFY: True,
            },
            private_template={
                Attribute.TOKEN:       True,
                Attribute.PRIVATE:     True,
                Attribute.SENSITIVE:   True,
                Attribute.EXTRACTABLE: False,   # clé non exportable
                Attribute.SIGN:        True,
            },
        )
        session.close()
        print("[INIT] Paire RSA-2048 générée dans SoftHSM.")
except Exception as e:
    print(f"[INIT] ERREUR PKCS#11 : {e}")
    sys.exit(1)
PYEOF

# ── 3. Obtenir le certificat via agent.py (mode enrôlement) ─────────────
# agent.py va :
#   Init SE → Générer CSR → Envoyer PKI → Recevoir cert → Stocker → exit
# On détecte la fin via le fichier signal /tmp/cert_ready

CERT_PATH="${CERT_STORE}/${DEVICE_ID}.crt"
KEY_PATH="${CERT_STORE}/${DEVICE_ID}_private.pem"

if [ -f "${CERT_PATH}" ] && [ -f "${KEY_PATH}" ]; then
    echo "[INIT] Certificat déjà présent : ${CERT_PATH}"
else
    echo "[INIT] Lancement de agent.py en mode enrôlement (--cert-only)..."
    rm -f /tmp/cert_ready

    # CERT_ONLY_MODE : agent.py s'arrête après avoir stocké le certificat
    export CERT_ONLY_MODE=1
    python3 /app/agent.py &
    AGENT_PID=$!

    # Attendre le fichier signal (max 90s)
    TIMEOUT=90
    ELAPSED=0
    while [ ! -f "/tmp/cert_ready" ] && [ $ELAPSED -lt $TIMEOUT ]; do
        sleep 2
        ELAPSED=$((ELAPSED + 2))
        echo "[INIT] Attente certificat... ${ELAPSED}s/${TIMEOUT}s"
    done

    # Arrêter agent.py mode enrôlement
    kill $AGENT_PID 2>/dev/null || true
    wait $AGENT_PID 2>/dev/null || true

    if [ ! -f "/tmp/cert_ready" ]; then
        echo "[ERREUR] Certificat non obtenu après ${TIMEOUT}s. Vérifiez la PKI."
        exit 1
    fi

    if [ ! -f "${CERT_PATH}" ]; then
        echo "[ERREUR] Fichier certificat introuvable : ${CERT_PATH}"
        exit 1
    fi

    if [ ! -f "${KEY_PATH}" ]; then
        echo "[ERREUR] Clé privée introuvable : ${KEY_PATH}"
        exit 1
    fi

    echo "[OK] Certificat obtenu et stocké."
fi

# ── 4. Générer stunnel.conf avec les bons chemins ───────────────────────
echo "[INIT] Génération de /etc/stunnel/stunnel.conf..."

cat > /etc/stunnel/stunnel.conf << EOF
; stunnel.conf — Client mTLS MQTT
; Généré automatiquement par entrypoint.sh
; Flux : agent.py → 127.0.0.1:${STUNNEL_LOCAL_PORT} → stunnel → ${MQTT_BROKER}:${MQTT_PORT} (mTLS)

foreground = yes
debug = 4
output = /var/log/stunnel/stunnel.log
pid = /tmp/stunnel.pid

; Désactiver les protocoles obsolètes
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1

[mqtts-client]
; Mode client : stunnel chiffre vers le broker
client  = yes

; Port TCP local — agent.py se connecte ici (MQTT_PORT=11883 dans agent.py)
accept  = 127.0.0.1:${STUNNEL_LOCAL_PORT}

; Broker MQTT avec TLS
connect = ${MQTT_BROKER}:${MQTT_PORT}

; Certificat de l'agent (obtenu via PKI dans l'étape 3)
cert   = ${CERT_PATH}
key    = ${KEY_PATH}

; CA pour vérifier le certificat du broker (anti-MITM)
CAfile = ${CA_CERT}

; Authentification mutuelle
verifyChain = yes
checkHost   = ${MQTT_BROKER}

sslVersion   = TLSv1.2
TIMEOUTclose = 5
sessionResume = no
EOF

echo "[INIT] stunnel.conf généré (port local : ${STUNNEL_LOCAL_PORT})."

# ── 5. Lancer stunnel en arrière-plan ────────────────────────────────────
echo "[INIT] Démarrage de stunnel..."
stunnel /etc/stunnel/stunnel.conf &
STUNNEL_PID=$!
sleep 2

# Vérifier que stunnel tourne
if ! kill -0 $STUNNEL_PID 2>/dev/null; then
    echo "[ERREUR] stunnel n'a pas démarré. Vérifiez la config et les certificats."
    cat /var/log/stunnel/stunnel.log 2>/dev/null || true
    exit 1
fi

echo "[OK] stunnel actif — 127.0.0.1:${STUNNEL_LOCAL_PORT} → ${MQTT_BROKER}:${MQTT_PORT} (mTLS)"

# ── 6. Lancer agent.py en mode normal ───────────────────────────────────
echo "[INIT] Démarrage de agent.py (mode MQTT normal)..."

# S'assurer que CERT_ONLY_MODE n'est plus actif
unset CERT_ONLY_MODE

# agent.py se connecte à stunnel local sur STUNNEL_LOCAL_PORT
export MQTT_BROKER=127.0.0.1
export MQTT_PORT=${STUNNEL_LOCAL_PORT}

# exec remplace le shell par agent.py (PID 1 dans le container)
exec python3 /app/agent.py
