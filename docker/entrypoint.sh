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

# Port local stunnel (FIXE et UNIQUE)
STUNNEL_LOCAL_PORT=11883

mkdir -p "${CERT_STORE}"
mkdir -p /etc/stunnel
mkdir -p /var/log/stunnel

echo "==============================================================="
echo "ENTRYPOINT START — Device: $DEVICE_ID"
echo "==============================================================="
echo "STUNNEL_LOCAL_PORT: $STUNNEL_LOCAL_PORT"
echo "MQTT_BROKER: $MQTT_BROKER:$MQTT_PORT"
echo "CA_CERT: $CA_CERT"
echo "==============================================================="

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

python3 << 'PYEOF'
import os, sys, pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType

try:
    lib = pkcs11.lib(os.getenv("PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so"))
    token_label = os.getenv("SE_TOKEN_LABEL", "iot-token")
    user_pin = os.getenv("SE_USER_PIN", "1234")
    key_label = os.getenv("SE_KEY_LABEL", "iot-device-key")
    
    tokens = list(lib.get_tokens(token_label=token_label))
    if not tokens:
        print("[INIT] ERREUR : Token introuvable depuis Python")
        sys.exit(1)

    session = tokens[0].open(user_pin=user_pin, rw=True)
    keys = list(session.get_objects({
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        Attribute.LABEL: key_label,
    }))
    session.close()

    if keys:
        print("[INIT] Clé présente dans le token.")
    else:
        print("[INIT] Génération RSA-2048...")
        session = tokens[0].open(user_pin=user_pin, rw=True)
        pub, priv = session.generate_keypair(
            KeyType.RSA, 2048, store=True, label=key_label,
            public_template={
                Attribute.TOKEN: True,
                Attribute.VERIFY: True,
            },
            private_template={
                Attribute.TOKEN:       True,
                Attribute.PRIVATE:     True,
                Attribute.SENSITIVE:   True,
                Attribute.EXTRACTABLE: False,
                Attribute.SIGN:        True,
            },
        )
        session.close()
        print("[INIT] Paire RSA-2048 générée dans SoftHSM.")
except Exception as e:
    print(f"[INIT] ERREUR PKCS#11 : {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

# ── 3. Obtenir le certificat via agent.py (mode enrôlement) ─────────────
CERT_PATH="${CERT_STORE}/${DEVICE_ID}.crt"
KEY_PATH="${CERT_STORE}/${DEVICE_ID}_private.pem"

if [ -f "${CERT_PATH}" ] && [ -f "${KEY_PATH}" ]; then
    echo "[INIT] Certificat et clé déjà présents"
    ls -la "${CERT_PATH}" "${KEY_PATH}"
else
    echo "[INIT] Lancement de agent.py en mode enrôlement..."
    #DEBUG CA CERT
    echo "[DEBUG] CA  cert check before enrollement"
    ls -la "${CA_CERT}" || echo "CA cert MISSING AT ${CA_CERT}"
    rm -f /tmp/cert_ready

    export CERT_ONLY_MODE=1
    python3 /app/agent.py &
    AGENT_PID=$!

    TIMEOUT=120
    ELAPSED=0
    while [ ! -f "/tmp/cert_ready" ] && [ $ELAPSED -lt $TIMEOUT ]; do
        sleep 2
        ELAPSED=$((ELAPSED + 2))
        echo "[INIT] Attente certificat... ${ELAPSED}s/${TIMEOUT}s"
    done

    kill $AGENT_PID 2>/dev/null || true
    wait $AGENT_PID 2>/dev/null || true

    if [ ! -f "/tmp/cert_ready" ]; then
        echo "[ERREUR] Certificat non obtenu après ${TIMEOUT}s"
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

    echo "[OK] Certificat et clé obtenu(e)s"
    ls -la "${CERT_PATH}" "${KEY_PATH}"
fi

# ── 4. Vérifier que les fichiers existent et sont accessibles ────────────
echo "[INIT] Vérification des fichiers de certificat..."
if [ ! -f "${CERT_PATH}" ]; then
    echo "[ERREUR] Certificat manquant : ${CERT_PATH}"
    exit 1
fi
if [ ! -f "${KEY_PATH}" ]; then
    echo "[ERREUR] Clé privée manquante : ${KEY_PATH}"
    exit 1
fi
if [ ! -f "${CA_CERT}" ]; then
    echo "[ERREUR] CA cert manquant : ${CA_CERT}"
    exit 1
fi

echo "[OK] Tous les certificats sont présents"
chmod 644 "${CERT_PATH}"
chmod 600 "${KEY_PATH}"
chmod 644 "${CA_CERT}"

# ── 5. Générer stunnel.conf ───────────────────────────────────────────────
echo "[INIT] Génération de stunnel.conf..."

cat > /etc/stunnel/stunnel.conf << 'STUNNEL_EOF'
; stunnel.conf — Client mTLS MQTT
foreground = yes
debug = 7
output = stdout

; Désactiver protocoles obsolètes
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1

[mqtts-client]
client      = yes
accept      = 127.0.0.1:11883
connect     = MQTT_BROKER:MQTT_PORT
cert        = CERT_PATH
key         = KEY_PATH
CAfile      = CA_CERT_FILE
verify      = 2
checkHost   = MQTT_BROKER
sslVersion  = TLSv1.2
TIMEOUTclose = 5
sessionResume = no
STUNNEL_EOF

# Remplacer les placeholders
sed -i "s|MQTT_BROKER|${MQTT_BROKER}|g" /etc/stunnel/stunnel.conf
sed -i "s|MQTT_PORT|${MQTT_PORT}|g" /etc/stunnel/stunnel.conf
sed -i "s|CERT_PATH|${CERT_PATH}|g" /etc/stunnel/stunnel.conf
sed -i "s|KEY_PATH|${KEY_PATH}|g" /etc/stunnel/stunnel.conf
sed -i "s|CA_CERT_FILE|${CA_CERT}|g" /etc/stunnel/stunnel.conf

echo "[OK] stunnel.conf généré"
cat /etc/stunnel/stunnel.conf

# ── 6. Lancer stunnel en arrière-plan ────────────────────────────────────
echo "[INIT] Démarrage de stunnel..."
stunnel /etc/stunnel/stunnel.conf &
STUNNEL_PID=$!
sleep 3

if ! kill -0 $STUNNEL_PID 2>/dev/null; then
    echo "[ERREUR] stunnel n'a pas démarré"
    exit 1
fi

echo "[OK] stunnel est actif (PID=$STUNNEL_PID)"
echo "[OK] Port local: 127.0.0.1:${STUNNEL_LOCAL_PORT}"
echo "[OK] Connecté à: ${MQTT_BROKER}:${MQTT_PORT} (mTLS)"

# ── 7. Lancer agent.py en mode MQTT normal ───────────────────────────────
echo "[INIT] Démarrage de agent.py (mode MQTT)..."

unset CERT_ONLY_MODE

# CRITICAL: Force MQTT_BROKER et MQTT_PORT pour agent.py
export MQTT_BROKER=127.0.0.1
export MQTT_PORT=${STUNNEL_LOCAL_PORT}
export STUNNEL_MODE=1

echo "[AGENT] MQTT_BROKER=$MQTT_BROKER"
echo "[AGENT] MQTT_PORT=$MQTT_PORT"
echo "[AGENT] STUNNEL_MODE=$STUNNEL_MODE"

# Lancer agent.py
exec python3 /app/agent.py
