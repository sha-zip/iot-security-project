#!/usr/bin/env bash
# entrypoint.sh — Init SoftHSM + stunnel + agent
# Flux : SoftHSM ← PKCS#11 → stunnel → mTLS → Mosquitto:8883
#        agent.py → localhost:1883 (loopback interne)
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

mkdir -p "${CERT_STORE}"

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

# ── 2. Générer la clé RSA si absente ────────────────────────────────────
echo "[INIT] Vérification clé RSA dans le token..."
KEY_EXISTS=$(softhsm2-util --show-slots 2>/dev/null | grep -c "${KEY_LABEL}" || true)

# On utilise python-pkcs11 pour vérifier (plus fiable que grep)
python3 - << PYEOF
import os, pkcs11
lib = pkcs11.lib("${PKCS11_LIB}")
tokens = list(lib.get_tokens(token_label="${TOKEN_LABEL}"))
if not tokens:
    print("[INIT] Token introuvable depuis Python")
    exit(1)
session = tokens[0].open(user_pin="${USER_PIN}", rw=True)
from pkcs11 import Attribute, ObjectClass, KeyType
keys = list(session.get_objects({
    Attribute.CLASS: ObjectClass.PRIVATE_KEY,
    Attribute.LABEL: "${KEY_LABEL}",
}))
session.close()
if keys:
    print("[INIT] Clé '${KEY_LABEL}' déjà présente dans le token.")
else:
    print("[INIT] Clé absente — génération...")
    session = tokens[0].open(user_pin="${USER_PIN}", rw=True)
    pub, priv = session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="${KEY_LABEL}",
        public_template={
            Attribute.TOKEN: True, Attribute.VERIFY: True,
        },
        private_template={
            Attribute.TOKEN: True, Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
            Attribute.SIGN: True,
        },
    )
    session.close()
    print("[INIT] Paire RSA-2048 générée dans SoftHSM.")
PYEOF

# ── 3. Générer stunnel.conf avec le bon DEVICE_ID ───────────────────────
echo "[INIT] Génération de stunnel.conf pour device=${DEVICE_ID}..."

CERT_PATH="${CERT_STORE}/${DEVICE_ID}.crt"

cat > /etc/stunnel/stunnel.conf << EOF
; stunnel.conf — Proxy mTLS MQTT
; agent.py → 127.0.0.1:1883 → stunnel → ${MQTT_BROKER}:${MQTT_PORT} (mTLS)
; Clé privée dans SoftHSM via PKCS#11 — ne quitte jamais le token

foreground = yes
debug = 4
pid = /tmp/stunnel.pid


[mqtts-client]
client  = yes
accept  = 127.0.0.1:1883
connect = ${MQTT_BROKER}:${MQTT_PORT}

cert   = ${CERT_PATH}
key    = /tmp/device_certs/${DEVICE_ID}_private.pem
CAfile = ${CA_CERT}
verify = 2

sslVersion = TLSv1.2
EOF

echo "[INIT] stunnel.conf généré."

# ── 4. Attendre que le certificat soit disponible ───────────────────────
# Le certificat est généré par agent.py via la PKI.
# stunnel sera lancé APRÈS que agent.py ait obtenu son certificat.
# agent.py écrit un fichier signal quand le cert est prêt.
# Générer la clé privée éphémère si absente
mkdir -p /tmp/device_certs
if [ ! -f "/tmp/device_certs/${DEVICE_ID}_private.pem" ]; then
    echo "[INIT] Génération de la clé privée éphémère..."
    openssl genrsa -out /tmp/device_certs/${DEVICE_ID}_private.pem 2048
    chmod 600 /tmp/device_certs/${DEVICE_ID}_private.pem
    echo "[INIT] Clé privée générée."
fi

echo "[INIT] Lancement de agent.py (obtention du certificat)..."

# Lancer agent.py en mode "cert-only" — il s'arrête après avoir obtenu le cert
# En attendant le certificat, on utilise STUNNEL_READY comme signal
export STUNNEL_MODE=1  # agent.py détectera cette variable

# Lancer agent.py normalement — il va :
# 1. Init SE
# 2. Générer CSR via PKCS#11
# 3. Envoyer à la PKI → recevoir le certificat
# 4. Stocker le cert dans CERT_STORE
# 5. Détecter STUNNEL_MODE=1 → écrire /tmp/cert_ready et s'arrêter
python3 /app/agent.py --cert-only 2>&1 &
AGENT_PID=$!

# Attendre le fichier signal (max 60s)
echo "[INIT] Attente du certificat..."
TIMEOUT=60
ELAPSED=0
while [ ! -f "/tmp/cert_ready" ] && [ $ELAPSED -lt $TIMEOUT ]; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    echo "[INIT] Attente certificat... ${ELAPSED}s"
done

if [ ! -f "/tmp/cert_ready" ]; then
    echo "[ERREUR] Certificat non obtenu après ${TIMEOUT}s. Arrêt."
    kill $AGENT_PID 2>/dev/null || true
    exit 1
fi

# Arrêter agent.py mode cert-only
kill $AGENT_PID 2>/dev/null || true
sleep 1

echo "[INIT] Certificat obtenu : ${CERT_PATH}"

# ── 5. Lancer stunnel en arrière-plan ────────────────────────────────────
echo "[INIT] Démarrage stunnel (mTLS via PKCS#11)..."
stunnel /etc/stunnel/stunnel.conf &
STUNNEL_PID=$!
sleep 2

# Vérifier que stunnel tourne
if ! kill -0 $STUNNEL_PID 2>/dev/null; then
    echo "[ERREUR] stunnel n'a pas démarré. Vérifiez la config."
    exit 1
fi

echo "[OK] stunnel actif — port local 1883 → ${MQTT_BROKER}:${MQTT_PORT} (mTLS)"

# ── 6. Lancer agent.py en mode normal (connect localhost:1883) ───────────
echo "[INIT] Démarrage agent.py (mode MQTT via stunnel)..."
unset STUNNEL_MODE
exec python3 /app/agent.py
