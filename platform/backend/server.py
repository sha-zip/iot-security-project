"""
server.py — Backend de la Plateforme IoT Sécurisée
====================================================
Implémente côté serveur les étapes de l'organigramme :
 
  POST /api/v1/enroll   → Validation CSR → Signature certificat
  POST /api/v1/data     → Réception données → Pipeline IA
                          → Score risque → blocage / surveillance
                          → Écriture InfluxDB (risk score + XAI)
 
INTÉGRATION IA + INFLUX :
  - Le pipeline IA (feature_extractor → attack_model → risk_scoring → xai_explainer)
    est appelé dans _analyze_behavior()
  - Chaque prédiction est écrite dans InfluxDB via write_prediction()
  - Le dashboard Grafana consomme la mesure `iot_predictions`
 
Dépendances :
    pip install flask cryptography paho-mqtt scikit-learn numpy influxdb-client
"""

import os
import sys
import ssl
import json
import time
import logging
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from functools import wraps

from flask import Flask, request, jsonify, abort
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_csr
import datetime

# Imports locaux
sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_registry import DeviceRegistry, DeviceStatus
from logger import AuditLogger

# ── Chemins ──────────────────────────────────────────────────────────────────
ROOT_DIR  = Path(__file__).resolve().parent
AI_DIR    = ROOT_DIR / "platform" / "ai_engine"
# Ajoute les modules locaux
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(AI_DIR))

# ── Registre & Audit ─────────────────────────────────────────────────────────
try:
    from device_registry import DeviceRegistry, DeviceStatus
    from logger import AuditLogger
    REGISTRY_AVAILABLE = True
except ImportError:
    REGISTRY_AVAILABLE = False
  
# ── Moteur IA ─────────────────────────────────────────────────────────────────
try:
    from feature_extractor import extract_features, FEATURE_NAMES
    from attack_model      import AttackModel
    from risk_scoring      import compute_risk
    from xai_explainer     import explain
    AI_AVAILABLE = True
except ImportError as _ai_err:
    AI_AVAILABLE = False
    _AI_IMPORT_ERROR = str(_ai_err)
 
# ── InfluxDB ──────────────────────────────────────────────────────────────────
try:
    from influx_writer import write_prediction, write_log
    INFLUX_AVAILABLE = True
except ImportError:
    INFLUX_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BACKEND] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/backend.log", mode="a"),
    ]
)
log = logging.getLogger("backend")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CA_CERT_PATH    = os.getenv("CA_CERT",     "/app/pki/ca.crt")
CA_KEY_PATH     = os.getenv("CA_KEY",      "/app/pki/ca.key")
CERTS_DIR       = os.getenv("CERTS_DIR",   "/app/pki/issued")
CRL_PATH        = os.getenv("CRL_PATH",    "/app/pki/crl.pem")
DB_PATH         = os.getenv("DB_PATH",     "/app/monitoring/logs.db")
MQTT_BROKER     = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT       = int(os.getenv("MQTT_PORT", "8883"))
RISK_THRESHOLD_BLOCK    = float(os.getenv("RISK_BLOCK",     "0.75"))
RISK_THRESHOLD_MONITOR  = float(os.getenv("RISK_MONITOR",   "0.45"))
API_KEY         = os.getenv("API_KEY",      "changeme-secret-key")  # Pour admin
MODEL_PATH     = os.getenv("MODEL_PATH", str(ROOT_DIR / "attack_model.pkl"))

Path(CERTS_DIR).mkdir(parents=True, exist_ok=True)

app     = Flask(__name__)
if REGISTRY_AVAILABLE:
    registry = DeviceRegistry(DB_PATH)
    audit    = AuditLogger(DB_PATH)
else:
    registry = audit = None
    log.warning("DeviceRegistry / AuditLogger non disponibles.")
# ── Chargement du modèle IA ───────────────────────────────────────────────────
_attack_model: Optional["AttackModel"] = None
 
if AI_AVAILABLE:
    if Path(MODEL_PATH).exists():
        try:
            _attack_model = AttackModel()
            _attack_model.load(MODEL_PATH)
            log.info("Modèle IA chargé depuis %s", MODEL_PATH)
        except Exception as exc:
            log.warning("Impossible de charger le modèle : %s", exc)
    else:
        log.warning(
            "Modèle introuvable (%s) — lancez main.py pour l'entraîner.", MODEL_PATH
        )
else:
    log.warning("Moteur IA non disponible : %s", _AI_IMPORT_ERROR if not AI_AVAILABLE else "")
 

# ---------------------------------------------------------------------------
# Middleware d'authentification (routes admin)
# ---------------------------------------------------------------------------

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if key != API_KEY:
            audit.log_event("auth_failure", {"endpoint": request.path, "ip": request.remote_addr})
            abort(401, "Clé API invalide.")
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# ── Étape 3 / 4 : Enrôlement du device (validation CSR + signature cert)
# ---------------------------------------------------------------------------

@app.route("/api/v1/enroll", methods=["POST"])
def enroll_device():
    """
    POST /api/v1/enroll
    Body JSON : { "device_id": str, "csr": str (PEM), "fingerprint": str }

    Implémente l'organigramme :
      « La CSR est-elle valide ? »
        Oui → Signature du certificat
              « Le certificat a-t-il été généré avec succès ? »
                Oui → 200 { status: cert_generated, certificate: PEM }
                Non → 200 { status: cert_failed }
        Non → Rejet de la CSR → 200 { status: rejected, reason: ... }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"status": "rejected", "reason": "Payload JSON invalide"}), 400

    device_id   = str(data.get("device_id",   "")).strip()
    csr_pem     = str(data.get("csr",         "")).strip()
    fingerprint = str(data.get("fingerprint", "")).strip()

    log.info("[ENROLL] Device=%s fingerprint=%s", device_id, fingerprint[:16])
    audit.log_event("enroll_attempt", {
        "device_id": device_id, "fingerprint": fingerprint, "ip": request.remote_addr
    })

    # ── Validation de la CSR ─────────────────────────────────────────────
    valid, reason = _validate_csr(csr_pem, device_id)
    if not valid:
        log.warning("[REJET CSR] device=%s raison=%s", device_id, reason)
        audit.log_event("csr_rejected", {"device_id": device_id, "reason": reason})
        return jsonify({"status": "rejected", "reason": reason})

    # ── Signature du certificat par la CA ────────────────────────────────
    log.info("[PKI] Signature du certificat pour device=%s", device_id)
    cert_pem, err = _sign_certificate(csr_pem, device_id)

    if err:
        log.error("[ÉCHEC CERT] device=%s erreur=%s", device_id, err)
        audit.log_event("cert_failed", {"device_id": device_id, "error": err})
        return jsonify({"status": "cert_failed", "reason": err})

    # ── Enregistrement du device dans le registre ─────────────────────────
    registry.register_device(
        device_id=device_id,
        fingerprint=fingerprint,
        certificate_pem=cert_pem,
    )

    log.info("[OK] Certificat émis pour device=%s", device_id)
    audit.log_event("cert_issued", {"device_id": device_id})

    return jsonify({
        "status":      "cert_generated",
        "certificate": cert_pem,
    })


# ---------------------------------------------------------------------------
# ── Étape 8-N : Réception des données + pipeline IA
# ---------------------------------------------------------------------------

@app.route("/api/v1/data", methods=["POST"])
def receive_data():
    """
    POST /api/v1/data
    Body JSON : { "device_id": str, "timestamp": float, ... telemetry ... }

    Implémente les étapes de l'organigramme :
      « Le comportement est-il normal ? »
        Oui → Autorisation maintenue
        Non → Détection d'anomalies (IA) → Calcul score de risque
               → « Le risque est-il élevé ? »
                    Oui → Blocage du dispositif
                    Non → Surveillance renforcée
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"action": "reject", "reason": "payload invalide"}), 400

    device_id = str(data.get("device_id", "")).strip()
    if not device_id:
        return jsonify({"action": "reject", "reason": "device_id manquant"}), 400

    # ── Vérifier que le device est autorisé ─────────────────────────────
    device = registry.get_device(device_id)
    if not device:
        log.warning("[UNAUTHORIZED] Device inconnu : %s", device_id)
        audit.log_event("unknown_device", {"device_id": device_id})
        return jsonify({"action": "reject", "reason": "device inconnu"}), 403

    if device["status"] == DeviceStatus.BLOCKED:
        log.warning("[BLOCKED] Device bloqué tente d'envoyer des données : %s", device_id)
        return jsonify({"action": "block", "reason": "device bloqué"}), 403

    # ── Enregistrement de l'événement ───────────────────────────────────
    audit.log_event("data_received", {
        "device_id": device_id,
        "timestamp": data.get("timestamp"),
    })
    registry.update_last_seen(device_id)

   # ── Pipeline IA ───────────────────────────────────────────────────────────
    analysis = _run_ai_pipeline(device_id, data)
 
    action     = analysis["action"]
    risk       = analysis["risk_score"]
    level      = analysis["level"]
    reasons    = analysis["reasons"]
    confidence = analysis.get("confidence", 0.0)
    predicted  = analysis.get("predicted_attack", 0)
 
    log.info(
        "[IA] device=%s | predicted_attack=%s | score=%d | level=%s | action=%s",
        device_id, predicted, risk, level, action,
    )

    if action == "block":
        # ── Organigramme : Risque élevé → Blocage du dispositif ─────────
        log.critical("[BLOCAGE] Blocage du device %s (score=%.3f)", device_id, risk)
        registry.update_device_status(device_id, DeviceStatus.BLOCKED)
        audit.log_event("device_blocked", {
            "device_id": device_id, "risk_score": risk,
            "reasons": analysis.get("reasons", [])
        })
        _notify_device(device_id, "block", risk, analysis.get("reasons", []))

    elif action == "enhanced_monitoring":
        # ── Organigramme : Risque modéré → Surveillance renforcée ────────
        log.warning("[MONITORING+] Surveillance renforcée pour %s (score=%.3f)",
                    device_id, risk)
        registry.update_device_status(device_id, DeviceStatus.MONITORED)
        audit.log_event("enhanced_monitoring", {
            "device_id": device_id, "risk_score": risk
        })
        _notify_device(device_id, "enhanced_monitoring", risk, [])
# ── Écriture InfluxDB ─────────────────────────────────────────────────────
    if INFLUX_AVAILABLE:
        try:
            write_prediction(
                device_id=device_id,
                action=action,
                risk_score=risk,
                explanation=reasons,
                data=data,
                level=level,
                confidence=confidence,
            )
            log.info("[INFLUX] Prédiction écrite pour %s", device_id)
        except Exception as exc:
            log.error("[INFLUX] Écriture échouée pour %s : %s", device_id, exc)
 
    return jsonify({
        "action":     action,
        "risk_score": risk,
        "risk_level": level,
        "reasons":    reasons,
        "confidence": confidence,
        "timestamp":  time.time(),
    })
# ---------------------------------------------------------------------------
# ── Routes d'administration
# ---------------------------------------------------------------------------

@app.route("/api/v1/devices", methods=["GET"])
@require_api_key
def list_devices():
    """Liste tous les devices enregistrés."""
    devices = registry.list_devices()
    return jsonify({"devices": devices})


@app.route("/api/v1/devices/<device_id>/revoke", methods=["POST"])
@require_api_key
def revoke_device(device_id: str):
    """Révoque le certificat d'un device et le bloque."""
    device = registry.get_device(device_id)
    if not device:
        return jsonify({"error": "device inconnu"}), 404

    # Révocation OpenSSL
    err = _revoke_certificate(device_id)
    registry.update_device_status(device_id, DeviceStatus.BLOCKED)
    _notify_device(device_id, "revoke_cert", 1.0, ["manuel"])
    audit.log_event("cert_revoked", {"device_id": device_id, "admin": True})

    return jsonify({"status": "revoked", "device_id": device_id})


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status":           "ok",
        "ai_available":     AI_AVAILABLE,
        "model_loaded":     _attack_model is not None,
        "influx_available": INFLUX_AVAILABLE,
        "registry":         REGISTRY_AVAILABLE,
    })
 
# ---------------------------------------------------------------------------
# Fonctions internes PKI
# ---------------------------------------------------------------------------

def _validate_csr(csr_pem: str, device_id: str) -> Tuple[bool, str]:
    """
    Valide la CSR avant signature.
    Organigramme : « La CSR est-elle valide ? »

    Contrôles :
      1. Décodage PEM valide
      2. CN correspond au device_id attendu
      3. Signature de la CSR elle-même valide
      4. Device non déjà révoqué
    """
    if not csr_pem or not csr_pem.strip().startswith("-----BEGIN"):
        return False, "CSR PEM invalide ou vide"

    try:
        csr = load_pem_x509_csr(csr_pem.encode(), default_backend())
    except Exception as exc:
        return False, f"Impossible de décoder la CSR : {exc}"

    # Vérification CN
    try:
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cn_attrs:
            return False, "CN manquant dans la CSR"
        cn = cn_attrs[0].value
        if cn != device_id:
            return False, f"CN mismatch : attendu '{device_id}', reçu '{cn}'"
    except Exception as exc:
        return False, f"Erreur lecture CN : {exc}"

    # Vérification signature interne de la CSR
    if not csr.is_signature_valid:
        return False, "Signature de la CSR invalide"

    # Vérification liste noire (device déjà révoqué)
    device = registry.get_device(device_id)
    if device and device["status"] == DeviceStatus.BLOCKED:
        return False, "Device révoqué — enrôlement refusé"

    return True, ""


def _sign_certificate(csr_pem: str, device_id: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Signe le CSR avec la CA pour produire un certificat X.509.
    Organigramme : « Signature du certificat (création) »

    Utilise OpenSSL via subprocess pour une compatibilité maximale.
    Retourne (cert_pem, None) en cas de succès, (None, error_msg) sinon.
    """
    if not os.path.exists(CA_CERT_PATH) or not os.path.exists(CA_KEY_PATH):
        return None, "Fichiers CA introuvables"

    with tempfile.TemporaryDirectory() as tmpdir:
        csr_file  = os.path.join(tmpdir, "device.csr")
        cert_file = os.path.join(tmpdir, "device.crt")
        ext_file  = os.path.join(tmpdir, "v3.ext")

        # Écriture de la CSR
        with open(csr_file, "w") as f:
            f.write(csr_pem)

        # Extension X.509 v3
        ext_content = (
            "authorityKeyIdentifier=keyid,issuer\n"
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=clientAuth\n"
            f"subjectAltName=DNS:{device_id}\n"
        )
        with open(ext_file, "w") as f:
            f.write(ext_content)

        # Signature via OpenSSL
        serial = str(int(time.time() * 1000))
        cmd = [
            "openssl", "x509",
            "-req",
            "-in",      csr_file,
            "-CA",      CA_CERT_PATH,
            "-CAkey",   CA_KEY_PATH,
            "-set_serial", serial,
            "-days",    "365",
            "-sha256",
            "-extfile", ext_file,
            "-out",     cert_file,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
        except FileNotFoundError:
            return None, "OpenSSL introuvable"
        except subprocess.TimeoutExpired:
            return None, "Timeout lors de la signature du certificat"

        if result.returncode != 0:
            return None, f"openssl x509 échoué : {result.stderr.strip()}"

        if not os.path.exists(cert_file):
            return None, "Fichier de certificat non généré"

        with open(cert_file, "r") as f:
            cert_pem = f.read()

        # Sauvegarde dans le répertoire des certificats émis
        issued_path = os.path.join(CERTS_DIR, f"{device_id}.crt")
        with open(issued_path, "w") as f:
            f.write(cert_pem)
        os.chmod(issued_path, 0o644)

        return cert_pem, None


def _revoke_certificate(device_id: str) -> Optional[str]:
    """Révoque le certificat d'un device via openssl ca."""
    cert_path = os.path.join(CERTS_DIR, f"{device_id}.crt")
    if not os.path.exists(cert_path):
        return f"Certificat introuvable pour {device_id}"

    cmd = [
        "openssl", "ca",
        "-revoke", cert_path,
        "-keyfile", CA_KEY_PATH,
        "-cert",    CA_CERT_PATH,
        "-crl_reason", "keyCompromise",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode != 0:
        return result.stderr.strip()
    return None


# ---------------------------------------------------------------------------
# Pipeline IA — Analyse comportementale
# ---------------------------------------------------------------------------

def _run_ai_pipeline(device_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pipeline complet :
      extract_features → attack_model.predict → compute_risk → xai_explainer.explain
    Retourne un dict normalisé consommé par receive_data() et write_prediction().
    """
    if not AI_AVAILABLE or _attack_model is None:
        return _fallback_heuristic(device_id, data)
 
    try:
        # 1. Features (list → dict pour risk_scoring et xai)
        features_list = extract_features(data)
        feature_names = [
            "failed_attempts_24h", "latency_ms", "auth_result",
            "attack", "secure_element", "auth_method",
        ]
        row = dict(zip(feature_names, features_list))
 
        # 2. Prédiction attaque + confiance
        import numpy as np
        X = np.array([features_list])
        predictions = _attack_model.predict_with_confidence(X)
        predicted_attack, confidence = predictions[0]
 
        # 3. Risk score (0-100)
        risk = compute_risk(row, predicted_attack)
 
        # 4. XAI + niveau
        level, reasons = explain(row, predicted_attack, confidence, risk)
 
        # 5. Décision
        action = _decide(risk)
 
        return {
            "action":           action,
            "risk_score":       risk,
            "level":            level,
            "reasons":          reasons,
            "confidence":       float(confidence),
            "predicted_attack": int(predicted_attack),
        }
 
    except Exception as exc:
        log.error("[IA] Erreur pipeline pour %s : %s", device_id, exc)
        return _fallback_heuristic(device_id, data)
 
 
def _decide(risk: int) -> str:
    """Convertit un risk score (0-100) en action."""
    if risk >= RISK_THRESHOLD_BLOCK:
        return "block"
    if risk >= RISK_THRESHOLD_MONITOR:
        return "enhanced_monitoring"
    return "allow"
 
 
def _fallback_heuristic(device_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyse heuristique de secours quand le modèle n'est pas disponible."""
    risk    = 0
    reasons = []
 
    if data.get("attack_type", "None") != "None":
        risk += 30
        reasons.append(f"Attack type détecté : {data.get('attack_type')}")
 
    if str(data.get("auth_result", "")).lower() in ("failure", "0"):
        risk += 10
        reasons.append("Authentification échouée")
 
    fails = int(data.get("failed_attempts_24h", 0))
    if fails > 5:
        risk += 10
        reasons.append(f"{fails} tentatives échouées en 24h")
 
    latency = float(data.get("latency_ms", 0))
    if latency > 150:
        risk += 5
        reasons.append(f"Latence élevée : {latency} ms")
 
    risk  = min(risk, 100)
    level = ("HIGH RISK" if risk > 50 else "MEDIUM RISK" if risk > 20 else "LOW RISK")
 
    return {
        "action":           _decide(risk),
        "risk_score":       risk,
        "level":            level,
        "reasons":          reasons,
        "confidence":       0.0,
        "predicted_attack": 1 if risk >= RISK_MONITOR else 0,
    }
 
 

# ---------------------------------------------------------------------------
# Notification MQTT vers le device
# ---------------------------------------------------------------------------

def _notify_device(device_id: str, action: str, risk_score: int, reasons: list) -> None:
    try:
        import paho.mqtt.publish as publish
 
        topic   = f"iot/{device_id}/cmd"
        payload = json.dumps({
            "action":     action,
            "risk_score": risk_score,
            "reasons":    reasons,
            "timestamp":  time.time(),
        })
        tls_dict = {
            "ca_certs":    CA_CERT_PATH,
            "cert_reqs":   ssl.CERT_REQUIRED,
            "tls_version": ssl.PROTOCOL_TLS_CLIENT,
        }
        publish.single(topic, payload=payload, qos=1,
                       hostname=MQTT_BROKER, port=MQTT_PORT,
                       tls=tls_dict, transport="tcp")
        log.info("[MQTT→] device=%s action=%s", device_id, action)
 
    except Exception as exc:
        log.error("[MQTT] Impossible d'envoyer à %s : %s", device_id, exc)
 

#----------------------------
#MQTT
#-------------------------------
def start_mqtt_subscriber():
   #subscribe to mqtt to receive telemetry qnd forward to ai pipeline
    import paho.mqtt.client as mqtt
    def on_connect(client, userdata, flags, rc, properties=None):
     if rc == 0:
      client.subscribe("iot/+/data", qos=1)
      log.info("[MQTT SUB] Abonne au topic iot/+/data")
    def on_message(client, userdata, msg):
     try:
      data = json.loads(msg.payload.decode("utf-8"))
      device_id = data.get("device_is", "")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Backend IoT sécurisé")
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  default=8443, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    # TLS côté serveur (HTTPS)
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert = os.getenv("SERVER_CERT", "/app/pki/server.crt")
    server_key  = os.getenv("SERVER_KEY",  "/app/pki/server.key")

    if os.path.exists(server_cert) and os.path.exists(server_key):
        ssl_ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
        ssl_ctx.load_verify_locations(cafile=CA_CERT_PATH)
        log.info("HTTPS activé sur %s:%d", args.host, args.port)
        app.run(
            host=args.host,
            port=args.port,
            ssl_context=ssl_ctx,
            debug=args.debug,
            threaded=True,
        )
    else:
        log.warning(
            "Certificats serveur introuvables — démarrage en HTTP (DÉVELOPPEMENT UNIQUEMENT)."
        )
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True,
        )
