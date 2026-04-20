"""
server.py — Backend de la Plateforme IoT Sécurisée
====================================================
Implémente côté serveur les étapes de l'organigramme :

  POST /api/v1/enroll   → Validation CSR → Signature certificat
  POST /api/v1/data     → Réception données → Pipeline IA
                          → Score risque → blocage / surveillance

Conformément au cahier des charges :
  - Authentification mutuelle (mTLS) Objet ↔ Plateforme
  - PKI simplifiée (X.509, OpenSSL)
  - Détection d'anomalies (IA)
  - Score de risque → blocage ou surveillance renforcée

Dépendances :
    pip install flask cryptography paho-mqtt scikit-learn numpy
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

# Import du moteur IA
ai_path = str(Path(__file__).resolve().parent.parent / "ai_engine")
sys.path.insert(0, ai_path)
try:
    from anomaly_model  import AnomalyDetector
    from risk_scoring   import RiskScorer
    from feature_extractor import FeatureExtractor
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

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

Path(CERTS_DIR).mkdir(parents=True, exist_ok=True)

app     = Flask(__name__)
registry = DeviceRegistry(DB_PATH)
audit    = AuditLogger(DB_PATH)

if AI_AVAILABLE:
    feature_extractor = FeatureExtractor()
    anomaly_detector  = AnomalyDetector()
    risk_scorer       = RiskScorer()
    log.info("Moteur IA chargé avec succès.")
else:
    log.warning("Moteur IA non disponible — analyse désactivée.")


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

    # ── Analyse comportementale (IA) ──────────────────────────────────────
    analysis = _analyze_behavior(device_id, data)
    action   = analysis["action"]
    risk     = analysis.get("risk_score", 0.0)

    log.info(
        "[IA] device=%s | normal=%s | score=%.3f | action=%s",
        device_id, analysis.get("is_normal"), risk, action
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

    return jsonify({
        "action":     action,
        "risk_score": risk,
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
    return jsonify({"status": "ok", "ai_available": AI_AVAILABLE})


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

def _analyze_behavior(device_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pipeline IA complet :
      1. Extraction de features
      2. Détection d'anomalies
      3. Calcul du score de risque
      4. Décision : normal | surveillance | blocage

    Organigramme :
      « Le comportement est-il normal ? »
        Non → « Détection d'anomalies (IA) » → « Calcul score de risque »
               → « Le risque est-il élevé ? »
    """
    if not AI_AVAILABLE:
        return _fallback_heuristic_analysis(device_id, data)

    try:
        # Récupérer l'historique du device pour le contexte
        history = audit.get_recent_events(device_id, limit=100)

        # 1. Extraction de features
        features = feature_extractor.extract(data, history)

        # 2. Détection d'anomalies
        is_anomaly, anomaly_score, reasons = anomaly_detector.predict(features)

        if not is_anomaly:
            # ── Organigramme : Comportement normal → Autorisation maintenue
            return {"action": "allow", "is_normal": True, "risk_score": anomaly_score}

        # 3. Calcul du score de risque
        risk_score = risk_scorer.score(features, anomaly_score, history)

        # 4. Décision basée sur le seuil
        if risk_score >= RISK_THRESHOLD_BLOCK:
            # ── Organigramme : Risque élevé → Blocage
            return {
                "action":    "block",
                "is_normal": False,
                "risk_score": risk_score,
                "reasons":   reasons,
            }
        else:
            # ── Organigramme : Risque modéré → Surveillance renforcée
            return {
                "action":    "enhanced_monitoring",
                "is_normal": False,
                "risk_score": risk_score,
                "reasons":   reasons,
            }

    except Exception as exc:  # pylint: disable=broad-except
        log.error("Erreur pipeline IA pour %s : %s", device_id, exc)
        return _fallback_heuristic_analysis(device_id, data)


def _fallback_heuristic_analysis(
    device_id: str, data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Analyse heuristique de secours quand le moteur IA n'est pas disponible.
    Détecte des anomalies simples basées sur des règles.
    """
    risk_score = 0.0
    reasons    = []

    # Règle 1 : fréquence anormalement élevée (anti-DoS)
    recent = audit.get_recent_events(device_id, limit=60, window_seconds=60)
    if len(recent) > 50:
        risk_score += 0.4
        reasons.append("Trop de messages en 60s")

    # Règle 2 : température hors plage normale
    temp = data.get("temperature")
    if temp is not None:
        if not (-20 <= float(temp) <= 85):
            risk_score += 0.3
            reasons.append(f"Température anormale : {temp}°C")

    # Règle 3 : timestamp aberrant
    ts = data.get("timestamp", 0)
    now = time.time()
    if abs(now - float(ts)) > 300:
        risk_score += 0.2
        reasons.append("Timestamp trop éloigné de l'heure serveur")

    is_normal = risk_score < 0.3

    if risk_score >= RISK_THRESHOLD_BLOCK:
        action = "block"
    elif risk_score >= RISK_THRESHOLD_MONITOR:
        action = "enhanced_monitoring"
    else:
        action = "allow"

    return {
        "action":    action,
        "is_normal": is_normal,
        "risk_score": min(risk_score, 1.0),
        "reasons":   reasons,
    }


# ---------------------------------------------------------------------------
# Notification MQTT vers le device
# ---------------------------------------------------------------------------

def _notify_device(
    device_id: str,
    action: str,
    risk_score: float,
    reasons: list
) -> None:
    """Envoie une commande au device via MQTT (QoS 1, retain=False)."""
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
            "ca_certs":  CA_CERT_PATH,
            "cert_reqs": ssl.CERT_REQUIRED,
            "tls_version": ssl.PROTOCOL_TLS_CLIENT,
        }

        publish.single(
            topic,
            payload=payload,
            qos=1,
            hostname=MQTT_BROKER,
            port=MQTT_PORT,
            tls=tls_dict,
            transport="tcp",
        )
        log.info("[NOTIF→DEVICE] device=%s action=%s", device_id, action)

    except Exception as exc:  # pylint: disable=broad-except
        log.error("Impossible d'envoyer la commande à %s : %s", device_id, exc)


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
