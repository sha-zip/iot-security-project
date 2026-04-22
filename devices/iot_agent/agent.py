"""
agent.py — Agent IoT Sécurisé
==============================
Client MQTT qui implémente l'intégralité de l'organigramme :

  Initialisation → Génération CSR → Envoi à la PKI (backend)
    → Validation CSR → Signature certificat
    → Stockage cert + clé privée (via SE)
    → Tentative connexion TLS → Validation cert
    → Connexion mTLS broker MQTT
    → Envoi données → Analyse comportement (IA backend)
    → Résultat : autorisation maintenue | anomalie → score risque
      → blocage | surveillance renforcée

Conformément au cahier des charges :
  - Authentification mutuelle (mTLS) Objet ↔ Plateforme
  - Clé privée protégée dans le Secure Element (SoftHSM/PKCS#11)
  - On-boarding sécurisé
  - Reconnexion / gestion des erreurs robuste

Dépendances :
    pip install paho-mqtt cryptography requests python-pkcs11
"""

import os
import sys
import ssl
import json
import time
import uuid
import logging
import hashlib
import tempfile
import threading
import signal
from pathlib import Path
from typing import Optional, Dict, Any

import requests
import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Import local du module Secure Element
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "secure_element"))
from se_module import SecureElement, SEError

# ---------------------------------------------------------------------------
# Logging structuré
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/agent.log", mode="a"),
    ]
)
log = logging.getLogger("agent")

# ---------------------------------------------------------------------------
# Configuration — surcharger via variables d'environnement
# ---------------------------------------------------------------------------
DEVICE_ID       = os.getenv("DEVICE_ID",        str(uuid.uuid4()))
PKI_URL         = os.getenv("PKI_URL",           "https://localhost:8443")
MQTT_BROKER     = os.getenv("MQTT_BROKER",       "localhost")
MQTT_PORT       = int(os.getenv("MQTT_PORT",     "8883"))
MQTT_TOPIC_DATA = os.getenv("MQTT_TOPIC_DATA",   f"iot/{DEVICE_ID}/data")
MQTT_TOPIC_CMD  = os.getenv("MQTT_TOPIC_CMD",    f"iot/{DEVICE_ID}/cmd")
CA_CERT_PATH    = os.getenv("CA_CERT",           "/app/pki/ca.crt")
CERT_STORE_DIR  = os.getenv("CERT_STORE_DIR",    "/tmp/device_certs")
MAX_CSR_RETRIES = int(os.getenv("MAX_CSR_RETRIES", "3"))
MAX_CERT_RETRIES= int(os.getenv("MAX_CERT_RETRIES","3"))
SEND_INTERVAL   = float(os.getenv("SEND_INTERVAL", "5.0"))   # secondes
VERIFY_TLS_BACKEND = os.getenv("VERIFY_TLS_BACKEND", "true").lower() == "true"

Path(CERT_STORE_DIR).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# États de l'agent (machine à états de l'organigramme)
# ---------------------------------------------------------------------------
class AgentState:
    INIT            = "INIT"
    CSR_GENERATING  = "CSR_GENERATING"
    CSR_SENT        = "CSR_SENT"
    CERT_STORED     = "CERT_STORED"
    CONNECTING      = "CONNECTING"
    CONNECTED       = "CONNECTED"
    BLOCKED         = "BLOCKED"
    MONITORING      = "MONITORING"
    ERROR           = "ERROR"


# ---------------------------------------------------------------------------
# Agent principal
# ---------------------------------------------------------------------------
class IoTAgent:
    """
    Agent IoT qui suit exactement le flux de l'organigramme.
    """

    def __init__(self):
        self.state: str = AgentState.INIT
        self.device_id: str = DEVICE_ID
        self.se: Optional[SecureElement] = None
        self.mqtt_client: Optional[mqtt.Client] = None
        self._cert_path: Optional[str] = None
        self._key_path: Optional[str] = None
        self._running: bool = False
        self._send_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        log.info("Agent IoT créé — Device-ID : %s", self.device_id)

    # ------------------------------------------------------------------
    # Point d'entrée principal : suit l'organigramme
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Exécute la boucle principale de l'organigramme :
        Init → CSR → PKI → Cert → TLS → MQTT → données → analyse…
        """
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT,  self._handle_signal)

        try:
            # ── Étape 1 : Initialisation de l'objet IoT ─────────────────
            self._step_init()

            # ── Étapes 2-5 : CSR → PKI → Cert ───────────────────────────
            csr_ok = self._step_csr_lifecycle()
            if not csr_ok:
                log.error("Impossible d'obtenir un certificat. Arrêt.")
                self.state = AgentState.ERROR
                return

            # ── Étapes 6-7 : Connexion TLS / validation cert ─────────────
            tls_ok = self._step_tls_connect()
            if not tls_ok:
                log.error("Connexion TLS refusée. Arrêt.")
                self.state = AgentState.BLOCKED
                return

            # ── Étapes 8-N : Envoi données + analyse comportement ────────
            self._step_run_loop()

        except KeyboardInterrupt:
            log.info("Interruption clavier reçue.")
        except Exception as exc:  # pylint: disable=broad-except
            log.exception("Erreur fatale : %s", exc)
            self.state = AgentState.ERROR
        finally:
            self._cleanup()

    # ------------------------------------------------------------------
    # Étape 1 — Initialisation de l'objet IoT
    # ------------------------------------------------------------------

    def _step_init(self) -> None:
        log.info("[ÉTAPE 1] Initialisation de l'objet IoT")
        self.state = AgentState.INIT
        self.se = SecureElement()
        self.se.initialize()
        log.info("[OK] Secure Element opérationnel. Fingerprint : %s",
                 self.se.get_device_fingerprint())

    # ------------------------------------------------------------------
    # Étapes 2-5 — CSR lifecycle
    # ------------------------------------------------------------------

    def _step_csr_lifecycle(self) -> bool:
        """
        Retourne True si un certificat valide a été obtenu et stocké.
        Implémente la boucle de l'organigramme :
          Génération CSR → envoi PKI → validation → signature cert
          (avec retry si CSR invalide ou génération échouée)
        """
        for csr_attempt in range(1, MAX_CSR_RETRIES + 1):
            # ── Étape 2 : Génération d'une requête CSR ──────────────
            log.info("[ÉTAPE 2] Génération du CSR (tentative %d/%d)",
                     csr_attempt, MAX_CSR_RETRIES)
            self.state = AgentState.CSR_GENERATING
            try:
                csr_pem = self.se.generate_csr(self.device_id)
            except SEError as exc:
                log.error("Génération CSR échouée : %s", exc)
                continue

            # ── Étape 3 : Envoi de la CSR à la PKI ─────────────────
            log.info("[ÉTAPE 3] Envoi de la CSR à la PKI → %s", PKI_URL)
            self.state = AgentState.CSR_SENT

            for cert_attempt in range(1, MAX_CERT_RETRIES + 1):
                result = self._submit_csr_to_pki(csr_pem)

                if result is None:
                    # Échec réseau → nouvelle tentative de génération CSR
                    log.warning("Erreur réseau vers la PKI.")
                    break

                if result["status"] == "rejected":
                    # ── Organigramme : CSR invalide → Rejet → Nouvelle CSR
                    log.warning(
                        "[REJET PKI] La CSR a été rejetée : %s. "
                        "Génération d'une nouvelle CSR…",
                        result.get("reason", "inconnu")
                    )
                    break  # sort de la boucle cert → retente CSR

                if result["status"] == "cert_generated":
                    # ── Organigramme : Certificat signé avec succès
                    log.info("[OK] Certificat reçu de la PKI.")
                    if self._step_store_certificate(result["certificate"]):
                        return True
                    # Stockage échoué → retenter la génération
                    log.error("Stockage du certificat échoué.")
                    break

                if result["status"] == "cert_failed":
                    # ── Organigramme : Nouvelle tentative de génération cert
                    log.warning(
                        "[ÉCHEC CERT] Tentative %d/%d…",
                        cert_attempt, MAX_CERT_RETRIES
                    )
                    time.sleep(2 ** cert_attempt)   # backoff exponentiel

            # Petite pause avant nouvelle génération de CSR
            time.sleep(2)

        log.error("Toutes les tentatives d'obtention de certificat ont échoué.")
        return False

    def _submit_csr_to_pki(self, csr_pem: bytes) -> Optional[Dict[str, Any]]:
        """
        Envoie la CSR au backend/PKI et retourne la réponse JSON.
        Retourne None en cas d'erreur réseau.
        """
        endpoint = f"{PKI_URL}/api/v1/enroll"
        payload = {
            "device_id":   self.device_id,
            "csr":         csr_pem.decode("utf-8"),
            "fingerprint": self.se.get_device_fingerprint(),
        }
        try:
            resp = requests.post(
                endpoint,
                json=payload,
                verify=CA_CERT_PATH if VERIFY_TLS_BACKEND else False,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.SSLError as exc:
            log.error("Erreur SSL vers la PKI : %s", exc)
            return None
        except requests.exceptions.ConnectionError as exc:
            log.error("Impossible de joindre la PKI : %s", exc)
            return None
        except requests.exceptions.Timeout:
            log.error("Timeout en attendant la réponse de la PKI.")
            return None
        except requests.exceptions.HTTPError as exc:
            log.error("Erreur HTTP PKI [%s] : %s", resp.status_code, exc)
            return {"status": "rejected", "reason": str(exc)}

    # ------------------------------------------------------------------
    # Étape 4-5 — Stockage du certificat et de la clé privée
    # ------------------------------------------------------------------

    def _step_store_certificate(self, cert_pem: str) -> bool:
        """
        Étape « Stockage du certificat et de la clé privée » de l'organigramme.
        La clé privée reste dans le token ; on stocke uniquement le certificat.
        """
        log.info("[ÉTAPE 5] Stockage du certificat.")
        try:
            cert_path = os.path.join(CERT_STORE_DIR, f"{self.device_id}.crt")
            # Écriture sécurisée (permissions 0600)
            with open(cert_path, "w") as f:
                f.write(cert_pem)
            os.chmod(cert_path, 0o600)

            # Vérification de la validité du certificat reçu
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            log.info(
                "[OK] Certificat stocké : CN=%s, expire=%s",
                cert.subject.get_attributes_for_oid(
                    x509.oid.NameOID.COMMON_NAME
                )[0].value,
                cert.not_valid_after,
            )

            self._cert_path = cert_path
            self.state = AgentState.CERT_STORED
            return True

        except Exception as exc:  # pylint: disable=broad-except
            log.error("Erreur de stockage du certificat : %s", exc)
            return False

    # ------------------------------------------------------------------
    # Étape 6-7 — Tentative de connexion TLS
    # ------------------------------------------------------------------

    def _step_tls_connect(self) -> bool:
        """
        Étape « Tentative de connexion TLS » puis « Le certificat est-il valide ? ».
        Configure mTLS et tente la connexion au broker MQTT.
        Retourne True si la connexion est acceptée.
        """
        log.info("[ÉTAPE 6] Tentative de connexion TLS au broker MQTT.")
        self.state = AgentState.CONNECTING

        key_pem = self._get_tls_private_key_pem()
        if key_pem is None:
            return False

        # Écriture temporaire de la clé (effacée après connexion)
        key_path = os.path.join(CERT_STORE_DIR, f"{self.device_id}.key")
        try:
            with open(key_path, "wb") as f:
                f.write(key_pem)
            os.chmod(key_path, 0o600)
            self._key_path = key_path
        except OSError as exc:
            log.error("Impossible d'écrire la clé temporaire : %s", exc)
            return False

        # Configurer le client MQTT
        client_id = f"iot-{self.device_id}"
        self.mqtt_client = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv5,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        )

        # Callbacks
        self.mqtt_client.on_connect    = self._on_mqtt_connect
        self.mqtt_client.on_disconnect = self._on_mqtt_disconnect
        self.mqtt_client.on_message    = self._on_mqtt_message
        self.mqtt_client.on_publish    = self._on_mqtt_publish

        # TLS mutuel (mTLS)
        try:
            self.mqtt_client.tls_set(
                ca_certs=CA_CERT_PATH,
                certfile=self._cert_path,
                keyfile=self._key_path,
                cert_reqs=ssl.CERT_REQUIRED,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
            self.mqtt_client.tls_insecure_set(False)
        except ssl.SSLError as exc:
            log.error("[REFUS TLS] Configuration SSL échouée : %s", exc)
            return False

        # Tentative de connexion
        try:
            self.mqtt_client.connect(
                MQTT_BROKER,
                MQTT_PORT,
                keepalive=60,
                clean_start=True,
            )
        except ConnectionRefusedError as exc:
            log.error("[REFUS CONNEXION] Broker a refusé : %s", exc)
            return False
        except OSError as exc:
            log.error("[REFUS CONNEXION] Erreur réseau : %s", exc)
            return False

        # Démarrer la boucle MQTT en arrière-plan
        self.mqtt_client.loop_start()

        # Attendre la confirmation de connexion (max 10 s)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.state == AgentState.CONNECTED:
                return True
            if self.state == AgentState.BLOCKED:
                return False
            time.sleep(0.2)

        log.error("[TIMEOUT] Pas de réponse du broker MQTT après 10s.")
        return False

    def _get_tls_private_key_pem(self) -> Optional[bytes]:
        """
        Retourne une représentation PEM de la clé privée utilisable par paho.
        Dans le mode simulation SoftHSM, on doit avoir une clé extractable.
        En production, utiliser wolfSSL ou mbedTLS avec moteur PKCS#11.
        """
        # Mode simulation : lire la clé depuis le répertoire de certs si disponible
        possible_key = os.path.join(CERT_STORE_DIR, f"{self.device_id}_private.pem")
        if os.path.exists(possible_key):
            with open(possible_key, "rb") as f:
                return f.read()

        # Fallback : générer une clé éphémère pour la démo (à remplacer en prod)
        log.warning(
            "Clé privée non trouvée dans %s. "
            "Utilisation d'une clé éphémère (DÉMO UNIQUEMENT).",
            possible_key
        )
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives import serialization as _ser

        ephemeral = _rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return ephemeral.private_bytes(
            encoding=_ser.Encoding.PEM,
            format=_ser.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=_ser.NoEncryption()
        )

    # ------------------------------------------------------------------
    # Étape 8-N — Boucle d'envoi de données + analyse comportement
    # ------------------------------------------------------------------

    def _step_run_loop(self) -> None:
        """
        Étape « Envoi des données » + « Le comportement est-il normal ? ».
        Publie des données périodiques et réagit aux commandes du backend.
        """
        log.info("[ÉTAPE 8] Boucle d'envoi de données démarrée.")

        # Abonnement aux commandes du backend (blocage, surveillance)
        self.mqtt_client.subscribe(MQTT_TOPIC_CMD, qos=1)
        log.info("Abonné au topic commandes : %s", MQTT_TOPIC_CMD)

        while self._running and self.state not in (
            AgentState.BLOCKED, AgentState.ERROR
        ):
            payload = self._build_telemetry_payload()
            result = self.mqtt_client.publish(
                MQTT_TOPIC_DATA,
                json.dumps(payload),
                qos=1,
                retain=False,
            )

            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                log.warning("Échec de publication MQTT (code %d).", result.rc)

            time.sleep(SEND_INTERVAL)

        if self.state == AgentState.BLOCKED:
            log.critical(
                "[BLOQUÉ] Le device a été bloqué par la plateforme. "
                "Arrêt de l'agent."
            )

    def _build_telemetry_payload(self) -> Dict[str, Any]:
        """Construit la charge utile de télémétrie."""
        import random
        return {
            "device_id":   self.device_id,
            "timestamp":   time.time(),
            "temperature": round(20 + random.uniform(-2, 2), 2),
            "humidity":    round(50 + random.uniform(-5, 5), 2),
            "uptime_s":    int(time.time()),
            "fingerprint": self.se.get_device_fingerprint() if self.se else "",
        }

    # ------------------------------------------------------------------
    # Callbacks MQTT
    # ------------------------------------------------------------------

    def _on_mqtt_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            log.info(
                "[ÉTAPE 7] Connexion sécurisée au broker MQTT (mTLS) établie."
            )
            self.state = AgentState.CONNECTED
        elif rc == 5:
            log.error("[REFUS CONNEXION] Authentification refusée (rc=5).")
            self.state = AgentState.BLOCKED
        else:
            log.error(
                "[REFUS CONNEXION] Connexion refusée par le broker (rc=%d).", rc
            )
            self.state = AgentState.BLOCKED

    def _on_mqtt_disconnect(self, client, userdata, rc, properties=None):
        if rc != 0:
            log.warning("Déconnexion inattendue du broker (rc=%d).", rc)
            if self._running and self.state not in (
                AgentState.BLOCKED, AgentState.ERROR
            ):
                self.state = AgentState.CONNECTING
                log.info("Tentative de reconnexion dans 5s…")
                time.sleep(5)
                try:
                    client.reconnect()
                except Exception as exc:
                    log.error("Reconnexion échouée : %s", exc)
                    self.state = AgentState.ERROR

    def _on_mqtt_message(self, client, userdata, msg):
        """
        Traite les commandes reçues du backend (blocage, surveillance renforcée).
        Étape « Résultat analyse IA » de l'organigramme.
        """
        try:
            cmd = json.loads(msg.payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            log.warning("Message reçu invalide : %s", exc)
            return

        action = cmd.get("action", "")
        log.info("[CMD REÇU] Action : %s | Raison : %s",
                 action, cmd.get("reason", "N/A"))

        if action == "block":
            # ── Organigramme : Risque élevé → Blocage du dispositif
            log.critical(
                "[BLOCAGE] Dispositif bloqué par la plateforme. "
                "Score de risque : %s",
                cmd.get("risk_score", "N/A")
            )
            self.state = AgentState.BLOCKED
            self._running = False

        elif action == "enhanced_monitoring":
            # ── Organigramme : Risque modéré → Surveillance renforcée
            log.warning(
                "[SURVEILLANCE RENFORCÉE] Réduction de l'intervalle d'envoi."
            )
            self.state = AgentState.MONITORING
            global SEND_INTERVAL
            SEND_INTERVAL = max(1.0, SEND_INTERVAL / 2)

        elif action == "revoke_cert":
            log.critical("[RÉVOCATION] Certificat révoqué. Déconnexion.")
            self.state = AgentState.BLOCKED
            self._running = False

    def _on_mqtt_publish(self, client, userdata, mid, reason_code=None, properties=None):
        log.debug("Message publié (mid=%d).", mid)

    # ------------------------------------------------------------------
    # Nettoyage
    # ------------------------------------------------------------------

    def _cleanup(self) -> None:
        log.info("Nettoyage des ressources…")

        if self.mqtt_client:
            try:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
            except Exception:  # pylint: disable=broad-except
                pass

        # Effacement sécurisé de la clé temporaire
        if self._key_path and os.path.exists(self._key_path):
            try:
                size = os.path.getsize(self._key_path)
                with open(self._key_path, "wb") as f:
                    f.write(os.urandom(size))
                os.unlink(self._key_path)
                log.info("Clé privée temporaire effacée de façon sécurisée.")
            except OSError as exc:
                log.warning("Impossible d'effacer la clé temporaire : %s", exc)

        if self.se:
            self.se.close()

    def _handle_signal(self, signum, frame):
        log.info("Signal %d reçu. Arrêt propre…", signum)
        self._running = False


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Démarrage de l'agent IoT sécurisé — Device : %s", DEVICE_ID)
    agent = IoTAgent()
    agent.run()
    log.info("Agent arrêté.")
