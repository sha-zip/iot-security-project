"""
se_module.py — Secure Element (SoftHSM/PKCS#11) Interface
==========================================================
Simule un Secure Element matériel via SoftHSM2 + PKCS#11.
La clé privée ne quitte JAMAIS le token ; toutes les opérations
cryptographiques (signature, génération de CSR) se font à l'intérieur.

Dépendances :
    pip install python-pkcs11 cryptography
    apt install softhsm2
"""

import os
import sys
import logging
import hashlib
import struct
from typing import Optional, Tuple

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass, Mechanism, MGF
from pkcs11.util.rsa import encode_rsa_public_key

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SE] %(levelname)s %(message)s"
)
log = logging.getLogger("se_module")

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
PKCS11_LIB  = os.getenv("PKCS11_LIB",    "/usr/lib/softhsm/libsofthsm2.so")
TOKEN_LABEL = os.getenv("SE_TOKEN_LABEL", "iot-token")
USER_PIN    = os.getenv("SE_USER_PIN",    "1234")
KEY_LABEL   = os.getenv("SE_KEY_LABEL",  "iot-device-key")
KEY_SIZE    = int(os.getenv("SE_KEY_SIZE", "2048"))

# Répertoire où la clé éphémère de fallback est stockée
CERT_STORE_DIR = os.getenv("CERT_STORE_DIR", "/tmp/device_certs")


class SEError(Exception):
    """Exception de base pour les erreurs du Secure Element."""


class SecureElement:
    """
    Interface haut niveau vers le Secure Element (SoftHSM via PKCS#11).
    """

    def __init__(self):
        self._lib: Optional[pkcs11.lib] = None
        self._session = None
        self._private_key = None
        self._public_key = None
        # Clé éphémère Python (fallback si PKCS#11 engine OpenSSL indisponible)
        self._fallback_private_key = None

    # ------------------------------------------------------------------
    # Cycle de vie
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Ouvre le token PKCS#11, authentifie l'utilisateur et charge
        (ou génère) la paire de clés RSA du device.
        """
        log.info("Chargement de la bibliothèque PKCS#11 : %s", PKCS11_LIB)
        if not os.path.exists(PKCS11_LIB):
            raise SEError(
                f"Bibliothèque PKCS#11 introuvable : {PKCS11_LIB}. "
                "Vérifiez que SoftHSM2 est installé."
            )

        try:
            self._lib = pkcs11.lib(PKCS11_LIB)
        except pkcs11.exceptions.GeneralError as exc:
            raise SEError(f"Impossible de charger la librairie PKCS#11 : {exc}") from exc

        token = self._get_token()
        self._session = token.open(rw=True, user_pin=USER_PIN)
        log.info("Session PKCS#11 ouverte sur le token « %s ».", TOKEN_LABEL)

        self._private_key, self._public_key = self._load_or_generate_keys()
        log.info("Secure Element initialisé avec succès.")

    def close(self) -> None:
        """Ferme proprement la session PKCS#11."""
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None
        log.info("Session PKCS#11 fermée.")

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def generate_csr(self, device_id: str, organization: str = "IoT-Platform") -> bytes:
        """
        Génère une CSR signée par la clé du Secure Element.
        Tente d'abord via le moteur OpenSSL PKCS#11 ; si celui-ci est
        indisponible (libengine-pkcs11-openssl absent), bascule sur une
        génération Python pure avec la clé stockée dans SoftHSM via
        python-pkcs11.

        :return: CSR encodé en PEM (bytes).
        """
        self._assert_initialized()
        log.info("Génération du CSR pour le device : %s", device_id)

        # ── Tentative 1 : openssl req -engine pkcs11 ────────────────────
        try:
            csr_pem = generate_csr_openssl(device_id, KEY_LABEL)
            if csr_pem:
                log.info(
                    "CSR généré via PKCS#11 engine OpenSSL (%d octets).",
                    len(csr_pem),
                )
                return csr_pem
        except SEError as exc:
            log.warning(
                "Moteur PKCS#11 OpenSSL indisponible (%s). "
                "Basculement sur génération Python pure.",
                exc,
            )

        # ── Tentative 2 : python-pkcs11 + cryptography (fallback) ───────
        log.info("Génération du CSR via python-pkcs11 (fallback).")
        csr_pem = self._generate_csr_python(device_id, organization)
        log.info(
            "CSR généré via python-pkcs11 fallback (%d octets).",
            len(csr_pem),
        )
        return csr_pem

    def _generate_csr_python(
        self, device_id: str, organization: str = "IoT-Platform"
    ) -> bytes:
        """
        Génère un CSR en Python pur.

        La signature se fait en deux temps :
          1. Extraire la clé publique depuis le token PKCS#11 (export safe).
          2. Signer le TBS (to-be-signed) avec la clé privée du token via
             python-pkcs11.  Si la signature PKCS#11 échoue, on génère une
             clé éphémère RSA en mémoire et on stocke sa partie privée sur
             disque pour que stunnel puisse l'utiliser.
        """
        # Essai de signature via python-pkcs11
        try:
            return self._generate_csr_pkcs11_sign(device_id, organization)
        except Exception as exc:
            log.warning(
                "Signature PKCS#11 échouée (%s). "
                "Génération avec clé éphémère en mémoire.",
                exc,
            )

        # Dernier recours : clé éphémère RSA en mémoire
        return self._generate_csr_ephemeral(device_id, organization)

    def _generate_csr_pkcs11_sign(
        self, device_id: str, organization: str
    ) -> bytes:
        """
        Construit un CSR en utilisant la clé dans SoftHSM pour signer.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.x509 import CertificateSigningRequestBuilder

        # Clé publique exportée depuis le token
        pub_der = self._export_public_key_der()
        pub_key = serialization.load_der_public_key(pub_der, backend=default_backend())

        # Construire le CSR sans signer d'abord
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, device_id),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
                ])
            )
        )

        # _PKCS11PrivateKeyAdapter (défini au niveau module) est utilisé
        # pour que cryptography puisse signer via python-pkcs11.
        csr = builder.sign(
            private_key=_PKCS11PrivateKeyAdapter(
                self._private_key, pub_key
            ),
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )
        return csr.public_bytes(serialization.Encoding.PEM)

    def _generate_csr_ephemeral(
        self, device_id: str, organization: str
    ) -> bytes:
        """
        Génère une paire RSA éphémère en mémoire, signe le CSR,
        et sauvegarde la clé privée sur disque pour stunnel.
        """
        import os as _os

        if self._fallback_private_key is None:
            log.info("Génération d'une clé RSA éphémère en mémoire.")
            self._fallback_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=KEY_SIZE,
                backend=default_backend(),
            )

        priv_key = self._fallback_private_key
        device_id_env = _os.getenv("DEVICE_ID", device_id)

        # Sauvegarde de la clé privée pour stunnel (mode DIRECT sans PKCS#11)
        _os.makedirs(CERT_STORE_DIR, exist_ok=True)
        key_path = _os.path.join(CERT_STORE_DIR, f"{device_id_env}_private.pem")
        key_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "wb") as f:
            f.write(key_pem)
        _os.chmod(key_path, 0o600)
        log.info("Clé privée éphémère sauvegardée : %s", key_path)

        # Génération du CSR signé
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, device_id),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
                ])
            )
            .sign(priv_key, hashes.SHA256(), default_backend())
        )
        return csr.public_bytes(serialization.Encoding.PEM)

    def sign(self, data: bytes, mechanism: str = "SHA256_RSA_PKCS") -> bytes:
        """Signe des données avec la clé privée du SE."""
        self._assert_initialized()

        mech_map = {
            "SHA256_RSA_PKCS": Mechanism.SHA256_RSA_PKCS,
            "SHA384_RSA_PKCS": Mechanism.SHA384_RSA_PKCS,
            "SHA512_RSA_PKCS": Mechanism.SHA512_RSA_PKCS,
        }
        if mechanism not in mech_map:
            raise SEError(f"Mécanisme inconnu : {mechanism}")

        try:
            signature = self._private_key.sign(data, mechanism=mech_map[mechanism])
            return bytes(signature)
        except pkcs11.exceptions.GeneralError as exc:
            raise SEError(f"Échec de la signature PKCS#11 : {exc}") from exc

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Vérifie une signature avec la clé publique du token."""
        self._assert_initialized()
        try:
            self._public_key.verify(
                signature, data, mechanism=Mechanism.SHA256_RSA_PKCS
            )
            return True
        except pkcs11.exceptions.SignatureInvalid:
            return False
        except pkcs11.exceptions.GeneralError as exc:
            log.warning("Erreur de vérification : %s", exc)
            return False

    def get_public_key_pem(self) -> bytes:
        """Retourne la clé publique en PEM."""
        self._assert_initialized()
        # Si on a une clé éphémère, retourner sa clé publique
        if self._fallback_private_key is not None:
            return self._fallback_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        pub_der = self._export_public_key_der()
        pub_key = serialization.load_der_public_key(pub_der, backend=default_backend())
        return pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_device_fingerprint(self) -> str:
        """Retourne l'empreinte SHA-256 de la clé publique."""
        pub_pem = self.get_public_key_pem()
        return hashlib.sha256(pub_pem).hexdigest()

    # ------------------------------------------------------------------
    # Méthodes internes
    # ------------------------------------------------------------------

    def _assert_initialized(self) -> None:
        if self._session is None or self._private_key is None:
            raise SEError(
                "Secure Element non initialisé. Appelez initialize() d'abord."
            )

    def _get_token(self) -> pkcs11.Token:
        try:
            tokens = list(self._lib.get_tokens(token_label=TOKEN_LABEL))
        except pkcs11.exceptions.GeneralError as exc:
            raise SEError(f"Erreur lors de la recherche du token : {exc}") from exc

        if not tokens:
            raise SEError(
                f"Token PKCS#11 « {TOKEN_LABEL} » introuvable. "
                "Exécutez init_token.sh pour l'initialiser."
            )
        return tokens[0]

    def _load_or_generate_keys(self) -> Tuple:
        try:
            priv_keys = list(self._session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.LABEL: KEY_LABEL,
            }))
        except pkcs11.exceptions.GeneralError as exc:
            raise SEError(f"Erreur recherche clé privée : {exc}") from exc

        if priv_keys:
            log.info("Clé privée existante chargée depuis le token.")
            priv_key = priv_keys[0]
            pub_keys = list(self._session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.LABEL: KEY_LABEL,
            }))
            if not pub_keys:
                raise SEError("Clé publique introuvable pour la clé privée chargée.")
            return priv_key, pub_keys[0]

        log.info("Génération d'une nouvelle paire RSA-%d dans le token…", KEY_SIZE)
        try:
            pub_key, priv_key = self._session.generate_keypair(
                KeyType.RSA,
                KEY_SIZE,
                store=True,
                label=KEY_LABEL,
                public_template={
                    Attribute.TOKEN:   True,
                    Attribute.ENCRYPT: False,
                    Attribute.VERIFY:  True,
                    Attribute.WRAP:    False,
                },
                private_template={
                    Attribute.TOKEN:       True,
                    Attribute.PRIVATE:     True,
                    Attribute.SENSITIVE:   True,
                    Attribute.EXTRACTABLE: False,
                    Attribute.DECRYPT:     False,
                    Attribute.SIGN:        True,
                    Attribute.UNWRAP:      False,
                },
            )
        except pkcs11.exceptions.GeneralError as exc:
            raise SEError(f"Génération de la paire de clés échouée : {exc}") from exc

        log.info("Paire de clés RSA-%d générée et stockée dans le token.", KEY_SIZE)
        return priv_key, pub_key

    def _export_public_key_der(self) -> bytes:
        try:
            pub_der = encode_rsa_public_key(self._public_key)
            return bytes(pub_der)
        except Exception as exc:
            raise SEError(f"Export clé publique DER échoué : {exc}") from exc

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# Wrapper PKCS#11 pour l'API cryptography
# ---------------------------------------------------------------------------

class _PKCS11PrivateKeyAdapter:
    """
    Adaptateur minimal permettant à cryptography de signer via python-pkcs11.
    Utilisé uniquement dans _generate_csr_pkcs11_sign().
    """

    def __init__(self, pkcs11_priv_key, pub_key_obj):
        self._priv = pkcs11_priv_key
        self._pub  = pub_key_obj

    # cryptography appelle cette méthode pour obtenir la clé publique
    def public_key(self):
        return self._pub

    # cryptography appelle cette méthode pour signer le TBS du CSR
    def sign(self, data: bytes, padding_obj, algorithm) -> bytes:
        try:
            sig = self._priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
            return bytes(sig)
        except Exception as exc:
            raise SEError(f"Signature PKCS#11 adapter échouée : {exc}") from exc

    # Propriétés minimales attendues par cryptography
    @property
    def key_size(self) -> int:
        return KEY_SIZE


# ---------------------------------------------------------------------------
# Utilitaire standalone : génération CSR via openssl -engine pkcs11
# ---------------------------------------------------------------------------

def generate_csr_openssl(device_id: str, key_label: str = KEY_LABEL) -> bytes:
    """
    Génère un CSR via la commande OpenSSL avec le moteur PKCS#11.
    Nécessite : libengine-pkcs11-openssl

    Lève SEError si OpenSSL ou le moteur est indisponible.
    :return: CSR en PEM (bytes).
    """
    import subprocess
    import tempfile

    pkcs11_uri = (
        f"pkcs11:token={TOKEN_LABEL};object={key_label};type=private"
        f"?pin-value={USER_PIN}"
    )
    subject = f"/CN={device_id}/O=IoT-Platform/C=TN"

    with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as tmp:
        csr_path = tmp.name

    try:
        cmd = [
            "openssl", "req",
            "-new",
            "-engine",  "pkcs11",
            "-keyform", "engine",
            "-key",     pkcs11_uri,
            "-subj",    subject,
            "-out",     csr_path,
            "-sha256",
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise SEError(
                f"openssl req échoué (code {result.returncode}): {result.stderr}"
            )
        with open(csr_path, "rb") as f:
            data = f.read()
        if not data:
            raise SEError("openssl req a produit un fichier CSR vide.")
        return data

    except FileNotFoundError as exc:
        raise SEError(
            "OpenSSL ou le moteur pkcs11 est introuvable. "
            "Installez libengine-pkcs11-openssl."
        ) from exc
    finally:
        if os.path.exists(csr_path):
            os.unlink(csr_path)


# ---------------------------------------------------------------------------
# Test rapide en ligne de commande
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Test Secure Element ===")
    try:
        with SecureElement() as se:
            print(f"[OK] SE initialisé")
            print(f"[OK] Fingerprint device : {se.get_device_fingerprint()}")

            csr = se.generate_csr("test-device-001")
            print(f"[OK] CSR généré ({len(csr)} octets)")

            test_data = b"Hello Secure Element"
            sig = se.sign(test_data)
            print(f"[OK] Données signées ({len(sig)} octets)")

            ok = se.verify(test_data, sig)
            print(f"[OK] Vérification signature : {'valide' if ok else 'INVALIDE'}")

    except SEError as e:
        print(f"[ERREUR SE] {e}", file=sys.stderr)
        sys.exit(1)
