from flask import Flask, request, Response
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import subprocess
import os
import re
import logging
import tempfile
import hmac
import secrets

from device_registry import load_registry, is_device_active, mark_device_enrolled

# ================= CONFIG =================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

CA_CERT = os.environ.get("CA_CERT", "ca_cert.pem")
PKCS11_KEY = os.environ.get(
    "PKCS11_KEY",
    "pkcs11:token=IoT_Secure_Element;object=ca-key;type=private"
)
CERT_VALIDITY = int(os.environ.get("CERT_VALIDITY_DAYS", "365"))
API_KEY = os.environ.get("API_KEY")
OPENSSL_BIN = os.environ.get("OPENSSL_BIN", "openssl")
PORT = int(os.environ.get("PORT", "5000"))
DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")

# Vérifications démarrage
if not os.path.exists(CA_CERT):
    raise FileNotFoundError(f"CA certificate introuvable: {CA_CERT}")

if not API_KEY:
    raise EnvironmentError("API_KEY non définie")


# ================= HELPERS =================
def is_device_authorized(device_id: str) -> bool:
    registry = load_registry()
    return is_device_active(registry, device_id)


def check_api_key(req) -> bool:
    provided = req.headers.get("X-API-KEY", "")
    return hmac.compare_digest(provided, API_KEY)


def normalize_device_id(device_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", device_id)


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """
    Vérifie la signature de la CSR.
    Utilise csr.is_signature_valid si disponible, sinon fallback RSA manuel.
    """
    try:
        return csr.is_signature_valid
    except AttributeError:
        pass

    public_key = csr.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm
            )
            return True
        except InvalidSignature:
            return False

    raise ValueError("Type de clé non supporté pour vérification de signature CSR")


def build_openssl_extfile(device_id: str) -> str:
    """
    Extensions adaptées à un certificat client mTLS.
    """
    return f"""[v3_client]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=URI:urn:iot:device:{device_id}
"""


# ================= ROUTES =================
@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


@app.route("/enroll", methods=["POST"])
def enroll():
    if not check_api_key(request):
        logger.warning("Unauthorized enroll attempt from %s", request.remote_addr)
        return "Unauthorized", 401

    csr_data = request.data

    if not csr_data:
        return "CSR vide", 400

    if len(csr_data) > 10 * 1024:
        return "CSR trop volumineuse", 400

    # 1. Charger CSR
    try:
        csr = x509.load_pem_x509_csr(csr_data)
    except Exception:
        logger.exception("Erreur parsing CSR")
        return "CSR invalide ou malformée", 400

    # 2. Vérifier signature
    try:
        if not verify_csr_signature(csr):
            return "Signature CSR invalide", 400
    except Exception:
        logger.exception("Erreur vérification signature CSR")
        return "Impossible de vérifier la signature CSR", 400

    # 3. Vérifier clé publique
    public_key = csr.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        return "Type de clé non supporté (RSA requis)", 400

    if public_key.key_size < 2048:
        return "Clé trop faible (min 2048 bits)", 400

    # 4. Extraire device_id depuis le CN
    try:
        device_id = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return "Common Name manquant", 400

    device_id = normalize_device_id(device_id)

    # 5. Vérifier cohérence header / CSR
    claimed_device_id = request.headers.get("X-Device-Id", "").strip()
    if claimed_device_id:
        claimed_device_id = normalize_device_id(claimed_device_id)
        if claimed_device_id != device_id:
            logger.warning(
                "Mismatch header/csr: header=%s csr=%s",
                claimed_device_id,
                device_id
            )
            return "Mismatch entre X-Device-Id et CN de la CSR", 400

    logger.info("[ENROLL] device=%s ip=%s", device_id, request.remote_addr)

    # 6. Vérifier registry
    if not is_device_authorized(device_id):
        logger.warning("Device non autorisé: %s", device_id)
        return f"Device '{device_id}' non autorisé", 403

    csr_path = None
    crt_path = None
    ext_path = None

    try:
        # 7. Sauvegarder CSR dans un fichier temporaire
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
            csr_file.write(csr_data)
            csr_path = csr_file.name

        crt_path = csr_path.replace(".csr", ".crt")

        # 8. Fichier d’extensions OpenSSL pour certificat client mTLS
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".cnf") as ext_file:
            ext_file.write(build_openssl_extfile(device_id))
            ext_path = ext_file.name

        # 9. Numéro de série unique
        serial = "0x" + secrets.token_hex(16)

        # 10. Signature du certificat
       cmd = [
    OPENSSL_BIN, "x509", "-req",
    "-engine", "pkcs11",
    "-CAkeyform", "engine",
    "-CA", CA_CERT,
    "-CAkey", "pkcs11:object=ca-key;type=private",
    "-passin", "pass:0000",
    "-in", csr_path,
    "-out", crt_path,
    "-days", str(CERT_VALIDITY),
    "-sha256",
    "-extfile", ext_path,
    "-extensions", "v3_client"
]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
        except subprocess.TimeoutExpired:
            logger.error("OpenSSL timeout")
            return "Timeout lors de la signature", 500

        if result.returncode != 0:
            logger.error("Erreur OpenSSL: %s", result.stderr.strip())
            return f"Erreur lors de la signature: {result.stderr.strip()}", 500

        # 11. Lire certificat signé
        with open(crt_path, "rb") as f:
            cert_pem = f.read()

        # 12. Marquer device enrôlé
        mark_device_enrolled(device_id)

        logger.info("[SUCCESS] Certificat généré pour %s", device_id)

        return Response(
            cert_pem,
            status=200,
            mimetype="application/x-pem-file",
            headers={
                "Content-Disposition": f'attachment; filename="{device_id}.crt"'
            }
        )

    finally:
        for path in (csr_path, crt_path, ext_path):
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    logger.warning("Impossible de supprimer le fichier temporaire: %s", path)


# ================= MAIN =================
if __name__ == "__main__":
    logger.info("=== SERVER STARTING ===")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)

