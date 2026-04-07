from flask import Flask, request, Response
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
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

CA_CERT       = os.environ.get("CA_CERT", "ca_cert.pem")
PKCS11_KEY    = os.environ.get(
    "PKCS11_KEY",
    "pkcs11:token=IoT_Secure_Element;object=ca-key;type=private"
)
CERT_VALIDITY = int(os.environ.get("CERT_VALIDITY_DAYS", "365"))
API_KEY       = os.environ.get("API_KEY")

# Vérifications
if not os.path.exists(CA_CERT):
    raise FileNotFoundError(f"CA certificate introuvable: {CA_CERT}")

if not API_KEY:
    raise EnvironmentError("API_KEY non définie")

# ================= HELPERS =================
def is_device_authorized(device_id):
    registry = load_registry()
    return is_device_active(registry, device_id)

def check_api_key(req):
    provided = req.headers.get("X-API-KEY", "")
    return hmac.compare_digest(provided, API_KEY)

# ================= ROUTE =================
@app.route("/enroll", methods=["POST"])
def enroll():

    # 🔐 API KEY check
    if not check_api_key(request):
        return "Unauthorized", 401

    csr_data = request.data

    if not csr_data:
        return "CSR vide", 400

    # 🔥 Protection DoS
    if len(csr_data) > 10 * 1024:
        return "CSR trop volumineuse", 400

    # 1. Charger CSR
    try:
        csr = x509.load_pem_x509_csr(csr_data)
    except Exception:
        return "CSR invalide ou malformée", 400

    # 2. Vérifier signature
    if not csr.is_signature_valid:
        return "Signature CSR invalide", 400

    # 3. Vérifier clé publique
    public_key = csr.public_key()

    if not isinstance(public_key, rsa.RSAPublicKey):
        return "Type de clé non supporté (RSA requis)", 400

    if public_key.key_size < 2048:
        return "Clé trop faible (min 2048 bits)", 400

    # 4. Extraire device ID
    try:
        device_id = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        return "Common Name manquant", 400

    # 🔒 Nettoyage
    device_id = re.sub(r'[^a-zA-Z0-9_-]', '_', device_id)

    logger.info(f"[ENROLL] device={device_id} ip={request.remote_addr}")

    # 5. Vérifier registry
    if not is_device_authorized(device_id):
        logger.warning(f"Device non autorisé: {device_id}")
        return f"Device '{device_id}' non autorisé", 403

    csr_path = None
    crt_path = None

    try:
        # 6. Fichier temporaire CSR
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csr") as csr_file:
            csr_file.write(csr_data)
            csr_path = csr_file.name

        crt_path = csr_path.replace(".csr", ".crt")

        # 🔥 Serial unique
        serial = hex(secrets.randbits(64))

        # 7. Signature avec Secure Element (PKCS#11)
        try:
            result = subprocess.run([
                "openssl", "x509", "-req",
                "-in", csr_path,
                "-CA", CA_CERT,
                "-CAkey", PKCS11_KEY,
                "-set_serial", serial,
                "-CAcreateserial",
                "-out", crt_path,
                "-days", str(CERT_VALIDITY),
                "-sha256",
                "-provider", "pkcs11",
                "-provider", "default"
            ], capture_output=True, timeout=10)

        except subprocess.TimeoutExpired:
            logger.error("OpenSSL timeout")
            return "Timeout lors de la signature", 500

        if result.returncode != 0:
            logger.error(result.stderr.decode())
            return "Erreur lors de la signature", 500

        # 8. Lire certificat
        with open(crt_path, "rb") as f:
            cert_pem = f.read()

        # 9. Marquer device comme enrôlé
        mark_device_enrolled(device_id)

        logger.info(f"[SUCCESS] Certificat généré pour {device_id}")

        return Response(
            cert_pem,
            status=200,
            mimetype="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename={device_id}.crt"}
        )

    finally:
        # 10. Nettoyage
        for path in [csr_path, crt_path]:
            if path and os.path.exists(path):
                os.remove(path)

# ================= MAIN =================
if __name__ == "__main__":
    print("=== SERVER STARTING ===")
    app.run(host="0.0.0.0", port=5000, debug=True)
