from flask import Flask, request, Response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from device_registry import load_registry, can_publish
import datetime

print("===== SERVER STARTING =====")

app = Flask(__name__)
registry = load_registry()

# ===================== LOAD KEYS =====================

# Clé publique (pour auth actuelle - HMAC/RSA)
with open("iot_pubkey2.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Clé privée CA (signature certificats)
with open("iot_privkey.pem", "rb") as f:
    ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

print(" Keys loaded")

# ===================== ROUTE AUTH =====================

@app.route("/auth", methods=["POST"])
def auth():
    print("📥 AUTH REQUEST RECEIVED")

    message = request.data
    sig_hex = request.headers.get("X-Signature")
    device_id = request.headers.get("X-Device-ID")
    topic = request.headers.get("X-Topic")

    if not device_id or not topic:
        return "Missing X-Device-ID or X-Topic\n", 400

    if not sig_hex:
        return "Missing X-Signature\n", 400

    try:
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        return "Invalid signature format\n", 400

    # Vérification signature
    try:
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        return "AUTH FAILED\n", 401

    # Vérification autorisation
    if not can_publish(device_id, topic, registry):
        return "NOT AUTHORIZED\n", 403

    return "AUTH OK\n", 200


# ===================== ROUTE ENROLL =====================

@app.route("/enroll", methods=["POST"])
def enroll():
    print(" CSR RECEIVED")

    try:
        csr_data = request.data

        if not csr_data:
            return "Missing CSR\n", 400

        # Charger CSR
        csr = x509.load_pem_x509_csr(csr_data)

        # Vérifier signature CSR
        if not csr.is_signature_valid:
            return "Invalid CSR signature\n", 400

        print(" CSR valid")

        # ================= CA IDENTITY =================
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "IoT-CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT_Project"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        ])

        # ================= CERT GENERATION =================
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(issuer)  # ✅ corrigé
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        )

        # ================= EXTENSIONS =================
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("iot-device")
            ]),
            critical=False
        )

        # ================= SIGNATURE =================
        cert = cert_builder.sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256()
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        print("Certificate generated and signed")

        return Response(
            cert_pem,
            status=200,
            mimetype="application/x-pem-file"
        )

    except Exception as e:
        print(f" ENROLL ERROR: {e}")
        return f"Error: {e}\n", 500


# ===================== MAIN =====================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
