import requests
import os
import time
import uuid
import hmac
import hashlib
import json
import inspect
from cryptography import x509

#  import depuis ton Secure Element
from devices.secure_element.se_module import generate_csr

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:5000").rstrip("/")
SECRET = os.environ["SECRET_KEY"].encode("utf-8")
API_KEY = os.environ["API_KEY"]
DEVICE_ID = os.environ.get("DEVICE_ID", "iot-agent-01")

CERT_FILE = os.environ.get("CERT_FILE", "device.crt")
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "10"))
VERIFY_TLS = os.environ.get("VERIFY_TLS", "false").lower() in ("1", "true", "yes")


# ===================== JSON =====================
def canonical_json(data):
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


# ===================== HMAC =====================
def sign_request(method, endpoint, data):
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    body = canonical_json(data)

    message = f"{method.upper()}\n{endpoint}\n{timestamp}\n{nonce}\n{body}"

    signature = hmac.new(
        SECRET,
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return {
        "X-Device-Id": DEVICE_ID,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Signature": signature,
        "Content-Type": "application/json"
    }


# ===================== CSR =====================
def build_csr():
    """
    Compatibilité avec :
    - generate_csr()
    - generate_csr(device_id)
    """
    try:
        sig = inspect.signature(generate_csr)
        if len(sig.parameters) >= 1:
            csr = generate_csr(DEVICE_ID)
        else:
            csr = generate_csr()
    except (TypeError, ValueError):
        csr = generate_csr()

    if isinstance(csr, str):
        csr = csr.encode("utf-8")

    if not isinstance(csr, (bytes, bytearray)):
        raise TypeError("generate_csr() doit retourner bytes ou str (PEM)")

    if b"BEGIN CERTIFICATE REQUEST" not in csr:
        raise ValueError("CSR invalide: format PEM attendu")

    return bytes(csr)


# ===================== CERTIFICAT =====================
def certificate_exists():
    if not os.path.exists(CERT_FILE):
        return False

    if os.path.getsize(CERT_FILE) == 0:
        return False

    try:
        with open(CERT_FILE, "rb") as f:
            cert_data = f.read()
        x509.load_pem_x509_certificate(cert_data)
        return True
    except Exception:
        print(" Certificat local invalide/corrompu -> nouvel enrollment")
        return False


def save_certificate(cert):
    if isinstance(cert, str):
        cert = cert.encode("utf-8")

    if b"BEGIN CERTIFICATE" not in cert:
        raise ValueError("Réponse PKI invalide: certificat PEM attendu")

    cert_dir = os.path.dirname(os.path.abspath(CERT_FILE))
    os.makedirs(cert_dir, exist_ok=True)

    with open(CERT_FILE, "wb") as f:
        f.write(cert)

    print(f" Certificat sauvegardé dans {CERT_FILE}")


def send_csr_to_pki(csr):
    print(" Envoi du CSR à la PKI...")

    headers = {
        "Content-Type": "application/x-pem-file",
        "X-API-KEY": API_KEY,
        "X-Device-Id": DEVICE_ID
    }

    response = requests.post(
        f"{BACKEND_URL}/enroll",
        data=csr,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Échec enrollment [{response.status_code}] : {response.text}"
        )

    print(" Certificat reçu depuis la PKI")
    return response.content


# ===================== ENROLLMENT =====================
def enroll_if_needed():
    if certificate_exists():
        print(" Certificat déjà présent")
        return

    print(" Aucun certificat trouvé -> génération CSR")
    csr = build_csr()
    print(" CSR générée")

    cert = send_csr_to_pki(csr)
    save_certificate(cert)


# ===================== ENVOI DATA =====================
def send_data():
    data = {"message": "hello"}
    endpoint = "/data"

    headers = sign_request("POST", endpoint, data)

    response = requests.post(
        f"{BACKEND_URL}{endpoint}",
        data=canonical_json(data).encode("utf-8"),
        headers=headers,
        timeout=REQUEST_TIMEOUT,
        verify=VERIFY_TLS
    )

    response.raise_for_status()
    print(" Réponse serveur :", response.text)


# ===================== MAIN =====================
if __name__ == "__main__":
    try:
        enroll_if_needed()
        send_data()

    except requests.exceptions.RequestException as e:
        print(f" Erreur réseau: {e}")

    except Exception as e:
        print(f" Erreur: {e}")
