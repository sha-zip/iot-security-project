import requests
import os
import time
import uuid
import hmac
import hashlib
import json

# 👉 import depuis ton Secure Element
from se_module import generate_csr  

BACKEND_URL = os.environ.get("BACKEND_URL", "https://127.0.0.1:5000")
SECRET = os.environ["SECRET_KEY"].encode()
DEVICE_ID = os.environ.get("DEVICE_ID", "iot-agent-01")

CERT_FILE = "device.crt"


# ===================== JSON =====================
def canonical_json(data):
    return json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False)


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


# ===================== CERTIFICAT =====================
def certificate_exists():
    return os.path.exists(CERT_FILE)


def save_certificate(cert):
    with open(CERT_FILE, "wb") as f:
        f.write(cert)
    print("✅ Certificat sauvegardé")


def send_csr_to_pki(csr):
    print("📤 Envoi du CSR à la PKI...")

    response = requests.post(
        BACKEND_URL + "/enroll",
        data=csr,
        headers={"Content-Type": "application/x-pem-file"},
        verify=False  # ⚠️ dev seulement
    )

    response.raise_for_status()

    print("✅ Certificat reçu")
    return response.content


# ===================== ENROLLMENT =====================
def enroll_if_needed():
    if certificate_exists():
        print("✔ Certificat déjà موجود")
        return

    print("⚠ Aucun certificat trouvé → génération CSR")

    csr = generate_csr()
    cert = send_csr_to_pki(csr)
    save_certificate(cert)


# ===================== ENVOI DATA =====================
def send_data():
    data = {"message": "hello"}
    endpoint = "/data"

    headers = sign_request("POST", endpoint, data)

    response = requests.post(
        BACKEND_URL + endpoint,
        data=canonical_json(data).encode("utf-8"),
        headers=headers,
        timeout=10,
        verify=False
    )

    response.raise_for_status()
    print("📡 Réponse serveur :", response.text)


# ===================== MAIN =====================
if __name__ == "__main__":
    try:
        enroll_if_needed()   # 🔥 NOUVEAU
        send_data()          # ancien comportement

    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur réseau: {e}")

    except Exception as e:
        print(f"❌ Erreur: {e}")
