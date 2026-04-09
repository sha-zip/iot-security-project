import requests
import os
import time
import uuid
import hmac
import hashlib
import json

from se_module import generate_csr

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:5000")
SECRET = os.environ["SECRET_KEY"].encode()
API_KEY = os.environ["API_KEY"]  
DEVICE_ID = os.environ.get("DEVICE_ID", "iot-agent-01")

CERT_FILE = "device.crt"


def canonical_json(data):
    return json.dumps(data, separators=(',', ':'), sort_keys=True, ensure_ascii=False)


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


def certificate_exists():
    return os.path.exists(CERT_FILE) and os.path.getsize(CERT_FILE) > 0


def save_certificate(cert):
    with open(CERT_FILE, "wb") as f:
        f.write(cert)
    print(" Certificat sauvegardé")


def send_csr_to_pki(csr):
    print(" Envoi du CSR à la PKI...")

    if isinstance(csr, str):
        csr = csr.encode("utf-8")

    headers = {
        "Content-Type": "application/x-pem-file",
        "X-API-KEY": API_KEY,        
        "X-Device-Id": DEVICE_ID       
    }

    response = requests.post(
        BACKEND_URL + "/enroll",
        data=csr,
        headers=headers,
        timeout=10,
        verify=False
    )

    if response.status_code != 200:
        raise RuntimeError(f"Échec enrollment [{response.status_code}] : {response.text}")

    print(" Certificat reçu")
    return response.content


def enroll_if_needed():
    if certificate_exists():
        print("Certificat déjà existe")
        return

    print("Aucun certificat trouvé → génération CSR")

    csr = generate_csr()
    cert = send_csr_to_pki(csr)
    save_certificate(cert)


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


if __name__ == "__main__":
    try:
        enroll_if_needed()
        send_data()

    except requests.exceptions.RequestException as e:
        print(f" Erreur réseau: {e}")

    except Exception as e:
        print(f" Erreur: {e}")
