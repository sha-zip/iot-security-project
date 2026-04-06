import os
import logging
import subprocess
from pkcs11 import lib, ObjectClass, KeyType, Mechanism
import pkcs11.exceptions

logging.basicConfig(level=logging.INFO)


PKCS11_MODULE = os.environ.get("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so")
TOKEN_LABEL = os.environ.get("SE_TOKEN_LABEL", "IoT_Secure_Element")
KEY_LABEL = os.environ.get("SE_KEY_LABEL", "IoT_RSA_Key")
USER_PIN = os.environ.get("SE_USER_PIN", "0000")
DEVICE_ID = os.environ.get("DEVICE_ID", "iot-agent-01")


def sign_data(data: bytes) -> bytes:
    if not isinstance(data, bytes) or len(data) == 0:
        raise ValueError("Données invalides")

    try:
        hsm = lib(PKCS11_MODULE)
        token = hsm.get_token(token_label=TOKEN_LABEL)

        with token.open(user_pin=USER_PIN) as session:
            private_key = session.get_key(
                label=KEY_LABEL,
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.RSA
            )

            if private_key is None:
                raise RuntimeError(f"Clé '{KEY_LABEL}' introuvable")

            signature = private_key.sign(
                data,
                mechanism=Mechanism.SHA256_RSA_PKCS
            )

            logging.info(" Signature réussie avec la clé '%s'", KEY_LABEL)
            return signature

    except pkcs11.exceptions.PinIncorrect:
        logging.error(" PIN incorrect")
        raise RuntimeError("PIN incorrect")

    except pkcs11.exceptions.PKCS11Error as e:
        logging.error(" Erreur PKCS11: %s", e)
        raise RuntimeError(f"Erreur PKCS11: {e}") from e

    except Exception as e:
        logging.exception(" Erreur inattendue")
        raise RuntimeError("Erreur interne Secure Element") from e



def generate_csr(output_file="device.csr"):
    """
    Génère un CSR signé par la clé dans le Secure Element
    en utilisant OpenSSL + PKCS11 engine
    """

    try:
        cmd = [
            "openssl", "req", "-new",
            "-engine", "pkcs11",
            "-keyform", "engine",
            "-key", f"pkcs11:token={TOKEN_LABEL};object={KEY_LABEL};type=private;pin-value={USER_PIN}",
            "-subj", f"/CN={DEVICE_ID}/O=IoT_Project/C=TN",
            "-out", output_file
        ]

        logging.info(" Génération CSR via Secure Element...")
        subprocess.run(cmd, check=True)

        logging.info(" CSR généré : %s", output_file)

        with open(output_file, "rb") as f:
            return f.read()

    except subprocess.CalledProcessError as e:
        logging.error(" Erreur OpenSSL lors de la génération CSR")
        raise RuntimeError("Erreur génération CSR") from e

    except Exception as e:
        logging.exception(" Erreur inattendue CSR")
        raise RuntimeError("Erreur interne CSR") from e


# 🔍 VERIFIER LA CLE
def check_key_exists():
    try:
        hsm = lib(PKCS11_MODULE)
        token = hsm.get_token(token_label=TOKEN_LABEL)

        with token.open(user_pin=USER_PIN) as session:
            key = session.get_key(
                label=KEY_LABEL,
                object_class=ObjectClass.PRIVATE_KEY
            )

            if key:
                logging.info(" Clé trouvée dans Secure Element")
                return True
            else:
                logging.error(" Clé introuvable")
                return False

    except Exception as e:
        logging.error(" Erreur vérification clé: %s", e)
        return False

if __name__ == "__main__":
	data = b"test message"
	try :
		signature = sign_data(data)
		print("Signature OK :", signature.hex())
	except Exception as e :
		print ("Erreur :" , e)
if __name__ == "__main__":
	csr = generate_csr()
	print(csr.decode())
