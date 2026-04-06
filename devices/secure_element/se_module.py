import os
import logging
import pkcs11
import pkcs11.exceptions
from pkcs11 import lib, Mechanism, ObjectClass, KeyType
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization 
from cryptography.x509.oid import NameOID
logging.basicConfig(level=logging.INFO)

PKCS11_MODULE = os.environ.get("PKCS11_MODULE" , "/usr/lib/softhsm/libsofthsm2.so")
TOKEN_LABEL = os.environ.get("SE_TOKEN_LABEL", "IoT_Secure_Element")
KEY_LABEL = os.environ.get("SE_KEY_LABEL", "IoT_RSA_Key")
USER_PIN = os.environ.get("SE_USER_PIN")
DEVICE_ID= os.environ.get("DEVICE_ID", "iot-agent-01")

def sign_data(data: bytes) -> bytes:
	if not isinstance(data, bytes):
		raise TypeError("sign_data attend des bytes")

	if USER_PIN is None:
		raise RuntimeError("PIN non defini")

	try:
		hsm= lib(PKCS11_MODULE)
		token = hsm.get_token(token_label=TOKEN_LABEL)

		with token.open(user_pin= USER_PIN) as session:
			private_key = session.get_key(label=KEY_LABEL, object_class=ObjectClass.PRIVATE_KEY, key_type= KeyType.RSA )
			signature = private_key.sign( data, mechanism= Mechanism.SHA256_RSA_PKCS )
			logging.info("Signature reussie pour cle '%s' ", KEY_LABEL)
			return signature 
	except pkcs11.exceptions.PinIncorrect:
		logging.error("PIN incorrect pour le token '%s' ", TOKEN_LABEL)
		raise RuntimeError("PIN PKCS11 incorrect")
	except pkcs11.exceptions.PKCS11Error as e:
		logging.error("Erreur PKCS11: %s" , e)
		raise RuntimeError(f"Erreur PKCS11: {e}") from e 

	except Exception as e :
		logging.exception("Erreur inattendue dans sign_data")
		raise RuntimeError("Erreur interne Secure Element") from e 

def generate_csr(session, key_label: str) -> bytes:
	private_key = session.get_key(lable=key_label,object_class=pkcs11.ObjectClass.PRIVATE_KEY )
	if private_key is None:
		raise RuntimeError(f"Cle '{key_label}' introuvable pour la CSR")
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DEVICE_ID), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoT_Project"), x509.NameAttribute(NameOID.Country_Name, "TN"),])).sign(private_key, hashes.SHA256())
	logging.info("CSR generee pour '%s'", DEVICE_ID)
	return csr.public_bytes(serialization.Encoding.PEM)
