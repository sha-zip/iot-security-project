from pkcs11 import lib, Mechanism, ObjectClass

PKCS11_MODULE= "/usr/lib/softhsm/libsofthsm2.so"
TOKEN_LABEL= "iot_secure_element"
KEY_LABEL= "iot_rsa_key"
USER_PIN= "0000"

def sign_data(data: bytes) -> bytes:
    pkcs11 = lib(PKCS11_MODULE)
    
    token = pkcs11.get_token(token_label=TOKEN_LABEL)
    with token.open(user_pin=USER_PIN) as session:
     private_key = session.get_key(label=KEY_LABEL, object_class=ObjectClass.PRIVATE_KEY)
     signature = private_key.sign(data,mechanism=Mechanism.SHA256_RSA_PKCS)
     return signature

