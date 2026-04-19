import os, pkcs11

libpath = os.getenv("PKCS11_LIB", "/usr/lib/softhsm/libsofthsm2.so")
label = os.getenv("SE_TOKEN_LABEL", "iot-token")
pin = os.getenv("SE_USER_PIN", "1234")

lib = pkcs11.lib(libpath)
tokens = list(lib.get_tokens(token_label=label))
print("Tokens trouvés:", len(tokens))
if not tokens:
    raise SystemExit("Token introuvable")

token = tokens[0]
print("Token:", token)
session = token.open(user_pin=pin, rw=True)
print("Session ouverte OK")
session.close()
print("Session fermée OK")
