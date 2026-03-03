
from flask import Flask, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from device_registry import load_registry, can_publish
print ("=====SERVER STARTING====")

app = Flask(__name__)

registry= load_registry()

with open("iot_pubkey2.pem","rb") as f:
    public_key = serialization.load_pem_public_key(f.read())
print ("PUBLIC KEY LOADED")


@app.route("/auth", methods=["POST"])
def auth():
    print ("REQUEST RECEIVED")
    message = request.data
    print ("MESSAGE:",message)

    sig_hex = request.headers.get("X-Signature")
    device_id= request.headers.get("X-Device-ID")
    topic= request.headers.get("X-Topic")
    if not device_id or not topic:
     return ";issing X-Device or X-Topic\n", 400
    if not sig_hex:
     return "Missing X-Signature\n", 400

    try:
     signature = bytes.fromhex(request.headers["X-Signature"])
    except ValueError : 
     return "Invalid X-Signature (not hex)\n", 400
 
    try:
     public_key.verify(signature,message,padding.PKCS1v15(),hashes.SHA256())
    except Exception:
     return "AUTH FAILED\n", 401
    if not can_publish(device_id, topic, registry):
     return "DEVICE NOT AUTHORIZED FOR THIS TOPIC\n", 403 
    return "AUTH OK\n"

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)

