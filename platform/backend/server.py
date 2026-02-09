<<<<<<< HEAD
from flask import Flask, request 
from cryptography.hazmat.primitives import hashes, serialization 
from cryptography.hazmat.primitives.asymmetric import padding 
app = Flask(__name__)
with open("iot_pubkey.pem", "rb") as f :
	public_key = serialization.load_pem_public_key(f.read())
@app.route("/auth" , methods=["POST"])
def auth():
	message= request.data 
	signature= bytes.fromhex(request.headers["X-signature"])
	try:
		public_key.verify (signature, message , padding.PKCS1v15(),hashes.SHA256())
		return "AUTH OK \n"
	except Exception:
		return "AUTH FAILED \n" , 401
if __name__== "__main__":
	app.run()
=======
from flask import Flask, request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
print ("=====SERVER STARTING====")

app = Flask(__name__)

with open("iot_pubkey2.pem","rb") as f:
    public_key = serialization.load_pem_public_key(f.read())
print ("PUBLIC KEY LOADED")
print (public_key)

@app.route("/auth", methods=["POST"])
def auth():
    print ("REQUEST RECEIVED")
    message = request.data
    print ("MESSAGE:",message)

    signature = bytes.fromhex(request.headers["X-Signature"])
    print ("SIGNATURE:", signature.hex())
    try:
     public_key.verify(signature,message,padding.PKCS1v15(),hashes.SHA256())
     return "AUTH OK\n"
    except Exception:
     return "AUTH FAILED\n", 401
     

if __name__ == "__main__":
    app.run()

>>>>>>> 039e4ea (Initial implementation de iot secure archi)
