import requests 
import os
import time
import uuid
import hmac
import hashlib
import json

BACKEND_URL = os.environ.get("BACKEND_URL","https://127.0.0.1:8000") 
SECRET = os.environ["SECRET_KEY"].encode()
DEVICE_ID = os.environ.get("DEVICE_ID","iot-agent-01")

def canonical_json(data):
	return json.dumps(data, separators=(',',':'), sort_keys=True,ensure_ascii=False)

def sign_request(method, endpoint, data):
	timestamp = str(int(time.time()))
	nonce = str(uuid.uuid4())
	body = canonical_json(data)
	message = f"{method.upper()}\n{endpoint}\n{timestamp}\n{nonce}\n{body}"
	signature = hmac.new(SECRET, message.encode("utf-8"), hashlib.sha256).hexdigest()
	return {
		"X-Device-Id": DEVICE_ID,
		"X-Timestamp": timestamp,
		"X-Nonce": nonce,
		"X-Signature": signature,
		"Content-Type": "application/json"
		}
data = {"message": "hello"}
endpoint = "/data"
headers = sign_request("POST", endpoint, data)

try:
	reponse = requests.post( BACKEND_URL + endpoint, data=canonical_json(data).encode("utf-8"), headers=headers, timeout=10 ) 
	response.raise_for_status()
	print ("Serveur reponse :" response.text) 
except requests.exceptions.RequestException as e:
	print (f"Erreur" {e}")
