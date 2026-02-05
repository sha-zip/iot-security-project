import requests
from se_module import sign_data

BACKEND_URL = "http://127.0.0.1:5000/auth"

message = b"hello-from-iot-device"

signature = sign_data(message)
print ("SIGNATURE SENT", signature.hex())
response = requests.post(BACKEND_URL,data=message,headers={"X-Signature":signature.hex()})

print("Server response:",response.text)
