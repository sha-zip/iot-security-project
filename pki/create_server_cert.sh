#!/bin/bash
cd $(dirname $0)
# Etape1.generer cle prive
openssl genrsa -out server.key 2048

#Etape2:generer CSR avec subject pour mqtt
openssl req -new -key server.key -out server.csr
 -subj "/C=TN/ST=Tunis/L=Tunis/CN=mosquitto.server/0=IoT"
 -config openssl.cnf
 -addtext "subjectALtName=DNS:localhost,DNS:mosquitto,IP:127.0.0.1"
 -batch
#Etape 3: signe avec CA 
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions server_ext -extfile openssl.cnf

#Etape 4: Nettoie
rm server.csr
echo "server.crt + server.key generes !"

