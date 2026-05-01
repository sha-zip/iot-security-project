#!/bin/bash
set -e
cd $(dirname $0)

echo "[PKI] Generating server key..."
openssl genrsa -out server.key 2048

echo "[PKI] Creating SAN config..."
cat > san.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = TN
ST = Tunis
L = Tunis
O = IoT
CN = backend

[v3_req]
subjectAltName = DNS:backend,DNS:mqtt,DNS:mosquitto,DNS:localhost,IP:127.0.0.1
EOF

echo "[PKI] Generating CSR..."
openssl req -new -key server.key -out server.csr -config san.cnf

echo "[PKI] Signing with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365 \
    -extfile san.cnf -extensions v3_req

echo "[PKI] Cleaning up..."
rm -f server.csr san.cnf

echo "server.crt + server.key generated!"
