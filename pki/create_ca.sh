#!/usr/bin/env bash
set -euo pipefail

echo "[PKI] Generating CA key and certificate..."
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
    -days 365 -nodes -subj "/CN=iot-ca/O=IoT_Project/C=TN"

echo "[PKI] Generating server key and CSR..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=mqtt-broker/O=IoT_Project/C=TN"

echo "[PKI] Signing server certificate with CA..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 365

echo "[PKI] Cleaning up..."
rm -f server.csr ca.srl

echo "[PKI] Done! Files generated:"
ls -la *.crt *.key
