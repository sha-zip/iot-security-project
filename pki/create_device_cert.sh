#!/bin/bash
set -e
cd $(dirname $0)

DEVICE_NAME=${1:-device001}

echo "[PKI] Generating private key for $DEVICE_NAME..."
openssl genrsa -out ${DEVICE_NAME}.key 2048

echo "[PKI] Generating CSR..."
openssl req -new -key ${DEVICE_NAME}.key -out ${DEVICE_NAME}.csr \
    -subj "/C=TN/O=IoT_Project/CN=${DEVICE_NAME}"

echo "[PKI] Signing with CA..."
openssl x509 -req -in ${DEVICE_NAME}.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out ${DEVICE_NAME}.crt -days 365 \
    -extfile <(cat << EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:${DEVICE_NAME}
EOF
)

echo "[PKI] Cleaning up..."
rm -f ${DEVICE_NAME}.csr

echo "[PKI] Done! Certificate: ${DEVICE_NAME}.crt"
