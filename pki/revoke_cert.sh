#!/usr/bin/env bash
set -euo pipefail

# Usage: ./revoke_cert.sh <device_id>
# Example: ./revoke_cert.sh device-001

DEVICE_ID="${1:-}"

if [ -z "$DEVICE_ID" ]; then
    echo "Usage: $0 <device_id>"
    exit 1
fi

CERT_FILE="${DEVICE_ID}.crt"

if [ ! -f "$CERT_FILE" ]; then
    echo "[PKI] Certificate $CERT_FILE not found."
    exit 1
fi

echo "[PKI] Revoking certificate for device: $DEVICE_ID"

# Initialize CRL database if not exists
[ ! -f index.txt ] && touch index.txt
[ ! -f crlnumber ] && echo "1000" > crlnumber

# Revoke the certificate
openssl ca -config openssl.cnf -revoke "$CERT_FILE" \
    -keyfile ca.key -cert ca.crt

# Regenerate the CRL
openssl ca -config openssl.cnf -gencrl \
    -keyfile ca.key -cert ca.crt -out crl.pem

echo "[PKI] Certificate revoked. CRL updated: crl.pem"
