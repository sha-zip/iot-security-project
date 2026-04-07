#!/bin/bash
DEVICE_NAME=device

echo "generation cle prive..."
openssl genrsa -out ${DEVICE_NAME}.key 2048

echo 
