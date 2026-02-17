#!/usr/bin/env bash
set -euo pipefail
softhsm2-util --init-token --slot 0 --label "iot_secure_element" --so-pin 1234 --pin 0000
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 0000 keypairgen --key-type rsa:2048 --id 01 --label iot_rsa_key 
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --read-object --type pubkey --label iot _rsa_key --output-file iot_pubkey.der 
