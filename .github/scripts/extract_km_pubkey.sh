#!/usr/bin/env bash
set -euo pipefail

# For reference:
# extract_km_pubkey.sh <config.json> <km_manifest_key> <output.pem>

CONFIG=$1
MANIFEST_KEY=$2
OUTPUT_PEM=$3

jq -r '."'"$MANIFEST_KEY"'".kmKeySignature.ksKey.keyData' "$CONFIG" | base64 -d > /tmp/keydata.bin

EXPONENT_HEX=$(dd if=/tmp/keydata.bin bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n' | fold -w2 | tac | tr -d '\n')
MODULUS_HEX=$(dd if=/tmp/keydata.bin bs=1 skip=4 2>/dev/null | od -An -tx1 | tr -d ' \n' | fold -w2 | tac | tr -d '\n')

cat > /tmp/rsa_key.asn1 << EOF
asn1=SEQUENCE:rsa_key
[rsa_key]
n=INTEGER:0x${MODULUS_HEX}
e=INTEGER:0x${EXPONENT_HEX}
EOF

openssl asn1parse -genconf /tmp/rsa_key.asn1 -out /tmp/rsa_key.der -noout
openssl rsa -in /tmp/rsa_key.der \
  -inform DER \
  -RSAPublicKey_in \
  -pubout \
  -out "$OUTPUT_PEM"

rm -f /tmp/keydata.bin /tmp/rsa_key.asn1 /tmp/rsa_key.der
