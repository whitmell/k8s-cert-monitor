#!/usr/bin/env bash
# Generates throwaway test certificates with a spread of expiry dates into ./certs.
# Private keys go to a temp dir and are deleted. Requires openssl.
set -euo pipefail
cd "$(dirname "$0")"
OUT=certs; KEYS=$(mktemp -d ./.keys.XXXXXX); trap 'rm -rf "$KEYS"' EXIT
mkdir -p "$OUT"
export MSYS_NO_PATHCONV=1
ca() { # name subject days
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$KEYS/$1.key" \
    -out "$OUT/$1.pem" -days "$3" -subj "$2" 2>/dev/null; }
leaf() { # name subject days san
  openssl req -newkey rsa:2048 -nodes -keyout "$KEYS/$1.key" -out "$KEYS/$1.csr" -subj "$2" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\n' "$4" > "$KEYS/$1.ext"
  openssl x509 -req -in "$KEYS/$1.csr" -CA "$OUT/root-ca.pem" -CAkey "$KEYS/root-ca.key" -CAcreateserial \
    -days "$3" -extfile "$KEYS/$1.ext" -out "$OUT/$1.pem" 2>/dev/null; }
ca   root-ca     "/C=US/O=Shorebreak Test/CN=Shorebreak Test Root CA" 3650
leaf payments   "/O=Shorebreak Test/OU=Payments/CN=payments.apps.test" 9   "DNS:payments.apps.test,DNS:pay.apps.test"
leaf gateway    "/O=Shorebreak Test/CN=gateway.apps.test"            25  "DNS:gateway.apps.test,DNS:*.gateway.apps.test,IP:10.20.0.15"
leaf portal     "/O=Shorebreak Test/CN=portal.apps.test"             75  "DNS:portal.apps.test"
leaf reporting  "/O=Shorebreak Test/CN=reporting.apps.test"          400 "DNS:reporting.apps.test,DNS:reports.apps.test"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$KEYS/old.key" -out "$OUT/legacy.pem" \
  -not_before 20240101000000Z -not_after 20250101000000Z -subj "/CN=legacy.apps.test" \
  -addext "subjectAltName=DNS:legacy.apps.test" 2>/dev/null
cat "$OUT/gateway.pem" "$OUT/root-ca.pem" > "$OUT/gateway-bundle.pem"
openssl x509 -in "$OUT/root-ca.pem" -outform DER -out "$OUT/root-ca.der"
ls "$OUT"
