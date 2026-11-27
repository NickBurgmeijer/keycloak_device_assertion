#!/usr/bin/env bash
# Generates throwaway test PKI into test/certs/:
#   tls-ca     -> server.pem (idp.localhost, device.localhost)
#   device-ca  -> device.pem / device.p12 (CN=device-1, the "good" device)
#   rogue-ca   -> rogue.pem (a client cert from a CA nobody trusts)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs && cd certs

ca() { # name cn
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$2" \
        -keyout "$1.key" -out "$1.pem" 2>/dev/null
}
leaf() { # name cn ca extensions
    openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$2" -keyout "$1.key" 2>/dev/null |
        openssl x509 -req -days 30 -CA "$3.pem" -CAkey "$3.key" -CAcreateserial \
            -extfile <(printf '%s\n' "$4") -out "$1.pem" 2>/dev/null
}

ca tls-ca "Test TLS CA"
leaf server idp.localhost tls-ca "subjectAltName=DNS:idp.localhost,DNS:device.localhost
extendedKeyUsage=serverAuth"

ca device-ca "Test Device CA"
leaf device device-1 device-ca "extendedKeyUsage=clientAuth"

ca rogue-ca "Rogue CA"
leaf rogue rogue-device rogue-ca "extendedKeyUsage=clientAuth"

# For importing into a browser/keychain. Password is "changeit". 3DES so macOS Keychain accepts it.
openssl pkcs12 -export -inkey device.key -in device.pem -certfile device-ca.pem -out device.p12 \
    -passout pass:changeit -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1

chmod 644 ./*.key # containers read them as non-root; test-only keys
echo "Certs in $(pwd)"
