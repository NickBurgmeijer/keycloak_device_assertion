#!/usr/bin/env bash
# End-to-end test against the compose stack: logs in as test/test, then checks the
# device-cert endpoint's accept/reject paths and that the cert reaches handleDeviceState.
set -euo pipefail
cd "$(dirname "$0")"

BASE=https://idp.localhost:8443
DEV=https://device.localhost:8443
C=certs
COMPOSE=${COMPOSE:-$(command -v docker >/dev/null && echo "docker compose" || echo "podman compose")}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT

curl_() {
    curl -sS --cacert "$C/tls-ca.pem" \
        --resolve idp.localhost:8443:127.0.0.1 --resolve device.localhost:8443:127.0.0.1 \
        -c "$JAR" -b "$JAR" "$@"
}
code() { curl_ -o /dev/null -w '%{http_code}' "$@" || true; }
form_action() { { grep -o "<form[^>]*$1[^>]*>" || true; } | head -1 | sed 's/.*action="//;s/".*//;s/&amp;/\&/g'; }
check() { # name actual expected
    if [[ "$2" == "$3" ]]; then echo "PASS  $1"; else echo "FAIL  $1 (expected $3, got $2)"; exit 1; fi
}

echo "Waiting for Keycloak..."
for _ in $(seq 90); do
    [[ $(code "$BASE/realms/test") == 200 ]] && break
    sleep 2
done
check "realm reachable" "$(code "$BASE/realms/test")" 200

# 1. Username/password -> device-check page
page=$(curl_ "$BASE/realms/test/protocol/openid-connect/auth?client_id=test-client&response_type=code&scope=openid&redirect_uri=https://example.invalid/cb")
login=$(form_action 'id="kc-form-login"' <<<"$page")
check "login form found" "$([[ -n $login ]] && echo yes)" yes
page=$(curl_ --data-urlencode username=test --data-urlencode password=test "$login")
prove=$(grep -o "$DEV/realms/test/device-check/prove?nonce=[A-Za-z0-9]*" <<<"$page" | head -1 || true)
submit=$(form_action 'id="device-check-form"' <<<"$page")
check "device-check page has prove URL" "$([[ -n $prove ]] && echo yes)" yes

# 2. Rejections (none of these may consume the nonce)
check "no client cert -> 401" "$(code -X POST -H "Origin: $BASE" "$prove")" 401
check "rogue-CA cert rejected by nginx -> 400" \
    "$(code -X POST -H "Origin: $BASE" --cert "$C/rogue.pem" --key "$C/rogue.key" "$prove")" 400
forged=$(python3 -I -c 'import sys,urllib.parse;print(urllib.parse.quote(open(sys.argv[1]).read()))' "$C/device.pem")
check "forged cert header via main host -> 401" \
    "$(code -X POST -H "Origin: $BASE" -H "ssl-client-cert: $forged" -H "ssl-client-verify: SUCCESS" "${prove/$DEV/$BASE}")" 401
check "wrong Origin -> 403" \
    "$(code -X POST -H "Origin: https://evil.example" --cert "$C/device.pem" --key "$C/device.key" "$prove")" 403
check "unknown nonce -> 404" \
    "$(code -X POST -H "Origin: $BASE" --cert "$C/device.pem" --key "$C/device.key" "$DEV/realms/test/device-check/prove?nonce=bogus")" 404

# 3. Submitting without a proven cert is refused; the retry page carries a fresh nonce
page=$(curl_ --data-urlencode 'deviceState={"source":"smoke-test"}' "$submit")
check "login without cert refused" "$(grep -c 'No valid device certificate' <<<"$page" || true)" 1
old=$prove
prove=$(grep -o "$DEV/realms/test/device-check/prove?nonce=[A-Za-z0-9]*" <<<"$page" | head -1 || true)
submit=$(form_action 'id="device-check-form"' <<<"$page")
check "retry page has a new nonce" "$([[ -n $prove && $prove != "$old" ]] && echo yes)" yes
check "old nonce is consumed -> 404" \
    "$(code -X POST -H "Origin: $BASE" --cert "$C/device.pem" --key "$C/device.key" "$old")" 404

# 4. Happy path
check "device cert -> 204" \
    "$(code -X POST -H "Origin: $BASE" --cert "$C/device.pem" --key "$C/device.key" "$prove")" 204
check "same nonce again -> 404" \
    "$(code -X POST -H "Origin: $BASE" --cert "$C/device.pem" --key "$C/device.key" "$prove")" 404

# 5. Submit device state -> redirected back to the client with a code
loc=$(curl_ -o /dev/null -w '%{redirect_url}' --data-urlencode 'deviceState={"source":"smoke-test"}' "$submit")
check "login completes with code" "$([[ $loc == https://example.invalid/cb*code=* ]] && echo yes)" yes

# 6. The cert actually reached handleDeviceState
logs=$($COMPOSE -f compose.yml logs keycloak 2>&1 | grep 'Device state for realm=test' | tail -1 || true)
check "handleDeviceState saw device-1" "$([[ $logs == *deviceCert=CN=device-1* ]] && echo yes)" yes

echo "All checks passed."
