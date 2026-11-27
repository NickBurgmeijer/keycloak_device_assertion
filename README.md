# Keycloak Device Check authenticator

A Keycloak authenticator step that shows a page with a small script. The script collects device state in the browser and posts it back. The server then runs your custom action on it.

## Layout

| File | Role |
|---|---|
| `src/main/resources/theme-resources/templates/device-check.ftl` | Page + client script (`collectDeviceState()`); auto-submits JSON in `deviceState` |
| `src/main/java/.../DeviceCheckAuthenticator.java` | Parses the JSON and calls `handleDeviceState(...)`, **your custom action** |
| `src/main/java/.../DeviceCheckAuthenticatorFactory.java` | Registers the step as "Device Check" |
| `META-INF/services/org.keycloak.authentication.AuthenticatorFactory` | SPI registration |

The example action logs the payload, stores it as user-session note `device-state`, and continues.

## Build

```bash
./build.sh                          # -> dist/device-check-authenticator.jar
KC_HOME=~/keycloak ./build.sh       # also copies into $KC_HOME/providers
```

It needs Maven + JDK 17+ (`brew install openjdk@21 maven`) or Docker/Podman. Set `keycloak.version` in `pom.xml` to match your server.

## Deploy

1. Put the jar in `$KC_HOME/providers/`, then run `kc.sh build` (or restart `kc.sh start-dev`).
2. In the admin console, go to **Authentication**, duplicate the `browser` flow, and add the execution **Device Check** (for example after Username Password Form).
3. Bind the new flow as the browser flow.

## Device certificate (second hostname)

The user's own mTLS login stays on the main host. Device certificates are proven on a separate host, because one TLS connection carries only one client certificate.

```
browser ── idp.example.com ──────────► Keycloak     (login page; user mTLS as before)
   └──── device.idp.example.com ─────► Keycloak     (proxy requires a device-CA cert)
          POST /realms/<realm>/device-check/prove?nonce=…
```

1. The authenticator issues a nonce (single-use, 5 min) and passes the prove URL to the page.
2. The page `fetch`es that URL on the device host. TLS asks for the device cert, and the endpoint checks that it is signed by the device CA and that the request's `Origin` is the login page. It then records the cert against the nonce.
3. On submit, the authenticator consumes the nonce and passes the cert (or `null`) to `handleDeviceState`.

Keycloak options:

```
--spi-authenticator-device-check-authenticator-device-host-url=https://device.idp.example.com
--spi-realm-restapi-extension-device-check-device-ca-file=/opt/keycloak/conf/device-ca.pem
--spi-x509cert-lookup-provider=nginx   # or haproxy/apache/envoy, matching your proxy
```

(On Keycloak 26.2+ the SPI option names use `--` between parts, e.g. `--spi-authenticator--device-check-authenticator--device-host-url`.)

Proxy requirements:
- `device.idp.example.com`: require client certs and trust **only** the device CA, so the browser offers only device certs. Forward the verified cert in the header your `x509cert-lookup` provider reads.
- **Every** host in front of Keycloak must overwrite or strip that header on incoming requests. Otherwise a client can send a forged certificate header.
- If user mTLS on the main host also goes through the proxy, both hosts use the same header. The endpoint's CA check is what keeps user certs from counting as device certs.

## Test setup (Docker / Podman)

nginx serves `idp.localhost` and `device.localhost` on port 8443, in front of Keycloak 26 with the plugin and a `test` realm (user `test` / `test`, admin `admin` / `admin`).

```bash
./build.sh
test/certs.sh
docker compose -f test/compose.yml up -d      # or: podman compose
test/smoke.sh                                 # end-to-end checks
```

`smoke.sh` logs in with curl and checks the following: no cert → 401, rogue-CA cert → rejected by nginx, forged cert header on the main host → 401, wrong `Origin` → 403, unknown or reused nonce → 404, device cert → 204, login completes, and `handleDeviceState` receives `CN=device-1`.

To try it in a browser:
1. Trust `test/certs/tls-ca.pem`, and import `test/certs/device.p12` (password `changeit`).
2. Open `https://idp.localhost:8443/realms/test/account`.

Remove both from your keychain afterwards.

## Caveat

Device state comes from the client and can be spoofed. Treat it as a risk signal, not as proof.
