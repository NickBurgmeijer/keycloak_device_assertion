# Keycloak Device Check authenticator (vibecode)

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

## LDAP device allow-list (optional)

When `ldap-url` is set, a valid device certificate is not enough. The certificate's CN must match exactly one device entry in LDAP, and that entry must be a `member` of the allowed-devices group. Anything else refuses the login: an unknown device, a device outside the group, duplicate entries, or LDAP being down or slow. That last case is fail-closed.

```
--spi-authenticator-device-check-authenticator-ldap-url=ldaps://ldap.example.com
--spi-authenticator-device-check-authenticator-ldap-bind-dn=cn=keycloak,ou=services,dc=example,dc=com
--spi-authenticator-device-check-authenticator-ldap-bind-password=...
--spi-authenticator-device-check-authenticator-ldap-device-base-dn=ou=devices,dc=example,dc=com
--spi-authenticator-device-check-authenticator-ldap-allowed-group-dn=cn=allowed-devices,ou=groups,dc=example,dc=com
# optional:
--spi-authenticator-device-check-authenticator-ldap-device-filter=(&(objectClass=device)(cn={0}))
--spi-authenticator-device-check-authenticator-ldap-timeout-ms=3000
```

- To allow a device, add it to the group. To revoke one, remove it. No schema changes are needed: it uses the standard `device` and `groupOfNames` object classes.
- For Active Directory computer objects, set the filter to `(&(objectClass=computer)(cn={0}))`.
- For `ldaps://`, the LDAP server's CA must be in the JVM truststore Keycloak runs with.
- The bind account only needs read access to the device OU and the group.
- Don't pass the bind password on the command line in production. Use the matching `KC_SPI_…` environment variable or a config file instead.
- Devices are matched by CN, so your device CA must never issue the same CN to two devices.

## Condition - user in group

A flow condition, **Condition - user in group**, matches when the user is in a configured Keycloak group or one of its subgroups (LDAP-synced groups count too). With **Negate output** on, it matches when the user is *not* in the group. Like Keycloak's built-in conditions, it gates a CONDITIONAL sub-flow, so you can put any step behind it: deny access, require OTP, skip or require Device Check, and so on.

Example: only `/staff` may sign in. This is what `test/realm.json` does:

```
device browser
├─ Username Password Form            REQUIRED
├─ staff only                        CONDITIONAL  (sub-flow)
│  ├─ Condition - user in group      REQUIRED     group=/staff, negate=on
│  └─ Deny access                    REQUIRED     error message: "You are not allowed to sign in here."
└─ Device Check                      REQUIRED
```

Set the group and negate options with ⚙ on the condition. An unset or unknown group counts as "not a member", so the negated deny pattern refuses everyone (fail-closed), and a non-negated condition never matches. Either way, a warning is logged.

## Test setup (Docker / Podman)

nginx serves `idp.localhost` and `device.localhost` on port 8443, in front of Keycloak 26 with the plugin and a `test` realm (user `test` / `test`, admin `admin` / `admin`). An OpenLDAP container (`test/ldap/`) holds the device directory:
- `device-1` is in the allowed group.
- `device-2` is in LDAP but not in the group.
- `device-3` has no LDAP entry.

```bash
./build.sh
test/certs.sh
docker compose -f test/compose.yml up -d      # or: podman compose
test/smoke.sh                                 # end-to-end checks
```

`smoke.sh` logs in with curl (user `test` is in `/staff`; user `outsider` / `outsider` is not, and is refused) and checks the following: no cert → 401, rogue-CA cert → rejected by nginx, forged cert header on the main host → 401, wrong `Origin` → 403, unknown or reused nonce → 404, device cert → 204, login completes, and `handleDeviceState` receives `CN=device-1`. It also checks the LDAP allow-list: `device-1` gets in, `device-2` and `device-3` are refused, and a stopped LDAP container refuses everyone until it's back.

To try it in a browser:
1. Trust `test/certs/tls-ca.pem`, and import `test/certs/device.p12` (password `changeit`).
2. Open `https://idp.localhost:8443/realms/test/account`.

Remove both from your keychain afterwards.

## Caveat

Device state comes from the client and can be spoofed. Treat it as a risk signal, not as proof.

## Possible improvements

### Quick win: no certificate picker on managed devices

On managed devices, push this Chromium policy (Chrome, Edge, Brave) through your MDM. The browser then selects the device certificate for the device host silently:

```json
"AutoSelectCertificateForUrls": ["{\"pattern\":\"https://device.idp.example.com\",\"filter\":{\"ISSUER\":{\"CN\":\"Your Device CA\"}}}"]
```

No code changes are needed. Firefox has its own setting, `security.default_personal_cert = Select Automatically`.

### Second authenticator: PKeyAuth-style device proof

An HTTP-level challenge–response, modelled on Microsoft's PKeyAuth. The server issues a nonce, and a component on the device signs a short JWT with the device key. Compared with mTLS:

- **+** It doesn't depend on TLS, so it works behind CDNs and TLS-inspecting proxies, and needs no second hostname.
- **+** The device can sign more than its identity, for example a health report collected by native code (more trustworthy than the page script's `deviceState`).
- **+** No picker at all when the helper is installed.
- **−** Every device needs a helper: a browser extension plus a native-messaging host that can use the key (Keychain/Secure Enclave, CNG/TPM). That is most of the work.

#### Protocol

```
page shows challenge  { nonce, context, certAuthorities, aud }
helper signs JWS      header  { "alg": "RS256", "x5c": ["<device cert, base64 DER>"] }
                      payload { "aud": "<login-actions URL>", "nonce": "...", "iat": ..., "health": {...optional} }
page posts            pkeyAuthToken=<jws>   (empty if no helper answered)
```

Server checks, in order:
1. The nonce equals the auth-session note and hasn't been used. Then remove the note.
2. `aud` is this realm's login-actions URL.
3. `iat` is within about 60 seconds.
4. The signature is valid for the public key of the `x5c[0]` certificate.
5. That certificate is valid and signed by the device CA.
6. It passes the LDAP allow-list, matching by CN.

Checks 5 and 6 are the existing code.

#### Code changes

| File | Change |
|---|---|
| `DeviceCertificates.java` (new) | Move the device-CA load and the `checkValidity()` + `verify(caKey)` logic out of `DeviceProveResource`, so both authenticators share it. |
| `PKeyAuthAuthenticator.java` (new) | `authenticate()`: create a nonce, store it as an auth note, render `pkeyauth.ftl`. `action()`: read `pkeyAuthToken`. If it's empty, call `context.attempted()` so the next ALTERNATIVE (mTLS) runs. Otherwise parse it with Keycloak's `JWSInput`, run the checks above, then reuse `DeviceDirectory`. On failure, `failureChallenge(...)`. |
| `PKeyAuthAuthenticatorFactory.java` (new) | id `device-check-pkeyauth`, display type "Device Check (PKeyAuth)". `isConfigurable()` returns `true`, with properties for the helper timeout (ms), the accepted clock skew, and "require health report". Register it in `META-INF/services/org.keycloak.authentication.AuthenticatorFactory` (second line). |
| `theme-resources/templates/pkeyauth.ftl` (new) | Renders `<div id="pkeyauth-challenge" data-nonce data-context data-aud data-cert-authorities>`. The extension's content script finds it, asks the native host to sign, fills `pkeyAuthToken` and submits. A page script submits an empty token after the timeout, about 1.5 s, if no helper answered. |
| `DeviceCheckAuthenticator.java` | Unchanged apart from using `DeviceCertificates`. It stays the mTLS method. |

Configuration moves per flow step: the admin UI's ⚙ on the execution stores an `AuthenticatorConfigModel`, so different realms or flows can use different settings without a restart. Keep the existing `--spi-…` options as defaults.

#### Flow layout

```
browser (device)
├─ Cookie                        ALTERNATIVE
└─ forms                         ALTERNATIVE
   ├─ Username Password Form     REQUIRED
   └─ Device proof               REQUIRED  (sub-flow)
      ├─ Device Check (PKeyAuth) ALTERNATIVE   silent if the helper answers, else attempted()
      └─ Device Check (mTLS)     ALTERNATIVE   fallback: picker or auto-selected cert
```

Either method satisfies "Device proof". To require PKeyAuth only, remove the mTLS execution or set it to DISABLED. No server flag is needed: the flow is the switch.

#### Client helper

- **Browser extension** (Chromium Manifest V3, Firefox): a content script limited to `https://idp.example.com/*` that reads the challenge and calls `chrome.runtime.sendNativeMessage`. Force-install it with the `ExtensionInstallForcelist` policy.
- **Native-messaging host**, one per OS: finds the identity whose issuer matches `certAuthorities`, signs the JWS with the non-exportable key, and returns it. Only answer when the challenge comes from the expected origin; that check is the defence against relay/phishing proxies.
- Native apps can skip the extension and call the same check through a custom endpoint. That isn't covered here.

#### Tests

Add a smoke step that signs the JWS with `openssl` using `test/certs/device.key`. Check that:
- a valid token passes;
- an expired `iat` fails;
- a wrong `aud` fails;
- a reused nonce fails;
- a rogue-CA `x5c` fails;
- an empty token falls back to the mTLS step.

Unverified assumptions to check first:
- calling `context.attempted()` from `action()` in an ALTERNATIVE step on Keycloak 26;
- whether `JWSInput` exposes `x5c` from the header, or it has to be read as plain JSON.
