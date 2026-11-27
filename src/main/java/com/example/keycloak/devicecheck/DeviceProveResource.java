package com.example.keycloak.devicecheck;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * POST /realms/{realm}/device-check/prove?nonce=...
 *
 * Called by the login page on the device host, where the TLS layer asks for a
 * device certificate. Records "this nonce was proven by this device cert" for
 * the authenticator to pick up.
 */
public class DeviceProveResource {

    private static final Logger LOG = Logger.getLogger(DeviceProveResource.class);

    static final String KEY_PREFIX = "device-check:";

    private final KeycloakSession session;
    private final X509Certificate deviceCa;

    public DeviceProveResource(KeycloakSession session, X509Certificate deviceCa) {
        this.session = session;
        this.deviceCa = deviceCa;
    }

    @POST
    @Path("prove")
    public Response prove(@QueryParam("nonce") String nonce) {
        if (deviceCa == null) {
            LOG.warn("device-check prove called but no device CA is configured");
            return Response.status(Response.Status.SERVICE_UNAVAILABLE).build();
        }
        if (nonce == null || nonce.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        SingleUseObjectProvider store = session.singleUseObjects();
        String key = KEY_PREFIX + nonce;
        Map<String, String> notes = store.get(key);
        if (notes == null || notes.containsKey("cert")) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        // Stops another site from making a victim's browser prove its device for an attacker's login.
        String origin = session.getContext().getRequestHeaders().getHeaderString("Origin");
        if (origin == null || !origin.equals(notes.get("origin"))) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        X509Certificate cert;
        try {
            X509Certificate[] chain = session.getProvider(X509ClientCertificateLookup.class)
                    .getCertificateChain(session.getContext().getHttpRequest());
            if (chain == null || chain.length == 0) {
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            cert = chain[0];
            // Must check the CA here: the main host may forward *user* certs through the same lookup.
            // shortcut: only accepts certs signed directly by the device CA, add CertPathValidator if you use intermediates.
            cert.checkValidity();
            cert.verify(deviceCa.getPublicKey());

            Map<String, String> updated = new HashMap<>(notes);
            updated.put("cert", Base64.getEncoder().encodeToString(cert.getEncoded()));
            // Not replace(): Keycloak's replace() drops the lifespan, leaking entries for abandoned logins.
            store.put(key, DeviceCheckAuthenticator.NONCE_TTL_SECONDS, updated);
        } catch (GeneralSecurityException e) {
            LOG.debugf(e, "Rejected device certificate");
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        return Response.noContent()
                .header("Access-Control-Allow-Origin", origin)
                .header("Access-Control-Allow-Credentials", "true")
                .build();
    }

    static X509Certificate decode(String base64Der) {
        if (base64Der == null) {
            return null;
        }
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64Der)));
        } catch (GeneralSecurityException e) {
            return null;
        }
    }
}
