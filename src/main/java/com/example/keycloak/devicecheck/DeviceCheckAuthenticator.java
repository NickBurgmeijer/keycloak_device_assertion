package com.example.keycloak.devicecheck;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Renders a page whose inline script collects device state in the browser,
 * proves the device certificate on the device host, posts the state back,
 * and hands both to {@link #handleDeviceState}.
 */
public class DeviceCheckAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(DeviceCheckAuthenticator.class);

    static final String TEMPLATE = "device-check.ftl";
    static final String FORM_FIELD = "deviceState";
    static final String NOTE_KEY = "device-state";
    static final String NONCE_NOTE = "device-check-nonce";
    static final int NONCE_TTL_SECONDS = 300;

    /** e.g. https://device.idp.example.com — null disables the device-cert step. */
    private final String deviceHostUrl;

    public DeviceCheckAuthenticator(String deviceHostUrl) {
        this.deviceHostUrl = deviceHostUrl;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(newChallenge(context).createForm(TEMPLATE));
    }

    /** Issues a fresh nonce, registers it for the device host, and passes the prove URL to the page. */
    private LoginFormsProvider newChallenge(AuthenticationFlowContext context) {
        LoginFormsProvider form = context.form();
        if (deviceHostUrl == null) {
            return form;
        }
        String nonce = SecretGenerator.getInstance().randomString(32);
        URI base = context.getUriInfo().getBaseUri();
        String origin = base.getScheme() + "://" + base.getAuthority();

        // The prove endpoint only accepts nonces issued here, and only from this page's origin.
        context.getSession().singleUseObjects()
                .put(DeviceProveResource.KEY_PREFIX + nonce, NONCE_TTL_SECONDS, Map.of("origin", origin));
        context.getAuthenticationSession().setAuthNote(NONCE_NOTE, nonce);

        return form.setAttribute("deviceProveUrl",
                deviceHostUrl + "/realms/" + context.getRealm().getName() + "/device-check/prove?nonce=" + nonce);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String raw = context.getHttpRequest().getDecodedFormParameters().getFirst(FORM_FIELD);
        X509Certificate deviceCert = takeDeviceCert(context);

        JsonNode state;
        try {
            state = raw == null || raw.isBlank() ? null : JsonSerialization.readValue(raw, JsonNode.class);
        } catch (IOException e) {
            LOG.debugf(e, "Could not parse device state");
            state = null;
        }

        if (state == null) {
            failWithRetry(context, "Could not read device state.");
            return;
        }

        handleDeviceState(context, state, raw, deviceCert);
    }

    /** Shows the device-check page again with an error and a fresh nonce; the user can retry. */
    protected void failWithRetry(AuthenticationFlowContext context, String error) {
        Response challenge = newChallenge(context)
                .setError(error)
                .setAttribute("deviceCheckFailed", true)
                .createForm(TEMPLATE);
        context.failureChallenge(AuthenticationFlowError.ACCESS_DENIED, challenge);
    }

    /** Consumes this login's nonce; returns the device cert proven for it, or null. */
    private X509Certificate takeDeviceCert(AuthenticationFlowContext context) {
        String nonce = context.getAuthenticationSession().getAuthNote(NONCE_NOTE);
        if (nonce == null) {
            return null;
        }
        context.getAuthenticationSession().removeAuthNote(NONCE_NOTE);
        Map<String, String> proof = context.getSession().singleUseObjects().remove(DeviceProveResource.KEY_PREFIX + nonce);
        return proof == null ? null : DeviceProveResource.decode(proof.get("cert"));
    }

    /**
     * Your custom action goes here. The user may be null if this step runs
     * before the user is identified in the flow. deviceCert is null when the
     * browser did not present a valid device certificate on the device host.
     *
     * Call context.success() to continue, or context.failure(...) /
     * context.failureChallenge(...) to block.
     */
    protected void handleDeviceState(AuthenticationFlowContext context, JsonNode state, String raw,
                                     X509Certificate deviceCert) {
        UserModel user = context.getUser();
        LOG.infof("Device state for realm=%s user=%s deviceCert=%s: %s",
                context.getRealm().getName(),
                user == null ? "<unknown>" : user.getUsername(),
                deviceCert == null ? "<none>" : deviceCert.getSubjectX500Principal().getName(),
                raw);

        // deviceCert is only non-null if the prove endpoint saw it over mTLS, it chains to the
        // device CA and was within its validity period (see DeviceProveResource).
        if (deviceCert == null) {
            failWithRetry(context, "No valid device certificate was presented.");
            return;
        }

        // Example: keep it on the auth session so later steps / mappers can read it.
        context.getAuthenticationSession().setUserSessionNote(NOTE_KEY, raw);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
