package com.example.keycloak.devicecheck;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class DeviceCheckAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "device-check-authenticator";

    private DeviceCheckAuthenticator authenticator;

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Device Check";
    }

    @Override
    public String getHelpText() {
        return "Collects device state in the browser and runs a custom server-side action on it.";
    }

    @Override
    public String getReferenceCategory() {
        return "device-check";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return authenticator;
    }

    @Override
    public void init(Config.Scope config) {
        // --spi-authenticator-device-check-authenticator-device-host-url=https://device.idp.example.com
        // --spi-authenticator-device-check-authenticator-ldap-url=ldaps://... (see README for the rest)
        authenticator = new DeviceCheckAuthenticator(config.get("device-host-url"), DeviceDirectory.fromConfig(config));
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
