package com.example.keycloak.devicecheck;

import org.keycloak.Config;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class ConditionalUserGroupFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "conditional-user-group";
    static final String GROUP = "group";
    static final String NEGATE = "negate";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - user in group";
    }

    @Override
    public String getHelpText() {
        return "Matches when the user is (or, negated, is not) a member of the group or one of its subgroups.";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty group = new ProviderConfigProperty(GROUP, "Group",
                "Group path, e.g. /staff or /staff/finance.", ProviderConfigProperty.GROUP_TYPE, null);
        group.setRequired(true);
        ProviderConfigProperty negate = new ProviderConfigProperty(NEGATE, "Negate output",
                "Match users who are NOT in the group.", ProviderConfigProperty.BOOLEAN_TYPE, false);
        return List.of(group, negate);
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return ConditionalUserGroup.SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
