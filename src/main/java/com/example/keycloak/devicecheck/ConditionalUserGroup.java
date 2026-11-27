package com.example.keycloak.devicecheck;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Flow condition: true when the user is in the configured group (or a subgroup),
 * or, with "negate", when they are not. An unknown or unset group counts as
 * "not a member", so "not in group -> Deny access" refuses everyone (fail-closed).
 */
public class ConditionalUserGroup implements ConditionalAuthenticator {

    static final ConditionalUserGroup SINGLETON = new ConditionalUserGroup();
    private static final Logger LOG = Logger.getLogger(ConditionalUserGroup.class);

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        String path = cfg == null ? null : cfg.getConfig().get(ConditionalUserGroupFactory.GROUP);
        boolean negate = cfg != null && Boolean.parseBoolean(cfg.getConfig().get(ConditionalUserGroupFactory.NEGATE));

        GroupModel group = path == null || path.isBlank() ? null
                : KeycloakModelUtils.findGroupByPath(context.getSession(), context.getRealm(), path);
        if (group == null) {
            LOG.warnf("Condition - user in group: group '%s' not configured or not found in realm %s; treating user as not a member",
                    path, context.getRealm().getName());
        }
        boolean member = group != null && context.getUser().isMemberOf(group); // isMemberOf also counts subgroups
        return member != negate;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
