package com.example.keycloak.devicecheck;

import org.keycloak.Config;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;

/**
 * LDAP lookup: a device is allowed if exactly one entry matches its CN and that
 * entry is a member of the allowed-devices group. Any LDAP error is thrown so the
 * caller can fail closed.
 */
final class DeviceDirectory {

    private static final String DEFAULT_FILTER = "(&(objectClass=device)(cn={0}))";

    private final Hashtable<String, String> env = new Hashtable<>();
    private final String baseDn;
    private final String filter;
    private final String allowedGroupDn;

    private DeviceDirectory(Config.Scope config, String url) {
        baseDn = require(config, "ldap-device-base-dn");
        allowedGroupDn = require(config, "ldap-allowed-group-dn");
        filter = config.get("ldap-device-filter", DEFAULT_FILTER);

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        String bindDn = config.get("ldap-bind-dn");
        if (bindDn != null) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, bindDn);
            env.put(Context.SECURITY_CREDENTIALS, config.get("ldap-bind-password", ""));
        }
        // Short timeouts: a hanging directory must not hang logins (we fail closed instead).
        env.put("com.sun.jndi.ldap.connect.timeout", config.get("ldap-timeout-ms", "3000"));
        env.put("com.sun.jndi.ldap.read.timeout", config.get("ldap-timeout-ms", "3000"));
        env.put("com.sun.jndi.ldap.connect.pool", "true");
    }

    /** Returns null when ldap-url is not set, i.e. the directory check is disabled. */
    static DeviceDirectory fromConfig(Config.Scope config) {
        String url = config.get("ldap-url");
        return url == null ? null : new DeviceDirectory(config, url);
    }

    boolean isAllowed(String deviceCn) throws NamingException {
        DirContext ctx = new InitialDirContext(env);
        try {
            SearchControls subtree = new SearchControls();
            subtree.setSearchScope(SearchControls.SUBTREE_SCOPE);
            subtree.setReturningAttributes(new String[0]);

            // {0} filter args are escaped by JNDI, so a crafted CN can't inject filter syntax.
            NamingEnumeration<SearchResult> devices = ctx.search(baseDn, filter, new Object[]{deviceCn}, subtree);
            if (!devices.hasMore()) {
                return false;
            }
            String deviceDn = devices.next().getNameInNamespace();
            if (devices.hasMore()) {
                throw new NamingException("More than one directory entry for device CN " + deviceCn);
            }

            SearchControls object = new SearchControls();
            object.setSearchScope(SearchControls.OBJECT_SCOPE);
            object.setReturningAttributes(new String[0]);
            return ctx.search(allowedGroupDn, "(member={0})", new Object[]{deviceDn}, object).hasMore();
        } finally {
            ctx.close();
        }
    }

    private static String require(Config.Scope config, String key) {
        String value = config.get(key);
        if (value == null) {
            throw new IllegalStateException("device-check: ldap-url is set but " + key + " is missing");
        }
        return value;
    }
}
