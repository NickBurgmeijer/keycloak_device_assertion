package com.example.keycloak.devicecheck;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** Mounts {@link DeviceProveResource} at /realms/{realm}/device-check. */
public class DeviceProveResourceFactory implements RealmResourceProviderFactory {

    public static final String ID = "device-check";

    private X509Certificate deviceCa;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new RealmResourceProvider() {
            @Override
            public Object getResource() {
                return new DeviceProveResource(session, deviceCa);
            }

            @Override
            public void close() {
            }
        };
    }

    @Override
    public void init(Config.Scope config) {
        // --spi-realm-restapi-extension-device-check-device-ca-file=/opt/keycloak/conf/device-ca.pem
        String file = config.get("device-ca-file");
        if (file == null) {
            return;
        }
        try (InputStream in = Files.newInputStream(Path.of(file))) {
            deviceCa = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot load device CA from " + file, e);
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
