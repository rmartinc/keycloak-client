package org.keycloak.client.testsuite.authz;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import org.apache.http.impl.client.CloseableHttpClient;

import org.junit.jupiter.api.BeforeEach;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.client.testsuite.common.OAuthClient;
import org.keycloak.client.testsuite.framework.Inject;
import org.keycloak.client.testsuite.common.RealmImporter;
import org.keycloak.client.testsuite.common.RealmRepsSupplier;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.RealmRepresentation;
import static org.keycloak.testsuite.util.AuthzTestUtils.httpsAwareConfigurationStream;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractAuthzTest implements RealmRepsSupplier {

    static {
        CryptoIntegration.init(CryptoProvider.class.getClassLoader());
    }

    @Inject
    protected Keycloak adminClient;

    @Inject
    protected RealmImporter realmImporter;

    @Inject
    protected OAuthClient oauth;

    @Inject
    protected CloseableHttpClient httpClient;

    @BeforeEach
    public void importRealms() {
        realmImporter.importRealmsIfNotImported(this);
    }

    protected RealmRepresentation loadRealm(InputStream is) {
        try {
            return JsonSerialization.readValue(is, RealmRepresentation.class);
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    @Override
    public boolean removeVerifyProfileAtImport() {
        // remove verify profile by default because most tests are not prepared
        return true;
    }

    public RealmsResource realmsResource() {
        return adminClient.realms();
    }

    protected AccessToken toAccessToken(String rpt) {
        AccessToken accessToken;

        try {
            accessToken = new JWSInput(rpt).readJsonContent(AccessToken.class);
        } catch (JWSInputException cause) {
            throw new RuntimeException("Failed to deserialize RPT", cause);
        }
        return accessToken;
    }

    protected AuthzClient getAuthzClient(String filePath) {
        try {
            Configuration config = JsonSerialization.readValue(httpsAwareConfigurationStream(getClass().getResourceAsStream(filePath)), Configuration.class);
            config.setHttpClient(httpClient);
            return AuthzClient.create(config);
        } catch (IOException cause) {
            throw new RuntimeException("Failed to create authz client", cause);
        }
    }
}
