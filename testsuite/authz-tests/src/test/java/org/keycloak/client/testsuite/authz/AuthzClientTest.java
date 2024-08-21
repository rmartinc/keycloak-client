package org.keycloak.client.testsuite.authz;

import java.io.ByteArrayInputStream;
import java.util.Iterator;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.authorization.client.AuthzClient;
import org.testcontainers.shaded.org.hamcrest.MatcherAssert;
import org.testcontainers.shaded.org.hamcrest.Matchers;


public class AuthzClientTest {

    @Test
    public void testCreateWithEnvVars() {
        RuntimeException runtimeException = Assertions.assertThrows(RuntimeException.class, () -> {
            Map<String, String> env = System.getenv();
            Assertions.assertTrue(env.size() > 1);
            Iterator<String> names = env.keySet().iterator();
            AuthzClient.create(new ByteArrayInputStream(("{\n"
                    + "  \"realm\": \"${env." + names.next() + "}\",\n"
                    + "  \"auth-server-url\": \"${env." + names.next() + "}\",\n"
                    + "  \"ssl-required\": \"external\",\n"
                    + "  \"enable-cors\": true,\n"
                    + "  \"resource\": \"my-server\",\n"
                    + "  \"credentials\": {\n"
                    + "    \"secret\": \"${env.KEYCLOAK_SECRET}\"\n"
                    + "  },\n"
                    + "  \"confidential-port\": 0,\n"
                    + "  \"policy-enforcer\": {\n"
                    + "    \"enforcement-mode\": \"ENFORCING\"\n"
                    + "  }\n"
                    + "}").getBytes()));
        });

        MatcherAssert.assertThat(runtimeException.getMessage(), Matchers.containsString("Could not obtain configuration from server"));
    }
}
