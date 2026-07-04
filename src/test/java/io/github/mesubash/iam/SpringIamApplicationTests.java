package io.github.mesubash.iam;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Boots the full context against a local Postgres + Redis (docker compose up),
 * which also applies and validates every Flyway migration.
 */
@SpringBootTest(properties = {
        "spring.security.oauth2.client.registration.google.client-id=test-client",
        "spring.security.oauth2.client.registration.google.client-secret=test-secret"
})
class SpringIamApplicationTests {

    @Test
    void contextLoads() {
    }

}
