package io.github.mesubash.iam;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Boots the full context against a local Postgres + Redis (docker compose up),
 * which also applies and validates every Flyway migration.
 */
@SpringBootTest
class SpringIamApplicationTests {

    @Test
    void contextLoads() {
    }

}
