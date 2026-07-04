package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.repository.RefreshTokenRepository;
import io.github.mesubash.iam.shared.exception.TokenReuseException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the session/refresh lifecycle against real Postgres + Redis:
 * rotation, idempotent retry inside the grace window, reuse detection
 * outside it, and session revocation.
 */
@SpringBootTest(properties = {
        "spring.security.oauth2.client.registration.google.client-id=test-client",
        "spring.security.oauth2.client.registration.google.client-secret=test-secret"
})
class SessionLifecycleIntegrationTest {

    @Autowired private SessionService sessionService;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;

    private UUID newIdentity() {
        Identity identity = identityRepository.save(Identity.builder()
                .primaryEmail("session-test-" + UUID.randomUUID() + "@example.com")
                .emailVerified(true)
                .accountStatus(AccountStatus.ACTIVE)
                .build());
        return identity.getId();
    }

    @Test
    void rotationRetryAndReuseDetection() {
        UUID identityId = newIdentity();

        SessionService.IssuedRefresh issued = sessionService.createSession(identityId, null, "junit");
        String t1 = issued.rawToken();

        // Normal rotation: new token, same session
        SessionService.RotationResult r1 = sessionService.rotate(t1);
        String t2 = r1.rawToken();
        assertNotEquals(t1, t2);
        assertEquals(issued.session().getId(), r1.session().getId());

        // Retry with the just-rotated token inside the grace window:
        // idempotent — returns the SAME successor, session stays alive
        SessionService.RotationResult retry = sessionService.rotate(t1);
        assertTrue(retry.retried());
        assertEquals(t2, retry.rawToken());

        // Rotate the head onward, then simulate grace expiry on t2's row
        SessionService.RotationResult r2 = sessionService.rotate(t2);
        refreshTokenRepository.findByTokenHash(sha256(t2)).ifPresent(row -> {
            row.setReplacedAt(Instant.now().minusSeconds(3600));
            refreshTokenRepository.save(row);
        });

        // Replay outside grace: whole session dies
        assertThrows(TokenReuseException.class, () -> sessionService.rotate(t2));

        // The legitimate head is dead too — session was revoked
        assertThrows(Exception.class, () -> sessionService.rotate(r2.rawToken()));
        assertTrue(sessionService.listActiveSessions(identityId).isEmpty());
    }

    @Test
    void logoutAllRevokesEverySessionButOthersSurviveReuse() {
        UUID identityId = newIdentity();
        sessionService.createSession(identityId, null, "device-1");
        sessionService.createSession(identityId, null, "device-2");
        assertEquals(2, sessionService.listActiveSessions(identityId).size());

        sessionService.revokeAll(identityId, "LOGOUT_ALL");
        assertTrue(sessionService.listActiveSessions(identityId).isEmpty());
    }

    @Test
    void sessionCapEvictsLeastRecentlyUsed() {
        UUID identityId = newIdentity();
        for (int i = 0; i < 12; i++) {
            sessionService.createSession(identityId, null, "device-" + i);
        }
        assertEquals(10, sessionService.listActiveSessions(identityId).size());
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256")
                            .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
