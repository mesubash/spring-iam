package io.github.mesubash.iam.authn.mfa;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

/**
 * Short-lived opaque tokens for the two-step MFA login:
 *  - challenge: first factor OK, awaiting a TOTP/recovery code (burned on success)
 *  - enrollment: a role requires MFA but none is enrolled; may only call setup/enable
 */
@Service
@RequiredArgsConstructor
public class MfaChallengeService {

    private static final String CHALLENGE = "mfa:challenge:";
    private static final String ATTEMPTS = "mfa:challenge:attempts:";
    private static final String ENROLL = "mfa:enroll:";
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final Duration ENROLL_TTL = Duration.ofMinutes(15);
    private static final SecureRandom RNG = new SecureRandom();

    /** Wrong codes allowed on a single challenge before it is killed. */
    public static final int MAX_ATTEMPTS = 5;

    private final StringRedisTemplate redis;

    /**
     * Identity awaiting a second factor, the first factor it passed (amr value), and the token
     * audience the login asked for (null = default), so the session opens for the right app.
     */
    public record Pending(UUID identityId, String firstFactor, String audience) {}

    public String issueChallenge(UUID identityId, String firstFactor, String audience) {
        String token = token();
        // "<identityId> <firstFactor>[ <audience>]": audience last, so the split keeps it whole.
        redis.opsForValue().set(CHALLENGE + token,
                identityId + " " + firstFactor + (audience == null ? "" : " " + audience), CHALLENGE_TTL);
        return token;
    }

    public String issueEnrollment(UUID identityId) {
        String token = token();
        redis.opsForValue().set(ENROLL + token, identityId.toString(), ENROLL_TTL);
        return token;
    }

    /** Read the challenge without consuming it, so a mistyped code can be retried. */
    public Optional<Pending> peekChallenge(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        String v = redis.opsForValue().get(CHALLENGE + token);
        if (v == null) {
            return Optional.empty();
        }
        String[] parts = v.split(" ", 3);
        return Optional.of(new Pending(UUID.fromString(parts[0]), parts.length > 1 ? parts[1] : "pwd",
                parts.length > 2 ? parts[2] : null));
    }

    /** Burn the challenge. Call only after a successful verification. */
    public void clearChallenge(String token) {
        if (token != null) {
            redis.delete(CHALLENGE + token);
            redis.delete(ATTEMPTS + token);
        }
    }

    /** Count a wrong code against this challenge; returns attempts remaining. */
    public int registerFailure(String token) {
        Long used = redis.opsForValue().increment(ATTEMPTS + token);
        if (used != null && used == 1L) {
            redis.expire(ATTEMPTS + token, CHALLENGE_TTL);
        }
        return Math.max(0, MAX_ATTEMPTS - (used == null ? MAX_ATTEMPTS : used.intValue()));
    }

    /** Peeked, not burned, so setup and then enable can both use it; the TTL bounds the window. */
    public Optional<UUID> peekEnrollment(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        String id = redis.opsForValue().get(ENROLL + token);
        return id == null ? Optional.empty() : Optional.of(UUID.fromString(id));
    }

    public void clearEnrollment(String token) {
        if (token != null) {
            redis.delete(ENROLL + token);
        }
    }

    private static String token() {
        byte[] b = new byte[32];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
}
