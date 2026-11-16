package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.config.JwtConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

/**
 * Per-identity "revoked-before" cutoff in shared Redis: every access token issued to the
 * identity at or before the cutoff is dead. Resource servers verify access tokens by signature
 * alone, so this is how a whole-account revocation reaches them without the IAM's session store.
 *
 * <p>Key {@code auth:revoked-before:{identityId}} = epoch millis. Only the IAM writes this key.
 * It lives as long as an access token (plus skew); older tokens have expired by then anyway.
 */
@Service
@RequiredArgsConstructor
public class RevocationService {

    public static final String KEY_PREFIX = "auth:revoked-before:";
    private static final Duration CLOCK_SKEW = Duration.ofMinutes(5);

    private final StringRedisTemplate redis;
    private final JwtConfig jwtConfig;

    /** Invalidate every access token issued to this identity up to now. */
    public void revokeAllBefore(UUID identityId) {
        redis.opsForValue().set(KEY_PREFIX + identityId, Long.toString(System.currentTimeMillis()),
                Duration.ofMillis(jwtConfig.getExpiration()).plus(CLOCK_SKEW));
    }

    /** True if a token issued at {@code iatMillis} for this identity is at or before the cutoff. */
    public boolean isRevoked(UUID identityId, long iatMillis) {
        String cutoff = redis.opsForValue().get(KEY_PREFIX + identityId);
        return cutoff != null && iatMillis <= Long.parseLong(cutoff);
    }
}
