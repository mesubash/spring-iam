package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.entity.enums.TokenType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

/**
 * Redis-backed one-time tokens, stored hashed — a Redis dump yields nothing
 * replayable. No in-memory fallback: if Redis is down these flows fail
 * loudly instead of silently degrading to per-instance state.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class RedisTokenService implements TokenService {

    private static final long PASSWORD_RESET_TTL_MS = TimeUnit.MINUTES.toMillis(15);
    private static final long EMAIL_VERIFICATION_TTL_MS = TimeUnit.HOURS.toMillis(24);
    private static final long ACCOUNT_REACTIVATION_TTL_MS = TimeUnit.DAYS.toMillis(7);

    private final StringRedisTemplate redisTemplate;

    @Override
    public void store(String userId, String token, TokenType tokenType) {
        if (userId == null || token == null) {
            return;
        }
        redisTemplate.opsForValue().set(key(tokenType, token), userId,
                ttlFor(tokenType), TimeUnit.MILLISECONDS);
        log.info("Stored {} token for user {}", tokenType, userId);
    }

    @Override
    public String getTokenUserId(String token, TokenType tokenType) {
        if (token == null) {
            return null;
        }
        return redisTemplate.opsForValue().get(key(tokenType, token));
    }

    @Override
    public void revoke(String userId, String token, TokenType tokenType) {
        if (token != null) {
            redisTemplate.delete(key(tokenType, token));
        }
    }

    private String key(TokenType type, String token) {
        return "authn:ott:" + type.name().toLowerCase() + ":" + sha256(token);
    }

    private long ttlFor(TokenType type) {
        return switch (type) {
            case PASSWORD_RESET -> PASSWORD_RESET_TTL_MS;
            case EMAIL_VERIFICATION, EMAIL_CHANGE -> EMAIL_VERIFICATION_TTL_MS;
            case ACCOUNT_REACTIVATION -> ACCOUNT_REACTIVATION_TTL_MS;
            case REFRESH -> throw new IllegalArgumentException(
                    "Refresh tokens are managed by SessionService");
        };
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
