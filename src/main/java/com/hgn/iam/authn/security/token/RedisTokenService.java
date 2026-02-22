package com.hgn.iam.authn.security.token;

import com.hgn.iam.authn.config.JwtConfig;
import com.hgn.iam.authn.entity.enums.TokenType;
import com.hgn.iam.shared.exception.TokenReuseException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@Primary
@RequiredArgsConstructor
public class RedisTokenService implements TokenService {

    private static final String REFRESH_KEY_PREFIX = "refresh:token:";
    private static final String PASSWORD_KEY_PREFIX = "reset:token:";
    private static final String EMAIL_VERIFICATION_KEY_PREFIX = "email:token:";
    private static final String ACCOUNT_REACTIVATION_KEY_PREFIX = "reactivation:token:";
    private static final String BLACKLIST_KEY_PREFIX = "blacklist:token:";

    private static final long PASSWORD_RESET_TTL_MS = TimeUnit.MINUTES.toMillis(15);
    private static final long EMAIL_VERIFICATION_TTL_MS = TimeUnit.HOURS.toMillis(24);
    private static final long ACCOUNT_REACTIVATION_TTL_MS = TimeUnit.DAYS.toMillis(7);

    private final StringRedisTemplate redisTemplate;
    private final JwtConfig jwtConfig;
    private final Map<String, TokenEntry> inMemoryStore = new ConcurrentHashMap<>();

    private String keyFor(String userId, TokenType type) {
        return switch (type) {
            case PASSWORD_RESET -> PASSWORD_KEY_PREFIX + userId;
            case REFRESH -> REFRESH_KEY_PREFIX + userId;
            case EMAIL_VERIFICATION -> EMAIL_VERIFICATION_KEY_PREFIX + userId;
            case ACCOUNT_REACTIVATION -> ACCOUNT_REACTIVATION_KEY_PREFIX + "reactivation:" + userId;
        };
    }

    @Override
    public void store(String userId, String token, TokenType tokenType) {
        if (userId == null || token == null) return;

        String key = keyFor(userId, tokenType);
        String tokenKey = tokenType + token;
        long ttlMs = getTtlFor(tokenType);

        try {
            redisTemplate.opsForValue().set(key, token, ttlMs, TimeUnit.MILLISECONDS);
            redisTemplate.opsForValue().set(tokenKey, userId, ttlMs, TimeUnit.MILLISECONDS);
            log.info("Stored {} token for user {}", tokenType, userId);
        } catch (RedisConnectionFailureException ex) {
            log.error("Redis connection failed during store", ex);
            storeInMemory(key, token, ttlMs);
            storeInMemory(tokenKey, userId, ttlMs);
        }
    }

    @Override
    public void rotate(String userId, String oldToken, String newToken, TokenType tokenType) throws TokenReuseException {
        if (userId == null) throw new TokenReuseException("Missing userId for rotation");

        String key = keyFor(userId, tokenType);
        String oldTokenKey = tokenType + oldToken;
        String newTokenKey = tokenType + newToken;

        try {
            String storedToken = redisTemplate.opsForValue().get(key);

            if (storedToken == null) {
                throw new TokenReuseException("No refresh token found for user: " + userId);
            }

            if (!storedToken.equals(oldToken)) {
                redisTemplate.delete(key);
                redisTemplate.delete(tokenType + storedToken);
                redisTemplate.delete(oldTokenKey);
                throw new TokenReuseException("Refresh token reuse detected for user: " + userId);
            }

            long ttlMs = jwtConfig.getRefreshExpiration();
            redisTemplate.opsForValue().set(key, newToken, ttlMs, TimeUnit.MILLISECONDS);
            redisTemplate.opsForValue().set(newTokenKey, userId, ttlMs, TimeUnit.MILLISECONDS);
            redisTemplate.delete(oldTokenKey);

            log.info("Successfully rotated {} token for user {}", tokenType, userId);
        } catch (TokenReuseException ex) {
            throw ex;
        } catch (RedisConnectionFailureException ex) {
            log.error("Redis connection failed during rotation", ex);
            rotateInMemory(userId, oldToken, newToken, tokenType);
        }
    }

    @Override
    public boolean validate(String userId, String token, TokenType tokenType) {
        if (userId == null || token == null) return false;

        String tokenKey = tokenType + token;

        try {
            String storedUserId = redisTemplate.opsForValue().get(tokenKey);
            boolean isValid = userId.equals(storedUserId);

            if (!isValid && storedUserId == null) {
                String key = keyFor(userId, tokenType);
                String forwardToken = redisTemplate.opsForValue().get(key);
                if (forwardToken != null && forwardToken.equals(token)) {
                    long ttlMs = getTtlFor(tokenType);
                    redisTemplate.opsForValue().set(tokenKey, userId, ttlMs, TimeUnit.MILLISECONDS);
                    return true;
                }
            }

            return isValid;
        } catch (RedisConnectionFailureException ex) {
            String storedUserId = getInMemory(tokenKey);
            return userId.equals(storedUserId);
        }
    }

    @Override
    public void revokeAll(String userId, TokenType tokenType) {
        String key = keyFor(userId, tokenType);

        try {
            String token = redisTemplate.opsForValue().get(key);
            if (token != null) {
                redisTemplate.delete(key);
                redisTemplate.delete(tokenType + token);
            } else {
                redisTemplate.delete(key);
            }
            log.info("Revoked all {} tokens for user {}", tokenType, userId);
        } catch (RedisConnectionFailureException ex) {
            String token = getInMemory(key);
            deleteInMemory(key);
            if (token != null) deleteInMemory(tokenType + token);
        }
    }

    @Override
    public void revoke(String userId, String token, TokenType tokenType) {
        try {
            redisTemplate.delete(keyFor(userId, tokenType));
            redisTemplate.delete(tokenType + token);
        } catch (RedisConnectionFailureException ex) {
            deleteInMemory(keyFor(userId, tokenType));
            deleteInMemory(tokenType + token);
        }
    }

    @Override
    public String getTokenUserId(String token, TokenType tokenType) {
        if (token == null || tokenType == null) return null;
        String key = tokenType + token;
        try {
            return redisTemplate.opsForValue().get(key);
        } catch (RedisConnectionFailureException ex) {
            return getInMemory(key);
        }
    }

    @Override
    public void blacklistToken(String token, long durationMs) {
        if (token == null) return;
        String key = BLACKLIST_KEY_PREFIX + token;
        try {
            redisTemplate.opsForValue().set(key, "BLACKLISTED", durationMs, TimeUnit.MILLISECONDS);
        } catch (RedisConnectionFailureException ex) {
            storeInMemory(key, "BLACKLISTED", durationMs);
        }
    }

    @Override
    public boolean isTokenBlacklisted(String token) {
        if (token == null) return false;
        String key = BLACKLIST_KEY_PREFIX + token;
        try {
            return redisTemplate.hasKey(key);
        } catch (RedisConnectionFailureException ex) {
            return getInMemory(key) != null;
        }
    }

    private long getTtlFor(TokenType tokenType) {
        return switch (tokenType) {
            case REFRESH -> jwtConfig.getRefreshExpiration();
            case PASSWORD_RESET -> PASSWORD_RESET_TTL_MS;
            case EMAIL_VERIFICATION -> EMAIL_VERIFICATION_TTL_MS;
            case ACCOUNT_REACTIVATION -> ACCOUNT_REACTIVATION_TTL_MS;
        };
    }

    private void storeInMemory(String key, String value, long ttlMs) {
        long expiresAt = ttlMs > 0 ? System.currentTimeMillis() + ttlMs : 0;
        inMemoryStore.put(key, new TokenEntry(value, expiresAt));
    }

    private String getInMemory(String key) {
        TokenEntry entry = inMemoryStore.get(key);
        if (entry == null) return null;
        if (entry.expiresAt > 0 && System.currentTimeMillis() > entry.expiresAt) {
            inMemoryStore.remove(key);
            return null;
        }
        return entry.value;
    }

    private void deleteInMemory(String key) {
        inMemoryStore.remove(key);
    }

    private void rotateInMemory(String userId, String oldToken, String newToken, TokenType tokenType) {
        String key = keyFor(userId, tokenType);
        String storedToken = getInMemory(key);

        if (storedToken == null || !storedToken.equals(oldToken)) {
            deleteInMemory(key);
            if (storedToken != null) deleteInMemory(tokenType + storedToken);
            throw new TokenReuseException("Refresh token reuse detected for user: " + userId);
        }

        long ttlMs = jwtConfig.getRefreshExpiration();
        storeInMemory(key, newToken, ttlMs);
        storeInMemory(tokenType + newToken, userId, ttlMs);
        deleteInMemory(tokenType + oldToken);
    }

    private record TokenEntry(String value, long expiresAt) {}
}
