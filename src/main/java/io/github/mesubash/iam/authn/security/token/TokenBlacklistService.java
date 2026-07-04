package io.github.mesubash.iam.authn.security.token;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

/**
 * Access-token revocation: by jti (single token) or sid (every token of a
 * session). Entries live only for the access TTL — after that the token is
 * expired anyway. Redis down = fail closed (treat as blacklisted).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String JTI_PREFIX = "authn:bl:jti:";
    private static final String SID_PREFIX = "authn:bl:sid:";

    private final StringRedisTemplate redisTemplate;

    public void blacklistJti(String jti, long ttlMs) {
        if (jti != null && ttlMs > 0) {
            redisTemplate.opsForValue().set(JTI_PREFIX + jti, "1", Duration.ofMillis(ttlMs));
        }
    }

    public void blacklistSid(UUID sid, long ttlMs) {
        if (sid != null && ttlMs > 0) {
            redisTemplate.opsForValue().set(SID_PREFIX + sid, "1", Duration.ofMillis(ttlMs));
        }
    }

    public boolean isBlacklisted(String jti, UUID sid) {
        try {
            if (jti != null && Boolean.TRUE.equals(redisTemplate.hasKey(JTI_PREFIX + jti))) {
                return true;
            }
            return sid != null && Boolean.TRUE.equals(redisTemplate.hasKey(SID_PREFIX + sid));
        } catch (Exception e) {
            log.error("Blacklist check failed — failing closed", e);
            return true;
        }
    }
}
