package com.hgn.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class CacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String PERMISSION_CACHE_PREFIX = "auth:perms:";
    private static final String DENY_CACHE_PREFIX = "auth:deny:";
    private static final String SCOPE_CACHE_PREFIX = "auth:scope:";
    private static final String ASSIGNMENT_VERSION_PREFIX = "auth:version:";

    // ========================================================================
    // PERMISSION CACHING
    // ========================================================================

    /**
     * Cache user's permission set
     * Key: auth:perms:{subjectId}
     * Value: Set<String> permission keys
     * TTL: 5 minutes
     */
    public void cacheUserPermissions(String subjectId, Set<String> permissions) {
        String key = PERMISSION_CACHE_PREFIX + subjectId;
        try {
            redisTemplate.opsForValue().set(key, permissions, Duration.ofMinutes(5));
            log.debug("Cached permissions for subject: {}", subjectId);
        } catch (Exception e) {
            log.error("Failed to cache permissions for subject: {}", subjectId, e);
        }
    }

    /**
     * Get cached permissions
     */
    @SuppressWarnings("unchecked")
    public Set<String> getCachedUserPermissions(String subjectId) {
        String key = PERMISSION_CACHE_PREFIX + subjectId;
        try {
            return (Set<String>) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("Failed to get cached permissions for subject: {}", subjectId, e);
            return null;
        }
    }

    /**
     * Invalidate user's permission cache
     */
    public void invalidateUserPermissions(String subjectId) {
        String key = PERMISSION_CACHE_PREFIX + subjectId;
        redisTemplate.delete(key);
        log.info("Invalidated permission cache for subject: {}", subjectId);
    }

    // ========================================================================
    // DENY RULE CACHING
    // ========================================================================

    /**
     * Cache user's deny rules
     * TTL: 1 minute (shorter because deny rules are security-critical)
     */
    public void cacheDenyRules(String subjectId, Set<String> deniedPermissions) {
        String key = DENY_CACHE_PREFIX + subjectId;
        try {
            redisTemplate.opsForValue().set(key, deniedPermissions, Duration.ofMinutes(1));
            log.debug("Cached deny rules for subject: {}", subjectId);
        } catch (Exception e) {
            log.error("Failed to cache deny rules for subject: {}", subjectId, e);
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getCachedDenyRules(String subjectId) {
        String key = DENY_CACHE_PREFIX + subjectId;
        try {
            return (Set<String>) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("Failed to get cached deny rules for subject: {}", subjectId, e);
            return null;
        }
    }

    public void invalidateDenyRules(String subjectId) {
        String key = DENY_CACHE_PREFIX + subjectId;
        redisTemplate.delete(key);
        log.info("Invalidated deny rules cache for subject: {}", subjectId);
    }

    // ========================================================================
    // SCOPE CONTAINMENT CACHING
    // ========================================================================

    /**
     * Cache scope containment result
     * Key: auth:scope:{ancestorId}:{descendantId}
     * Value: Boolean
     * TTL: 1 hour (scopes change rarely)
     */
    public void cacheScopeContainment(UUID ancestorId, UUID descendantId, boolean contains) {
        String key = SCOPE_CACHE_PREFIX + ancestorId + ":" + descendantId;
        try {
            redisTemplate.opsForValue().set(key, contains, Duration.ofHours(1));
        } catch (Exception e) {
            log.error("Failed to cache scope containment", e);
        }
    }

    public Boolean getCachedScopeContainment(UUID ancestorId, UUID descendantId) {
        String key = SCOPE_CACHE_PREFIX + ancestorId + ":" + descendantId;
        try {
            return (Boolean) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("Failed to get cached scope containment", e);
            return null;
        }
    }

    public void invalidateScopeCache() {
        Set<String> keys = redisTemplate.keys(SCOPE_CACHE_PREFIX + "*");
        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
            log.info("Invalidated all scope cache entries");
        }
    }

    // ========================================================================
    // CACHE VERSIONING (for invalidation)
    // ========================================================================

    /**
     * Track assignment version for cache invalidation
     */
    public void incrementAssignmentVersion(String subjectId) {
        String key = ASSIGNMENT_VERSION_PREFIX + subjectId;
        redisTemplate.opsForValue().increment(key);
    }

    public Long getAssignmentVersion(String subjectId) {
        String key = ASSIGNMENT_VERSION_PREFIX + subjectId;
        Object value = redisTemplate.opsForValue().get(key);
        return value != null ? Long.parseLong(value.toString()) : 0L;
    }
}
