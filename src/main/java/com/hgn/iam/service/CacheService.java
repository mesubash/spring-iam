package com.hgn.iam.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class CacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String PERMISSION_CACHE_PREFIX = "auth:perms:";
    private static final String DENY_CACHE_PREFIX = "auth:deny:";
    private static final String SCOPE_CACHE_PREFIX = "auth:scope:";
    private static final String ROLE_CACHE_PREFIX = "auth:role:";  // ✅ NEW
    private static final String ASSIGNMENT_VERSION_PREFIX = "auth:version:";

    // ========================================================================
    // PERMISSION CACHING
    // ========================================================================

    /**
     * Cache user's permission set
     * ✅ FIXED: Now includes scope in cache key for accuracy
     */
    public void cacheUserPermissions(String cacheKey, Set<String> permissions) {
        String key = PERMISSION_CACHE_PREFIX + cacheKey;
        try {
            redisTemplate.opsForValue().set(key, permissions, Duration.ofMinutes(5));
            log.debug("Cached permissions for key: {}", cacheKey);
        } catch (Exception e) {
            log.error("Failed to cache permissions for key: {}", cacheKey, e);
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getCachedUserPermissions(String cacheKey) {
        String key = PERMISSION_CACHE_PREFIX + cacheKey;
        try {
            return (Set<String>) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("Failed to get cached permissions for key: {}", cacheKey, e);
            return null;
        }
    }

    /**
     * ✅ FIXED: Invalidate ALL permission caches for a user
     * (across all scopes)
     */
    public void invalidateUserPermissions(String subjectId) {
        String pattern = PERMISSION_CACHE_PREFIX + subjectId + "*";
        Set<String> keys = redisTemplate.keys(pattern);
        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
            log.info("Invalidated {} permission cache entries for subject: {}",
                    keys.size(), subjectId);
        }
    }

    // ========================================================================
    // DENY RULE CACHING
    // ========================================================================

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
    // ✅ NEW: ROLE PERMISSION CACHING
    // ========================================================================

    /**
     * Cache role's permission set
     * TTL: 30 minutes (roles change infrequently)
     */
    public void cacheRolePermissions(String cacheKey, Set<String> permissions) {
        String key = ROLE_CACHE_PREFIX + cacheKey;
        try {
            redisTemplate.opsForValue().set(key, permissions, Duration.ofMinutes(30));
            log.debug("Cached role permissions for key: {}", cacheKey);
        } catch (Exception e) {
            log.error("Failed to cache role permissions for key: {}", cacheKey, e);
        }
    }

    @SuppressWarnings("unchecked")
    public Set<String> getCachedRolePermissions(String cacheKey) {
        String key = ROLE_CACHE_PREFIX + cacheKey;
        try {
            return (Set<String>) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("Failed to get cached role permissions for key: {}", cacheKey, e);
            return null;
        }
    }

    public void invalidateRolePermissions(String cacheKey) {
        String key = ROLE_CACHE_PREFIX + cacheKey;
        redisTemplate.delete(key);
        log.info("Invalidated role permissions cache for key: {}", cacheKey);
    }

    // ========================================================================
    // SCOPE CONTAINMENT CACHING
    // ========================================================================

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
    // CACHE VERSIONING
    // ========================================================================

    public void incrementAssignmentVersion(String subjectId) {
        String key = ASSIGNMENT_VERSION_PREFIX + subjectId;
        redisTemplate.opsForValue().increment(key);
    }

    public Long getAssignmentVersion(String subjectId) {
        String key = ASSIGNMENT_VERSION_PREFIX + subjectId;
        Object value = redisTemplate.opsForValue().get(key);
        return value != null ? Long.parseLong(value.toString()) : 0L;
    }

    // ========================================================================
    // ✅ NEW: BULK CACHE OPERATIONS
    // ========================================================================

    /**
     * Warm up cache with frequently accessed data
     */
    public void warmUpCache(String subjectId, Set<String> permissions, Set<String> denyRules) {
        cacheUserPermissions(subjectId, permissions);
        cacheDenyRules(subjectId, denyRules);
        log.info("Warmed up cache for subject: {}", subjectId);
    }

    /**
     * Clear all authorization caches (use with caution!)
     */
    public void clearAllAuthCaches() {
        Set<String> allKeys = redisTemplate.keys("auth:*");
        if (allKeys != null && !allKeys.isEmpty()) {
            redisTemplate.delete(allKeys);
            log.warn("Cleared ALL authorization caches ({} keys)", allKeys.size());
        }
    }

    /**
     * Get cache statistics
     */
    public CacheStats getCacheStats() {
        long permCount = countKeys(PERMISSION_CACHE_PREFIX + "*");
        long denyCount = countKeys(DENY_CACHE_PREFIX + "*");
        long scopeCount = countKeys(SCOPE_CACHE_PREFIX + "*");
        long roleCount = countKeys(ROLE_CACHE_PREFIX + "*");

        return CacheStats.builder()
                .permissionCacheSize(permCount)
                .denyRuleCacheSize(denyCount)
                .scopeCacheSize(scopeCount)
                .roleCacheSize(roleCount)
                .totalCacheSize(permCount + denyCount + scopeCount + roleCount)
                .build();
    }

    private long countKeys(String pattern) {
        Set<String> keys = redisTemplate.keys(pattern);
        return keys != null ? keys.size() : 0;
    }

    @lombok.Data
    @lombok.Builder
    public static class CacheStats {
        private long permissionCacheSize;
        private long denyRuleCacheSize;
        private long scopeCacheSize;
        private long roleCacheSize;
        private long totalCacheSize;
    }
}