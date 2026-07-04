package io.github.mesubash.iam.authz.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

/**
 * Redis caching with versioned key prefixes: invalidation is one INCR on a
 * version counter — old keys become unreachable and die by TTL. No KEYS/SCAN
 * anywhere; every operation is O(1).
 */
@Slf4j
@Service
public class CacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private final Duration permissionsTtl;
    private final Duration denyRulesTtl;
    private final Duration scopeTtl;
    private final Duration roleTtl;
    private final Duration policyTtl;

    // Version counters. epoch covers everything; sub is per subject.
    private static final String VER_EPOCH = "auth:ver:epoch";
    private static final String VER_SUBJECT_PREFIX = "auth:ver:sub:";
    private static final String VER_ROLE = "auth:ver:role";
    private static final String VER_SCOPE = "auth:ver:scope";
    private static final String VER_POLICY = "auth:ver:policy";

    public CacheService(
            RedisTemplate<String, Object> redisTemplate,
            @Value("${iam.authorization.cache.permissions-ttl:300}") int permissionsTtlSec,
            @Value("${iam.authorization.cache.deny-rules-ttl:60}") int denyRulesTtlSec,
            @Value("${iam.authorization.cache.scope-ttl:3600}") int scopeTtlSec,
            @Value("${iam.authorization.cache.role-ttl:1800}") int roleTtlSec,
            @Value("${iam.authorization.cache.policy-ttl:120}") int policyTtlSec) {
        this.redisTemplate = redisTemplate;
        this.permissionsTtl = Duration.ofSeconds(permissionsTtlSec);
        this.denyRulesTtl = Duration.ofSeconds(denyRulesTtlSec);
        this.scopeTtl = Duration.ofSeconds(scopeTtlSec);
        this.roleTtl = Duration.ofSeconds(roleTtlSec);
        this.policyTtl = Duration.ofSeconds(policyTtlSec);
    }

    // ========================================================================
    // PERMISSION SETS (per subject + scope)
    // ========================================================================

    public void cacheUserPermissions(String subjectId, UUID scopeId, Set<String> permissions) {
        set(permissionsKey(subjectId, scopeId), permissions, permissionsTtl);
    }

    @SuppressWarnings("unchecked")
    public Set<String> getCachedUserPermissions(String subjectId, UUID scopeId) {
        return (Set<String>) get(permissionsKey(subjectId, scopeId));
    }

    /** One INCR invalidates the subject's permission sets AND deny rules. */
    public void invalidateUserPermissions(String subjectId) {
        increment(VER_SUBJECT_PREFIX + subjectId);
        log.info("Invalidated caches for subject: {}", subjectId);
    }

    // ========================================================================
    // DENY RULES (per subject)
    // ========================================================================

    public void cacheDenyRules(String subjectId, Set<CachedDenyRule> rules) {
        set(denyKey(subjectId), rules, denyRulesTtl);
    }

    @SuppressWarnings("unchecked")
    public Set<CachedDenyRule> getCachedDenyRules(String subjectId) {
        return (Set<CachedDenyRule>) get(denyKey(subjectId));
    }

    public void invalidateDenyRules(String subjectId) {
        increment(VER_SUBJECT_PREFIX + subjectId);
    }

    // ========================================================================
    // ROLE PERMISSION SETS
    // ========================================================================

    public void cacheRolePermissions(String cacheKey, Set<String> permissions) {
        set("auth:role:" + version(VER_ROLE) + ":" + cacheKey, permissions, roleTtl);
    }

    @SuppressWarnings("unchecked")
    public Set<String> getCachedRolePermissions(String cacheKey) {
        return (Set<String>) get("auth:role:" + version(VER_ROLE) + ":" + cacheKey);
    }

    public void invalidateRolePermissions(String cacheKey) {
        // Coarse by design: any role change bumps the family version
        increment(VER_ROLE);
        log.info("Invalidated role permission caches (trigger: {})", cacheKey);
    }

    public void invalidateAllRolePermissions() {
        increment(VER_ROLE);
    }

    // ========================================================================
    // SCOPE CONTAINMENT + ACTIVE FLAGS
    // ========================================================================

    public void cacheScopeContainment(UUID ancestorId, UUID descendantId, boolean contains) {
        set(scopeKey(ancestorId + ":" + descendantId), contains, scopeTtl);
    }

    public Boolean getCachedScopeContainment(UUID ancestorId, UUID descendantId) {
        return (Boolean) get(scopeKey(ancestorId + ":" + descendantId));
    }

    public void cacheScopeActive(UUID scopeId, boolean active) {
        set(scopeKey("active:" + scopeId), active, scopeTtl);
    }

    public Boolean getCachedScopeActive(UUID scopeId) {
        return (Boolean) get(scopeKey("active:" + scopeId));
    }

    public void invalidateScopeCache() {
        increment(VER_SCOPE);
        log.info("Invalidated scope caches");
    }

    // ========================================================================
    // POLICY CANDIDATES
    // ========================================================================

    public void cachePolicies(String cacheKey, java.util.List<PolicySnapshot> policies) {
        set("auth:policy:" + version(VER_POLICY) + ":" + cacheKey, policies, policyTtl);
    }

    @SuppressWarnings("unchecked")
    public java.util.List<PolicySnapshot> getCachedPolicies(String cacheKey) {
        return (java.util.List<PolicySnapshot>) get("auth:policy:" + version(VER_POLICY) + ":" + cacheKey);
    }

    public void invalidatePolicyCache() {
        increment(VER_POLICY);
        log.info("Invalidated policy caches");
    }

    // ========================================================================
    // GLOBAL
    // ========================================================================

    public void incrementAssignmentVersion(String subjectId) {
        increment(VER_SUBJECT_PREFIX + subjectId);
    }

    /** Bumps the global epoch — every cached entry becomes unreachable. */
    public void clearAllAuthCaches() {
        increment(VER_EPOCH);
        log.warn("Cleared ALL authorization caches (epoch bump)");
    }

    /** Combined monotonic token across the global version counters. */
    public long currentVersionToken() {
        return version(VER_EPOCH) + version(VER_ROLE) + version(VER_SCOPE) + version(VER_POLICY);
    }

    public CacheStats getCacheStats() {
        return CacheStats.builder()
                .epoch(version(VER_EPOCH))
                .roleVersion(version(VER_ROLE))
                .scopeVersion(version(VER_SCOPE))
                .policyVersion(version(VER_POLICY))
                .build();
    }

    // ========================================================================
    // internals
    // ========================================================================

    private String permissionsKey(String subjectId, UUID scopeId) {
        return "auth:perms:" + subjectVersion(subjectId) + ":" + subjectId + ":" + scopeId;
    }

    private String denyKey(String subjectId) {
        return "auth:deny:" + subjectVersion(subjectId) + ":" + subjectId;
    }

    private String scopeKey(String suffix) {
        return "auth:scope:" + version(VER_SCOPE) + ":" + suffix;
    }

    private String subjectVersion(String subjectId) {
        return version(VER_EPOCH) + "." + version(VER_SUBJECT_PREFIX + subjectId);
    }

    private long version(String counterKey) {
        try {
            Object value = redisTemplate.opsForValue().get(counterKey);
            return value != null ? Long.parseLong(value.toString()) : 0L;
        } catch (Exception e) {
            log.error("Failed to read cache version {}", counterKey, e);
            return -1L; // unreachable key namespace ⇒ behaves as cache miss
        }
    }

    private void increment(String counterKey) {
        try {
            redisTemplate.opsForValue().increment(counterKey);
        } catch (Exception e) {
            log.error("Failed to bump cache version {}", counterKey, e);
        }
    }

    private void set(String key, Object value, Duration ttl) {
        try {
            redisTemplate.opsForValue().set(key, value, ttl);
        } catch (Exception e) {
            log.error("Failed to cache {}", key, e);
        }
    }

    private Object get(String key) {
        try {
            return redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("Failed to read cache {}", key, e);
            return null;
        }
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class CachedDenyRule {
        private String permissionKey;
        private UUID scopeId;
    }

    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class PolicySnapshot {
        private UUID id;
        private String name;
        private String description;
        private String permissionKey;
        private String resourceType;
        private UUID scopeId;
        private String effect;
        private Integer priority;
        private java.util.Map<String, Object> conditions;
        private String enforcementMode;
        private Boolean active;

        public static PolicySnapshot fromPolicy(io.github.mesubash.iam.authz.entity.Policy policy) {
            return PolicySnapshot.builder()
                    .id(policy.getId())
                    .name(policy.getName())
                    .description(policy.getDescription())
                    .permissionKey(policy.getPermissionKey())
                    .resourceType(policy.getResourceType())
                    .scopeId(policy.getScopeId())
                    .effect(policy.getEffect())
                    .priority(policy.getPriority())
                    .conditions(policy.getConditions())
                    .enforcementMode(policy.getEnforcementMode())
                    .active(policy.getActive())
                    .build();
        }

        public io.github.mesubash.iam.authz.entity.Policy toPolicy() {
            return io.github.mesubash.iam.authz.entity.Policy.builder()
                    .id(id)
                    .name(name)
                    .description(description)
                    .permissionKey(permissionKey)
                    .resourceType(resourceType)
                    .scopeId(scopeId)
                    .effect(effect)
                    .priority(priority)
                    .conditions(conditions)
                    .enforcementMode(enforcementMode != null ? enforcementMode : "ENFORCE")
                    .active(active != null ? active : true)
                    .build();
        }
    }

    @lombok.Data
    @lombok.Builder
    public static class CacheStats {
        private long epoch;
        private long roleVersion;
        private long scopeVersion;
        private long policyVersion;
    }
}
