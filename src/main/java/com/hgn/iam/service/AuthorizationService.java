package com.hgn.iam.service;

import com.hgn.iam.entity.*;
import com.hgn.iam.repository.*;
import com.hgn.iam.dto.AuthorizationRequest;
import com.hgn.iam.dto.AuthorizationResponse;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final AssignmentRepository assignmentRepository;
    private final DenyRuleRepository denyRuleRepository;
    private final ScopeClosureRepository scopeClosureRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final AuthorizationAuditRepository auditRepository;
    private final CacheService cacheService;
    private final MeterRegistry meterRegistry;

    // Metrics
    private final Counter allowCounter;
    private final Counter denyCounter;
    private final Counter cacheHitCounter;
    private final Counter cacheMissCounter;
    private final Timer authorizationTimer;

    public AuthorizationService(
            AssignmentRepository assignmentRepository,
            DenyRuleRepository denyRuleRepository,
            ScopeClosureRepository scopeClosureRepository,
            PermissionRepository permissionRepository,
            RolePermissionRepository rolePermissionRepository, // ✅ ADD THIS
            AuthorizationAuditRepository auditRepository,
            CacheService cacheService,
            MeterRegistry meterRegistry) {

        this.assignmentRepository = assignmentRepository;
        this.denyRuleRepository = denyRuleRepository;
        this.scopeClosureRepository = scopeClosureRepository;
        this.permissionRepository = permissionRepository;
        this.rolePermissionRepository = rolePermissionRepository; // ✅ ADD THIS
        this.auditRepository = auditRepository;
        this.cacheService = cacheService;
        this.meterRegistry = meterRegistry;

        // Initialize metrics
        this.allowCounter = Counter.builder("authorization.decision.allow")
                .description("Number of ALLOW decisions")
                .register(meterRegistry);
        this.denyCounter = Counter.builder("authorization.decision.deny")
                .description("Number of DENY decisions")
                .register(meterRegistry);
        this.cacheHitCounter = Counter.builder("authorization.cache.hit")
                .description("Cache hits")
                .register(meterRegistry);
        this.cacheMissCounter = Counter.builder("authorization.cache.miss")
                .description("Cache misses")
                .register(meterRegistry);
        this.authorizationTimer = Timer.builder("authorization.check.duration")
                .description("Authorization check duration")
                .register(meterRegistry);
    }

    /**
     * MAIN AUTHORIZATION METHOD with MULTI-LAYER CACHING
     */
    public AuthorizationResponse authorize(AuthorizationRequest request) {
        return authorizationTimer.record(() -> doAuthorize(request));
    }

    private AuthorizationResponse doAuthorize(AuthorizationRequest request) {
        Instant startTime = Instant.now();

        try {
            String subject = request.getSubject();
            String permissionKey = request.getPermission();
            UUID resourceScopeId = request.getResource().getScopeId();

            log.debug("Authorization check: subject={}, permission={}, scope={}",
                    subject, permissionKey, resourceScopeId);

            // ================================================================
            // STEP 1: CHECK DENY RULES (Highest Priority)
            // ================================================================

            Set<String> cachedDenyRules = cacheService.getCachedDenyRules(subject);
            Set<String> deniedPermissions;

            if (cachedDenyRules != null) {
                cacheHitCounter.increment();
                deniedPermissions = cachedDenyRules;
                log.debug("Deny rules cache HIT for subject: {}", subject);
            } else {
                cacheMissCounter.increment();
                deniedPermissions = fetchDenyRules(subject);
                cacheService.cacheDenyRules(subject, deniedPermissions);
                log.debug("Deny rules cache MISS for subject: {}", subject);
            }

            if (deniedPermissions.contains(permissionKey) ||
                    deniedPermissions.contains("*.*.*")) {

                String reason = "DENY: Explicit deny rule exists";
                logAuditAsync(request, false, reason);
                denyCounter.increment();

                return buildResponse(false, reason, startTime);
            }

            // ================================================================
            // STEP 2: CHECK PERMISSIONS
            // ================================================================

            // Build cache key with scope for more accurate caching
            String cacheKey = subject + ":" + resourceScopeId;
            Set<String> cachedPermissions = cacheService.getCachedUserPermissions(cacheKey);
            Set<String> userPermissions;

            if (cachedPermissions != null) {
                cacheHitCounter.increment();
                userPermissions = cachedPermissions;
                log.debug("Permission cache HIT for subject: {}", subject);
            } else {
                cacheMissCounter.increment();
                userPermissions = fetchUserPermissions(subject, resourceScopeId);
                cacheService.cacheUserPermissions(cacheKey, userPermissions);
                log.debug("Permission cache MISS for subject: {}", subject);
            }

            if (!userPermissions.contains(permissionKey)) {
                String reason = "DENY: Permission not granted by any role";
                logAuditAsync(request, false, reason);
                denyCounter.increment();

                return buildResponse(false, reason, startTime);
            }

            // ================================================================
            // ALL CHECKS PASSED - ALLOW
            // ================================================================

            String reason = "ALLOW: Permission granted via role assignment";
            logAuditAsync(request, true, reason);
            allowCounter.increment();

            return buildResponse(true, reason, startTime, userPermissions);

        } catch (Exception e) {
            log.error("Authorization check failed", e);
            String reason = "DENY: Authorization service error - " + e.getMessage();
            logAuditAsync(request, false, reason);
            denyCounter.increment();

            return buildResponse(false, reason, startTime);
        }
    }

    /**
     * Fetch deny rules from database
     */
    private Set<String> fetchDenyRules(String subjectId) {
        List<DenyRule> rules = denyRuleRepository.findAllActiveDenyRulesForSubject(
                subjectId, Instant.now());

        return rules.stream()
                .map(DenyRule::getPermissionKey)
                .collect(Collectors.toSet());
    }

    /**
     * ✅ FIXED: Fetch and compute user's permissions
     */
    private Set<String> fetchUserPermissions(String subjectId, UUID resourceScopeId) {

        List<Assignment> assignments = assignmentRepository.findActiveAssignments(
                subjectId, Instant.now());

        if (assignments.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> permissions = new HashSet<>();

        for (Assignment assignment : assignments) {
            // Check if assignment scope contains resource scope
            Boolean scopeContains = cacheService.getCachedScopeContainment(
                    assignment.getScopeId(), resourceScopeId);

            if (scopeContains == null) {
                scopeContains = scopeClosureRepository.scopeContains(
                        assignment.getScopeId(), resourceScopeId);
                cacheService.cacheScopeContainment(
                        assignment.getScopeId(), resourceScopeId, scopeContains);
            }

            if (scopeContains) {
                // ✅ FIXED: Get actual role permissions
                Set<String> rolePermissions = getRolePermissions(assignment.getRoleId());
                permissions.addAll(rolePermissions);
            }
        }

        return permissions;
    }

    /**
     * ✅ FIXED: Get permissions for a role
     * Uses role-level caching for performance
     */
    private Set<String> getRolePermissions(UUID roleId) {
        // Try cache first
        String cacheKey = "role:" + roleId;
        Set<String> cached = cacheService.getCachedRolePermissions(cacheKey);

        if (cached != null) {
            cacheHitCounter.increment();
            return cached;
        }

        // Cache miss - fetch from database
        cacheMissCounter.increment();
        Set<String> permissions = rolePermissionRepository
                .findPermissionKeysByRoleId(roleId);

        // Cache the result (roles change infrequently, so longer TTL is OK)
        cacheService.cacheRolePermissions(cacheKey, permissions);

        return permissions;
    }

    /**
     * Log audit entry asynchronously
     */
    @Async("auditExecutor")
    @Transactional
    protected void logAuditAsync(AuthorizationRequest request,
                                 boolean decision,
                                 String reason) {

        try {
            AuthorizationAudit audit = AuthorizationAudit.builder()
                    .subjectId(request.getSubject())
                    .permissionKey(request.getPermission())
                    .resourceType(request.getResource().getType())
                    .resourceId(request.getResource().getId())
                    .scopeId(request.getResource().getScopeId())
                    .decision(decision)
                    .reason(reason)
                    .context(request.getContext() != null ?
                            request.getContext().getAdditionalContext() : null)
                    .requestId(request.getContext() != null ?
                            request.getContext().getRequestId() : null)
                    .ipAddress(request.getContext() != null ?
                            request.getContext().getIpAddress() : null)
                    .userAgent(request.getContext() != null ?
                            request.getContext().getUserAgent() : null)
                    .build();

            auditRepository.save(audit);
        } catch (Exception e) {
            log.error("Failed to save audit log", e);
        }
    }

    private AuthorizationResponse buildResponse(boolean authorized,
                                                String reason,
                                                Instant startTime) {
        return buildResponse(authorized, reason, startTime, Collections.emptySet());
    }

    private AuthorizationResponse buildResponse(boolean authorized,
                                                String reason,
                                                Instant startTime,
                                                Set<String> permissions) {
        long latencyMs = Duration.between(startTime, Instant.now()).toMillis();

        return AuthorizationResponse.builder()
                .authorized(authorized)
                .reason(reason)
                .effectivePermissions(new ArrayList<>(permissions))
                .timestamp(Instant.now())
                .latencyMs(latencyMs)
                .build();
    }

    /**
     * Invalidate cache when assignments change
     */
    public void invalidateUserCache(String subjectId) {
        // Invalidate all permission caches for this user
        // (across all scopes)
        cacheService.invalidateUserPermissions(subjectId);
        cacheService.invalidateDenyRules(subjectId);
        cacheService.incrementAssignmentVersion(subjectId);
        log.info("Invalidated all caches for subject: {}", subjectId);
    }

    /**
     * ✅ NEW: Invalidate role cache when role permissions change
     */
    public void invalidateRoleCache(UUID roleId) {
        String cacheKey = "role:" + roleId;
        cacheService.invalidateRolePermissions(cacheKey);
        log.info("Invalidated role cache for roleId: {}", roleId);
    }
}