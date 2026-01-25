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
            AuthorizationAuditRepository auditRepository,
            CacheService cacheService,
            MeterRegistry meterRegistry) {

        this.assignmentRepository = assignmentRepository;
        this.denyRuleRepository = denyRuleRepository;
        this.scopeClosureRepository = scopeClosureRepository;
        this.permissionRepository = permissionRepository;
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
     *
     * This is the method that gets called for EVERY request!
     * Performance is CRITICAL here!
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
            // Use cache first!
            // ================================================================

            Set<String> cachedDenyRules = cacheService.getCachedDenyRules(subject);
            Set<String> deniedPermissions;

            if (cachedDenyRules != null) {
                // CACHE HIT! ⚡
                cacheHitCounter.increment();
                deniedPermissions = cachedDenyRules;
                log.debug("Deny rules cache HIT for subject: {}", subject);
            } else {
                // Cache miss - query database
                cacheMissCounter.increment();
                deniedPermissions = fetchDenyRules(subject);
                cacheService.cacheDenyRules(subject, deniedPermissions);
                log.debug("Deny rules cache MISS for subject: {}", subject);
            }

            // Check if permission is denied
            if (deniedPermissions.contains(permissionKey) ||
                    deniedPermissions.contains("*.*.*")) {

                String reason = "DENY: Explicit deny rule exists";
                logAuditAsync(request, false, reason);
                denyCounter.increment();

                return buildResponse(false, reason, startTime);
            }

            // ================================================================
            // STEP 2-5: CHECK PERMISSIONS
            // Use cache first!
            // ================================================================

            Set<String> cachedPermissions = cacheService.getCachedUserPermissions(subject);
            Set<String> userPermissions;

            if (cachedPermissions != null) {
                // CACHE HIT! ⚡
                cacheHitCounter.increment();
                userPermissions = cachedPermissions;
                log.debug("Permission cache HIT for subject: {}", subject);
            } else {
                // Cache miss - query database and build permission set
                cacheMissCounter.increment();
                userPermissions = fetchUserPermissions(subject, resourceScopeId);
                cacheService.cacheUserPermissions(subject, userPermissions);
                log.debug("Permission cache MISS for subject: {}", subject);
            }

            // Check if user has the required permission
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
            String reason = "DENY: Authorization service error";
            logAuditAsync(request, false, reason);
            denyCounter.increment();

            return buildResponse(false, reason, startTime);
        }
    }

    /**
     * Fetch deny rules from database
     */
    private Set<String> fetchDenyRules(String subjectId) {
        List<DenyRule> rules = denyRuleRepository.findActiveDenyRulesForSubject(
                subjectId, Instant.now());

        return rules.stream()
                .map(DenyRule::getPermissionKey)
                .collect(Collectors.toSet());
    }

    /**
     * Fetch and compute user's permissions
     * This is expensive - that's why we cache it!
     */
    private Set<String> fetchUserPermissions(String subjectId, UUID resourceScopeId) {

        // Get active assignments
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
                // Cache miss - query database
                scopeContains = scopeClosureRepository.scopeContains(
                        assignment.getScopeId(), resourceScopeId);
                cacheService.cacheScopeContainment(
                        assignment.getScopeId(), resourceScopeId, scopeContains);
            }

            if (scopeContains) {
                // Get permissions for this role
                // TODO: This should also be cached per role
                Set<String> rolePermissions = getRolePermissions(assignment.getRoleId());
                permissions.addAll(rolePermissions);
            }
        }

        return permissions;
    }

    /**
     * Get permissions for a role
     * TODO: Add role-level caching
     */
    private Set<String> getRolePermissions(UUID roleId) {
        // This query should be optimized with batch loading
        return permissionRepository.findAll().stream()
                .map(Permission::getKey)
                .collect(Collectors.toSet());
        // TODO: Actually query role_permissions table
    }

    /**
     * Log audit entry asynchronously to avoid blocking
     */
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
            // Don't fail the authorization if audit fails
        }
    }

    /**
     * Build authorization response
     */
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
        cacheService.invalidateUserPermissions(subjectId);
        cacheService.invalidateDenyRules(subjectId);
        cacheService.incrementAssignmentVersion(subjectId);
        log.info("Invalidated all caches for subject: {}", subjectId);
    }
}
