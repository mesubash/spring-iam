package com.hgn.iam.authz.service;

import com.hgn.iam.authz.entity.*;
import com.hgn.iam.authz.repository.AssignmentRepository;
import com.hgn.iam.authz.repository.AuthorizationAuditRepository;
import com.hgn.iam.authz.repository.DenyRuleRepository;
import com.hgn.iam.authz.repository.RoleHierarchyRepository;
import com.hgn.iam.authz.repository.RolePermissionRepository;
import com.hgn.iam.authz.repository.ScopeClosureRepository;
import com.hgn.iam.authz.dto.AuthorizationRequest;
import com.hgn.iam.authz.dto.AuthorizationResponse;
import com.hgn.iam.authz.dto.EffectivePermissionsRequest;
import com.hgn.iam.authz.dto.EffectivePermissionsResponse;
import com.hgn.iam.shared.exception.AuthorizationServiceException;
import com.hgn.iam.util.IpRangeMatcher;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AuthorizationService {

    private final AssignmentRepository assignmentRepository;
    private final DenyRuleRepository denyRuleRepository;
    private final ScopeClosureRepository scopeClosureRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final AuthorizationAuditRepository auditRepository;
    private final CacheService cacheService;
    private final MeterRegistry meterRegistry;
    private final PolicyService policyService;
    private final PolicyEvaluator policyEvaluator;

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
            RolePermissionRepository rolePermissionRepository, // ✅ ADD THIS
            RoleHierarchyRepository roleHierarchyRepository,
            AuthorizationAuditRepository auditRepository,
            CacheService cacheService,
            MeterRegistry meterRegistry,
            PolicyService policyService,
            PolicyEvaluator policyEvaluator) {

        this.assignmentRepository = assignmentRepository;
        this.denyRuleRepository = denyRuleRepository;
        this.scopeClosureRepository = scopeClosureRepository;
        this.rolePermissionRepository = rolePermissionRepository; // ✅ ADD THIS
        this.roleHierarchyRepository = roleHierarchyRepository;
        this.auditRepository = auditRepository;
        this.cacheService = cacheService;
        this.meterRegistry = meterRegistry;
        this.policyService = policyService;
        this.policyEvaluator = policyEvaluator;

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

    public EffectivePermissionsResponse getEffectivePermissions(EffectivePermissionsRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request is required");
        }

        String subject = request.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }

        UUID scopeId = request.getScopeId();
        AuthorizationRequest.ResourceContext resource = request.getResource();
        if (scopeId == null && resource != null) {
            scopeId = resource.getScopeId();
        }
        if (scopeId == null) {
            throw new IllegalArgumentException("scopeId is required");
        }

        if (resource == null) {
            resource = AuthorizationRequest.ResourceContext.builder()
                    .scopeId(scopeId)
                    .build();
        } else if (resource.getScopeId() == null) {
            resource.setScopeId(scopeId);
        }

        AuthorizationRequest.RequestContext context = request.getContext();

        AuthorizationRequest baseRequest = AuthorizationRequest.builder()
                .subject(subject)
                .permission("*.*.*")
                .resource(resource)
                .context(context)
                .build();

        PermissionsResult permissionsResult = fetchUserPermissions(
                subject, null, scopeId, baseRequest);

        Set<String> allowedPermissions = new HashSet<>(permissionsResult.permissions);
        Set<String> deniedPermissions = new HashSet<>();

        Set<CacheService.CachedDenyRule> denyRules = cacheService.getCachedDenyRules(subject);
        if (denyRules == null) {
            denyRules = fetchDenyRules(subject);
            cacheService.cacheDenyRules(subject, denyRules);
        }

        if (denyRules != null && !denyRules.isEmpty()) {
            for (String permission : new HashSet<>(allowedPermissions)) {
                if (matchesDenyRule(denyRules, permission, scopeId)) {
                    allowedPermissions.remove(permission);
                    if (request.isIncludeDenied()) {
                        deniedPermissions.add(permission);
                    }
                }
            }
        }

        for (String permission : new HashSet<>(allowedPermissions)) {
            AuthorizationRequest policyRequest = AuthorizationRequest.builder()
                    .subject(subject)
                    .permission(permission)
                    .resource(resource)
                    .context(context)
                    .build();

            PolicyDecision policyDecision = evaluatePolicies(policyRequest);
            if (!policyDecision.allowed) {
                allowedPermissions.remove(permission);
                if (request.isIncludeDenied()) {
                    deniedPermissions.add(permission);
                }
            }
        }

        return EffectivePermissionsResponse.builder()
                .subject(subject)
                .scopeId(scopeId)
                .permissions(allowedPermissions)
                .deniedPermissions(request.isIncludeDenied() ? deniedPermissions : null)
                .build();
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

            Set<CacheService.CachedDenyRule> cachedDenyRules = cacheService.getCachedDenyRules(subject);
            Set<CacheService.CachedDenyRule> deniedPermissions;

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

            if (matchesDenyRule(deniedPermissions, permissionKey, resourceScopeId)) {
                String reason = "DENY: Explicit deny rule exists";
                UUID auditId = UUID.randomUUID();
                logAuditAsync(auditId, request, false, reason);
                denyCounter.increment();

                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

            // ================================================================
            // STEP 2: CHECK PERMISSIONS
            // ================================================================

            // Build cache key with scope for more accurate caching
            String cacheKey = subject + ":" + resourceScopeId;
            Set<String> cachedPermissions = null;
            Set<String> userPermissions;
            PermissionsResult permissionsResult = null;

            boolean hasConditionalAssignments = assignmentRepository
                    .existsActiveConditionalAssignments(subject, Instant.now());

            if (!hasConditionalAssignments) {
                cachedPermissions = cacheService.getCachedUserPermissions(cacheKey);
            }

            if (cachedPermissions != null) {
                cacheHitCounter.increment();
                userPermissions = cachedPermissions;
                log.debug("Permission cache HIT for subject: {}", subject);
            } else {
                cacheMissCounter.increment();
                permissionsResult = fetchUserPermissions(subject, permissionKey,
                        resourceScopeId, request);
                userPermissions = permissionsResult.permissions;
                if (permissionsResult.cacheable && !hasConditionalAssignments) {
                    cacheService.cacheUserPermissions(cacheKey, userPermissions);
                }
                log.debug("Permission cache MISS for subject: {}", subject);
            }

            if (!userPermissions.contains(permissionKey)) {
                String reason;
                if (permissionsResult != null && permissionsResult.permissionBlockedByConditions) {
                    reason = permissionsResult.conditionFailureReason != null
                            ? permissionsResult.conditionFailureReason
                            : "DENY: Assignment conditions not satisfied";
                } else if (hasConditionalAssignments) {
                    reason = "DENY: Permission not granted or assignment conditions not satisfied";
                } else {
                    reason = "DENY: Permission not granted by any role";
                }
                UUID auditId = UUID.randomUUID();
                logAuditAsync(auditId, request, false, reason);
                denyCounter.increment();

                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

            // ================================================================
            // STEP 3: POLICY ENGINE (ABAC/ReBAC)
            // ================================================================

            PolicyDecision policyDecision = evaluatePolicies(request);
            if (!policyDecision.allowed) {
                UUID auditId = UUID.randomUUID();
                String reason = policyDecision.reason != null
                        ? policyDecision.reason
                        : "DENY: Policy evaluation failed";
                logAuditAsync(auditId, request, false, reason);
                denyCounter.increment();

                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

            // ================================================================
            // ALL CHECKS PASSED - ALLOW
            // ================================================================

            String reason = "ALLOW: Permission granted via role assignment";
            UUID auditId = UUID.randomUUID();
            logAuditAsync(auditId, request, true, reason);
            allowCounter.increment();

            return buildResponse(true, reason, startTime, userPermissions, auditId);

        } catch (IllegalArgumentException e) {
            // Input validation errors — deny with reason
            log.warn("Authorization check failed due to bad input: {}", e.getMessage());
            String reason = "DENY: Invalid request - " + e.getMessage();
            UUID auditId = UUID.randomUUID();
            logAuditAsync(auditId, request, false, reason);
            denyCounter.increment();
            return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
        } catch (Exception e) {
            // Infrastructure errors (DB/Redis down) — throw 503, NOT a security denial
            log.error("Authorization service infrastructure error", e);
            throw new AuthorizationServiceException(
                    "Authorization service unavailable: " + e.getMessage(), e);
        }
    }

    /**
     * Fetch deny rules from database
     */
    private Set<CacheService.CachedDenyRule> fetchDenyRules(String subjectId) {
        List<DenyRule> rules = denyRuleRepository.findAllActiveDenyRulesForSubject(
                subjectId, Instant.now());

        return rules.stream()
                .map(rule -> CacheService.CachedDenyRule.builder()
                        .permissionKey(rule.getPermissionKey())
                        .scopeId(rule.getScopeId())
                        .build())
                .collect(Collectors.toSet());
    }

    /**
     * ✅ FIXED: Fetch and compute user's permissions
     */
    private PermissionsResult fetchUserPermissions(String subjectId,
                                                   String permissionKey,
                                                   UUID resourceScopeId,
                                                   AuthorizationRequest request) {

        List<Assignment> assignments = assignmentRepository.findActiveAssignments(
                subjectId, Instant.now());

        if (assignments.isEmpty()) {
            return PermissionsResult.empty();
        }

        Set<String> permissions = new HashSet<>();
        boolean cacheable = true;
        boolean permissionBlockedByConditions = false;
        String conditionFailureReason = null;

        for (Assignment assignment : assignments) {
            boolean hasConditions = assignment.getConditions() != null
                    && !assignment.getConditions().isEmpty();
            if (hasConditions) {
                cacheable = false;
            }

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
                Set<String> rolePermissions = getRolePermissions(assignment.getRoleId());
                if (hasConditions) {
                    ConditionResult conditionResult = evaluateConditions(assignment, request);
                    if (!conditionResult.allowed) {
                        if (rolePermissions.contains(permissionKey)) {
                            permissionBlockedByConditions = true;
                            if (conditionFailureReason == null) {
                                conditionFailureReason = conditionResult.reason;
                            }
                        }
                        continue;
                    }
                }
                permissions.addAll(rolePermissions);
            }
        }

        return new PermissionsResult(permissions, cacheable,
                permissionBlockedByConditions, conditionFailureReason);
    }

    private boolean matchesDenyRule(Set<CacheService.CachedDenyRule> rules,
                                    String permissionKey,
                                    UUID resourceScopeId) {
        if (rules == null || rules.isEmpty()) {
            return false;
        }

        for (CacheService.CachedDenyRule rule : rules) {
            if (!permissionMatches(rule.getPermissionKey(), permissionKey)) {
                continue;
            }

            if (rule.getScopeId() == null) {
                return true;
            }

            if (resourceScopeId == null) {
                continue;
            }

            if (scopeContainsCached(rule.getScopeId(), resourceScopeId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Matches a permission rule pattern against a permission key.
     * Supports wildcard (*) at each segment position and variable-length keys.
     * Examples:
     *   "order.order.approve" matches "order.order.approve" (exact)
     *   "order.*.approve" matches "order.order.approve" (wildcard segment)
     *   "*.*.*" matches any 3-segment permission
     *   "order.*" matches "order.read" (2-segment keys)
     */
    private boolean permissionMatches(String rulePermission, String permissionKey) {
        if (rulePermission.equals(permissionKey)) {
            return true;
        }

        // Check for full wildcard pattern (all segments are *)
        if (rulePermission.chars().allMatch(c -> c == '*' || c == '.')) {
            // Ensure same number of segments
            long ruleDots = rulePermission.chars().filter(c -> c == '.').count();
            long permDots = permissionKey.chars().filter(c -> c == '.').count();
            return ruleDots == permDots;
        }

        String[] ruleParts = rulePermission.split("\\.");
        String[] permParts = permissionKey.split("\\.");

        if (ruleParts.length != permParts.length) {
            return false;
        }

        for (int i = 0; i < ruleParts.length; i++) {
            if ("*".equals(ruleParts[i])) {
                continue;
            }
            if (!ruleParts[i].equals(permParts[i])) {
                return false;
            }
        }

        return true;
    }

    private boolean scopeContainsCached(UUID ancestorId, UUID descendantId) {
        Boolean cached = cacheService.getCachedScopeContainment(ancestorId, descendantId);
        if (cached != null) {
            return cached;
        }

        boolean contains = scopeClosureRepository.scopeContains(ancestorId, descendantId);
        cacheService.cacheScopeContainment(ancestorId, descendantId, contains);
        return contains;
    }

    private PolicyDecision evaluatePolicies(AuthorizationRequest request) {
        String permissionKey = request.getPermission();
        String resourceType = request.getResource() != null ? request.getResource().getType() : null;
        UUID resourceScopeId = request.getResource() != null ? request.getResource().getScopeId() : null;

        List<com.hgn.iam.authz.entity.Policy> candidates =
                policyService.getApplicablePolicies(permissionKey, resourceType);

        if (candidates.isEmpty()) {
            return PolicyDecision.allow();
        }

        // Separate DENY and ALLOW policies — evaluate ALL DENY policies first
        List<com.hgn.iam.authz.entity.Policy> denyPolicies = new ArrayList<>();
        List<com.hgn.iam.authz.entity.Policy> allowPolicies = new ArrayList<>();

        for (com.hgn.iam.authz.entity.Policy policy : candidates) {
            if (!policyApplies(policy, permissionKey, resourceType, resourceScopeId)) {
                continue;
            }
            if ("DENY".equalsIgnoreCase(policy.getEffect())) {
                denyPolicies.add(policy);
            } else if ("ALLOW".equalsIgnoreCase(policy.getEffect())) {
                allowPolicies.add(policy);
            }
        }

        // DENY always takes precedence — check all DENY policies first
        for (com.hgn.iam.authz.entity.Policy policy : denyPolicies) {
            if (policyEvaluator.evaluate(policy.getConditions(), request)) {
                return PolicyDecision.deny("DENY: Policy '" + policy.getName() + "'");
            }
        }

        // If ALLOW policies exist, at least one must match
        if (!allowPolicies.isEmpty()) {
            boolean allowMatched = false;
            for (com.hgn.iam.authz.entity.Policy policy : allowPolicies) {
                if (policyEvaluator.evaluate(policy.getConditions(), request)) {
                    allowMatched = true;
                    break;
                }
            }
            if (!allowMatched) {
                return PolicyDecision.deny("DENY: No ALLOW policy matched");
            }
        }

        return PolicyDecision.allow();
    }

    private boolean policyApplies(com.hgn.iam.authz.entity.Policy policy,
                                  String permissionKey,
                                  String resourceType,
                                  UUID resourceScopeId) {
        if (policy.getPermissionKey() != null
                && !permissionMatches(policy.getPermissionKey(), permissionKey)) {
            return false;
        }

        if (policy.getResourceType() != null
                && resourceType != null
                && !policy.getResourceType().equals(resourceType)) {
            return false;
        }

        if (policy.getResourceType() != null && resourceType == null) {
            return false;
        }

        if (policy.getScopeId() != null) {
            if (resourceScopeId == null) {
                return false;
            }
            return scopeContainsCached(policy.getScopeId(), resourceScopeId);
        }

        return true;
    }

    private ConditionResult evaluateConditions(Assignment assignment, AuthorizationRequest request) {
        Map<String, Object> conditions = assignment.getConditions();
        if (conditions == null || conditions.isEmpty()) {
            return ConditionResult.allowed();
        }

        AuthorizationRequest.RequestContext context = request.getContext();
        AuthorizationRequest.ResourceContext resource = request.getResource();
        String subjectId = request.getSubject();

        String timeWindow = getStringCondition(conditions, "time_window", "timeWindow");
        if (timeWindow != null) {
            ZoneId zoneId = resolveZoneId(conditions, context);
            Instant timestamp = context != null && context.getTimestamp() != null
                    ? context.getTimestamp()
                    : Instant.now();
            if (!isWithinTimeWindow(timeWindow, timestamp, zoneId)) {
                return ConditionResult.deny("DENY: Outside allowed time window");
            }
        }

        List<String> ipRanges = getStringListCondition(conditions, "ip_ranges", "ipRanges");
        if (!ipRanges.isEmpty()) {
            String ipAddress = context != null ? context.getIpAddress() : null;
            if (ipAddress == null || !matchesAnyRange(ipAddress, ipRanges)) {
                return ConditionResult.deny("DENY: IP address not allowed");
            }
        }

        boolean requireMfa = getBooleanCondition(conditions, "require_mfa", "requireMfa");
        if (requireMfa && !isMfaVerified(context)) {
            return ConditionResult.deny("DENY: MFA required");
        }

        boolean ownershipRequired = getBooleanCondition(conditions, "ownership_required", "ownershipRequired")
                || getBooleanCondition(conditions, "can_only_access_own_created", "canOnlyAccessOwnCreated");
        if (ownershipRequired && !isSubjectOwner(subjectId, resource, context)) {
            return ConditionResult.deny("DENY: Ownership required");
        }

        boolean cannotApproveOwnCreated = getBooleanCondition(conditions,
                "cannot_approve_own_created", "cannotApproveOwnCreated");
        if (cannotApproveOwnCreated && isSubjectOwner(subjectId, resource, context)) {
            return ConditionResult.deny("DENY: Cannot approve own created resource");
        }

        List<String> subjectMatchFields = getStringListCondition(conditions,
                "subject_match_fields", "subjectMatchFields");
        if (!subjectMatchFields.isEmpty()
                && !matchesAllResourceFields(subjectId, resource, context, subjectMatchFields)) {
            return ConditionResult.deny("DENY: Assignment requires subject match");
        }

        return ConditionResult.allowed();
    }

    private ZoneId resolveZoneId(Map<String, Object> conditions,
                                 AuthorizationRequest.RequestContext context) {
        String zone = getStringCondition(conditions, "timezone", "timeZone");
        if (zone == null && context != null && context.getAdditionalContext() != null) {
            zone = getStringValue(context.getAdditionalContext().get("timezone"));
        }
        if (zone == null || zone.isBlank()) {
            zone = "UTC";
        }
        try {
            return ZoneId.of(zone);
        } catch (DateTimeException e) {
            return ZoneId.of("UTC");
        }
    }

    private boolean isWithinTimeWindow(String window, Instant timestamp, ZoneId zoneId) {
        String[] parts = window.split("-");
        if (parts.length != 2) {
            return false;
        }

        try {
            LocalTime start = LocalTime.parse(parts[0].trim());
            LocalTime end = LocalTime.parse(parts[1].trim());
            LocalTime now = ZonedDateTime.ofInstant(timestamp, zoneId).toLocalTime();

            if (start.equals(end)) {
                return true; // 24-hour window
            }

            if (start.isBefore(end)) {
                // Normal window: e.g. 09:00-17:00
                return !now.isBefore(start) && !now.isAfter(end);
            }

            // Wraparound window: e.g. 22:00-06:00
            // User is within window if AFTER start OR BEFORE end
            return !now.isBefore(start) || !now.isAfter(end);
        } catch (DateTimeException e) {
            log.warn("Invalid time window format: {}", window);
            return false;
        }
    }

    private boolean matchesAnyRange(String ipAddress, List<String> ranges) {
        for (String range : ranges) {
            if (IpRangeMatcher.isInRange(ipAddress, range)) {
                return true;
            }
        }
        return false;
    }

    private boolean isMfaVerified(AuthorizationRequest.RequestContext context) {
        if (context == null || context.getAdditionalContext() == null) {
            return false;
        }

        Object mfaFlag = context.getAdditionalContext().get("mfa");
        if (mfaFlag == null) {
            mfaFlag = context.getAdditionalContext().get("mfaVerified");
        }
        if (mfaFlag == null) {
            mfaFlag = context.getAdditionalContext().get("mfa_authenticated");
        }

        return parseBoolean(mfaFlag);
    }

    private boolean isSubjectOwner(String subjectId,
                                   AuthorizationRequest.ResourceContext resource,
                                   AuthorizationRequest.RequestContext context) {
        if (subjectId == null) {
            return false;
        }

        String ownerId = null;
        if (resource != null && resource.getMetadata() != null) {
            ownerId = getStringValue(resource.getMetadata().get("ownerId"));
            if (ownerId == null) {
                ownerId = getStringValue(resource.getMetadata().get("createdBy"));
            }
            if (ownerId == null) {
                ownerId = getStringValue(resource.getMetadata().get("created_by"));
            }
        }

        if (ownerId == null && context != null && context.getAdditionalContext() != null) {
            ownerId = getStringValue(context.getAdditionalContext().get("ownerId"));
        }

        return subjectId.equals(ownerId);
    }

    private boolean matchesAllResourceFields(String subjectId,
                                             AuthorizationRequest.ResourceContext resource,
                                             AuthorizationRequest.RequestContext context,
                                             List<String> fields) {
        if (subjectId == null || fields.isEmpty()) {
            return false;
        }

        Map<String, Object> metadata = resource != null ? resource.getMetadata() : null;
        Map<String, Object> contextData = context != null ? context.getAdditionalContext() : null;

        for (String field : fields) {
            Object value = metadata != null ? metadata.get(field) : null;
            if (value == null && contextData != null) {
                value = contextData.get(field);
            }
            if (!subjectId.equals(getStringValue(value))) {
                return false;
            }
        }

        return true;
    }

    private String getStringCondition(Map<String, Object> conditions, String... keys) {
        Object value = getConditionValue(conditions, keys);
        return getStringValue(value);
    }

    private List<String> getStringListCondition(Map<String, Object> conditions, String... keys) {
        Object value = getConditionValue(conditions, keys);
        if (value == null) {
            return Collections.emptyList();
        }

        if (value instanceof List<?> list) {
            List<String> results = new ArrayList<>();
            for (Object item : list) {
                String stringValue = getStringValue(item);
                if (stringValue != null && !stringValue.isBlank()) {
                    results.add(stringValue);
                }
            }
            return results;
        }

        String stringValue = getStringValue(value);
        if (stringValue == null || stringValue.isBlank()) {
            return Collections.emptyList();
        }

        if (stringValue.contains(",")) {
            return Arrays.stream(stringValue.split(","))
                    .map(String::trim)
                    .filter(part -> !part.isBlank())
                    .collect(Collectors.toList());
        }

        return List.of(stringValue.trim());
    }

    private boolean getBooleanCondition(Map<String, Object> conditions, String... keys) {
        Object value = getConditionValue(conditions, keys);
        return parseBoolean(value);
    }

    private Object getConditionValue(Map<String, Object> conditions, String... keys) {
        for (String key : keys) {
            if (conditions.containsKey(key)) {
                return conditions.get(key);
            }
        }
        return null;
    }

    private String getStringValue(Object value) {
        if (value == null) {
            return null;
        }
        String stringValue = value.toString();
        return stringValue.isBlank() ? null : stringValue;
    }

    private boolean parseBoolean(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        return Boolean.parseBoolean(value.toString());
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
        Set<UUID> roleIds = resolveRoleHierarchy(roleId);
        Set<String> permissions = rolePermissionRepository
                .findPermissionKeysByRoleIds(roleIds);

        // Cache the result (roles change infrequently, so longer TTL is OK)
        cacheService.cacheRolePermissions(cacheKey, permissions);

        return permissions;
    }

    /**
     * Resolves the full role hierarchy using batch queries to avoid N+1.
     * Each iteration fetches all parent mappings for the current frontier in a single query.
     */
    private Set<UUID> resolveRoleHierarchy(UUID roleId) {
        Set<UUID> resolved = new HashSet<>();
        resolved.add(roleId);
        Set<UUID> frontier = new HashSet<>();
        frontier.add(roleId);

        while (!frontier.isEmpty()) {
            // Batch fetch: single query for all parents of the current frontier
            List<RoleHierarchy> hierarchies = roleHierarchyRepository.findAllByChildRoleIds(frontier);
            frontier = new HashSet<>();
            for (RoleHierarchy rh : hierarchies) {
                if (resolved.add(rh.getParentRoleId())) {
                    frontier.add(rh.getParentRoleId());
                }
            }
        }

        return resolved;
    }

    /**
     * Log audit entry asynchronously
     */
    @Async("auditExecutor")
    @Transactional
    protected void logAuditAsync(UUID auditId,
                                 AuthorizationRequest request,
                                 boolean decision,
                                 String reason) {

        try {
            Instant now = Instant.now();
            AuthorizationAudit audit = AuthorizationAudit.builder()
                    .id(auditId)
                    .subjectId(request.getSubject())
                    .permissionKey(request.getPermission())
                    .resourceType(request.getResource().getType())
                    .resourceId(request.getResource().getId())
                    .scopeId(request.getResource().getScopeId())
                    .decision(decision)
                    .reason(reason)
                    .context(request.getContext() != null && request.getContext().getAdditionalContext() != null
                            ? request.getContext().getAdditionalContext()
                            : new HashMap<>())
                    .requestId(request.getContext() != null ?
                            request.getContext().getRequestId() : null)
                    .ipAddress(request.getContext() != null ?
                            request.getContext().getIpAddress() : null)
                    .userAgent(request.getContext() != null ?
                            request.getContext().getUserAgent() : null)
                    .timestamp(now)
                    .build();

            auditRepository.save(audit);
        } catch (Exception e) {
            log.error("Failed to save audit log", e);
        }
    }

    private AuthorizationResponse buildResponse(boolean authorized,
                                                String reason,
                                                Instant startTime,
                                                Set<String> permissions,
                                                UUID auditId) {
        long latencyMs = Duration.between(startTime, Instant.now()).toMillis();

        return AuthorizationResponse.builder()
                .authorized(authorized)
                .reason(reason)
                .effectivePermissions(new ArrayList<>(permissions))
                .auditId(auditId)
                .timestamp(Instant.now())
                .latencyMs(latencyMs)
                .build();
    }

    private static final class PermissionsResult {
        private final Set<String> permissions;
        private final boolean cacheable;
        private final boolean permissionBlockedByConditions;
        private final String conditionFailureReason;

        private PermissionsResult(Set<String> permissions,
                                  boolean cacheable,
                                  boolean permissionBlockedByConditions,
                                  String conditionFailureReason) {
            this.permissions = permissions;
            this.cacheable = cacheable;
            this.permissionBlockedByConditions = permissionBlockedByConditions;
            this.conditionFailureReason = conditionFailureReason;
        }

        private static PermissionsResult empty() {
            return new PermissionsResult(Collections.emptySet(), true, false, null);
        }
    }

    private static final class ConditionResult {
        private final boolean allowed;
        private final String reason;

        private ConditionResult(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }

        private static ConditionResult allowed() {
            return new ConditionResult(true, "ALLOW");
        }

        private static ConditionResult deny(String reason) {
            return new ConditionResult(false, reason);
        }
    }

    private static final class PolicyDecision {
        private final boolean allowed;
        private final String reason;

        private PolicyDecision(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }

        private static PolicyDecision allow() {
            return new PolicyDecision(true, null);
        }

        private static PolicyDecision deny(String reason) {
            return new PolicyDecision(false, reason);
        }
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
