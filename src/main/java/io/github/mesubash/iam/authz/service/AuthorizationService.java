package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.*;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.DenyRuleRepository;
import io.github.mesubash.iam.authz.repository.ResourceGrantRepository;
import io.github.mesubash.iam.authz.repository.RoleHierarchyRepository;
import io.github.mesubash.iam.authz.repository.RolePermissionRepository;
import io.github.mesubash.iam.authz.repository.ScopeClosureRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import io.github.mesubash.iam.authz.repository.SubjectGroupMemberRepository;
import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.dto.AuthorizationResponse;
import io.github.mesubash.iam.authz.dto.EffectivePermissionsRequest;
import io.github.mesubash.iam.authz.dto.EffectivePermissionsResponse;
import io.github.mesubash.iam.authz.dto.AccessListEntry;
import io.github.mesubash.iam.authz.dto.ExplainResponse;
import io.github.mesubash.iam.authz.dto.FilterResourcesRequest;
import io.github.mesubash.iam.authz.dto.SimulateRequest;
import io.github.mesubash.iam.shared.exception.AuthorizationServiceException;
import io.github.mesubash.iam.util.IpRangeMatcher;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

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
    private final ScopeRepository scopeRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final AuditWriter auditWriter;
    private final CacheService cacheService;
    private final MeterRegistry meterRegistry;
    private final PolicyService policyService;
    private final PolicyEvaluator policyEvaluator;

    private final ResourceGrantRepository resourceGrantRepository;
    private final SubjectGroupMemberRepository subjectGroupMemberRepository;

    // deny-only: ALLOW policies ignored (policies can only restrict).
    // required-allow: if ALLOW candidates exist, at least one must match.
    private final String policyMode;

    private final boolean resourceGrantsEnabled;
    private final boolean groupsEnabled;

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
            ScopeRepository scopeRepository,
            RolePermissionRepository rolePermissionRepository,
            RoleHierarchyRepository roleHierarchyRepository,
            AuditWriter auditWriter,
            CacheService cacheService,
            MeterRegistry meterRegistry,
            PolicyService policyService,
            PolicyEvaluator policyEvaluator,
            ResourceGrantRepository resourceGrantRepository,
            SubjectGroupMemberRepository subjectGroupMemberRepository,
            @Value("${iam.authorization.policy-mode:deny-only}") String policyMode,
            @Value("${iam.features.resource-grants:false}") boolean resourceGrantsEnabled,
            @Value("${iam.features.groups:false}") boolean groupsEnabled) {

        this.assignmentRepository = assignmentRepository;
        this.denyRuleRepository = denyRuleRepository;
        this.scopeClosureRepository = scopeClosureRepository;
        this.scopeRepository = scopeRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.roleHierarchyRepository = roleHierarchyRepository;
        this.auditWriter = auditWriter;
        this.cacheService = cacheService;
        this.meterRegistry = meterRegistry;
        this.policyService = policyService;
        this.policyEvaluator = policyEvaluator;
        this.resourceGrantRepository = resourceGrantRepository;
        this.subjectGroupMemberRepository = subjectGroupMemberRepository;
        this.policyMode = policyMode;
        this.resourceGrantsEnabled = resourceGrantsEnabled;
        this.groupsEnabled = groupsEnabled;

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

        List<Policy> allPolicies = policyService.getAllActiveOrdered();
        for (String permission : new HashSet<>(allowedPermissions)) {
            AuthorizationRequest policyRequest = AuthorizationRequest.builder()
                    .subject(subject)
                    .permission(permission)
                    .resource(resource)
                    .context(context)
                    .build();

            PolicyDecision policyDecision = evaluatePolicies(policyRequest, allPolicies);
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

    /**
     * Dry-run trace of the decision pipeline. Same checks as authorize(),
     * but records every step and writes NO audit record.
     */
    public ExplainResponse explain(AuthorizationRequest request) {
        List<ExplainResponse.Step> steps = new ArrayList<>();
        String subject = request.getSubject();
        String permissionKey = request.getPermission();
        UUID resourceScopeId = request.getResource().getScopeId();

        if (!isScopeActive(resourceScopeId)) {
            steps.add(step("scope_validity", "DENY", "Scope inactive or not found"));
            return explainResult(false, "scope_inactive", steps);
        }
        steps.add(step("scope_validity", "PASS", "Scope is active"));

        Set<CacheService.CachedDenyRule> denies = fetchDenyRules(subject);
        if (matchesDenyRule(denies, permissionKey, resourceScopeId)) {
            steps.add(step("deny_rules", "DENY", "An explicit deny rule matched"));
            return explainResult(false, "explicit_deny", steps);
        }
        steps.add(step("deny_rules", "PASS",
                denies.isEmpty() ? "No deny rules for subject" : "No matching deny rule"));

        PermissionsResult pr = fetchUserPermissions(subject, permissionKey, resourceScopeId, request);
        boolean viaRole = pr.permissions.contains(permissionKey);
        if (viaRole) {
            steps.add(step("rbac_scope", "PASS", "A role grants the permission within a containing scope"));
            steps.add(step("conditions", "PASS", "Assignment conditions satisfied"));
        } else if (pr.permissionBlockedByConditions) {
            steps.add(step("rbac_scope", "PASS", "A role grants the permission"));
            steps.add(step("conditions", "FAIL",
                    pr.conditionFailureReason != null ? pr.conditionFailureReason : "Assignment conditions not satisfied"));
        } else {
            steps.add(step("rbac_scope", "FAIL", "No role grants the permission within a containing scope"));
        }

        boolean viaGrant = false;
        if (!viaRole) {
            if (resourceGrantsEnabled && resourceGrantAllows(request)) {
                viaGrant = true;
                steps.add(step("resource_grants", "PASS", "A resource grant allows this instance"));
            } else {
                steps.add(step("resource_grants", resourceGrantsEnabled ? "FAIL" : "SKIP",
                        resourceGrantsEnabled ? "No matching resource grant" : "Resource grants disabled"));
                return explainResult(false, pr.permissionBlockedByConditions ? "condition_failed" : "no_permission", steps);
            }
        }

        PolicyDecision policy = evaluatePolicies(request);
        if (!policy.allowed) {
            steps.add(step("policies", "DENY", policy.reason != null ? policy.reason : "Policy denied"));
            return explainResult(false, "policy_deny", steps);
        }
        steps.add(step("policies", "PASS", "No policy denied"));

        return explainResult(true, viaGrant ? "resource_grant" : "allowed", steps);
    }

    /** Filter a list of resource ids to those the subject may act on (no audit). */
    public List<String> filterResources(FilterResourcesRequest request) {
        List<String> allowed = new ArrayList<>();
        for (String resourceId : request.getResourceIds()) {
            AuthorizationRequest.RequestContext ctx = request.getContext() == null ? null
                    : AuthorizationRequest.RequestContext.builder()
                            .additionalContext(request.getContext()).build();
            AuthorizationRequest probe = AuthorizationRequest.builder()
                    .subject(request.getSubjectId())
                    .permission(request.getPermission())
                    .resource(AuthorizationRequest.ResourceContext.builder()
                            .type(request.getResourceType())
                            .id(resourceId)
                            .scopeId(request.getScopeId())
                            .build())
                    .context(ctx)
                    .build();
            if (decideNoAudit(probe)) {
                allowed.add(resourceId);
            }
        }
        return allowed;
    }

    /** What-if evaluation with a hypothetical assignment set. Never persists, never audits. */
    public ExplainResponse simulate(SimulateRequest sim) {
        AuthorizationRequest request = sim.getRequest();
        String subject = request.getSubject();
        String permissionKey = request.getPermission();
        UUID resourceScopeId = request.getResource().getScopeId();

        Set<UUID> removed = new HashSet<>(sim.getRemoveAssignmentIds());
        List<Assignment> assignments = new ArrayList<>(assignmentRepository
                .findActiveAssignmentsForSubjects(subjectKeys(subject), Instant.now()).stream()
                .filter(a -> !removed.contains(a.getId()))
                .toList());
        for (SimulateRequest.Hypothetical h : sim.getAddAssignments()) {
            assignments.add(Assignment.builder()
                    .id(UUID.randomUUID()).subjectId(subject).subjectType("USER")
                    .roleId(h.getRoleId()).scopeId(h.getScopeId())
                    .grantedBy("SIMULATION").active(true).conditions(new HashMap<>())
                    .build());
        }

        List<ExplainResponse.Step> steps = new ArrayList<>();
        if (matchesDenyRule(fetchDenyRules(subject), permissionKey, resourceScopeId)) {
            steps.add(step("deny_rules", "DENY", "An explicit deny rule matched"));
            return explainResult(false, "explicit_deny", steps);
        }
        steps.add(step("deny_rules", "PASS", "No matching deny rule"));

        PermissionsResult pr = computePermissions(assignments, permissionKey, resourceScopeId, request);
        boolean granted = pr.permissions.contains(permissionKey);
        steps.add(step("rbac_scope", granted ? "PASS" : "FAIL",
                granted ? "Granted by the (hypothetical) role set" : "Not granted by the (hypothetical) role set"));
        if (!granted) {
            return explainResult(false, "no_permission", steps);
        }

        PolicyDecision policy = evaluatePolicies(request);
        steps.add(step("policies", policy.allowed ? "PASS" : "DENY",
                policy.allowed ? "No policy denied" : (policy.reason != null ? policy.reason : "Policy denied")));
        return explainResult(policy.allowed, policy.allowed ? "allowed" : "policy_deny", steps);
    }

    /**
     * Point-in-time effective permissions (L0–L1 reconstruction from
     * assignment history). Live deny rules and policies are not versioned,
     * so this reflects role/scope grants as they stood at the instant.
     */
    public EffectivePermissionsResponse getEffectivePermissionsAsOf(String subject, UUID scopeId, Instant asOf) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }
        if (scopeId == null) {
            throw new IllegalArgumentException("scopeId is required");
        }

        List<Assignment> assignments = assignmentRepository.findAssignmentsAsOf(
                subjectKeys(subject), asOf);

        AuthorizationRequest probe = AuthorizationRequest.builder()
                .subject(subject).permission("*.*.*")
                .resource(AuthorizationRequest.ResourceContext.builder().scopeId(scopeId).build())
                .build();

        PermissionsResult pr = computePermissions(assignments, null, scopeId, probe);
        return EffectivePermissionsResponse.builder()
                .subject(subject)
                .scopeId(scopeId)
                .permissions(pr.permissions)
                .build();
    }

    /**
     * Reverse lookup: which subjects hold the permission at the scope.
     * Reflects L0–L2 truth (roles + scope + deny); entries whose grant carries
     * conditions or matching policies are flagged conditional (context-dependent).
     */
    public List<AccessListEntry> accessList(String permission, UUID scopeId) {
        List<String> candidates = assignmentRepository.findSubjectsWithAssignmentCoveringScope(scopeId);
        boolean hasPolicies = !policyService.getApplicablePolicies(permission, null).isEmpty();

        List<AccessListEntry> result = new ArrayList<>();
        for (String subject : candidates) {
            AuthorizationRequest probe = AuthorizationRequest.builder()
                    .subject(subject).permission(permission)
                    .resource(AuthorizationRequest.ResourceContext.builder().scopeId(scopeId).build())
                    .build();

            Set<CacheService.CachedDenyRule> denies = fetchDenyRules(subject);
            if (matchesDenyRule(denies, permission, scopeId)) {
                continue;
            }
            PermissionsResult pr = fetchUserPermissions(subject, permission, scopeId, probe);
            boolean holds = pr.permissions.contains(permission) || pr.permissionBlockedByConditions;
            if (holds) {
                result.add(AccessListEntry.builder()
                        .subjectId(subject)
                        .conditional(pr.permissionBlockedByConditions || hasPolicies)
                        .build());
            }
        }
        return result;
    }

    // Lean decision without audit or metrics — for filter/simulate.
    private boolean decideNoAudit(AuthorizationRequest request) {
        UUID resourceScopeId = request.getResource().getScopeId();
        if (!isScopeActive(resourceScopeId)) {
            return false;
        }
        if (matchesDenyRule(fetchDenyRules(request.getSubject()),
                request.getPermission(), resourceScopeId)) {
            return false;
        }
        PermissionsResult pr = fetchUserPermissions(
                request.getSubject(), request.getPermission(), resourceScopeId, request);
        boolean permitted = pr.permissions.contains(request.getPermission());
        if (!permitted && resourceGrantsEnabled && resourceGrantAllows(request)) {
            permitted = true;
        }
        if (!permitted) {
            return false;
        }
        return evaluatePolicies(request).allowed;
    }

    private ExplainResponse.Step step(String name, String outcome, String detail) {
        return ExplainResponse.Step.builder().name(name).outcome(outcome).detail(detail).build();
    }

    private ExplainResponse explainResult(boolean allowed, String reason, List<ExplainResponse.Step> steps) {
        return ExplainResponse.builder().allowed(allowed).reason(reason).steps(steps).build();
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
            // STEP 0: SCOPE VALIDITY
            // ================================================================

            if (!isScopeActive(resourceScopeId)) {
                String reason = "scope_inactive";
                UUID auditId = UUID.randomUUID();
                auditWriter.write(auditId, request, false, reason, null);
                denyCounter.increment();
                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

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
                String reason = "explicit_deny";
                UUID auditId = UUID.randomUUID();
                auditWriter.write(auditId, request, false, reason, null);
                denyCounter.increment();

                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

            // ================================================================
            // STEP 2: CHECK PERMISSIONS
            // ================================================================

            Set<String> cachedPermissions = null;
            Set<String> userPermissions;
            PermissionsResult permissionsResult = null;

            // Groups bypass the permission cache: group assignments aren't covered
            // by the per-subject conditional check or invalidation counters yet.
            boolean hasConditionalAssignments = groupsEnabled || assignmentRepository
                    .existsActiveConditionalAssignments(subject, Instant.now());

            if (!hasConditionalAssignments) {
                cachedPermissions = cacheService.getCachedUserPermissions(subject, resourceScopeId);
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
                    cacheService.cacheUserPermissions(subject, resourceScopeId, userPermissions);
                }
                log.debug("Permission cache MISS for subject: {}", subject);
            }

            // ================================================================
            // STEP 3: RESOURCE GRANT FALLBACK
            // The grant path is independent of the role path: a failed role
            // condition must not block a valid per-instance grant.
            // ================================================================

            boolean permitted = userPermissions.contains(permissionKey);
            boolean viaGrant = false;
            if (!permitted && resourceGrantsEnabled && resourceGrantAllows(request)) {
                permitted = true;
                viaGrant = true;
            }

            if (!permitted) {
                // Stable reason codes (see AUTHZ_DESIGN §4.13); the human detail
                // is available via /authorize/explain.
                String reason = (permissionsResult != null && permissionsResult.permissionBlockedByConditions)
                        ? "condition_failed"
                        : "no_permission";
                UUID auditId = UUID.randomUUID();
                auditWriter.write(auditId, request, false, reason, null);
                denyCounter.increment();

                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

            // ================================================================
            // STEP 4: POLICY ENGINE (ABAC)
            // ================================================================

            PolicyDecision policyDecision = evaluatePolicies(request);
            if (!policyDecision.allowed) {
                UUID auditId = UUID.randomUUID();
                String reason = policyDecision.reason != null ? policyDecision.reason : "policy_deny";
                auditWriter.write(auditId, request, false, reason, policyDecision.shadowResults);
                denyCounter.increment();

                return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
            }

            // ================================================================
            // ALL CHECKS PASSED - ALLOW
            // ================================================================

            String reason = viaGrant ? "resource_grant" : "allowed";
            UUID auditId = UUID.randomUUID();
            auditWriter.write(auditId, request, true, reason, policyDecision.shadowResults);
            allowCounter.increment();

            return buildResponse(true, reason, startTime, userPermissions, auditId);

        } catch (IllegalArgumentException e) {
            // Input validation errors — deny with reason
            log.warn("Authorization check failed due to bad input: {}", e.getMessage());
            String reason = "DENY: Invalid request - " + e.getMessage();
            UUID auditId = UUID.randomUUID();
            auditWriter.write(auditId, request, false, reason, null);
            denyCounter.increment();
            return buildResponse(false, reason, startTime, Collections.emptySet(), auditId);
        } catch (Exception e) {
            // Infrastructure errors (DB/Redis down) — throw 503, NOT a security denial
            log.error("Authorization service infrastructure error", e);
            throw new AuthorizationServiceException(
                    "Authorization service unavailable: " + e.getMessage(), e);
        }
    }

    private boolean isScopeActive(UUID scopeId) {
        if (scopeId == null) {
            return false;
        }
        Boolean cached = cacheService.getCachedScopeActive(scopeId);
        if (cached != null) {
            return cached;
        }
        boolean active = scopeRepository.findActiveFlag(scopeId).orElse(false);
        cacheService.cacheScopeActive(scopeId, active);
        return active;
    }

    /** Subject plus its active group ids — the identities a rule can match. */
    private List<String> subjectKeys(String subjectId) {
        if (!groupsEnabled) {
            return List.of(subjectId);
        }
        List<String> keys = new ArrayList<>();
        keys.add(subjectId);
        subjectGroupMemberRepository.findActiveGroupIds(subjectId)
                .forEach(id -> keys.add(id.toString()));
        return keys;
    }

    private boolean resourceGrantAllows(AuthorizationRequest request) {
        AuthorizationRequest.ResourceContext resource = request.getResource();
        if (resource == null || resource.getType() == null || resource.getId() == null) {
            return false;
        }

        List<ResourceGrant> grants = resourceGrantRepository.findActiveForResource(
                subjectKeys(request.getSubject()), resource.getType(), resource.getId(), Instant.now());

        for (ResourceGrant grant : grants) {
            if (!grantPermissionMatches(grant.getPermissionKey(), request.getPermission())) {
                continue;
            }
            if (grant.getScopeId() != null
                    && !scopeContainsCached(grant.getScopeId(), resource.getScopeId())) {
                continue;
            }
            return true;
        }
        return false;
    }

    // Exact key, or wildcard on the action segment only: doc.file.* matches
    // doc.file.read but never doc.other.read or doc.file.sub.read.
    private boolean grantPermissionMatches(String grantKey, String permissionKey) {
        if (grantKey.equals(permissionKey)) {
            return true;
        }
        if (grantKey.endsWith(".*")) {
            String prefix = grantKey.substring(0, grantKey.length() - 1);
            return permissionKey.startsWith(prefix)
                    && permissionKey.indexOf('.', prefix.length()) == -1;
        }
        return false;
    }

    /**
     * Fetch deny rules from database
     */
    private Set<CacheService.CachedDenyRule> fetchDenyRules(String subjectId) {
        List<DenyRule> rules = denyRuleRepository.findAllActiveDenyRulesForSubjects(
                subjectKeys(subjectId), Instant.now());

        return rules.stream()
                .map(rule -> CacheService.CachedDenyRule.builder()
                        .permissionKey(rule.getPermissionKey())
                        .scopeId(rule.getScopeId())
                        .build())
                .collect(Collectors.toSet());
    }

    /**
     * Fetch and compute user's permissions
     */
    private PermissionsResult fetchUserPermissions(String subjectId,
                                                   String permissionKey,
                                                   UUID resourceScopeId,
                                                   AuthorizationRequest request) {

        List<Assignment> assignments = assignmentRepository.findActiveAssignmentsForSubjects(
                subjectKeys(subjectId), Instant.now());

        return computePermissions(assignments, permissionKey, resourceScopeId, request);
    }

    // Shared by the live path and by /simulate (which passes a hypothetical set).
    private PermissionsResult computePermissions(List<Assignment> assignments,
                                                 String permissionKey,
                                                 UUID resourceScopeId,
                                                 AuthorizationRequest request) {
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
     * Matches a rule pattern against a permission key.
     * '*' matches exactly one segment; a trailing '**' matches one or more
     * remaining segments; '**' alone matches everything.
     * Without '**' the segment counts must be equal.
     */
    private boolean permissionMatches(String rulePermission, String permissionKey) {
        if (rulePermission.equals(permissionKey)) {
            return true;
        }
        if ("**".equals(rulePermission)) {
            return true;
        }

        String[] ruleParts = rulePermission.split("\\.");
        String[] permParts = permissionKey.split("\\.");

        boolean anyDepth = ruleParts.length > 0 && "**".equals(ruleParts[ruleParts.length - 1]);
        int fixed = anyDepth ? ruleParts.length - 1 : ruleParts.length;

        if (anyDepth ? permParts.length <= fixed : permParts.length != fixed) {
            return false;
        }

        for (int i = 0; i < fixed; i++) {
            if (!"*".equals(ruleParts[i]) && !ruleParts[i].equals(permParts[i])) {
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

        return evaluatePolicies(request,
                policyService.getApplicablePolicies(permissionKey, resourceType));
    }

    private PolicyDecision evaluatePolicies(AuthorizationRequest request, List<Policy> candidates) {
        String permissionKey = request.getPermission();
        String resourceType = request.getResource() != null ? request.getResource().getType() : null;
        UUID resourceScopeId = request.getResource() != null ? request.getResource().getScopeId() : null;

        if (candidates.isEmpty()) {
            return PolicyDecision.allow(null);
        }

        List<Policy> denyPolicies = new ArrayList<>();
        List<Policy> allowPolicies = new ArrayList<>();
        List<Map<String, Object>> shadowResults = new ArrayList<>();

        for (Policy policy : candidates) {
            if (!policyApplies(policy, permissionKey, resourceType, resourceScopeId)) {
                continue;
            }
            // SHADOW: evaluate and record the would-be verdict, never decide
            if ("SHADOW".equalsIgnoreCase(policy.getEnforcementMode())) {
                boolean matched = policyEvaluator.evaluate(policy.getConditions(), request);
                shadowResults.add(Map.of(
                        "policy", policy.getName(),
                        "effect", policy.getEffect(),
                        "matched", matched));
                continue;
            }
            if ("DENY".equalsIgnoreCase(policy.getEffect())) {
                denyPolicies.add(policy);
            } else if ("ALLOW".equalsIgnoreCase(policy.getEffect())) {
                allowPolicies.add(policy);
            }
        }

        List<Map<String, Object>> shadow = shadowResults.isEmpty() ? null : shadowResults;

        // DENY always takes precedence
        for (Policy policy : denyPolicies) {
            if (policyEvaluator.evaluate(policy.getConditions(), request)) {
                return PolicyDecision.deny("policy_deny", shadow);
            }
        }

        // required-allow mode only: ALLOW candidates gate the request.
        // In deny-only mode (default) ALLOW policies are inert — adding a
        // policy can only ever restrict, never flip a target to default-deny.
        if ("required-allow".equalsIgnoreCase(policyMode) && !allowPolicies.isEmpty()) {
            boolean allowMatched = false;
            for (Policy policy : allowPolicies) {
                if (policyEvaluator.evaluate(policy.getConditions(), request)) {
                    allowMatched = true;
                    break;
                }
            }
            if (!allowMatched) {
                return PolicyDecision.deny("no_matching_allow_policy", shadow);
            }
        }

        return PolicyDecision.allow(shadow);
    }

    private boolean policyApplies(Policy policy,
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
     * Get permissions for a role
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
                .policyVersion(cacheService.currentVersionToken())
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
        private final List<Map<String, Object>> shadowResults;

        private PolicyDecision(boolean allowed, String reason,
                               List<Map<String, Object>> shadowResults) {
            this.allowed = allowed;
            this.reason = reason;
            this.shadowResults = shadowResults;
        }

        private static PolicyDecision allow(List<Map<String, Object>> shadowResults) {
            return new PolicyDecision(true, null, shadowResults);
        }

        private static PolicyDecision deny(String reason, List<Map<String, Object>> shadowResults) {
            return new PolicyDecision(false, reason, shadowResults);
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
     * Invalidate role cache when role permissions change
     */
    public void invalidateRoleCache(UUID roleId) {
        String cacheKey = "role:" + roleId;
        cacheService.invalidateRolePermissions(cacheKey);
        log.info("Invalidated role cache for roleId: {}", roleId);
    }
}
