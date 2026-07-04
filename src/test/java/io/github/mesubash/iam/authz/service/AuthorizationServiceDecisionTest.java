package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.dto.AuthorizationResponse;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.DenyRule;
import io.github.mesubash.iam.authz.entity.Policy;
import io.github.mesubash.iam.authz.entity.ResourceGrant;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.AuthorizationAuditRepository;
import io.github.mesubash.iam.authz.repository.DenyRuleRepository;
import io.github.mesubash.iam.authz.repository.ResourceGrantRepository;
import io.github.mesubash.iam.authz.repository.RoleHierarchyRepository;
import io.github.mesubash.iam.authz.repository.RolePermissionRepository;
import io.github.mesubash.iam.authz.repository.ScopeClosureRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import io.github.mesubash.iam.authz.repository.SubjectGroupMemberRepository;
import io.github.mesubash.iam.shared.exception.AuthorizationServiceException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Decision-engine baseline suite. Pins the pipeline behavior documented in
 * docs/AUTHZ_DESIGN.md §5/§6 so the Phase-1 refactor happens under green.
 * Pure unit level: repositories and cache are mocked; cache always misses.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthorizationServiceDecisionTest {

    @Mock private AssignmentRepository assignmentRepository;
    @Mock private DenyRuleRepository denyRuleRepository;
    @Mock private ScopeClosureRepository scopeClosureRepository;
    @Mock private ScopeRepository scopeRepository;
    @Mock private RolePermissionRepository rolePermissionRepository;
    @Mock private RoleHierarchyRepository roleHierarchyRepository;
    @Mock private AuthorizationAuditRepository auditRepository;
    @Mock private CacheService cacheService;
    @Mock private PolicyService policyService;
    @Mock private ResourceGrantRepository resourceGrantRepository;
    @Mock private SubjectGroupMemberRepository subjectGroupMemberRepository;

    private AuthorizationService service;

    private static final String SUBJECT = "alice";
    private static final UUID ROLE = UUID.randomUUID();
    private static final UUID ORG_SCOPE = UUID.randomUUID();      // assignment scope (ancestor)
    private static final UUID PROJECT_SCOPE = UUID.randomUUID();  // resource scope (descendant)
    private static final String PERM = "invoice.invoice.approve";

    @BeforeEach
    void setUp() {
        service = buildService("deny-only", false, false);

        // cache always misses; scopes active; policies neutral by default
        when(cacheService.getCachedDenyRules(anyString())).thenReturn(null);
        when(cacheService.getCachedUserPermissions(anyString())).thenReturn(null);
        when(cacheService.getCachedRolePermissions(anyString())).thenReturn(null);
        when(cacheService.getCachedScopeContainment(any(), any())).thenReturn(null);
        when(cacheService.getCachedScopeActive(any())).thenReturn(null);
        when(scopeRepository.findActiveFlag(any())).thenReturn(Optional.of(true));
        when(policyService.getApplicablePolicies(anyString(), any())).thenReturn(List.of());
        when(denyRuleRepository.findAllActiveDenyRulesForSubjects(any(), any())).thenReturn(List.of());
        when(assignmentRepository.findActiveAssignmentsForSubjects(any(), any())).thenReturn(List.of());
        when(assignmentRepository.existsActiveConditionalAssignments(anyString(), any())).thenReturn(false);
        when(roleHierarchyRepository.findAllByChildRoleIds(any())).thenReturn(List.of());
        when(resourceGrantRepository.findActiveForResource(any(), any(), any(), any())).thenReturn(List.of());
        when(subjectGroupMemberRepository.findActiveGroupIds(anyString())).thenReturn(List.of());
    }

    private AuthorizationService buildService(String policyMode, boolean grants, boolean groups) {
        return new AuthorizationService(
                assignmentRepository, denyRuleRepository, scopeClosureRepository,
                scopeRepository, rolePermissionRepository, roleHierarchyRepository,
                auditRepository, cacheService, new SimpleMeterRegistry(),
                policyService, new PolicyEvaluator(),
                resourceGrantRepository, subjectGroupMemberRepository,
                policyMode, grants, groups);
    }

    // ── helpers ─────────────────────────────────────────────────────────

    private AuthorizationRequest request(String permission, UUID scopeId) {
        return request(permission, scopeId, null);
    }

    private AuthorizationRequest request(String permission, UUID scopeId,
                                         AuthorizationRequest.RequestContext ctx) {
        return AuthorizationRequest.builder()
                .subject(SUBJECT)
                .permission(permission)
                .resource(AuthorizationRequest.ResourceContext.builder()
                        .type("invoice").id("INV-1").scopeId(scopeId).build())
                .context(ctx)
                .build();
    }

    private void grantRole(Map<String, Object> conditions, String... permissions) {
        Assignment a = Assignment.builder()
                .id(UUID.randomUUID()).subjectId(SUBJECT).roleId(ROLE).scopeId(ORG_SCOPE)
                .grantedBy("test").active(true)
                .conditions(conditions == null ? Map.of() : conditions)
                .build();
        when(assignmentRepository.findActiveAssignmentsForSubjects(any(), any()))
                .thenReturn(List.of(a));
        when(scopeClosureRepository.scopeContains(ORG_SCOPE, PROJECT_SCOPE)).thenReturn(true);
        when(rolePermissionRepository.findPermissionKeysByRoleIds(Set.of(ROLE)))
                .thenReturn(Set.of(permissions));
    }

    private void denyRule(String permissionKey, UUID scopeId) {
        DenyRule rule = DenyRule.builder()
                .id(UUID.randomUUID()).subjectId(SUBJECT).permissionKey(permissionKey)
                .scopeId(scopeId).reason("test").createdBy("test").active(true).build();
        when(denyRuleRepository.findAllActiveDenyRulesForSubjects(any(), any()))
                .thenReturn(List.of(rule));
    }

    private Policy policy(String effect, String permissionKey, Map<String, Object> conditions) {
        Policy p = Policy.builder()
                .id(UUID.randomUUID()).name("p-" + effect + "-" + UUID.randomUUID())
                .permissionKey(permissionKey).effect(effect).priority(0)
                .conditions(conditions).active(true).build();
        when(policyService.getApplicablePolicies(anyString(), any())).thenReturn(List.of(p));
        return p;
    }

    // ── RBAC × scope ─────────────────────────────────────────────

    @Test
    void allowsWhenRoleGrantsPermissionAtAncestorScope() {
        grantRole(null, PERM);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized());
    }

    @Test
    void deniesWhenPermissionNotGrantedByAnyRole() {
        grantRole(null, "invoice.invoice.read");
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
        assertEquals("DENY: Permission not granted by any role", r.getReason());
    }

    @Test
    void deniesWhenAssignmentScopeDoesNotContainResourceScope() {
        grantRole(null, PERM);
        when(scopeClosureRepository.scopeContains(ORG_SCOPE, PROJECT_SCOPE)).thenReturn(false);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void deniesWhenNoAssignmentsExist() {
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void roleHierarchyGrantsParentPermissionsToChildRole() {
        UUID parentRole = UUID.randomUUID();
        grantRole(null, "invoice.invoice.read"); // own perms only
        when(roleHierarchyRepository.findAllByChildRoleIds(Set.of(ROLE)))
                .thenReturn(List.of(io.github.mesubash.iam.authz.entity.RoleHierarchy.builder()
                        .parentRoleId(parentRole).childRoleId(ROLE).build()));
        when(rolePermissionRepository.findPermissionKeysByRoleIds(Set.of(ROLE, parentRole)))
                .thenReturn(Set.of("invoice.invoice.read", PERM));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized());
    }

    // ── deny rules ──────────────────────────────────────────────────

    @Test
    void explicitDenyRuleWinsOverRoleGrant() {
        grantRole(null, PERM);
        denyRule(PERM, null);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
        assertEquals("DENY: Explicit deny rule exists", r.getReason());
    }

    @Test
    void fullWildcardDenyMatchesAnyPermission() {
        grantRole(null, PERM);
        denyRule("*.*.*", null);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void segmentWildcardDenyMatches() {
        grantRole(null, PERM);
        denyRule("invoice.*.approve", null);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void trailingDoubleStarDenyMatchesAnyDepth() {
        String deepPerm = "hgn.order.insurance.create";
        grantRole(null, deepPerm);
        denyRule("hgn.order.**", null);
        AuthorizationResponse r = service.authorize(request(deepPerm, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void doubleStarAloneDeniesEverything() {
        grantRole(null, PERM);
        denyRule("**", null);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    // ── scope validity ──────────────────────────────────────────────

    @Test
    void inactiveScopeDeniesBeforeAnyOtherCheck() {
        grantRole(null, PERM);
        when(scopeRepository.findActiveFlag(PROJECT_SCOPE)).thenReturn(Optional.of(false));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
        assertEquals("DENY: Scope inactive or not found", r.getReason());
    }

    @Test
    void scopedDenyAppliesOnlyWithinItsSubtree() {
        grantRole(null, PERM);
        UUID otherScope = UUID.randomUUID();
        denyRule(PERM, otherScope);
        when(scopeClosureRepository.scopeContains(otherScope, PROJECT_SCOPE)).thenReturn(false);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized()); // deny scope does not contain resource scope
    }

    // ── assignment conditions ───────────────────────────────────────

    @Test
    void timeWindowConditionDeniesOutsideWindow() {
        grantRole(Map.of("time_window", "09:00-17:00", "timezone", "UTC"), PERM);
        AuthorizationRequest.RequestContext ctx = AuthorizationRequest.RequestContext.builder()
                .timestamp(Instant.parse("2026-07-04T22:30:00Z")).build();
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE, ctx));
        assertFalse(r.getAuthorized());
        assertEquals("DENY: Outside allowed time window", r.getReason());
    }

    @Test
    void timeWindowConditionAllowsInsideWindow() {
        grantRole(Map.of("time_window", "09:00-17:00", "timezone", "UTC"), PERM);
        AuthorizationRequest.RequestContext ctx = AuthorizationRequest.RequestContext.builder()
                .timestamp(Instant.parse("2026-07-04T14:00:00Z")).build();
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE, ctx));
        assertTrue(r.getAuthorized());
    }

    @Test
    void ipRangeConditionDeniesOutsideCidr() {
        grantRole(Map.of("ip_ranges", List.of("203.0.113.0/24")), PERM);
        AuthorizationRequest.RequestContext ctx = AuthorizationRequest.RequestContext.builder()
                .ipAddress("198.51.100.7").build();
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE, ctx));
        assertFalse(r.getAuthorized());
    }

    @Test
    void mfaConditionDeniesWithoutMfaContext() {
        grantRole(Map.of("require_mfa", true), PERM);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
        assertEquals("DENY: MFA required", r.getReason());
    }

    @Test
    void separationOfDutiesDeniesOwnerApproval() {
        grantRole(Map.of("cannot_approve_own_created", true), PERM);
        AuthorizationRequest req = AuthorizationRequest.builder()
                .subject(SUBJECT).permission(PERM)
                .resource(AuthorizationRequest.ResourceContext.builder()
                        .type("invoice").id("INV-1").scopeId(PROJECT_SCOPE)
                        .metadata(Map.of("ownerId", SUBJECT)).build())
                .build();
        AuthorizationResponse r = service.authorize(req);
        assertFalse(r.getAuthorized());
    }

    // ── policies ────────────────────────────────────────────────────

    @Test
    void matchingDenyPolicyDenies() {
        grantRole(null, PERM);
        policy("DENY", PERM, Map.of("field", "subject", "op", "eq", "value", SUBJECT));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void nonMatchingDenyPolicyIsNeutral() {
        grantRole(null, PERM);
        policy("DENY", PERM, Map.of("field", "subject", "op", "eq", "value", "someone-else"));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized());
    }

    @Test
    void denyOnlyModeIgnoresAllowPolicies() {
        grantRole(null, PERM);
        policy("ALLOW", PERM, Map.of("field", "subject", "op", "eq", "value", "someone-else"));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized()); // ALLOW policies are inert in deny-only mode
    }

    @Test
    void requiredAllowModeDeniesWhenNoAllowPolicyMatches() {
        service = buildService("required-allow", false, false);
        grantRole(null, PERM);
        policy("ALLOW", PERM, Map.of("field", "subject", "op", "eq", "value", "someone-else"));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
        assertEquals("DENY: No ALLOW policy matched", r.getReason());
    }

    @Test
    void requiredAllowModeAllowsWhenAllowPolicyMatches() {
        service = buildService("required-allow", false, false);
        grantRole(null, PERM);
        policy("ALLOW", PERM, Map.of("field", "subject", "op", "eq", "value", SUBJECT));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized());
    }

    @Test
    void shadowPolicyNeverAffectsDecision() {
        grantRole(null, PERM);
        Policy p = Policy.builder()
                .id(UUID.randomUUID()).name("shadow-deny")
                .permissionKey(PERM).effect("DENY").priority(0)
                .enforcementMode("SHADOW")
                .conditions(Map.of("field", "subject", "op", "eq", "value", SUBJECT))
                .active(true).build();
        when(policyService.getApplicablePolicies(anyString(), any())).thenReturn(List.of(p));
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized()); // would-deny recorded in audit, decision unaffected
    }

    // ── resource grants & groups ────────────────────────────────────────

    private void grantResource(String permissionKey) {
        ResourceGrant grant = ResourceGrant.builder()
                .id(UUID.randomUUID()).subjectId(SUBJECT)
                .permissionKey(permissionKey).resourceType("invoice").resourceId("INV-1")
                .grantedBy("test").build();
        when(resourceGrantRepository.findActiveForResource(any(), eq("invoice"), eq("INV-1"), any()))
                .thenReturn(List.of(grant));
    }

    @Test
    void resourceGrantAllowsWithoutAnyRole() {
        service = buildService("deny-only", true, false);
        grantResource(PERM);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized());
        assertEquals("ALLOW: Permission granted via resource grant", r.getReason());
    }

    @Test
    void resourceGrantRescuesFailedRoleConditions() {
        service = buildService("deny-only", true, false);
        grantRole(Map.of("require_mfa", true), PERM); // role path fails without MFA
        grantResource(PERM);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized()); // grant path independent of role conditions
    }

    @Test
    void denyRuleStillBeatsResourceGrant() {
        service = buildService("deny-only", true, false);
        grantResource(PERM);
        denyRule(PERM, null);
        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertFalse(r.getAuthorized());
    }

    @Test
    void actionWildcardGrantMatchesOnlyItsResourcePath() {
        service = buildService("deny-only", true, false);
        grantResource("invoice.invoice.*");
        assertTrue(service.authorize(request(PERM, PROJECT_SCOPE)).getAuthorized());
        assertFalse(service.authorize(request("invoice.other.approve", PROJECT_SCOPE)).getAuthorized());
    }

    @Test
    void groupAssignmentGrantsPermissionToMember() {
        service = buildService("deny-only", false, true);
        UUID groupId = UUID.randomUUID();
        when(subjectGroupMemberRepository.findActiveGroupIds(SUBJECT)).thenReturn(List.of(groupId));

        Assignment groupAssignment = Assignment.builder()
                .id(UUID.randomUUID()).subjectId(groupId.toString()).subjectType("GROUP")
                .roleId(ROLE).scopeId(ORG_SCOPE).grantedBy("test").active(true)
                .conditions(Map.of()).build();
        when(assignmentRepository.findActiveAssignmentsForSubjects(any(), any()))
                .thenReturn(List.of(groupAssignment));
        when(scopeClosureRepository.scopeContains(ORG_SCOPE, PROJECT_SCOPE)).thenReturn(true);
        when(rolePermissionRepository.findPermissionKeysByRoleIds(Set.of(ROLE)))
                .thenReturn(Set.of(PERM));

        AuthorizationResponse r = service.authorize(request(PERM, PROJECT_SCOPE));
        assertTrue(r.getAuthorized());
    }

    // ── failure modes ───────────────────────────────────────────────────

    @Test
    void infrastructureFailureThrows503NotDeny() {
        when(denyRuleRepository.findAllActiveDenyRulesForSubjects(any(), any()))
                .thenThrow(new RuntimeException("db down"));
        assertThrows(AuthorizationServiceException.class,
                () -> service.authorize(request(PERM, PROJECT_SCOPE)));
    }
}
