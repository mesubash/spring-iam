package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyIterable;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Role names become ROLE_* authorities, so a claim must never be spoofable by naming. */
class RoleClaimsTest {

    private static final UUID ROOT = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID TENANT = UUID.randomUUID();
    private static final Role SUPER_ADMIN = role("10000000-0000-0000-0000-000000000001", "SuperAdmin", true, null);
    private static final Role SECURITY_ADMIN = role("10000000-0000-0000-0000-000000000004", "SecurityAdmin", true, null);

    private AssignmentRepository assignments;
    private RoleRepository roles;
    private AuthzQueryServiceImpl service;

    @BeforeEach
    void setUp() {
        assignments = mock(AssignmentRepository.class);
        roles = mock(RoleRepository.class);
        when(roles.findByIsSystemRoleTrue()).thenReturn(List.of(SUPER_ADMIN, SECURITY_ADMIN));
        service = new AuthzQueryServiceImpl(assignments, roles, mock(ScopeRepository.class),
                mock(AuthorizationService.class));
    }

    private List<String> claimsFor(Role role, UUID scope) {
        when(assignments.findActiveAssignments(anyString(), any()))
                .thenReturn(List.of(Assignment.builder().roleId(role.getId()).scopeId(scope).build()));
        when(roles.findAllById(anyIterable())).thenAnswer(inv -> {
            List<Role> out = new java.util.ArrayList<>();
            ((Iterable<UUID>) inv.getArgument(0)).forEach(id -> { if (id.equals(role.getId())) out.add(role); });
            return out;
        });
        return service.getRolesForIdentity(UUID.randomUUID()).getRoles();
    }

    @Test
    void superAdminAtRootIsClaimed() {
        assertThat(claimsFor(SUPER_ADMIN, ROOT)).containsExactly("SuperAdmin");
    }

    @Test
    void superAdminOutsideRootIsNotClaimed() {
        assertThat(claimsFor(SUPER_ADMIN, TENANT)).isEmpty();
    }

    @Test
    void tenantRoleNamedLikeBuiltInIsNotClaimed() {
        assertThat(claimsFor(role(UUID.randomUUID().toString(), "SuperAdmin", false, TENANT), TENANT)).isEmpty();
        assertThat(claimsFor(role(UUID.randomUUID().toString(), "SecurityAdmin", false, TENANT), TENANT)).isEmpty();
    }

    @Test
    void ordinaryTenantRoleIsClaimed() {
        assertThat(claimsFor(role(UUID.randomUUID().toString(), "Billing", false, TENANT), TENANT))
                .containsExactly("Billing");
    }

    private static Role role(String id, String name, boolean system, UUID owner) {
        return Role.builder().id(UUID.fromString(id)).name(name).isSystemRole(system)
                .ownerScopeId(owner).active(true).build();
    }
}
