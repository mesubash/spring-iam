package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.shared.exception.ConflictException;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Role deletion against real Postgres: the active-assignment guard and the revoked-row FK. */
@SpringBootTest
class RoleDeleteIntegrationTest {

    private static final UUID ROOT_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Autowired private RoleService roleService;
    @Autowired private RoleRepository roleRepository;
    @Autowired private AssignmentRepository assignmentRepository;

    private static UserPrincipal caller(String role) {
        return UserPrincipal.create(Identity.builder().id(UUID.randomUUID())
                .primaryEmail("caller@example.com").build(), null, List.of(role));
    }

    @Test
    void refusesWhileAssignedThenDeletesOnceRevoked() {
        Role role = roleRepository.save(Role.builder()
                .name("Deletable" + UUID.randomUUID().toString().substring(0, 8))
                .isSystemRole(false).active(true).createdBy("test").build());
        Assignment grant = assignmentRepository.save(Assignment.builder()
                .subjectId(UUID.randomUUID().toString()).roleId(role.getId()).scopeId(ROOT_SCOPE)
                .grantedBy("test").grantedAt(Instant.now()).build());

        assertThrows(ForbiddenException.class, () -> roleService.delete(caller("SecurityAdmin"), role.getId()));
        assertThrows(ConflictException.class, () -> roleService.delete(caller("SuperAdmin"), role.getId()));

        // Revoked, the row still references the role and would block a plain delete.
        grant.setRevokedAt(Instant.now());
        grant.setRevokedBy("test");
        grant.setActive(false);
        assignmentRepository.save(grant);

        roleService.delete(caller("SuperAdmin"), role.getId());
        assertFalse(roleRepository.existsById(role.getId()));
        assertFalse(assignmentRepository.existsById(grant.getId()));
    }

    @Test
    void refusesSystemRole() {
        Role system = roleRepository.findAll().stream()
                .filter(r -> Boolean.TRUE.equals(r.getIsSystemRole())).findFirst().orElseThrow();
        assertThrows(IllegalArgumentException.class, () -> roleService.delete(caller("SuperAdmin"), system.getId()));
    }
}
