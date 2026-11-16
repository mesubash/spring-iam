package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.dto.AdminUpdateStatusRequest;
import io.github.mesubash.iam.authn.dto.CredentialAdminView;
import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.repository.SecurityEventRepository;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Admin identity actions against real Postgres: peer-safe guard, verify-only, credentials view. */
@SpringBootTest
class IdentityAdminIntegrationTest {

    private static final UUID ROOT_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SUPER_ADMIN_ROLE = UUID.fromString("10000000-0000-0000-0000-000000000001");

    @Autowired private IdentityAdminService service;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private CredentialRepository credentialRepository;
    @Autowired private AssignmentRepository assignmentRepository;
    @Autowired private SecurityEventRepository securityEventRepository;

    private Identity newIdentity() {
        return identityRepository.save(Identity.builder()
                .primaryEmail("admin-test-" + UUID.randomUUID() + "@example.com")
                .emailVerified(false).accountStatus(AccountStatus.ACTIVE).build());
    }

    private Identity newSuperAdmin() {
        Identity identity = newIdentity();
        assignmentRepository.save(Assignment.builder().subjectId(identity.getId().toString())
                .roleId(SUPER_ADMIN_ROLE).scopeId(ROOT_SCOPE).grantedBy("test").grantedAt(Instant.now()).build());
        return identity;
    }

    private static UserPrincipal as(Identity identity, String role) {
        return UserPrincipal.create(identity, null, List.of(role));
    }

    @Test
    void superAdminTargetIsPeerSafeForNonRecoveryChanges() {
        Identity target = newSuperAdmin();
        UserPrincipal otherSuperAdmin = as(newIdentity(), "SuperAdmin");
        UserPrincipal securityAdmin = as(newIdentity(), "SecurityAdmin");
        UUID id = target.getId();

        assertThrows(ForbiddenException.class, () -> service.markEmailVerified(securityAdmin, id));
        assertThrows(ForbiddenException.class, () -> service.markEmailVerified(otherSuperAdmin, id));
        assertThrows(ForbiddenException.class, () -> service.setDisplayName(otherSuperAdmin, id, "X"));
        assertThrows(ForbiddenException.class, () -> service.updateStatus(otherSuperAdmin, id,
                new AdminUpdateStatusRequest("SUSPENDED", null)));

        // Acting on your own account is fine.
        assertEquals("Me", service.setDisplayName(as(target, "SuperAdmin"), id, "  Me ").displayName());
    }

    @Test
    void markEmailVerifiedIsVerifyOnlyAndAudited() throws InterruptedException {
        Identity target = newIdentity();
        UserPrincipal admin = as(newIdentity(), "SecurityAdmin");

        assertTrue(service.markEmailVerified(admin, target.getId()).emailVerified());
        assertTrue(identityRepository.findById(target.getId()).orElseThrow().getEmailVerified());

        // The event write is async; the CHECK constraint must accept it.
        long found = 0;
        for (int i = 0; i < 50 && found == 0; i++) {
            found = securityEventRepository.search(target.getId(), SecurityEventType.EMAIL_VERIFIED,
                    OffsetDateTime.now().minusMinutes(5), PageRequest.of(0, 10)).getTotalElements();
            if (found == 0) Thread.sleep(100);
        }
        assertEquals(1, found);
    }

    @Test
    void blankDisplayNameClearsIt() {
        Identity target = newIdentity();
        UserPrincipal admin = as(newIdentity(), "AccessAdmin");
        service.setDisplayName(admin, target.getId(), "Jane");
        assertNull(service.setDisplayName(admin, target.getId(), "  ").displayName());
    }

    @Test
    void credentialsAreMaskedAndSecretFree() {
        Identity target = newIdentity();
        credentialRepository.save(Credential.builder().identity(target)
                .credentialType(CredentialType.PASSWORD).identifier("ja" + UUID.randomUUID() + "@example.com")
                .secretHash("$2a$12$secret").build());

        List<CredentialAdminView> views = service.credentials(target.getId());
        assertEquals(1, views.size());
        assertEquals("PASSWORD", views.get(0).type());
        assertEquals("ja***@example.com", views.get(0).identifier());
    }
}
