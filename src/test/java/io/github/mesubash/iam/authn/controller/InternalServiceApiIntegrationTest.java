package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.token.SessionService;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Internal account and provisioning APIs: API-key auth and the platform-admin floors. */
@SpringBootTest(properties = "iam.security.internal-api-key=test-internal-key")
@AutoConfigureMockMvc
class InternalServiceApiIntegrationTest {

    private static final UUID ROOT_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID EXAMPLE_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000010");
    private static final UUID SUPER_ADMIN_ROLE = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID SECURITY_ADMIN_ROLE = UUID.fromString("10000000-0000-0000-0000-000000000004");
    private static final String HASH = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z3mCqLW8e1Z0o5yJ1Z1Z1Z1e";

    @Autowired private MockMvc mvc;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private AssignmentRepository assignmentRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private SessionService sessionService;

    private static MockHttpServletRequestBuilder key(MockHttpServletRequestBuilder req) {
        return req.header("X-Internal-Api-Key", "test-internal-key").contentType(MediaType.APPLICATION_JSON);
    }

    private Identity newIdentity() {
        return identityRepository.save(Identity.builder()
                .primaryEmail("internal-" + UUID.randomUUID() + "@example.com")
                .emailVerified(false).accountStatus(AccountStatus.ACTIVE).build());
    }

    private Identity holding(UUID roleId, UUID scopeId) {
        Identity identity = newIdentity();
        assignmentRepository.save(Assignment.builder().subjectId(identity.getId().toString())
                .roleId(roleId).scopeId(scopeId).grantedBy("test").grantedAt(Instant.now()).build());
        return identity;
    }

    private Role appRole() {
        return roleRepository.save(Role.builder().name("App_" + UUID.randomUUID().toString().replace("-", "")).isSystemRole(false)
                .active(true).createdBy("test").build());
    }

    private static String grant(String subject, UUID role, UUID scope) {
        return "{\"subjectId\":\"" + subject + "\",\"roleId\":\"" + role + "\",\"scopeId\":\"" + scope + "\"}";
    }

    @Test
    void requiresAnApiKey() throws Exception {
        mvc.perform(get("/api/v1/internal/accounts").param("email", "nobody@example.com"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/internal/accounts").param("email", "nobody@example.com")
                        .header("X-Internal-Api-Key", "wrong")).andExpect(status().isUnauthorized());
    }

    @Test
    void createsLooksUpAndDiscardsAnUnusedAccount() throws Exception {
        String email = "created-" + UUID.randomUUID() + "@example.com";
        mvc.perform(key(post("/api/v1/internal/accounts"))
                        .content("{\"email\":\"" + email + "\",\"passwordHash\":\"" + HASH + "\",\"verified\":false}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.provider").value("LOCAL"))
                .andExpect(jsonPath("$.emailVerified").value(false))
                .andExpect(jsonPath("$.secretHash").doesNotExist());
        mvc.perform(key(post("/api/v1/internal/accounts")).content("{\"email\":\"" + email + "\"}"))
                .andExpect(status().isConflict());

        Identity created = identityRepository.findByPrimaryEmail(email).orElseThrow();
        created.setDisplayName("Ada");
        identityRepository.save(created);
        mvc.perform(key(get("/api/v1/internal/accounts")).param("email", email))
                .andExpect(status().isOk()).andExpect(jsonPath("$.displayName").value("Ada"));
        mvc.perform(key(post("/api/v1/internal/accounts/" + created.getId() + "/verification-token")))
                .andExpect(status().isOk()).andExpect(jsonPath("$.token").isNotEmpty());

        mvc.perform(key(delete("/api/v1/internal/accounts/" + created.getId()))).andExpect(status().isNoContent());
        assertThat(identityRepository.findById(created.getId())).isEmpty();
        mvc.perform(key(delete("/api/v1/internal/accounts/" + created.getId()))).andExpect(status().isNoContent());
    }

    @Test
    void refusesToDiscardAnAccountInUse() throws Exception {
        Identity used = newIdentity();
        used.setLastLoginAt(OffsetDateTime.now());
        identityRepository.save(used);
        mvc.perform(key(delete("/api/v1/internal/accounts/" + used.getId()))).andExpect(status().isConflict());

        Identity granted = holding(appRole().getId(), EXAMPLE_SCOPE);
        mvc.perform(key(delete("/api/v1/internal/accounts/" + granted.getId()))).andExpect(status().isConflict());
    }

    @Test
    void accountWritesAreRefusedOnPlatformAdmins() throws Exception {
        // SuperAdmin, and any role held at ROOT, count as platform administration.
        for (Identity admin : new Identity[] {
                holding(SUPER_ADMIN_ROLE, ROOT_SCOPE), holding(SECURITY_ADMIN_ROLE, ROOT_SCOPE)}) {
            String base = "/api/v1/internal/accounts/" + admin.getId();
            mvc.perform(key(put(base + "/password")).content("{\"passwordHash\":\"" + HASH + "\"}"))
                    .andExpect(status().isForbidden());
            mvc.perform(key(put(base + "/verify"))).andExpect(status().isForbidden());
            mvc.perform(key(post(base + "/deactivate"))).andExpect(status().isForbidden());
            mvc.perform(key(post(base + "/verify-password")).content("{\"password\":\"guess\"}"))
                    .andExpect(status().isForbidden());
            Identity after = identityRepository.findById(admin.getId()).orElseThrow();
            assertThat(after.getEmailVerified()).isFalse();
            assertThat(after.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
        }
    }

    @Test
    void settingAPasswordCanEndSessions() throws Exception {
        Identity user = newIdentity();
        sessionService.createSession(user.getId(), "203.0.113.5", "junit");
        mvc.perform(key(put("/api/v1/internal/accounts/" + user.getId() + "/password"))
                        .content("{\"passwordHash\":\"" + HASH + "\",\"endSessions\":true}"))
                .andExpect(status().isNoContent());
        assertThat(sessionService.listActiveSessions(user.getId())).isEmpty();
    }

    @Test
    void provisioningRefusesPlatformEscalation() throws Exception {
        String subject = newIdentity().getId().toString();
        mvc.perform(key(post("/api/v1/internal/provisioning/grants"))
                        .content(grant(subject, SUPER_ADMIN_ROLE, ROOT_SCOPE))).andExpect(status().isForbidden());
        mvc.perform(key(post("/api/v1/internal/provisioning/grants"))
                        .content(grant(subject, appRole().getId(), ROOT_SCOPE))).andExpect(status().isForbidden());
        mvc.perform(key(post("/api/v1/internal/provisioning/grants"))
                        .content(grant(subject, SECURITY_ADMIN_ROLE, EXAMPLE_SCOPE))).andExpect(status().isForbidden());
        assertThat(assignmentRepository.findActiveAssignments(subject, Instant.now())).isEmpty();

        // An admin-made grant is not this API's to revoke, even outside ROOT.
        Identity admin = holding(SUPER_ADMIN_ROLE, ROOT_SCOPE);
        UUID adminGrant = assignmentRepository.findActiveAssignments(admin.getId().toString(), Instant.now())
                .get(0).getId();
        mvc.perform(key(delete("/api/v1/internal/provisioning/grants/" + adminGrant)))
                .andExpect(status().isNotFound());
        assertThat(assignmentRepository.findById(adminGrant).orElseThrow().getActive()).isTrue();
    }

    @Test
    void provisioningGrantsListsAndRevokesItsOwnGrants() throws Exception {
        String subject = newIdentity().getId().toString();
        UUID role = appRole().getId();
        for (int i = 0; i < 2; i++) { // idempotent
            mvc.perform(key(post("/api/v1/internal/provisioning/grants")).content(grant(subject, role, EXAMPLE_SCOPE)))
                    .andExpect(status().isNoContent());
        }
        Assignment made = assignmentRepository.findBySubjectRoleScope(subject, role, EXAMPLE_SCOPE).orElseThrow();
        assertThat(made.getOrigin()).isEqualTo("PROVISIONED");
        assertThat(made.getGrantedBy()).isEqualTo("internal-client");

        mvc.perform(key(get("/api/v1/internal/provisioning/grants")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.assignmentId == '" + made.getId() + "')]").exists())
                .andExpect(jsonPath("$[?(@.roleId == '" + SUPER_ADMIN_ROLE + "')]").doesNotExist());

        mvc.perform(key(delete("/api/v1/internal/provisioning/grants/" + made.getId())))
                .andExpect(status().isNoContent());
        assertThat(assignmentRepository.findById(made.getId()).orElseThrow().getActive()).isFalse();
    }
}
