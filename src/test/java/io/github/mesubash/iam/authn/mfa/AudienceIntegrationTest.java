package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.LoginResult;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Per-app audiences across password login, refresh, MFA and SSO. */
@SpringBootTest(properties = {
        "app.jwt.allowed-audiences=portal,billing",
        "iam.sso.login-url=http://localhost:3000/login",
        "iam.sso.consent-url=http://localhost:3000/consent"
})
@AutoConfigureMockMvc
class AudienceIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-Battery-9";
    private static final String APP = "http://localhost:3000/sso/callback";

    @Autowired private MockMvc mvc;
    @Autowired private AuthService authService;
    @Autowired private MfaService mfaService;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private TokenEncryptionUtil encryption;
    @Autowired private JwtTokenProvider jwt;
    @Autowired private org.springframework.data.redis.core.StringRedisTemplate redis;
    @Autowired private io.github.mesubash.iam.authz.repository.PermissionRepository permissionRepository;
    @Autowired private io.github.mesubash.iam.authz.repository.RoleRepository roleRepository;
    @Autowired private io.github.mesubash.iam.authz.repository.RolePermissionRepository rolePermissionRepository;
    @Autowired private io.github.mesubash.iam.authz.repository.AssignmentRepository assignmentRepository;
    @Autowired private io.github.mesubash.iam.authz.repository.ServiceClientRepository serviceClientRepository;

    private String newVerifiedUser() {
        String email = "aud-" + UUID.randomUUID() + "@example.com";
        RegisterRequest register = new RegisterRequest();
        register.setEmail(email);
        register.setPassword(PASSWORD);
        authService.register(register);
        identityRepository.findByPrimaryEmail(email).ifPresent(i -> {
            i.setEmailVerified(true);
            identityRepository.save(i);
        });
        return email;
    }

    private LoginResult login(String email, String audience) {
        LoginRequest req = new LoginRequest();
        req.setEmail(email);
        req.setPassword(PASSWORD);
        req.setAudience(audience);
        return authService.login(req, "203.0.113.5", "junit");
    }

    private Object aud(JwtResponse tokens) {
        return jwt.parseToken(tokens.getAccessToken()).getAudience();
    }

    @Test
    void loginWithoutAudienceGetsTheDefault() {
        assertThat(aud(login(newVerifiedUser(), null).tokens())).isEqualTo(java.util.Set.of("portal"));
    }

    @Test
    void loginWithAudienceKeepsItAcrossRefresh() {
        JwtResponse tokens = login(newVerifiedUser(), "billing").tokens();
        assertThat(aud(tokens)).isEqualTo(java.util.Set.of("billing"));
        assertThat(aud(authService.refreshToken(tokens.getRefreshToken()))).isEqualTo(java.util.Set.of("billing"));
    }

    @Test
    void unknownAudienceIsRejected() throws Exception {
        String email = newVerifiedUser();
        assertThatThrownBy(() -> login(email, "elsewhere")).isInstanceOf(BadRequestException.class);
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD
                                + "\",\"audience\":\"elsewhere\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void mfaLoginKeepsTheRequestedAudience() throws Exception {
        String email = newVerifiedUser();
        UUID id = identityRepository.findByPrimaryEmail(email).orElseThrow().getId();
        String secret = mfaService.setup(id, email).secret();
        long step = System.currentTimeMillis() / 1000L / 30;
        mfaService.enable(id, TotpServiceTest.codeFor(secret, step));

        LoginResult first = login(email, "billing");
        assertThat(first.status()).isEqualTo(LoginResult.Status.MFA_REQUIRED);
        JwtResponse tokens = authService.verifyMfaAndIssue(first.mfaToken(),
                TotpServiceTest.codeFor(secret, step + 1), null, "junit");
        assertThat(aud(tokens)).isEqualTo(java.util.Set.of("billing"));
    }

    @Test
    void ssoMintsTheAudienceTheAppAsksFor() throws Exception {
        JwtResponse hub = login(newVerifiedUser(), null).tokens(); // a portal session
        authService.grantSsoConsent(UUID.fromString(jwt.parseToken(hub.getAccessToken()).getSubject()),
                "http://localhost:3000");
        Cookie cookie = new Cookie("__Host-Refresh", encryption.encrypt(hub.getRefreshToken()));

        String back = mvc.perform(get("/api/auth/sso/authorize?redirect_uri=" + APP + "&prompt=none&audience=billing")
                        .cookie(cookie))
                .andExpect(status().isFound()).andReturn().getResponse().getRedirectedUrl();
        String code = UriComponentsBuilder.fromUriString(back).build().getQueryParams().getFirst("code");
        JwtResponse app = authService.exchangeOAuthCode(code, null, "junit").tokens();
        assertThat(aud(app)).isEqualTo(java.util.Set.of("billing"));
        assertThat(aud(authService.refreshToken(app.getRefreshToken()))).isEqualTo(java.util.Set.of("billing"));

        mvc.perform(get("/api/auth/sso/authorize?redirect_uri=" + APP + "&prompt=none&audience=elsewhere")
                        .cookie(cookie))
                .andExpect(status().isBadRequest());
    }

    @Test
    void oauthExchangeUsesTheAudienceTheFlowStartedWith() {
        UUID id = identityRepository.findByPrimaryEmail(newVerifiedUser()).orElseThrow().getId();
        String prefix = io.github.mesubash.iam.authn.security.oauth2.OAuth2AuthenticationSuccessHandler.EXCHANGE_PREFIX;
        redis.opsForValue().set(prefix + "c1", encryption.encrypt(id + " google billing"));
        redis.opsForValue().set(prefix + "c2", encryption.encrypt(id + " google elsewhere"));

        JwtResponse tokens = authService.exchangeOAuthCode("c1", null, "junit").tokens();
        assertThat(aud(tokens)).isEqualTo(java.util.Set.of("billing"));
        assertThat(jwt.parseToken(tokens.getAccessToken()).get("amr")).isEqualTo(java.util.List.of("google"));
        assertThatThrownBy(() -> authService.exchangeOAuthCode("c2", null, "junit"))
                .isInstanceOf(BadRequestException.class);
    }

    private io.github.mesubash.iam.authz.entity.Permission permission(String key) {
        String[] seg = key.split("\\.");
        return permissionRepository.findByKey(key).orElseGet(() -> permissionRepository.save(
                io.github.mesubash.iam.authz.entity.Permission.builder().key(key).domain(seg[0])
                        .resource(seg[1]).action(seg[2]).createdBy("test").build()));
    }

    private String[] mePermissions(JwtResponse tokens) throws Exception {
        String bearer = "Bearer " + tokens.getAccessToken();
        String perms = mvc.perform(get("/api/authz/me/permissions")
                        .param("scopeId", "00000000-0000-0000-0000-000000000001").header("Authorization", bearer))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String boot = mvc.perform(get("/api/authz/me/bootstrap").header("Authorization", bearer))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        java.util.List<String> fromPerms = com.jayway.jsonpath.JsonPath.read(perms, "$.data");
        java.util.List<String> fromBoot = com.jayway.jsonpath.JsonPath.read(boot, "$.data.permissions");
        assertThat(fromBoot).containsExactlyInAnyOrderElementsOf(fromPerms);
        return fromPerms.toArray(String[]::new);
    }

    @Test
    void mePermissionsAreScopedToTheAudiencesRegisteredDomains() throws Exception {
        if (serviceClientRepository.findByName("billing").isEmpty()) {
            serviceClientRepository.save(io.github.mesubash.iam.authz.entity.ServiceClient.builder()
                    .name("billing").displayName("Billing").ownedDomains(java.util.List.of("billing"))
                    .apiKeyHash("not-a-key-" + UUID.randomUUID()).createdAt(java.time.Instant.now()).build());
        }
        var role = roleRepository.save(io.github.mesubash.iam.authz.entity.Role.builder()
                .name("AudScoped" + UUID.randomUUID().toString().substring(0, 8))
                .isSystemRole(false).active(true).createdBy("test").build());
        for (String key : new String[]{"billing.invoice.read", "sales.order.read"}) {
            rolePermissionRepository.save(io.github.mesubash.iam.authz.entity.RolePermission.builder()
                    .roleId(role.getId()).permissionId(permission(key).getId())
                    .grantedAt(java.time.Instant.now()).grantedBy("test").build());
        }
        String email = newVerifiedUser();
        UUID id = identityRepository.findByPrimaryEmail(email).orElseThrow().getId();
        assignmentRepository.save(io.github.mesubash.iam.authz.entity.Assignment.builder()
                .subjectId(id.toString()).roleId(role.getId())
                .scopeId(UUID.fromString("00000000-0000-0000-0000-000000000001"))
                .grantedBy("test").grantedAt(java.time.Instant.now()).build());

        // billing is registered and owns "billing": its token sees only that domain.
        assertThat(mePermissions(login(email, "billing").tokens())).containsExactly("billing.invoice.read");
        // portal has no registered service: unfiltered.
        assertThat(mePermissions(login(email, "portal").tokens()))
                .containsExactlyInAnyOrder("billing.invoice.read", "sales.order.read");
    }
}
