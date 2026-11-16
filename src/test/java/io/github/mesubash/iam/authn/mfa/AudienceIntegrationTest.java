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
}
