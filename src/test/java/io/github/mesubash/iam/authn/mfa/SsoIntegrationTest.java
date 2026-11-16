package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.LoginResult;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.shared.exception.InvalidTokenException;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** SSO authorize end to end: allowlist, silent checks, consent, single-use codes, the MFA gate. */
@SpringBootTest(properties = {
        "iam.sso.login-url=http://localhost:3000/login",
        "iam.sso.consent-url=http://localhost:3000/consent"
})
@AutoConfigureMockMvc
class SsoIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-Battery-9";
    private static final String APP = "http://localhost:3000/sso/callback";

    @Autowired private MockMvc mvc;
    @Autowired private AuthService authService;
    @Autowired private MfaService mfaService;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private TokenEncryptionUtil encryption;
    @Autowired private JwtTokenProvider jwt;

    private String newVerifiedUser() {
        String email = "sso-" + UUID.randomUUID() + "@example.com";
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

    private LoginResult login(String email) {
        LoginRequest req = new LoginRequest();
        req.setEmail(email);
        req.setPassword(PASSWORD);
        return authService.login(req, "203.0.113.5", "junit");
    }

    private UUID idOf(String email) {
        return identityRepository.findByPrimaryEmail(email).orElseThrow().getId();
    }

    private Cookie session(JwtResponse tokens) {
        return new Cookie("__Host-Refresh", encryption.encrypt(tokens.getRefreshToken()));
    }

    private String authorize(Cookie cookie, String prompt) throws Exception {
        // A real query string (not .param()), so the continue URL is built as it is in production.
        var req = get("/api/auth/sso/authorize?redirect_uri=" + APP + "&state=s1"
                + (prompt == null ? "" : "&prompt=" + prompt));
        if (cookie != null) req.cookie(cookie);
        return mvc.perform(req).andExpect(status().isFound()).andReturn().getResponse().getRedirectedUrl();
    }

    private static Map<String, String> query(String url) {
        return UriComponentsBuilder.fromUriString(url).build().getQueryParams().toSingleValueMap();
    }

    private void consent(JwtResponse tokens) throws Exception {
        mvc.perform(post("/api/auth/sso/consent")
                        .header("Authorization", "Bearer " + tokens.getAccessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"redirect_uri\":\"" + APP + "\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void unknownRedirectIsRejected() throws Exception {
        mvc.perform(get("/api/auth/sso/authorize").param("redirect_uri", "https://evil.example/cb"))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/auth/sso/authorize").param("redirect_uri", "http://localhost:3000.evil.example/cb"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void withoutSessionSilentGoesBackToTheAppAndInteractiveGoesToLogin() throws Exception {
        String silent = authorize(null, "none");
        assertThat(silent).startsWith(APP + "?");
        assertThat(query(silent)).containsEntry("error", "login_required").containsEntry("state", "s1")
                .doesNotContainKey("code");

        String interactive = authorize(null, null);
        assertThat(interactive).startsWith("http://localhost:3000/login?continue=");
        assertThat(java.net.URLDecoder.decode(query(interactive).get("continue"), java.nio.charset.StandardCharsets.UTF_8))
                .contains("/api/auth/sso/authorize").contains("redirect_uri=");
    }

    @Test
    void asksBeforeTheFirstCodeThenIssuesSingleUseCodesThatKeepTheAmr() throws Exception {
        JwtResponse hub = login(newVerifiedUser()).tokens();

        assertThat(query(authorize(session(hub), "none"))).containsEntry("error", "consent_required");
        assertThat(authorize(session(hub), null)).startsWith("http://localhost:3000/consent?redirect_uri=");

        consent(hub);
        Map<String, String> back = query(authorize(session(hub), "none"));
        assertThat(back).containsEntry("state", "s1").containsKey("code");

        LoginResult app = authService.exchangeOAuthCode(back.get("code"), null, "junit");
        assertThat(app.status()).isEqualTo(LoginResult.Status.OK);
        assertThat(app.tokens().getRefreshToken()).isNotEqualTo(hub.getRefreshToken());
        assertThat(jwt.parseToken(app.tokens().getAccessToken()).get("amr")).isEqualTo(List.of("pwd"));

        assertThatThrownBy(() -> authService.exchangeOAuthCode(back.get("code"), null, "junit"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void ssoCannotBypassMfa() throws Exception {
        String email = newVerifiedUser();
        JwtResponse beforeMfa = login(email).tokens(); // amr [pwd]
        consent(beforeMfa);

        UUID id = idOf(email);
        String secret = mfaService.setup(id, email).secret();
        long step = System.currentTimeMillis() / 1000L / 30;
        mfaService.enable(id, TotpServiceTest.codeFor(secret, step));

        // The old single-factor session can no longer sign apps in.
        assertThat(query(authorize(session(beforeMfa), "none"))).containsEntry("error", "login_required");
        assertThat(authorize(session(beforeMfa), null)).startsWith("http://localhost:3000/login?");

        // A session that passed the second factor can, and the app's token says so.
        JwtResponse withMfa = authService.verifyMfaAndIssue(login(email).mfaToken(),
                TotpServiceTest.codeFor(secret, step + 1), null, "junit");
        String code = query(authorize(session(withMfa), "none")).get("code");
        JwtResponse app = authService.exchangeOAuthCode(code, null, "junit").tokens();
        assertThat(jwt.parseToken(app.getAccessToken()).get("amr")).isEqualTo(List.of("pwd", "otp", "mfa"));
    }

    @Test
    void aRotatedOrRevokedSessionGivesNoCode() throws Exception {
        JwtResponse hub = login(newVerifiedUser()).tokens();
        consent(hub);
        authService.refreshToken(hub.getRefreshToken()); // the old token is no longer the session's current one
        assertThat(query(authorize(session(hub), "none"))).containsEntry("error", "login_required");
    }
}
