package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.LoginResult;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.AuthService;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import io.github.mesubash.iam.authn.security.token.SessionService;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Cookie-authenticated session reads and self-service: whoami, /self/*. */
@SpringBootTest
@AutoConfigureMockMvc
class SelfServiceIntegrationTest {

    static final String PASSWORD = "Correct-Horse-Battery-9";

    @Autowired MockMvc mvc;
    @Autowired AuthService authService;
    @Autowired MfaService mfaService;
    @Autowired IdentityRepository identityRepository;
    @Autowired TokenEncryptionUtil encryption;
    @Autowired SessionService sessionService;

    String newVerifiedUser() {
        String email = "self-" + UUID.randomUUID() + "@example.com";
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

    LoginResult login(String email) {
        LoginRequest req = new LoginRequest();
        req.setEmail(email);
        req.setPassword(PASSWORD);
        return authService.login(req, "203.0.113.5", "junit");
    }

    UUID idOf(String email) {
        return identityRepository.findByPrimaryEmail(email).orElseThrow().getId();
    }

    Cookie session(JwtResponse tokens) {
        return new Cookie("__Host-Refresh", encryption.encrypt(tokens.getRefreshToken()));
    }

    /** Turns MFA on for the account and returns the TOTP secret. */
    String enableMfa(String email) throws Exception {
        String secret = mfaService.setup(idOf(email), email).secret();
        mfaService.enable(idOf(email), TotpServiceTest.codeFor(secret, System.currentTimeMillis() / 1000L / 30));
        return secret;
    }

    @Test
    void whoamiNeedsTheCookie() throws Exception {
        mvc.perform(get("/api/auth/whoami")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/whoami").cookie(new Cookie("__Host-Refresh", "garbage")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void whoamiReadsTheSessionWithoutRotatingIt() throws Exception {
        String email = newVerifiedUser();
        JwtResponse tokens = login(email).tokens();

        for (int i = 0; i < 2; i++) {
            mvc.perform(get("/api/auth/whoami").cookie(session(tokens)))
                    .andExpect(status().isOk())
                    .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                    .andExpect(jsonPath("$.data.email").value(email))
                    .andExpect(jsonPath("$.data.id").value(idOf(email).toString()))
                    .andExpect(jsonPath("$.data.mfaEnabled").value(false));
        }
        // Still the session's current token: a rotation would have made this a replay.
        assertThat(authService.refreshToken(tokens.getRefreshToken()).getRefreshToken()).isNotBlank();
    }

    @Test
    void whoamiRejectsASessionThatNoLongerMeetsMfa() throws Exception {
        String email = newVerifiedUser();
        JwtResponse beforeMfa = login(email).tokens();
        enableMfa(email);
        mvc.perform(get("/api/auth/whoami").cookie(session(beforeMfa))).andExpect(status().isUnauthorized());
    }

    static String changePassword(String current, String next) {
        return "{\"currentPassword\":\"" + current + "\",\"newPassword\":\"" + next
                + "\",\"confirmPassword\":\"" + next + "\"}";
    }

    @Test
    void selfEndpointsRequireTheCookie() throws Exception {
        for (String path : new String[] {"/api/auth/self/change-password", "/api/auth/self/mfa/setup",
                "/api/auth/self/mfa/enable", "/api/auth/self/mfa/disable", "/api/auth/self/profile"}) {
            mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                            .content("{\"currentPassword\":\"" + PASSWORD + "\",\"newPassword\":\"New-Password-77\","
                                    + "\"confirmPassword\":\"New-Password-77\",\"code\":\"123456\",\"name\":\"X\"}"))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void selfEndpointsRequireAJsonBody() throws Exception {
        String email = newVerifiedUser();
        Cookie cookie = session(login(email).tokens());
        // What a cross-site HTML form can send: refused before anything runs.
        mvc.perform(post("/api/auth/self/profile").cookie(cookie)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("name=Mallory"))
                .andExpect(status().isUnsupportedMediaType());
        mvc.perform(post("/api/auth/self/logout").cookie(cookie)).andExpect(status().isUnsupportedMediaType());
        assertThat(identityRepository.findById(idOf(email)).orElseThrow().getDisplayName()).isNull();

        mvc.perform(post("/api/auth/self/profile").cookie(cookie)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"  Ada \"}"))
                .andExpect(status().isOk());
        assertThat(identityRepository.findById(idOf(email)).orElseThrow().getDisplayName()).isEqualTo("Ada");
    }

    @Test
    void selfChangePasswordEnforcesCurrentPasswordAndPolicy() throws Exception {
        String email = newVerifiedUser();
        Cookie cookie = session(login(email).tokens());
        mvc.perform(post("/api/auth/self/change-password").cookie(cookie).contentType(MediaType.APPLICATION_JSON)
                        .content(changePassword("Wrong-Password-1", "New-Password-77")))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/auth/self/change-password").cookie(cookie).contentType(MediaType.APPLICATION_JSON)
                        .content(changePassword(PASSWORD, "onlyletterspassword")))
                .andExpect(status().isBadRequest());

        mvc.perform(post("/api/auth/self/change-password").cookie(cookie).contentType(MediaType.APPLICATION_JSON)
                        .content(changePassword(PASSWORD, "New-Password-77")))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, org.hamcrest.Matchers.containsString("Max-Age=0")));
        assertThat(sessionService.listActiveSessions(idOf(email))).isEmpty();
    }

    @Test
    void selfMfaDisableNeedsACurrentCodeAndAnMfaSession() throws Exception {
        String email = newVerifiedUser();
        JwtResponse beforeMfa = login(email).tokens();

        // Enrolment through /self, then the single-factor session no longer counts.
        String secret = mvcSetup(session(beforeMfa));
        long step = System.currentTimeMillis() / 1000L / 30;
        mvc.perform(post("/api/auth/self/mfa/enable").cookie(session(beforeMfa))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + TotpServiceTest.codeFor(secret, step) + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.recoveryCodes").isArray());
        mvc.perform(post("/api/auth/self/mfa/disable").cookie(session(beforeMfa))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + TotpServiceTest.codeFor(secret, step + 1) + "\"}"))
                .andExpect(status().isUnauthorized());

        JwtResponse withMfa = authService.verifyMfaAndIssue(login(email).mfaToken(),
                TotpServiceTest.codeFor(secret, step + 1), null, "junit");
        mvc.perform(post("/api/auth/self/mfa/disable").cookie(session(withMfa))
                        .contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"000000\"}"))
                .andExpect(status().isBadRequest());
        assertThat(mfaService.isEnabled(idOf(email))).isTrue();
    }

    String mvcSetup(Cookie cookie) throws Exception {
        String body = mvc.perform(post("/api/auth/self/mfa/setup").cookie(cookie).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return com.jayway.jsonpath.JsonPath.read(body, "$.data.secret");
    }

    @Test
    void selfLogoutEndsOnlyThisSession() throws Exception {
        String email = newVerifiedUser();
        JwtResponse here = login(email).tokens();
        JwtResponse elsewhere = login(email).tokens();

        mvc.perform(post("/api/auth/self/logout").cookie(session(here)).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
        mvc.perform(get("/api/auth/whoami").cookie(session(here))).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/auth/whoami").cookie(session(elsewhere))).andExpect(status().isOk());

        // Idempotent, with or without a cookie.
        mvc.perform(post("/api/auth/self/logout").cookie(session(here)).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
        mvc.perform(post("/api/auth/self/logout").contentType(MediaType.APPLICATION_JSON)).andExpect(status().isOk());
    }
}
