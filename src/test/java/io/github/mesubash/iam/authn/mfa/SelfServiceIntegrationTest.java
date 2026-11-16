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
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
}
