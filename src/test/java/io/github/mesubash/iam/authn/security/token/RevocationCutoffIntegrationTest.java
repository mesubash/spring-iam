package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The sign-out cutoff: written on revoke-all, and enforced on the IAM's own endpoints. */
@SpringBootTest
@AutoConfigureMockMvc
class RevocationCutoffIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-Battery-9";

    @Autowired private MockMvc mvc;
    @Autowired private AuthService authService;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private RevocationService revocationService;
    @Autowired private SessionService sessionService;
    @Autowired private StringRedisTemplate redis;

    private String loginNewUser(String email) {
        RegisterRequest register = new RegisterRequest();
        register.setEmail(email);
        register.setPassword(PASSWORD);
        authService.register(register);
        identityRepository.findByPrimaryEmail(email).ifPresent(i -> {
            i.setEmailVerified(true);
            identityRepository.save(i);
        });
        LoginRequest login = new LoginRequest();
        login.setEmail(email);
        login.setPassword(PASSWORD);
        return authService.login(login, "203.0.113.7", "junit").tokens().getAccessToken();
    }

    @Test
    void tokenIssuedBeforeTheCutoffIsRejected() throws Exception {
        String email = "cutoff-" + UUID.randomUUID() + "@example.com";
        String token = loginNewUser(email);
        UUID id = identityRepository.findByPrimaryEmail(email).orElseThrow().getId();

        mvc.perform(get("/api/auth/sessions").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Cutoff alone (session still alive): the token must die anyway.
        revocationService.revokeAllBefore(id);

        mvc.perform(get("/api/auth/sessions").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cutoffComparesIssuedAtAndRevokeAllWritesIt() {
        UUID id = UUID.randomUUID();
        assertThat(revocationService.isRevoked(id, System.currentTimeMillis())).isFalse();

        sessionService.revokeAll(id, "LOGOUT_ALL");
        long cutoff = Long.parseLong(redis.opsForValue().get(RevocationService.KEY_PREFIX + id));

        assertThat(revocationService.isRevoked(id, cutoff - 1)).isTrue();
        assertThat(revocationService.isRevoked(id, cutoff)).isTrue();
        assertThat(revocationService.isRevoked(id, cutoff + 1)).isFalse();
        assertThat(redis.getExpire(RevocationService.KEY_PREFIX + id)).isPositive();
    }
}
