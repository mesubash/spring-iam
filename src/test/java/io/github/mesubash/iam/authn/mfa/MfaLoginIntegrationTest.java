package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.LoginResult;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.security.oauth2.OAuth2AuthenticationSuccessHandler;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.shared.exception.UnauthorizedException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The MFA gate end to end against real Postgres + Redis, on both first-factor paths. */
@SpringBootTest
class MfaLoginIntegrationTest {

    private static final String PASSWORD = "Correct-Horse-Battery-9";

    @Autowired private AuthService authService;
    @Autowired private MfaService mfaService;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private StringRedisTemplate redis;
    @Autowired private TokenEncryptionUtil encryption;
    @Autowired private io.github.mesubash.iam.authn.security.JwtTokenProvider jwt;

    private String newVerifiedUser() {
        String email = "mfa-" + UUID.randomUUID() + "@example.com";
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

    private long nowStep() {
        return System.currentTimeMillis() / 1000L / 30;
    }

    @Test
    void passwordLoginRequiresTheSecondFactorOnceEnabled() throws Exception {
        String email = newVerifiedUser();
        assertThat(login(email).status()).isEqualTo(LoginResult.Status.OK);

        UUID id = identityRepository.findByPrimaryEmail(email).orElseThrow().getId();
        String secret = mfaService.setup(id, email).secret();
        assertThat(mfaService.enable(id, TotpServiceTest.codeFor(secret, nowStep()))).hasSize(10);

        LoginResult gated = login(email);
        assertThat(gated.status()).isEqualTo(LoginResult.Status.MFA_REQUIRED);
        assertThat(gated.tokens()).isNull();

        assertThatThrownBy(() -> authService.verifyMfaAndIssue(gated.mfaToken(), "000000", null, "junit"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("4 attempts left");

        // The enable call consumed the current step (replay guard), so use the next one.
        JwtResponse tokens = authService.verifyMfaAndIssue(
                gated.mfaToken(), TotpServiceTest.codeFor(secret, nowStep() + 1), null, "junit");
        assertThat(tokens.getAccessToken()).isNotBlank();
        assertThat(tokens.getRefreshToken()).isNotBlank();
        assertThat(jwt.parseToken(tokens.getAccessToken()).get("amr")).isEqualTo(List.of("pwd", "otp", "mfa"));
        // A refreshed token keeps the session's amr.
        assertThat(jwt.parseToken(authService.refreshToken(tokens.getRefreshToken()).getAccessToken()).get("amr"))
                .isEqualTo(List.of("pwd", "otp", "mfa"));

        // The challenge is single-use.
        assertThatThrownBy(() -> authService.verifyMfaAndIssue(gated.mfaToken(), "123456", null, "junit"))
                .isInstanceOf(UnauthorizedException.class);
    }

    @Test
    void oauthExchangeCannotSkipTheSecondFactor() throws Exception {
        String email = newVerifiedUser();
        UUID id = identityRepository.findByPrimaryEmail(email).orElseThrow().getId();
        String secret = mfaService.setup(id, email).secret();
        mfaService.enable(id, TotpServiceTest.codeFor(secret, nowStep()));

        String code = "test-" + UUID.randomUUID();
        redis.opsForValue().set(OAuth2AuthenticationSuccessHandler.EXCHANGE_PREFIX + code,
                encryption.encrypt(id + " google"), Duration.ofSeconds(60));

        LoginResult result = authService.exchangeOAuthCode(code, null, "junit");
        assertThat(result.status()).isEqualTo(LoginResult.Status.MFA_REQUIRED);
        assertThat(result.tokens()).isNull();
    }
}
