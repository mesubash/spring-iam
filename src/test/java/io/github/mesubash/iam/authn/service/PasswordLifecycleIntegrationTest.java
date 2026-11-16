package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.dto.PasswordChangeRequest;
import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.entity.enums.TokenType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.token.SessionService;
import io.github.mesubash.iam.authn.security.token.TokenService;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Reset and change against real Postgres + Redis: policy, session revocation. */
@SpringBootTest
class PasswordLifecycleIntegrationTest {

    @Autowired private AuthService authService;
    @Autowired private SessionService sessionService;
    @Autowired private TokenService tokenService;
    @Autowired private IdentityRepository identityRepository;
    @Autowired private CredentialRepository credentialRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private Identity newIdentity(boolean verified) {
        Identity identity = identityRepository.save(Identity.builder()
                .primaryEmail("pw-test-" + UUID.randomUUID() + "@example.com")
                .emailVerified(verified)
                .accountStatus(AccountStatus.ACTIVE)
                .build());
        credentialRepository.save(Credential.builder()
                .identity(identity)
                .credentialType(CredentialType.PASSWORD)
                .identifier(identity.getPrimaryEmail())
                .secretHash(passwordEncoder.encode("old-pass-1"))
                .build());
        sessionService.createSession(identity.getId(), null, "device-1");
        sessionService.createSession(identity.getId(), null, "device-2");
        return identity;
    }

    private String resetToken(Identity identity) {
        String token = UUID.randomUUID().toString();
        tokenService.store(identity.getId().toString(), token, TokenType.PASSWORD_RESET);
        return token;
    }

    @Test
    void resetEndsEverySession() {
        Identity identity = newIdentity(true);

        authService.resetPassword(resetToken(identity), "new-pass-2");

        assertThat(sessionService.listActiveSessions(identity.getId())).isEmpty();
    }

    @Test
    void resetRejectsPolicyViolationAndKeepsSessions() {
        Identity identity = newIdentity(true);

        assertThatThrownBy(() -> authService.resetPassword(resetToken(identity), "aaaaaaaa"))
                .isInstanceOf(BadRequestException.class);
        assertThat(sessionService.listActiveSessions(identity.getId())).hasSize(2);
    }

    @Test
    void changeEndsEverySessionAndChecksConfirmation() {
        Identity identity = newIdentity(true);

        assertThatThrownBy(() -> authService.changePassword(identity.getPrimaryEmail(),
                new PasswordChangeRequest("old-pass-1", "new-pass-2", "new-pass-3")))
                .isInstanceOf(BadRequestException.class);

        authService.changePassword(identity.getPrimaryEmail(),
                new PasswordChangeRequest("old-pass-1", "new-pass-2", "new-pass-2"));
        assertThat(sessionService.listActiveSessions(identity.getId())).isEmpty();
    }
}
