package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.SecurityEventService;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A stolen session must not be able to brute-force the 6-digit TOTP against the
 * code-verifying MFA operations. The per-IP rate limiter is bypassable by rotating
 * IPs, so the identity-scoped counter is the real guard.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaServiceLockoutTest {

    @Mock private TotpService totpService;
    @Mock private MfaMethodRepository methodRepository;
    @Mock private MfaRecoveryCodeRepository recoveryRepository;
    @Mock private TokenEncryptionUtil encryptionUtil;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private IdentityRepository identityRepository;
    @Mock private SecurityEventService securityEventService;
    @Mock private StringRedisTemplate redis;
    @Mock private ValueOperations<String, String> ops;

    @InjectMocks private MfaService service;

    private final UUID id = UUID.randomUUID();

    private void withFailureCount(String count) {
        when(redis.opsForValue()).thenReturn(ops);
        when(ops.get("mfa:fail:" + id)).thenReturn(count);
    }

    private void enrolledMethod() {
        MfaMethod m = MfaMethod.builder().identityId(id).secretEnc("enc").build();
        m.setConfirmedAt(java.time.OffsetDateTime.now());
        when(methodRepository.findByIdentityIdAndType(any(), any())).thenReturn(Optional.of(m));
        when(encryptionUtil.decrypt("enc")).thenReturn("SECRET");
        when(recoveryRepository.findByIdentityIdAndUsedAtIsNull(id)).thenReturn(List.of());
    }

    @Test
    void disable_is_blocked_once_the_failure_cap_is_reached() {
        withFailureCount("10");
        assertThatThrownBy(() -> service.disable(id, "000000"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Too many incorrect codes");
        // Locked out before any code check — no bcrypt/TOTP work is done.
        verify(methodRepository, never()).findByIdentityIdAndType(any(), any());
    }

    @Test
    void regenerate_recovery_codes_is_blocked_once_locked_out() {
        withFailureCount("10");
        assertThatThrownBy(() -> service.regenerateRecoveryCodes(id, "000000"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Too many incorrect codes");
    }

    @Test
    void login_verify_is_blocked_once_locked_out() {
        withFailureCount("10");
        assertThatThrownBy(() -> service.verifyForLogin(id, "000000"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Too many incorrect codes");
    }

    @Test
    void a_wrong_code_increments_the_counter() {
        withFailureCount(null);
        enrolledMethod();
        when(totpService.verify(anyString(), anyString(), any())).thenReturn(Optional.empty());

        assertThat(service.verifyForLogin(id, "000000")).isFalse();
        verify(ops).increment("mfa:fail:" + id);
    }

    @Test
    void a_correct_code_clears_the_counter() {
        withFailureCount(null);
        enrolledMethod();
        when(totpService.verify(anyString(), anyString(), any())).thenReturn(Optional.of(123L));

        assertThat(service.verifyForLogin(id, "111111")).isTrue();
        verify(redis).delete("mfa:fail:" + id);
    }
}
