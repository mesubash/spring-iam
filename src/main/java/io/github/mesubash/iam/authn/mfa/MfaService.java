package io.github.mesubash.iam.authn.mfa;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.SecurityEventService;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Enrollment, verification and lifecycle for TOTP MFA. */
@Slf4j
@Service
@RequiredArgsConstructor
public class MfaService {

    private static final String TOTP = "TOTP";
    private static final int RECOVERY_CODE_COUNT = 10;
    private static final SecureRandom RNG = new SecureRandom();

    private final TotpService totpService;
    private final MfaMethodRepository methodRepository;
    private final MfaRecoveryCodeRepository recoveryRepository;
    private final TokenEncryptionUtil encryptionUtil;
    private final PasswordEncoder passwordEncoder;
    private final IdentityRepository identityRepository;
    private final SecurityEventService securityEventService;
    private final org.springframework.data.redis.core.StringRedisTemplate redis;

    @Value("${iam.mfa.issuer:spring-iam}")
    private String issuer;

    /** Per-identity brute-force guard, independent of the per-IP rate limiter. */
    private static final String FAIL_PREFIX = "mfa:fail:";
    private static final int MAX_FAILURES = 10;
    private static final java.time.Duration FAIL_WINDOW = java.time.Duration.ofMinutes(15);

    private void assertNotLockedOut(UUID identityId) {
        String v = redis.opsForValue().get(FAIL_PREFIX + identityId);
        if (v != null && Integer.parseInt(v) >= MAX_FAILURES) {
            throw new BadRequestException(
                    "Too many incorrect codes. Try again later or use a recovery code.");
        }
    }

    private void recordFailure(UUID identityId) {
        String key = FAIL_PREFIX + identityId;
        Long used = redis.opsForValue().increment(key);
        if (used != null && used == 1L) {
            redis.expire(key, FAIL_WINDOW);
        }
    }

    private void clearFailures(UUID identityId) {
        redis.delete(FAIL_PREFIX + identityId);
    }

    public record SetupResult(String otpauthUri, String secret) {}

    public boolean isEnabled(UUID identityId) {
        return methodRepository.findByIdentityIdAndType(identityId, TOTP)
                .map(m -> m.getConfirmedAt() != null).orElse(false);
    }

    /** Generate a fresh secret and store it pending. Overwrites any prior PENDING TOTP. */
    @Transactional
    public SetupResult setup(UUID identityId, String email) {
        // Refuse to re-enroll over an already-active method — a hijacked session
        // must not be able to silently swap the authenticator. Disable first
        // (which requires a current code), then set up again.
        methodRepository.findByIdentityIdAndType(identityId, TOTP).ifPresent(m -> {
            if (m.getConfirmedAt() != null) {
                throw new BadRequestException("MFA is already enabled. Disable it before enrolling a new authenticator.");
            }
        });
        String secret = totpService.newSecret();
        String encrypted = encryptionUtil.encrypt(secret);
        MfaMethod method = methodRepository.findByIdentityIdAndType(identityId, TOTP)
                .orElseGet(() -> MfaMethod.builder().identityId(identityId).type(TOTP).build());
        method.setSecretEnc(encrypted);
        method.setConfirmedAt(null);
        method.setLastStep(null);
        try {
            methodRepository.saveAndFlush(method);
        } catch (org.springframework.dao.DataIntegrityViolationException race) {
            // Concurrent setup (e.g. a double-fired client) inserted the row first —
            // update that existing row in place instead of failing.
            MfaMethod existing = methodRepository.findByIdentityIdAndType(identityId, TOTP)
                    .orElseThrow(() -> race);
            existing.setSecretEnc(encrypted);
            existing.setConfirmedAt(null);
            existing.setLastStep(null);
            methodRepository.save(existing);
        }
        return new SetupResult(totpService.provisioningUri(issuer, email, secret), secret);
    }

    /** Confirm a pending secret with a live code; enable MFA and return recovery codes once. */
    @Transactional
    public List<String> enable(UUID identityId, String code) {
        MfaMethod method = methodRepository.findByIdentityIdAndType(identityId, TOTP)
                .orElseThrow(() -> new BadRequestException("Start MFA setup first"));
        String secret = encryptionUtil.decrypt(method.getSecretEnc());
        long step = totpService.verify(secret, code, method.getLastStep())
                .orElseThrow(() -> new BadRequestException("Invalid code"));
        method.setLastStep(step);
        method.setConfirmedAt(OffsetDateTime.now());
        methodRepository.save(method);

        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        identity.setMfaEnabled(true);
        identityRepository.save(identity);

        List<String> codes = regenerate(identityId);
        securityEventService.logEvent(identity, SecurityEventType.MFA_ENABLED, null, null);
        return codes;
    }

    /** Verify a login-time code (TOTP or recovery). Updates replay guard / burns the code. */
    @Transactional
    public boolean verifyForLogin(UUID identityId, String code) {
        assertNotLockedOut(identityId);
        boolean ok = consume(identityId, code);
        if (ok) clearFailures(identityId); else recordFailure(identityId);
        identityRepository.findById(identityId).ifPresent(identity ->
                securityEventService.logEvent(identity,
                        ok ? SecurityEventType.MFA_VERIFIED : SecurityEventType.MFA_FAILED, null, null));
        return ok;
    }

    /** Disable MFA — requires a current code (TOTP or recovery). */
    @Transactional
    public void disable(UUID identityId, String code) {
        assertNotLockedOut(identityId);
        if (!consume(identityId, code)) {
            recordFailure(identityId);
            throw new BadRequestException("Invalid code");
        }
        clearFailures(identityId);
        clear(identityId);
        identityRepository.findById(identityId).ifPresent(identity -> {
            identity.setMfaEnabled(false);
            identityRepository.save(identity);
            securityEventService.logEvent(identity, SecurityEventType.MFA_DISABLED, null, null);
        });
    }

    /** Regenerate recovery codes — requires a current code. */
    @Transactional
    public List<String> regenerateRecoveryCodes(UUID identityId, String code) {
        assertNotLockedOut(identityId);
        if (!consumeTotpOnly(identityId, code)) {
            recordFailure(identityId);
            throw new BadRequestException("Invalid code");
        }
        clearFailures(identityId);
        return regenerate(identityId);
    }

    /** Admin reset — clears MFA so the target must re-enroll. Audited by the caller + event. */
    @Transactional
    public void adminReset(UUID identityId) {
        clear(identityId);
        identityRepository.findById(identityId).ifPresent(identity -> {
            identity.setMfaEnabled(false);
            identityRepository.save(identity);
            securityEventService.logEvent(identity, SecurityEventType.MFA_RESET_BY_ADMIN, null, null);
        });
    }

    // --- internals ---

    /** Try TOTP, then recovery codes. Burns a recovery code on match. */
    private boolean consume(UUID identityId, String code) {
        if (consumeTotpOnly(identityId, code)) return true;
        return consumeRecovery(identityId, code);
    }

    private boolean consumeTotpOnly(UUID identityId, String code) {
        MfaMethod method = methodRepository.findByIdentityIdAndType(identityId, TOTP).orElse(null);
        if (method == null || method.getConfirmedAt() == null) return false;
        String secret = encryptionUtil.decrypt(method.getSecretEnc());
        var step = totpService.verify(secret, code, method.getLastStep());
        if (step.isEmpty()) return false;
        method.setLastStep(step.get());
        methodRepository.save(method);
        return true;
    }

    private boolean consumeRecovery(UUID identityId, String code) {
        for (MfaRecoveryCode rc : recoveryRepository.findByIdentityIdAndUsedAtIsNull(identityId)) {
            if (passwordEncoder.matches(code, rc.getCodeHash())) {
                rc.setUsedAt(OffsetDateTime.now());
                recoveryRepository.save(rc);
                identityRepository.findById(identityId).ifPresent(identity ->
                        securityEventService.logEvent(identity, SecurityEventType.MFA_RECOVERY_USED, null, null));
                return true;
            }
        }
        return false;
    }

    private List<String> regenerate(UUID identityId) {
        recoveryRepository.deleteByIdentityId(identityId);
        List<String> plain = new ArrayList<>();
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            String c = randomRecoveryCode();
            plain.add(c);
            recoveryRepository.save(MfaRecoveryCode.builder()
                    .identityId(identityId)
                    .codeHash(passwordEncoder.encode(c))
                    .build());
        }
        return plain;
    }

    private void clear(UUID identityId) {
        methodRepository.deleteByIdentityId(identityId);
        recoveryRepository.deleteByIdentityId(identityId);
    }

    private static String randomRecoveryCode() {
        // 16 hex chars (64 bits), dash-grouped: e.g. a1b2c3d4-e5f60718.
        // 40 bits was thin for a standalone bearer credential that bypasses TOTP.
        byte[] b = new byte[8];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.substring(0, 8) + "-" + sb.substring(8, 16);
    }
}
