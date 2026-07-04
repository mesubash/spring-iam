package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * Failed-login accounting. Runs in its OWN transaction (REQUIRES_NEW) so the
 * incremented attempt counter and any lockout COMMIT even though the caller
 * (login) then throws and rolls its own transaction back. Without this,
 * brute-force lockout never accumulates past one attempt.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private final IdentityRepository identityRepository;
    private final SecurityEventService securityEventService;

    @Value("${iam.account.lockout.max-attempts:5}")
    private int maxLoginAttempts;

    @Value("${iam.account.lockout.lockout-duration-minutes:30}")
    private int lockoutDurationMinutes;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(String email) {
        identityRepository.findByPrimaryEmail(email).ifPresent(identity -> {
            int attempts = (identity.getFailedLoginAttempts() != null ? identity.getFailedLoginAttempts() : 0) + 1;
            identity.setFailedLoginAttempts(attempts);

            if (attempts >= maxLoginAttempts) {
                identity.setAccountStatus(AccountStatus.LOCKED);
                identity.setAccountLockedUntil(OffsetDateTime.now().plusMinutes(lockoutDurationMinutes));
                securityEventService.logEvent(identity, SecurityEventType.ACCOUNT_LOCKED, null, null,
                        Map.of("reason", "max_login_attempts_exceeded", "attempts", attempts));
                log.warn("Account locked for {} after {} failed attempts", email, attempts);
            } else {
                securityEventService.logEvent(identity, SecurityEventType.LOGIN_FAILED, null, null,
                        Map.of("attempts", attempts));
            }
            identityRepository.save(identity);
        });
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void unlockIfExpired(Identity identity) {
        if (identity.getAccountStatus() == AccountStatus.LOCKED
                && identity.getAccountLockedUntil() != null
                && OffsetDateTime.now().isAfter(identity.getAccountLockedUntil())) {
            identity.setAccountStatus(AccountStatus.ACTIVE);
            identity.setFailedLoginAttempts(0);
            identity.setAccountLockedUntil(null);
            identityRepository.save(identity);
            securityEventService.logEvent(identity, SecurityEventType.ACCOUNT_UNLOCKED, null, null,
                    Map.of("reason", "lockout_expired"));
            log.info("Account auto-unlocked for: {}", identity.getPrimaryEmail());
        }
    }
}
