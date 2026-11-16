package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LoginAttemptServiceTest {

    private Identity identity;
    private NotificationPort notifications;
    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        identity = Identity.builder().primaryEmail("a@example.com")
                .accountStatus(AccountStatus.ACTIVE).failedLoginAttempts(0).build();
        IdentityRepository repo = mock(IdentityRepository.class);
        when(repo.findByPrimaryEmail("a@example.com")).thenReturn(Optional.of(identity));
        notifications = mock(NotificationPort.class);
        service = new LoginAttemptService(repo, mock(SecurityEventService.class), notifications);
        ReflectionTestUtils.setField(service, "maxLoginAttempts", 3);
        ReflectionTestUtils.setField(service, "lockoutDurationMinutes", 30);
        ReflectionTestUtils.setField(service, "windowMinutes", 15);
    }

    @Test
    void failuresInsideTheWindowLockAndNotify() {
        for (int i = 0; i < 3; i++) {
            service.recordFailure("a@example.com");
        }
        assertThat(identity.getAccountStatus()).isEqualTo(AccountStatus.LOCKED);
        verify(notifications).sendAccountLocked("a@example.com");
    }

    @Test
    void failuresOlderThanTheWindowDoNotCount() {
        identity.setFailedLoginAttempts(2);
        identity.setLastFailedLoginAt(OffsetDateTime.now().minusHours(1));

        service.recordFailure("a@example.com");

        assertThat(identity.getFailedLoginAttempts()).isEqualTo(1);
        assertThat(identity.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
    }
}
