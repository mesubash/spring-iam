package io.github.mesubash.iam.authn.service.impl;

import io.github.mesubash.iam.authn.dto.AdminCreateIdentityRequest;
import io.github.mesubash.iam.authn.dto.AdminSetPasswordRequest;
import io.github.mesubash.iam.authn.dto.AdminUpdateStatusRequest;
import io.github.mesubash.iam.authn.dto.IdentityAdminView;
import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.security.token.SessionService;
import io.github.mesubash.iam.authn.service.IdentityAdminService;
import io.github.mesubash.iam.authn.service.SecurityEventService;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import io.github.mesubash.iam.shared.exception.ConflictException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.github.mesubash.iam.shared.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class IdentityAdminServiceImpl implements IdentityAdminService {

    private final IdentityRepository identityRepository;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;
    private final SecurityEventService securityEventService;

    @Override
    @Transactional(readOnly = true)
    public List<IdentityAdminView> search(String query, String status, int limit) {
        int capped = Math.max(1, Math.min(limit, 200));
        AccountStatus statusFilter = parseStatus(status);
        String q = StringUtils.hasText(query) ? query.trim().toLowerCase() : "";
        List<Identity> identities = identityRepository.search(q, statusFilter,
                PageRequest.of(0, capped));
        return identities.stream().map(IdentityAdminView::from).toList();
    }

    @Override
    @Transactional(readOnly = true)
    public IdentityAdminView get(UUID id) {
        return identityRepository.findById(id)
                .map(IdentityAdminView::from)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    @Override
    @Transactional
    public CreatedIdentity create(UserPrincipal caller, AdminCreateIdentityRequest request) {
        String email = request.getEmail().trim().toLowerCase();
        if (identityRepository.existsByPrimaryEmail(email)) {
            throw new ConflictException("Email address already in use");
        }

        boolean generated = !StringUtils.hasText(request.getPassword());
        String password = generated ? PasswordUtil.generateSecureToken(12) : request.getPassword();

        Identity identity = Identity.builder()
                .primaryEmail(email)
                .emailVerified(request.getEmailVerified() == null || request.getEmailVerified())
                .accountStatus(AccountStatus.ACTIVE)
                .build();
        identity = identityRepository.save(identity);

        Credential credential = Credential.builder()
                .identity(identity)
                .credentialType(CredentialType.PASSWORD)
                .identifier(email)
                .secretHash(passwordEncoder.encode(password))
                .build();
        credentialRepository.save(credential);

        securityEventService.logEvent(identity, SecurityEventType.PASSWORD_RESET, null, null,
                Map.of("action", "ADMIN_CREATE", "by", caller.getId().toString()));
        log.info("Admin {} created identity {} ({})", caller.getId(), identity.getId(), email);

        return new CreatedIdentity(IdentityAdminView.from(identity), generated ? password : null);
    }

    @Override
    @Transactional
    public PasswordSet setPassword(UserPrincipal caller, UUID id, AdminSetPasswordRequest request) {
        Identity identity = identityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        boolean generated = !StringUtils.hasText(request.getNewPassword());
        String password = generated ? PasswordUtil.generateSecureToken(12) : request.getNewPassword();

        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseGet(() -> Credential.builder()
                        .identity(identity)
                        .credentialType(CredentialType.PASSWORD)
                        .identifier(identity.getPrimaryEmail())
                        .build());
        credential.setSecretHash(passwordEncoder.encode(password));
        credentialRepository.save(credential);

        boolean revoke = request.getRevokeSessions() == null || request.getRevokeSessions();
        if (revoke) {
            sessionService.revokeAll(identity.getId(), "ADMIN");
        }

        securityEventService.logEvent(identity, SecurityEventType.PASSWORD_RESET, null, null,
                Map.of("action", "ADMIN_RESET", "by", caller.getId().toString(),
                        "sessionsRevoked", revoke));
        log.info("Admin {} reset password for identity {}", caller.getId(), identity.getId());

        return new PasswordSet(generated ? password : null, revoke);
    }

    @Override
    @Transactional
    public IdentityAdminView updateStatus(UserPrincipal caller, UUID id, AdminUpdateStatusRequest request) {
        if (caller.getId().equals(id)) {
            throw new BadRequestException("You cannot change your own account status");
        }

        Identity identity = identityRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        AccountStatus newStatus = AccountStatus.valueOf(request.getStatus());
        AccountStatus oldStatus = identity.getAccountStatus();
        if (newStatus == oldStatus) {
            return IdentityAdminView.from(identity);
        }

        identity.setAccountStatus(newStatus);
        if (newStatus == AccountStatus.ACTIVE) {
            identity.setFailedLoginAttempts(0);
            identity.setAccountLockedUntil(null);
        }
        identityRepository.save(identity);

        // A suspended or deactivated user must not keep working sessions.
        if (newStatus != AccountStatus.ACTIVE) {
            sessionService.revokeAll(identity.getId(), "ADMIN");
        }

        SecurityEventType event = switch (newStatus) {
            case SUSPENDED -> SecurityEventType.ACCOUNT_SUSPENDED;
            case DEACTIVATED -> SecurityEventType.ACCOUNT_DEACTIVATED;
            default -> SecurityEventType.ACCOUNT_UNLOCKED;
        };
        securityEventService.logEvent(identity, event, null, null,
                Map.of("by", caller.getId().toString(),
                        "from", oldStatus.name(), "to", newStatus.name(),
                        "reason", request.getReason() == null ? "" : request.getReason()));
        log.info("Admin {} changed status of {} from {} to {}",
                caller.getId(), identity.getId(), oldStatus, newStatus);

        return IdentityAdminView.from(identity);
    }

    private AccountStatus parseStatus(String status) {
        if (!StringUtils.hasText(status)) return null;
        try {
            return AccountStatus.valueOf(status.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Unknown account status: " + status);
        }
    }
}
