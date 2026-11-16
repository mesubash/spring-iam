package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.entity.enums.TokenType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.token.TokenService;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.authn.service.IdentityAdminService;
import io.github.mesubash.iam.authn.service.NotificationPort;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.shared.dto.ScopeSummaryDto;
import io.github.mesubash.iam.shared.exception.ConflictException;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.github.mesubash.iam.shared.service.AuthzQueryService;
import io.github.mesubash.iam.shared.util.PasswordUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Account API for resource servers, authenticated by an API key (ROLE_INTERNAL). Lets a service
 * look people up, create accounts it onboards, and relay account actions it has already
 * confirmed with the person. Never returns password hashes.
 *
 * <p>Every caller here presents the same undifferentiated ROLE_INTERNAL, so there is no caller
 * identity to rank against a target. Writes that could take over or lock out an account are
 * therefore refused outright when the target is a platform administrator: an administrator
 * recovers through the audited admin API, not over an API key.
 */
@RestController
@RequestMapping("/api/v1/internal/accounts")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('INTERNAL', 'SuperAdmin')")
@Tag(name = "Internal accounts", description = "Account reads and writes for resource servers (API key)")
public class InternalAccountController {

    private static final List<CredentialType> SOCIAL =
            List.of(CredentialType.GOOGLE, CredentialType.APPLE, CredentialType.MICROSOFT);

    private final IdentityRepository identityRepository;
    private final CredentialRepository credentialRepository;
    private final AssignmentRepository assignmentRepository;
    private final AuthzQueryService authzQueryService;
    private final TokenService tokenService;
    private final NotificationPort notificationPort;
    private final IdentityAdminService identityAdminService;
    private final AuthService authService;

    /** provider: LOCAL or the first active social provider. */
    public record AccountView(UUID id, String email, boolean emailVerified,
                              String provider, String providerUserId, String displayName) {}

    /** sendVerificationEmail: null means true; false when the caller mails its own link. */
    public record CreateAccount(String email, String passwordHash, Boolean verified,
                                String provider, String providerUserId, Boolean sendVerificationEmail) {}

    public record VerificationToken(String token) {}

    public record SetPassword(String passwordHash, Boolean endSessions) {}

    public record VerifyPassword(String password) {}

    @GetMapping("/{id}")
    @Operation(summary = "Account by id")
    public AccountView byId(@PathVariable UUID id) {
        return toView(find(id));
    }

    @GetMapping
    @Operation(summary = "Account by email")
    public AccountView byEmail(@RequestParam String email) {
        return identityRepository.findByPrimaryEmail(email.trim().toLowerCase())
                .map(this::toView)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    /** For scope-aware decisions about a caller whose bearer token the service cannot forward. */
    @GetMapping("/{id}/scopes")
    @Operation(summary = "Scopes the account holds assignments in")
    public List<ScopeSummaryDto> scopes(@PathVariable UUID id) {
        return authzQueryService.getScopesForIdentity(id);
    }

    /**
     * Creates an account from a service, with an already-hashed password (encoder format) or a
     * social credential. An unverified LOCAL account is sent the same verification email
     * registration sends; login requires a verified address, so without it the account would
     * be stuck.
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    @Operation(summary = "Create an account")
    public AccountView create(@RequestBody CreateAccount req) {
        String email = req.email().trim().toLowerCase();
        boolean verified = Boolean.TRUE.equals(req.verified());
        if (identityRepository.existsByPrimaryEmail(email)) {
            throw new ConflictException("Email address already in use");
        }
        Identity identity = identityRepository.save(Identity.builder()
                .primaryEmail(email)
                .emailVerified(verified)
                .build());
        boolean social = req.provider() != null && !"LOCAL".equalsIgnoreCase(req.provider());
        if (social) {
            credentialRepository.save(Credential.builder()
                    .identity(identity)
                    .credentialType(CredentialType.valueOf(req.provider().toUpperCase()))
                    .identifier(req.providerUserId() != null ? req.providerUserId() : email)
                    .build());
        } else if (req.passwordHash() != null && !req.passwordHash().isBlank()) {
            credentialRepository.save(Credential.builder()
                    .identity(identity)
                    .credentialType(CredentialType.PASSWORD)
                    .identifier(email)
                    .secretHash(req.passwordHash())
                    .build());
        }
        if (!social && !verified && !Boolean.FALSE.equals(req.sendVerificationEmail())) {
            notificationPort.sendEmailVerification(email, mintVerificationToken(identity));
        }
        return toView(identity);
    }

    /**
     * Discards an account whose creator could not finish provisioning it (the caller's own
     * transaction rolled back; this one did not). Only fresh debris qualifies: an account that
     * has signed in or holds an assignment belongs to somebody. Credentials and sessions go with
     * the row. Idempotent.
     */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    @Operation(summary = "Discard an account that was never used")
    public void delete(@PathVariable UUID id) {
        identityRepository.findById(id).ifPresent(identity -> {
            if (identity.getLastLoginAt() != null
                    || !assignmentRepository.findActiveAssignments(id.toString(), Instant.now()).isEmpty()) {
                throw new ConflictException("Account " + id + " is in use and cannot be discarded");
            }
            identityRepository.delete(identity);
        });
    }

    /** Re-sends the verification email. No-op once the address is verified. */
    @PostMapping("/{id}/verification-email")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Re-send the verification email")
    public void resendVerification(@PathVariable UUID id) {
        Identity identity = find(id);
        if (!Boolean.TRUE.equals(identity.getEmailVerified())) {
            notificationPort.sendEmailVerification(identity.getPrimaryEmail(), mintVerificationToken(identity));
        }
    }

    /** Mints a verification token without mailing it, for a service that sends its own link. */
    @PostMapping("/{id}/verification-token")
    @Operation(summary = "Mint a verification token without sending email")
    public VerificationToken verificationToken(@PathVariable UUID id) {
        Identity identity = find(id);
        if (Boolean.TRUE.equals(identity.getEmailVerified())) {
            throw new ConflictException("Account " + id + " is already verified");
        }
        return new VerificationToken(mintVerificationToken(identity));
    }

    /** Sets the password hash; endSessions also signs the account out everywhere. */
    @PutMapping("/{id}/password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    @Operation(summary = "Set the password hash (refused for platform administrators)")
    public void setPassword(@PathVariable UUID id, @RequestBody SetPassword req) {
        Identity identity = find(id);
        refuseIfPlatformAdmin(id, "set the password of");
        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(id, CredentialType.PASSWORD)
                .orElseGet(() -> Credential.builder().identity(identity)
                        .credentialType(CredentialType.PASSWORD).identifier(identity.getPrimaryEmail()).build());
        credential.setSecretHash(req.passwordHash());
        credentialRepository.save(credential);
        if (Boolean.TRUE.equals(req.endSessions())) {
            authService.logoutAll(id.toString());
        }
    }

    @PutMapping("/{id}/verify")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    @Operation(summary = "Mark the email verified (refused for platform administrators)")
    public void markVerified(@PathVariable UUID id) {
        Identity identity = find(id);
        refuseIfPlatformAdmin(id, "mark verified");
        identity.setEmailVerified(true);
        identityRepository.save(identity);
    }

    /** Self-deactivation relayed by a service after it has confirmed the person's password. */
    @PostMapping("/{id}/deactivate")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Deactivate on the person's behalf (refused for platform administrators)")
    public void deactivate(@PathVariable UUID id) {
        refuseIfPlatformAdmin(id, "deactivate");
        authService.deactivate(id);
    }

    /**
     * 204 when the password is right, 401 when wrong. Wrong answers count toward the lock, so
     * this is refused for administrators: a key holder could otherwise lock one out.
     */
    @PostMapping("/{id}/verify-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Confirm the person's current password (refused for platform administrators)")
    public void verifyPassword(@PathVariable UUID id, @RequestBody VerifyPassword req) {
        refuseIfPlatformAdmin(id, "check the password of");
        authService.verifyPassword(id, req.password());
    }

    private void refuseIfPlatformAdmin(UUID id, String action) {
        if (identityAdminService.isPlatformAdmin(id)) {
            throw new ForbiddenException(
                    "A service cannot " + action + " an account that holds a platform administrator role");
        }
    }

    private Identity find(UUID id) {
        return identityRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private String mintVerificationToken(Identity identity) {
        String token = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), token, TokenType.EMAIL_VERIFICATION);
        return token;
    }

    private AccountView toView(Identity identity) {
        Optional<Credential> social = credentialRepository.findByIdentityId(identity.getId()).stream()
                .filter(c -> Boolean.TRUE.equals(c.getIsActive()) && SOCIAL.contains(c.getCredentialType()))
                .findFirst();
        return new AccountView(identity.getId(), identity.getPrimaryEmail(),
                Boolean.TRUE.equals(identity.getEmailVerified()),
                social.map(c -> c.getCredentialType().name()).orElse("LOCAL"),
                social.map(Credential::getIdentifier).orElse(null),
                identity.getDisplayName());
    }
}
