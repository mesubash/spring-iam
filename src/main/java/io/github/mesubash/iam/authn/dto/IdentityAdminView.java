package io.github.mesubash.iam.authn.dto;

import io.github.mesubash.iam.authn.entity.Identity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Admin-facing projection of an identity. Carries lockout state and the last login
 * origin for support diagnostics (the endpoints are admin-gated); never credentials.
 */
public record IdentityAdminView(
        UUID id,
        String email,
        String displayName,
        boolean emailVerified,
        String accountStatus,
        boolean mfaEnabled,
        OffsetDateTime lastLoginAt,
        OffsetDateTime createdAt,
        OffsetDateTime updatedAt,
        int failedLoginAttempts,
        OffsetDateTime accountLockedUntil,
        String lastLoginIp
) {
    public static IdentityAdminView from(Identity identity) {
        return new IdentityAdminView(
                identity.getId(),
                identity.getPrimaryEmail(),
                identity.getDisplayName(),
                Boolean.TRUE.equals(identity.getEmailVerified()),
                identity.getAccountStatus().name(),
                Boolean.TRUE.equals(identity.getMfaEnabled()),
                identity.getLastLoginAt(),
                identity.getCreatedAt(),
                identity.getUpdatedAt(),
                identity.getFailedLoginAttempts() == null ? 0 : identity.getFailedLoginAttempts(),
                identity.getAccountLockedUntil(),
                identity.getLastLoginIp()
        );
    }
}
