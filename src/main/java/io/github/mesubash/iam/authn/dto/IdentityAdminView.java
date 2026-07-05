package io.github.mesubash.iam.authn.dto;

import io.github.mesubash.iam.authn.entity.Identity;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Admin-facing projection of an identity. Never exposes credentials,
 * lockout counters, or login IPs.
 */
public record IdentityAdminView(
        UUID id,
        String email,
        boolean emailVerified,
        String accountStatus,
        boolean mfaEnabled,
        OffsetDateTime lastLoginAt,
        OffsetDateTime createdAt
) {
    public static IdentityAdminView from(Identity identity) {
        return new IdentityAdminView(
                identity.getId(),
                identity.getPrimaryEmail(),
                Boolean.TRUE.equals(identity.getEmailVerified()),
                identity.getAccountStatus().name(),
                Boolean.TRUE.equals(identity.getMfaEnabled()),
                identity.getLastLoginAt(),
                identity.getCreatedAt()
        );
    }
}
