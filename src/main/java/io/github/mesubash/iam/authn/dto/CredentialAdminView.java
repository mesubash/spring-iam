package io.github.mesubash.iam.authn.dto;

import io.github.mesubash.iam.authn.entity.Credential;

import java.time.OffsetDateTime;

/**
 * Admin-facing projection of a credential: how an identity can sign in.
 * The identifier is masked and the secret is never exposed.
 */
public record CredentialAdminView(
        String type,
        String identifier,
        boolean active,
        OffsetDateTime lastUsedAt,
        OffsetDateTime createdAt
) {
    public static CredentialAdminView from(Credential credential) {
        return new CredentialAdminView(
                credential.getCredentialType().name(),
                mask(credential.getIdentifier()),
                Boolean.TRUE.equals(credential.getIsActive()),
                credential.getLastUsedAt(),
                credential.getCreatedAt()
        );
    }

    /** "someone@example.com" becomes "so***@example.com"; opaque ids keep 4 characters. */
    static String mask(String identifier) {
        if (identifier == null || identifier.isBlank()) return null;
        int at = identifier.indexOf('@');
        if (at > 0) {
            return identifier.substring(0, Math.min(2, at)) + "***" + identifier.substring(at);
        }
        return identifier.substring(0, Math.min(4, identifier.length())) + "***";
    }
}
