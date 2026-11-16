package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.dto.AdminCreateIdentityRequest;
import io.github.mesubash.iam.authn.dto.AdminSetPasswordRequest;
import io.github.mesubash.iam.authn.dto.AdminUpdateStatusRequest;
import io.github.mesubash.iam.authn.dto.CredentialAdminView;
import io.github.mesubash.iam.authn.dto.IdentityAdminView;
import io.github.mesubash.iam.authn.security.UserPrincipal;

import java.util.List;
import java.util.UUID;

/**
 * Admin-side identity lifecycle: list/search users, create accounts,
 * reset passwords, and change account status. All operations are audited
 * as security events.
 */
public interface IdentityAdminService {

    record CreatedIdentity(IdentityAdminView identity, String temporaryPassword) {}

    record PasswordSet(String temporaryPassword, boolean sessionsRevoked) {}

    List<IdentityAdminView> search(String query, String status, int limit, int page);

    IdentityAdminView get(UUID id);

    /** Create an account. Generates a temporary password when none is given. */
    CreatedIdentity create(UserPrincipal caller, AdminCreateIdentityRequest request);

    /** Replace the user's password; optionally revoke all their sessions. */
    PasswordSet setPassword(UserPrincipal caller, UUID id, AdminSetPasswordRequest request);

    IdentityAdminView updateStatus(UserPrincipal caller, UUID id, AdminUpdateStatusRequest request);

    /** How the identity can sign in; identifiers masked, never secrets. */
    List<CredentialAdminView> credentials(UUID id);

    /** Verify-only: marks the email verified for users who cannot finish the email loop. */
    IdentityAdminView markEmailVerified(UserPrincipal caller, UUID id);

    /** Sets or (blank) clears the display name. */
    IdentityAdminView setDisplayName(UserPrincipal caller, UUID id, String name);

    /** Clears MFA so the user must re-enroll (lost device). Refused on a SuperAdmin unless caller is one. */
    void resetMfa(UserPrincipal caller, UUID id);

    /**
     * Whether the identity holds SuperAdmin or any role at ROOT. Callers with no identity of their
     * own to rank (a service on an API key) must leave such an account alone.
     */
    boolean isPlatformAdmin(UUID id);
}
