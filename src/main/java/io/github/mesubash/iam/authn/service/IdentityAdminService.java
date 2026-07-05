package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.dto.AdminCreateIdentityRequest;
import io.github.mesubash.iam.authn.dto.AdminSetPasswordRequest;
import io.github.mesubash.iam.authn.dto.AdminUpdateStatusRequest;
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

    List<IdentityAdminView> search(String query, String status, int limit);

    IdentityAdminView get(UUID id);

    /** Create an account. Generates a temporary password when none is given. */
    CreatedIdentity create(UserPrincipal caller, AdminCreateIdentityRequest request);

    /** Replace the user's password; optionally revoke all their sessions. */
    PasswordSet setPassword(UserPrincipal caller, UUID id, AdminSetPasswordRequest request);

    IdentityAdminView updateStatus(UserPrincipal caller, UUID id, AdminUpdateStatusRequest request);
}
