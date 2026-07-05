package io.github.mesubash.iam.authz.dto;

import io.github.mesubash.iam.shared.dto.ScopeSummaryDto;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Everything a freshly-loaded console needs in one call: who you are, where you
 * can act, what you can do at the active scope, and which features are on.
 * Replaces the login/refresh identity blob + separate scopes/permissions/features
 * requests. Permissions are per-scope; on a scope switch the client re-fetches
 * GET /api/authz/me/permissions?scopeId=… for the new scope only.
 */
public record MeBootstrapResponse(
        Identity identity,
        UUID scopeId,
        List<ScopeSummaryDto> scopes,
        List<String> permissions,
        Map<String, Boolean> features
) {
    public record Identity(UUID id, String email, String displayName, Boolean emailVerified) {}
}
