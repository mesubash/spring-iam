package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authz.dto.MeBootstrapResponse;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.dto.ApiResponse;
import io.github.mesubash.iam.shared.dto.ScopeSummaryDto;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.github.mesubash.iam.shared.service.AuthzQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/authz/me")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
@Tag(name = "AuthZ - User Facing", description = "User-facing authorization endpoints for org switcher and permissions")
public class AuthzMeController {

    private final AuthzQueryService authzQueryService;
    private final IdentityRepository identityRepository;
    private final FeatureFlags featureFlags;

    @GetMapping("/bootstrap")
    @Operation(summary = "Bootstrap the session",
            description = "One call for a freshly-loaded client: identity, scopes, permissions at the "
                    + "active scope, and feature flags. Pass scopeId to target a remembered scope.")
    public ResponseEntity<ApiResponse<MeBootstrapResponse>> bootstrap(
            @AuthenticationPrincipal Object principal,
            @RequestParam(required = false) UUID scopeId) {
        UUID identityId = extractIdentityId(principal);
        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        List<ScopeSummaryDto> scopes = authzQueryService.getScopesForIdentity(identityId);

        // Resolve the active scope: a valid requested scope, else the first one.
        UUID active = null;
        if (scopeId != null && scopes.stream().anyMatch(s -> scopeId.equals(s.getId()))) {
            active = scopeId;
        } else if (!scopes.isEmpty()) {
            active = scopes.get(0).getId();
        }

        List<String> permissions = active != null
                ? authzQueryService.getEffectivePermissions(identityId, active)
                : List.of();

        MeBootstrapResponse body = new MeBootstrapResponse(
                new MeBootstrapResponse.Identity(
                        identity.getId(),
                        identity.getPrimaryEmail(),
                        null,
                        identity.getEmailVerified()),
                active,
                scopes,
                permissions,
                featureFlags.asMap());
        return ResponseEntity.ok(ApiResponse.success("Bootstrap", body));
    }

    @GetMapping("/scopes")
    @Operation(summary = "List my scopes", description = "Returns the scopes (orgs/teams) where the current user has active role assignments. Used for the org-switcher UI.")
    public ResponseEntity<ApiResponse<List<ScopeSummaryDto>>> getMyScopes(
            @AuthenticationPrincipal Object principal) {
        UUID identityId = extractIdentityId(principal);
        List<ScopeSummaryDto> scopes = authzQueryService.getScopesForIdentity(identityId);
        return ResponseEntity.ok(ApiResponse.success("Scopes retrieved", scopes));
    }

    @GetMapping("/permissions")
    @Operation(summary = "Get my permissions at a scope", description = "Returns the effective permissions for the current user at the given scope. Used to drive permission-based UI rendering.")
    public ResponseEntity<ApiResponse<List<String>>> getMyPermissions(
            @AuthenticationPrincipal Object principal,
            @RequestParam UUID scopeId) {
        UUID identityId = extractIdentityId(principal);
        List<String> permissions = authzQueryService.getEffectivePermissions(identityId, scopeId);
        return ResponseEntity.ok(ApiResponse.success("Permissions retrieved", permissions));
    }

    private UUID extractIdentityId(Object principal) {
        if (principal instanceof io.github.mesubash.iam.authn.security.UserPrincipal userPrincipal) {
            return userPrincipal.getId();
        }
        // Fallback for string-based principals (e.g., from service JWT)
        return UUID.fromString(principal.toString());
    }
}
