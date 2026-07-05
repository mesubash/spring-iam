package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.dto.AdminCreateIdentityRequest;
import io.github.mesubash.iam.authn.dto.AdminSetPasswordRequest;
import io.github.mesubash.iam.authn.dto.AdminUpdateStatusRequest;
import io.github.mesubash.iam.authn.dto.IdentityAdminView;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.service.IdentityAdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Admin user management. Reads are open to all admin-tier roles (they back
 * the console's user picker); mutations are restricted to identity-lifecycle
 * owners. Client UIs gate on the matching platform.identity.* permissions.
 */
@RestController
@RequestMapping("/api/v1/identities")
@RequiredArgsConstructor
@Tag(name = "Identity admin", description = "Admin-side user management")
public class IdentityAdminController {

    private final IdentityAdminService identityAdminService;

    @GetMapping
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','AccessAdmin','SecurityAdmin'," +
            "'OperationsAdmin','AuditViewer','GovernmentOversight')")
    @Operation(summary = "List/search users",
            description = "Substring match on email; optional status filter; capped at 200 rows")
    public ResponseEntity<List<IdentityAdminView>> search(
            @RequestParam(required = false) String query,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(identityAdminService.search(query, status, limit));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','AccessAdmin','SecurityAdmin'," +
            "'OperationsAdmin','AuditViewer','GovernmentOversight')")
    public ResponseEntity<IdentityAdminView> get(@PathVariable UUID id) {
        return ResponseEntity.ok(identityAdminService.get(id));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','SecurityAdmin')")
    @Operation(summary = "Create a user",
            description = "Password optional — a temporary one is generated and returned once")
    public ResponseEntity<IdentityAdminService.CreatedIdentity> create(
            @AuthenticationPrincipal UserPrincipal caller,
            @Valid @RequestBody AdminCreateIdentityRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(identityAdminService.create(caller, request));
    }

    @PutMapping("/{id}/password")
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','SecurityAdmin')")
    @Operation(summary = "Admin password reset",
            description = "Sets a new password (or generates one) and revokes sessions by default")
    public ResponseEntity<IdentityAdminService.PasswordSet> setPassword(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id,
            @Valid @RequestBody AdminSetPasswordRequest request) {
        return ResponseEntity.ok(identityAdminService.setPassword(caller, id, request));
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','SecurityAdmin')")
    @Operation(summary = "Change account status",
            description = "ACTIVE / SUSPENDED / DEACTIVATED; non-active revokes sessions; cannot target yourself")
    public ResponseEntity<IdentityAdminView> updateStatus(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id,
            @Valid @RequestBody AdminUpdateStatusRequest request) {
        return ResponseEntity.ok(identityAdminService.updateStatus(caller, id, request));
    }
}
