package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Permission;
import io.github.mesubash.iam.authz.entity.ResourceGrant;
import io.github.mesubash.iam.authz.repository.PermissionRepository;
import io.github.mesubash.iam.authz.repository.ResourceGrantRepository;
import io.github.mesubash.iam.authz.service.DelegatedManagementGuard;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/resource-grants")
@RequiredArgsConstructor
@Tag(name = "Resource Grants", description = "Per-instance permissions: share one resource with one subject")
public class ResourceGrantController {

    private final ResourceGrantRepository grantRepository;
    private final PermissionRepository permissionRepository;
    private final DelegatedManagementGuard delegationGuard;
    private final FeatureFlags featureFlags;

    @PostMapping
    @Operation(summary = "Create grant",
            description = "Grantor must hold the granted permission (ceiling); wildcard-action grants need SuperAdmin")
    public ResponseEntity<ResourceGrant> create(
            @AuthenticationPrincipal UserPrincipal caller,
            @Valid @RequestBody CreateGrantRequest request) {
        requireEnabled();

        // Ceiling: nobody hands out capabilities they don't hold themselves
        if (request.getPermissionKey().endsWith(".*")) {
            if (!delegationGuard.isPlatformAdmin(caller)) {
                throw new ForbiddenException("Wildcard grants require SuperAdmin");
            }
        } else {
            Permission permission = permissionRepository.findByKey(request.getPermissionKey())
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + request.getPermissionKey()));
            delegationGuard.assertWithinPermissionCeiling(caller, List.of(permission.getId()));
        }
        if (request.getScopeId() != null) {
            delegationGuard.assertCanManageScope(caller, request.getScopeId());
        }

        ResourceGrant grant = grantRepository.save(ResourceGrant.builder()
                .subjectId(request.getSubjectId())
                .subjectType(request.getSubjectType() != null ? request.getSubjectType() : "USER")
                .permissionKey(request.getPermissionKey())
                .resourceType(request.getResourceType())
                .resourceId(request.getResourceId())
                .scopeId(request.getScopeId())
                .grantedBy(caller.getId().toString())
                .grantedAt(Instant.now())
                .expiresAt(request.getExpiresAt())
                .build());

        return ResponseEntity.status(HttpStatus.CREATED).body(grant);
    }

    @GetMapping
    public ResponseEntity<List<ResourceGrant>> list(
            @RequestParam(required = false) String subjectId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId) {
        requireEnabled();
        if (subjectId != null) {
            return ResponseEntity.ok(grantRepository.findActiveBySubject(subjectId, Instant.now()));
        }
        if (resourceType != null && resourceId != null) {
            return ResponseEntity.ok(
                    grantRepository.findActiveByResource(resourceType, resourceId, Instant.now()));
        }
        throw new IllegalArgumentException("Provide subjectId, or resourceType and resourceId");
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revoke(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id) {
        requireEnabled();
        ResourceGrant grant = grantRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Grant not found"));

        // Grantor or platform admin may revoke
        if (!grant.getGrantedBy().equals(caller.getId().toString())
                && !delegationGuard.isPlatformAdmin(caller)) {
            throw new ForbiddenException("Only the grantor or a SuperAdmin may revoke this grant");
        }

        grant.setRevokedAt(Instant.now());
        grant.setRevokedBy(caller.getId().toString());
        grantRepository.save(grant);
        return ResponseEntity.noContent().build();
    }

    private void requireEnabled() {
        if (!featureFlags.isResourceGrants()) {
            throw new ResourceNotFoundException("Resource grants are not enabled");
        }
    }

    @Data
    public static class CreateGrantRequest {
        @NotBlank
        private String subjectId;
        private String subjectType;
        @NotBlank
        private String permissionKey;
        @NotBlank
        private String resourceType;
        @NotBlank
        private String resourceId;
        private UUID scopeId;
        private Instant expiresAt;
    }
}
