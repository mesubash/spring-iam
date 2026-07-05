package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authz.entity.ServiceClient;
import io.github.mesubash.iam.authz.service.ServiceRegistryService;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/services")
@RequiredArgsConstructor
@Tag(name = "Services", description = "Consumer service registry and permission manifest sync")
public class ServiceRegistryController {

    private final ServiceRegistryService registryService;
    private final FeatureFlags featureFlags;

    @PostMapping
    @PreAuthorize("hasRole('SuperAdmin')")
    @Operation(summary = "Register a service",
            description = "Returns the API key ONCE — only its hash is stored")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterServiceRequest request) {
        requireEnabled();
        ServiceRegistryService.RegisteredService registered = registryService.register(
                request.getName(), request.getDisplayName(), request.getOwnedDomains());

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "id", registered.service().getId(),
                "name", registered.service().getName(),
                "ownedDomains", registered.service().getOwnedDomains(),
                "apiKey", registered.rawApiKey()));
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<List<ServiceClient>> list() {
        requireEnabled();
        return ResponseEntity.ok(registryService.listAll());
    }

    @PutMapping("/{name}/permissions")
    @Operation(summary = "Sync permission manifest",
            description = "Idempotent upsert of the service's own permission keys; "
                    + "callable by the service itself (its API key) or a SuperAdmin")
    public ResponseEntity<ServiceRegistryService.SyncResult> syncPermissions(
            @PathVariable String name,
            @RequestBody ManifestRequest request,
            Authentication authentication) {
        requireEnabled();
        assertServiceItselfOrSuperAdmin(authentication, name);

        ServiceRegistryService.SyncResult result = registryService.syncPermissions(
                name, request.getPermissions(),
                request.getDeprecateMissing() == null || request.getDeprecateMissing());
        return ResponseEntity.ok(result);
    }

    private void requireEnabled() {
        if (!featureFlags.isServiceRegistry()) {
            throw new ResourceNotFoundException("Service registry is not enabled");
        }
    }

    private void assertServiceItselfOrSuperAdmin(Authentication authentication, String name) {
        boolean superAdmin = authentication.getAuthorities()
                .contains(new SimpleGrantedAuthority("ROLE_SuperAdmin"));
        boolean self = ("service:" + name).equals(authentication.getName());
        if (!superAdmin && !self) {
            throw new ForbiddenException("Only the service itself or a SuperAdmin may sync this manifest");
        }
    }

    @Data
    public static class RegisterServiceRequest {
        @NotBlank
        private String name;
        private String displayName;
        private List<String> ownedDomains;
    }

    @Data
    public static class ManifestRequest {
        private List<Map<String, String>> permissions;
        private Boolean deprecateMissing;
    }
}
