package com.hgn.iam.authz.controller;

import com.hgn.iam.authz.dto.CreatePermissionRequest;
import com.hgn.iam.authz.entity.Permission;
import com.hgn.iam.authz.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/permissions")
@RequiredArgsConstructor
@Tag(name = "Permissions", description = "Permission management")
public class PermissionController {

    private final PermissionService permissionService;

    @GetMapping
    public ResponseEntity<List<Permission>> getAllPermissions(
            @RequestParam(required = false) String domain) {

        List<Permission> permissions = domain != null
                ? permissionService.getByDomain(domain)
                : permissionService.getAllActive();

        return ResponseEntity.ok(permissions);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Permission> getPermission(@PathVariable UUID id) {
        return permissionService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @Operation(
            summary = "Create permission(s)",
            description = "Accepts either a single permission object or an array of permission objects."
    )
    public ResponseEntity<?> createPermission(
            @Valid @RequestBody List<@Valid CreatePermissionRequest> requests) {

        if (requests == null || requests.isEmpty()) {
            throw new IllegalArgumentException("At least one permission is required.");
        }

        List<Permission> created = permissionService.createBatch(requests);
        if (created.size() == 1) {
            return ResponseEntity.status(HttpStatus.CREATED).body(created.get(0));
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }
}
