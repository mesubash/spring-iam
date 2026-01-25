package com.hgn.iam.controller;

import com.hgn.iam.dto.CreatePermissionRequest;
import com.hgn.iam.entity.Permission;
import com.hgn.iam.service.PermissionService;
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
    public ResponseEntity<Permission> createPermission(
            @Valid @RequestBody CreatePermissionRequest request) {

        Permission permission = permissionService.create(
                request.getKey(),
                request.getDomain(),
                request.getResource(),
                request.getAction(),
                request.getDescription()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(permission);
    }
}
