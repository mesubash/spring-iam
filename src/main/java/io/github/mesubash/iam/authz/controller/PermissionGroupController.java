package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authz.dto.CreatePermissionGroupRequest;
import io.github.mesubash.iam.authz.dto.UpdatePermissionGroupPermissionsRequest;
import io.github.mesubash.iam.authz.entity.Permission;
import io.github.mesubash.iam.authz.entity.PermissionGroup;
import io.github.mesubash.iam.authz.service.PermissionGroupService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/permission-groups")
@RequiredArgsConstructor
@Tag(name = "Permission Groups", description = "Permission grouping for management UI")
public class PermissionGroupController {

    private final PermissionGroupService permissionGroupService;

    @GetMapping
    public ResponseEntity<List<PermissionGroup>> getGroups() {
        return ResponseEntity.ok(permissionGroupService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<PermissionGroup> getGroup(@PathVariable UUID id) {
        return permissionGroupService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<PermissionGroup> createGroup(
            @Valid @RequestBody CreatePermissionGroupRequest request) {
        PermissionGroup group = permissionGroupService.create(
                request.getName(),
                request.getDescription(),
                request.getParentGroupId()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(group);
    }

    @GetMapping("/{id}/permissions")
    public ResponseEntity<List<Permission>> getGroupPermissions(@PathVariable UUID id) {
        return ResponseEntity.ok(permissionGroupService.getGroupPermissions(id));
    }

    @PutMapping("/{id}/permissions")
    public ResponseEntity<Void> updateGroupPermissions(
            @PathVariable UUID id,
            @RequestBody UpdatePermissionGroupPermissionsRequest request) {
        permissionGroupService.setGroupPermissions(id, request.getPermissionIds());
        return ResponseEntity.ok().build();
    }
}
