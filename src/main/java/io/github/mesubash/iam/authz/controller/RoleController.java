package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.dto.CreateRoleRequest;
import io.github.mesubash.iam.authz.entity.Permission;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.service.RoleService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
@Tag(name = "Roles", description = "Role management")
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    public ResponseEntity<List<Role>> getAllRoles(
            @RequestParam(required = false) String orgType) {

        List<Role> roles = orgType != null
                ? roleService.getByOrgType(orgType)
                : roleService.getAllActive();

        return ResponseEntity.ok(roles);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Role> getRole(@PathVariable UUID id) {
        return roleService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/permissions")
    public ResponseEntity<List<Permission>> getRolePermissions(@PathVariable UUID id) {
        List<Permission> permissions = roleService.getRolePermissions(id);
        return ResponseEntity.ok(permissions);
    }

    @PostMapping
    public ResponseEntity<Role> createRole(
            @AuthenticationPrincipal UserPrincipal caller,
            @Valid @RequestBody CreateRoleRequest request) {

        Role role = roleService.create(
                caller,
                request.getName(),
                request.getDisplayName(),
                request.getDescription(),
                request.getOrgType(),
                request.getPermissionIds()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }

    @PutMapping("/{id}/permissions")
    public ResponseEntity<Void> updateRolePermissions(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id,
            @RequestBody List<UUID> permissionIds) {

        roleService.updatePermissions(caller, id, permissionIds);
        return ResponseEntity.ok().build();
    }
}
