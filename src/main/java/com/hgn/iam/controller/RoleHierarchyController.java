package com.hgn.iam.controller;

import com.hgn.iam.dto.CreateRoleHierarchyRequest;
import com.hgn.iam.entity.RoleHierarchy;
import com.hgn.iam.service.RoleHierarchyService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/role-hierarchy")
@RequiredArgsConstructor
@Tag(name = "Role Hierarchy", description = "Role inheritance management")
public class RoleHierarchyController {

    private final RoleHierarchyService roleHierarchyService;

    @GetMapping("/parents/{roleId}")
    public ResponseEntity<Set<UUID>> getParents(@PathVariable UUID roleId) {
        return ResponseEntity.ok(roleHierarchyService.getParents(roleId));
    }

    @GetMapping("/children/{roleId}")
    public ResponseEntity<Set<UUID>> getChildren(@PathVariable UUID roleId) {
        return ResponseEntity.ok(roleHierarchyService.getChildren(roleId));
    }

    @PostMapping
    public ResponseEntity<RoleHierarchy> addHierarchy(
            @Valid @RequestBody CreateRoleHierarchyRequest request) {
        RoleHierarchy hierarchy = roleHierarchyService.addParentRole(
                request.getParentRoleId(),
                request.getChildRoleId()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(hierarchy);
    }

    @DeleteMapping
    public ResponseEntity<Void> removeHierarchy(
            @RequestParam UUID parentRoleId,
            @RequestParam UUID childRoleId) {
        roleHierarchyService.removeParentRole(parentRoleId, childRoleId);
        return ResponseEntity.ok().build();
    }
}
