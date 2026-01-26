package com.hgn.iam.service;

import com.hgn.iam.entity.Permission;
import com.hgn.iam.entity.Role;
import com.hgn.iam.entity.RolePermission;
import com.hgn.iam.repository.PermissionRepository;
import com.hgn.iam.repository.RoleHierarchyRepository;
import com.hgn.iam.repository.RolePermissionRepository;
import com.hgn.iam.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;
    private final PermissionRepository permissionRepository;
    private final AuthorizationService authorizationService;

    @Transactional(readOnly = true)
    public List<Role> getAllActive() {
        return roleRepository.findAllActive();
    }

    @Transactional(readOnly = true)
    public List<Role> getByOrgType(String orgType) {
        return roleRepository.findByOrgType(orgType);
    }

    @Transactional(readOnly = true)
    public Optional<Role> getById(UUID id) {
        return roleRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<Role> getByName(String name) {
        return roleRepository.findByName(name);
    }

    @Transactional(readOnly = true)
    public List<Permission> getRolePermissions(UUID roleId) {
        Set<UUID> roleIds = resolveRoleHierarchy(roleId);
        return rolePermissionRepository.findPermissionsByRoleIds(roleIds);
    }

    @Transactional
    public Role create(String name, String displayName, String description,
                       String orgType, List<UUID> permissionIds) {

        // Check if role already exists
        Optional<Role> existing = roleRepository.findByName(name);
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Role already exists: " + name);
        }

        // Validate all permissions exist
        for (UUID permissionId : permissionIds) {
            permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permissionId));
        }

        // Create role
        Role role = Role.builder()
                .name(name)
                .displayName(displayName)
                .description(description)
                .orgType(orgType)
                .isSystemRole(false)
                .active(true)
                .createdBy("system")
                .build();

        Role savedRole = roleRepository.save(role);

        // Create role-permission mappings
        for (UUID permissionId : permissionIds) {
            RolePermission rp = RolePermission.builder()
                    .roleId(savedRole.getId())
                    .permissionId(permissionId)
                    .grantedBy("system")
                    .build();
            rolePermissionRepository.save(rp);
        }

        log.info("Created role: {} with {} permissions", name, permissionIds.size());

        return savedRole;
    }

    @Transactional
    public void updatePermissions(UUID roleId, List<UUID> permissionIds) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        if (role.getIsSystemRole()) {
            throw new IllegalArgumentException("Cannot modify system role permissions");
        }

        // Validate all permissions exist
        for (UUID permissionId : permissionIds) {
            permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permissionId));
        }

        // Delete existing mappings
        rolePermissionRepository.deleteByRoleId(roleId);

        // Create new mappings
        for (UUID permissionId : permissionIds) {
            RolePermission rp = RolePermission.builder()
                    .roleId(roleId)
                    .permissionId(permissionId)
                    .grantedBy("system")
                    .build();
            rolePermissionRepository.save(rp);
        }

        // Invalidate role cache
        authorizationService.invalidateRoleCache(roleId);

        log.info("Updated permissions for role: {} (new count: {})",
                role.getName(), permissionIds.size());
    }

    @Transactional
    public Role deactivate(UUID roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        if (role.getIsSystemRole()) {
            throw new IllegalArgumentException("Cannot deactivate system role");
        }

        role.setActive(false);
        Role updated = roleRepository.save(role);

        // Invalidate role cache
        authorizationService.invalidateRoleCache(roleId);

        log.info("Deactivated role: {}", role.getName());
        return updated;
    }

    private Set<UUID> resolveRoleHierarchy(UUID roleId) {
        Set<UUID> resolved = new HashSet<>();
        Deque<UUID> queue = new ArrayDeque<>();
        queue.add(roleId);

        while (!queue.isEmpty()) {
            UUID current = queue.removeFirst();
            if (!resolved.add(current)) {
                continue;
            }
            Set<UUID> parents = roleHierarchyRepository.findParentRoleIdsByChildId(current);
            if (parents != null) {
                queue.addAll(parents);
            }
        }

        return resolved;
    }
}
