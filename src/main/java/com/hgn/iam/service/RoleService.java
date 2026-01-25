package com.hgn.iam.service;

import com.hgn.iam.entity.Permission;
import com.hgn.iam.entity.Role;
import com.hgn.iam.repository.PermissionRepository;
import com.hgn.iam.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final CacheService cacheService;

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
        // TODO: Implement via RolePermissionRepository
        return new ArrayList<>();
    }

    @Transactional
    public Role create(String name, String displayName, String description,
                       String orgType, List<UUID> permissionIds) {

        // Check if role already exists
        Optional<Role> existing = roleRepository.findByName(name);
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Role already exists: " + name);
        }

        Role role = Role.builder()
                .name(name)
                .displayName(displayName)
                .description(description)
                .orgType(orgType)
                .isSystemRole(false)
                .active(true)
                .createdBy("system")
                .build();

        Role saved = roleRepository.save(role);

        // Add permissions
        if (permissionIds != null && !permissionIds.isEmpty()) {
            updatePermissions(saved.getId(), permissionIds);
        }

        log.info("Created role: {}", name);
        return saved;
    }

    @Transactional
    public void updatePermissions(UUID roleId, List<UUID> permissionIds) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        // TODO: Delete existing role_permissions
        // TODO: Insert new role_permissions

        // Invalidate cache for all users with this role
        log.info("Updated permissions for role: {}", role.getName());
    }
}
