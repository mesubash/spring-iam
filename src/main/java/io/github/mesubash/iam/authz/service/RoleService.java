package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Permission;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.entity.RolePermission;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.PermissionRepository;
import io.github.mesubash.iam.authz.repository.RoleHierarchyRepository;
import io.github.mesubash.iam.authz.repository.RolePermissionRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.shared.exception.ConflictException;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
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
    private final DelegatedManagementGuard delegationGuard;
    private final AssignmentRepository assignmentRepository;
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
        return roleRepository.findByOwnerScopeIdIsNullAndName(name);
    }

    @Transactional(readOnly = true)
    public List<Permission> getRolePermissions(UUID roleId) {
        Set<UUID> roleIds = resolveRoleHierarchy(roleId);
        return rolePermissionRepository.findPermissionsByRoleIds(roleIds);
    }

    @Transactional
    public Role create(UserPrincipal caller, String name, String displayName, String description,
                       String orgType, UUID ownerScopeId, List<UUID> permissionIds) {

        // Enforce permission ceiling: caller cannot grant permissions they don't hold
        delegationGuard.assertWithinPermissionCeiling(caller, permissionIds);

        // Tenant-scoped role: caller must have authority over the owning subtree
        if (ownerScopeId != null) {
            delegationGuard.assertCanManageScope(caller, ownerScopeId);
        }

        // Uniqueness is per owner scope — tenant roles may share names across subtrees
        Optional<Role> existing = roleRepository.findByOwnerAndName(ownerScopeId, name);
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Role already exists: " + name);
        }

        // Validate all permissions exist
        for (UUID permissionId : permissionIds) {
            permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permissionId));
        }

        String createdBy = caller.getId().toString();

        // Create role
        Role role = Role.builder()
                .name(name)
                .displayName(displayName)
                .description(description)
                .orgType(orgType)
                .ownerScopeId(ownerScopeId)
                .isSystemRole(false)
                .active(true)
                .createdBy(createdBy)
                .build();

        Role savedRole = roleRepository.save(role);

        // Create role-permission mappings
        for (UUID permissionId : permissionIds) {
            RolePermission rp = RolePermission.builder()
                    .roleId(savedRole.getId())
                    .permissionId(permissionId)
                    .grantedBy(createdBy)
                    .build();
            rolePermissionRepository.save(rp);
        }

        log.info("Created role: {} with {} permissions", name, permissionIds.size());

        return savedRole;
    }

    @Transactional
    public void updatePermissions(UserPrincipal caller, UUID roleId, List<UUID> permissionIds) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        if (role.getIsSystemRole()) {
            throw new IllegalArgumentException("Cannot modify system role permissions");
        }

        // Enforce permission ceiling: caller cannot grant permissions they don't hold
        delegationGuard.assertWithinPermissionCeiling(caller, permissionIds);

        // Validate all permissions exist
        for (UUID permissionId : permissionIds) {
            permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permissionId));
        }

        // Invalidate role cache BEFORE modifying data to prevent serving stale empty set.
        // A concurrent reader that misses cache will see the DB state which is protected
        // by this transaction's isolation level (read committed).
        authorizationService.invalidateRoleCache(roleId);

        // Delete existing mappings
        rolePermissionRepository.deleteByRoleId(roleId);

        // Create new mappings
        String grantedBy = caller.getId().toString();
        for (UUID permissionId : permissionIds) {
            RolePermission rp = RolePermission.builder()
                    .roleId(roleId)
                    .permissionId(permissionId)
                    .grantedBy(grantedBy)
                    .build();
            rolePermissionRepository.save(rp);
        }

        // Invalidate again AFTER commit to clear any cache populated during the transaction
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

    /**
     * Deletes a custom role. Refused for system roles and while any active assignment still uses
     * the role, so nobody silently loses access: revoke first. A global role needs a SuperAdmin;
     * a tenant role needs authority over its owning scope.
     */
    @Transactional
    public void delete(UserPrincipal caller, UUID roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        if (Boolean.TRUE.equals(role.getIsSystemRole())) {
            throw new IllegalArgumentException("Cannot delete a system role");
        }
        if (role.getOwnerScopeId() != null) {
            delegationGuard.assertCanManageScope(caller, role.getOwnerScopeId());
        } else if (!delegationGuard.isPlatformAdmin(caller)) {
            throw new ForbiddenException("Only a SuperAdmin may delete a global role");
        }

        long active = assignmentRepository.countByRoleIdAndActiveTrue(roleId);
        if (active > 0) {
            throw new ConflictException(
                    "Role has " + active + " active assignment(s); revoke them before deleting");
        }

        // Revoking only deactivates an assignment, so revoked rows still hold the
        // assignments.role_id foreign key (ON DELETE RESTRICT). Permission grants and hierarchy
        // edges cascade with the role.
        assignmentRepository.deleteByRoleId(roleId);
        roleRepository.delete(role);

        // Roles that inherited from this one change too, so drop every role entry, not just this one.
        cacheService.invalidateAllRolePermissions();
        log.info("Deleted role: {} ({})", role.getName(), roleId);
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
