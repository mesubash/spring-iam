package com.hgn.iam.authz.service;

import com.hgn.iam.authn.security.UserPrincipal;
import com.hgn.iam.authz.entity.Assignment;
import com.hgn.iam.authz.entity.Permission;
import com.hgn.iam.authz.repository.AssignmentRepository;
import com.hgn.iam.authz.repository.RoleHierarchyRepository;
import com.hgn.iam.authz.repository.RolePermissionRepository;
import com.hgn.iam.authz.repository.ScopeClosureRepository;
import com.hgn.iam.shared.exception.ForbiddenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Enforces two delegation rules on management write operations:
 *
 * 1. Scope containment — the caller must hold an active assignment whose scope contains
 *    (or equals) the target scope. Prevents org admins from managing resources
 *    outside their own scope tree.
 *
 * 2. Permission ceiling — when creating/updating a role's permissions, the caller
 *    cannot grant permissions that they do not themselves hold. Prevents privilege
 *    escalation through role crafting.
 *
 * SuperAdmin bypasses all checks.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DelegatedManagementGuard {

    private final AssignmentRepository assignmentRepository;
    private final ScopeClosureRepository scopeClosureRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RoleHierarchyRepository roleHierarchyRepository;

    /**
     * Returns true if the caller is a SuperAdmin (full bypass of all delegation checks).
     */
    public boolean isPlatformAdmin(UserPrincipal caller) {
        return caller.getAuthorities().stream()
                .anyMatch(a -> "ROLE_SuperAdmin".equals(a.getAuthority()));
    }

    /**
     * Asserts that the caller has management authority over the given target scope.
     *
     * The caller is authorized if at least one of their active assignments has a scope
     * that contains (or equals) the target scope, as determined by the scope_closure table.
     *
     * SuperAdmin bypasses this check entirely.
     *
     * @param caller        the authenticated principal
     * @param targetScopeId the scope of the resource being managed
     * @throws ForbiddenException if the caller has no authority over the target scope
     */
    public void assertCanManageScope(UserPrincipal caller, UUID targetScopeId) {
        if (isPlatformAdmin(caller)) {
            return;
        }

        String subjectId = caller.getId().toString();
        List<Assignment> callerAssignments = assignmentRepository.findActiveAssignments(subjectId, Instant.now());

        boolean authorized = callerAssignments.stream()
                .anyMatch(a -> scopeClosureRepository.scopeContains(a.getScopeId(), targetScopeId));

        if (!authorized) {
            log.warn("Delegation guard blocked {}: no authority over scope {}", subjectId, targetScopeId);
            throw new ForbiddenException(
                    "You do not have management authority over the target scope.");
        }
    }

    /**
     * Asserts that all requested permission IDs are within the caller's effective permission set.
     *
     * This enforces the permission ceiling — you cannot grant a permission you do not hold.
     * The caller's effective permissions are the union of all permissions across all their
     * active role assignments.
     *
     * SuperAdmin bypasses this check entirely. An empty or null request is always allowed.
     *
     * @param caller                the authenticated principal
     * @param requestedPermissionIds the permission IDs the caller wants to grant
     * @throws ForbiddenException if any requested permission exceeds the caller's ceiling
     */
    public void assertWithinPermissionCeiling(UserPrincipal caller, List<UUID> requestedPermissionIds) {
        if (requestedPermissionIds == null || requestedPermissionIds.isEmpty()) {
            return;
        }

        if (isPlatformAdmin(caller)) {
            return;
        }

        String subjectId = caller.getId().toString();
        List<Assignment> callerAssignments = assignmentRepository.findActiveAssignments(subjectId, Instant.now());

        if (callerAssignments.isEmpty()) {
            throw new ForbiddenException(
                    "You have no active assignments and cannot grant permissions.");
        }

        // Resolve role hierarchy so inherited permissions are included in the ceiling
        Set<UUID> callerRoleIds = callerAssignments.stream()
                .map(Assignment::getRoleId)
                .collect(Collectors.toSet());

        Set<UUID> resolvedRoleIds = resolveAllRoleHierarchies(callerRoleIds);

        List<Permission> callerPermissions = rolePermissionRepository.findPermissionsByRoleIds(resolvedRoleIds);

        Set<UUID> callerPermissionIds = callerPermissions.stream()
                .map(Permission::getId)
                .collect(Collectors.toSet());

        List<UUID> exceeded = requestedPermissionIds.stream()
                .filter(id -> !callerPermissionIds.contains(id))
                .toList();

        if (!exceeded.isEmpty()) {
            log.warn("Delegation guard blocked {}: attempted to grant permissions beyond ceiling: {}",
                    subjectId, exceeded);
            throw new ForbiddenException(
                    "You cannot grant permissions that you do not hold. " +
                    "Requested permission IDs exceed your ceiling: " + exceeded);
        }
    }

    /**
     * Resolves full role hierarchy for a set of role IDs, including all inherited parent roles.
     * Uses BFS to traverse the hierarchy and prevent cycles.
     */
    private Set<UUID> resolveAllRoleHierarchies(Set<UUID> roleIds) {
        Set<UUID> resolved = new HashSet<>();
        Deque<UUID> queue = new ArrayDeque<>(roleIds);

        while (!queue.isEmpty()) {
            UUID current = queue.removeFirst();
            if (!resolved.add(current)) {
                continue; // Already visited — prevents cycles
            }
            Set<UUID> parents = roleHierarchyRepository.findParentRoleIdsByChildId(current);
            if (parents != null) {
                for (UUID parent : parents) {
                    if (!resolved.contains(parent)) {
                        queue.add(parent);
                    }
                }
            }
        }

        return resolved;
    }
}
