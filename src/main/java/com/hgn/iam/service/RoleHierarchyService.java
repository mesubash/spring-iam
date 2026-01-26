package com.hgn.iam.service;

import com.hgn.iam.entity.Role;
import com.hgn.iam.entity.RoleHierarchy;
import com.hgn.iam.entity.RoleHierarchyId;
import com.hgn.iam.repository.RoleHierarchyRepository;
import com.hgn.iam.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleHierarchyService {

    private final RoleHierarchyRepository roleHierarchyRepository;
    private final RoleRepository roleRepository;
    private final CacheService cacheService;

    @Transactional(readOnly = true)
    public Set<UUID> getParents(UUID childRoleId) {
        return roleHierarchyRepository.findParentRoleIdsByChildId(childRoleId);
    }

    @Transactional(readOnly = true)
    public Set<UUID> getChildren(UUID parentRoleId) {
        return roleHierarchyRepository.findChildRoleIdsByParentId(parentRoleId);
    }

    @Transactional
    public RoleHierarchy addParentRole(UUID parentRoleId, UUID childRoleId) {
        if (parentRoleId.equals(childRoleId)) {
            throw new IllegalArgumentException("Role cannot inherit from itself");
        }

        Role parent = roleRepository.findById(parentRoleId)
                .orElseThrow(() -> new IllegalArgumentException("Parent role not found"));
        Role child = roleRepository.findById(childRoleId)
                .orElseThrow(() -> new IllegalArgumentException("Child role not found"));

        if (wouldCreateCycle(parentRoleId, childRoleId)) {
            throw new IllegalArgumentException("Role hierarchy cycle detected");
        }

        RoleHierarchyId id = new RoleHierarchyId(parentRoleId, childRoleId);
        if (roleHierarchyRepository.existsById(id)) {
            throw new IllegalArgumentException("Role hierarchy already exists");
        }

        RoleHierarchy hierarchy = RoleHierarchy.builder()
                .parentRoleId(parentRoleId)
                .childRoleId(childRoleId)
                .build();

        RoleHierarchy saved = roleHierarchyRepository.save(hierarchy);
        cacheService.invalidateAllRolePermissions();

        log.info("Added role hierarchy: {} -> {}", parent.getName(), child.getName());
        return saved;
    }

    @Transactional
    public void removeParentRole(UUID parentRoleId, UUID childRoleId) {
        RoleHierarchyId id = new RoleHierarchyId(parentRoleId, childRoleId);
        if (!roleHierarchyRepository.existsById(id)) {
            throw new IllegalArgumentException("Role hierarchy not found");
        }

        roleHierarchyRepository.deleteById(id);
        cacheService.invalidateAllRolePermissions();
        log.info("Removed role hierarchy: {} -> {}", parentRoleId, childRoleId);
    }

    private boolean wouldCreateCycle(UUID parentRoleId, UUID childRoleId) {
        Set<UUID> visited = new HashSet<>();
        Deque<UUID> queue = new ArrayDeque<>();
        queue.add(parentRoleId);

        while (!queue.isEmpty()) {
            UUID current = queue.removeFirst();
            if (!visited.add(current)) {
                continue;
            }
            if (current.equals(childRoleId)) {
                return true;
            }
            Set<UUID> parents = roleHierarchyRepository.findParentRoleIdsByChildId(current);
            if (parents != null) {
                queue.addAll(parents);
            }
        }

        return false;
    }
}
