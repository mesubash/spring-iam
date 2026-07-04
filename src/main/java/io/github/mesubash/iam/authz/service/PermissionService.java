package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Permission;
import org.springframework.stereotype.Service;

import io.github.mesubash.iam.authz.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public List<Permission> getAllActive() {
        return permissionRepository.findAllActive();
    }

    @Transactional(readOnly = true)
    public List<Permission> getByDomain(String domain) {
        return permissionRepository.findByDomain(domain);
    }

    @Transactional(readOnly = true)
    public Optional<Permission> getById(UUID id) {
        return permissionRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<Permission> getByKey(String key) {
        return permissionRepository.findByKey(key);
    }

    @Transactional
    public Permission create(String key, String domain, String resource,
                             String action, String description) {

        // Check if permission already exists
        Optional<Permission> existing = permissionRepository.findByKey(key);
        if (existing.isPresent()) {
            throw new IllegalArgumentException("Permission already exists: " + key);
        }

        Permission permission = Permission.builder()
                .key(key)
                .domain(domain.toLowerCase())
                .resource(resource.toLowerCase())
                .action(action.toLowerCase())
                .description(description)
                .isDeprecated(false)
                .createdBy("system")
                .build();

        Permission saved = permissionRepository.save(permission);
        log.info("Created permission: {}", key);

        return saved;
    }

    @Transactional
    public List<Permission> createBatch(List<io.github.mesubash.iam.authz.dto.CreatePermissionRequest> requests) {
        List<Permission> created = new ArrayList<>();
        for (io.github.mesubash.iam.authz.dto.CreatePermissionRequest request : requests) {
            Permission permission = create(
                    request.getKey(),
                    request.getDomain(),
                    request.getResource(),
                    request.getAction(),
                    request.getDescription()
            );
            created.add(permission);
        }
        return created;
    }

    @Transactional
    public Permission deprecate(UUID id) {
        Permission permission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Permission not found"));

        permission.setIsDeprecated(true);
        Permission updated = permissionRepository.save(permission);

        log.info("Deprecated permission: {}", permission.getKey());
        return updated;
    }
}
