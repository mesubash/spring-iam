package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Permission;
import io.github.mesubash.iam.authz.entity.PermissionGroup;
import io.github.mesubash.iam.authz.entity.PermissionGroupMember;
import io.github.mesubash.iam.authz.repository.PermissionGroupMemberRepository;
import io.github.mesubash.iam.authz.repository.PermissionGroupRepository;
import io.github.mesubash.iam.authz.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionGroupService {

    private final PermissionGroupRepository permissionGroupRepository;
    private final PermissionGroupMemberRepository memberRepository;
    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public List<PermissionGroup> getAll() {
        return permissionGroupRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<PermissionGroup> getById(UUID id) {
        return permissionGroupRepository.findById(id);
    }

    @Transactional
    public PermissionGroup create(String name, String description, UUID parentGroupId) {
        permissionGroupRepository.findByName(name).ifPresent(group -> {
            throw new IllegalArgumentException("Permission group already exists: " + name);
        });

        if (parentGroupId != null) {
            permissionGroupRepository.findById(parentGroupId)
                    .orElseThrow(() -> new IllegalArgumentException("Parent group not found"));
        }

        PermissionGroup group = PermissionGroup.builder()
                .name(name)
                .description(description)
                .parentGroupId(parentGroupId)
                .build();

        PermissionGroup saved = permissionGroupRepository.save(group);
        log.info("Created permission group: {}", name);
        return saved;
    }

    @Transactional(readOnly = true)
    public List<Permission> getGroupPermissions(UUID groupId) {
        Set<UUID> permissionIds = memberRepository.findPermissionIdsByGroupId(groupId);
        if (permissionIds.isEmpty()) {
            return List.of();
        }
        return permissionRepository.findAllById(permissionIds);
    }

    @Transactional
    public void setGroupPermissions(UUID groupId, List<UUID> permissionIds) {
        permissionGroupRepository.findById(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Permission group not found"));

        List<UUID> validated = new ArrayList<>();
        if (permissionIds != null) {
            for (UUID permissionId : permissionIds) {
                permissionRepository.findById(permissionId)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Permission not found: " + permissionId));
                validated.add(permissionId);
            }
        }

        memberRepository.deleteByGroupId(groupId);
        for (UUID permissionId : validated) {
            PermissionGroupMember member = PermissionGroupMember.builder()
                    .groupId(groupId)
                    .permissionId(permissionId)
                    .build();
            memberRepository.save(member);
        }

        log.info("Updated permission group {} with {} permissions", groupId, validated.size());
    }
}
