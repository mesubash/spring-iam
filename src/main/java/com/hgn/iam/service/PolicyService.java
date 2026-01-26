package com.hgn.iam.service;

import com.hgn.iam.entity.Policy;
import com.hgn.iam.repository.PermissionRepository;
import com.hgn.iam.repository.PolicyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyService {

    private final PolicyRepository policyRepository;
    private final CacheService cacheService;
    private final PermissionRepository permissionRepository;

    @Transactional(readOnly = true)
    public List<Policy> getAll() {
        return policyRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<Policy> getById(UUID id) {
        return policyRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<Policy> getApplicablePolicies(String permissionKey, String resourceType) {
        String cacheKey = cacheKey(permissionKey, resourceType);
        List<CacheService.PolicySnapshot> cached = cacheService.getCachedPolicies(cacheKey);
        if (cached != null) {
            return cached.stream()
                    .map(CacheService.PolicySnapshot::toPolicy)
                    .collect(Collectors.toList());
        }

        List<Policy> candidates = policyRepository.findCandidatePolicies(
                permissionKey, resourceType);

        List<Policy> ordered = candidates.stream()
                .sorted(Comparator.comparing(Policy::getPriority).reversed())
                .collect(Collectors.toList());

        cacheService.cachePolicies(cacheKey, ordered.stream()
                .map(CacheService.PolicySnapshot::fromPolicy)
                .collect(Collectors.toList()));

        return ordered;
    }

    @Transactional
    public Policy create(Policy policy) {
        policyRepository.findByName(policy.getName()).ifPresent(existing -> {
            throw new IllegalArgumentException("Policy already exists: " + policy.getName());
        });

        validatePolicy(policy);
        Policy saved = policyRepository.save(policy);
        cacheService.invalidatePolicyCache();
        log.info("Created policy {}", policy.getName());
        return saved;
    }

    @Transactional
    public Policy update(UUID id, Policy updated) {
        Policy existing = policyRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));

        existing.setDescription(updated.getDescription());
        existing.setPermissionKey(updated.getPermissionKey());
        existing.setResourceType(updated.getResourceType());
        existing.setScopeId(updated.getScopeId());
        existing.setEffect(updated.getEffect());
        existing.setPriority(updated.getPriority());
        existing.setConditions(updated.getConditions());
        existing.setActive(updated.getActive());

        validatePolicy(existing);
        Policy saved = policyRepository.save(existing);
        cacheService.invalidatePolicyCache();
        log.info("Updated policy {}", existing.getName());
        return saved;
    }

    @Transactional
    public void deactivate(UUID id) {
        Policy existing = policyRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));
        existing.setActive(false);
        policyRepository.save(existing);
        cacheService.invalidatePolicyCache();
        log.info("Deactivated policy {}", existing.getName());
    }

    private void validatePolicy(Policy policy) {
        if (policy.getEffect() != null) {
            String effect = policy.getEffect().toUpperCase();
            if (!effect.equals("ALLOW") && !effect.equals("DENY")) {
                throw new IllegalArgumentException("Invalid policy effect: " + policy.getEffect());
            }
            policy.setEffect(effect);
        }

        if (policy.getPermissionKey() != null) {
            String key = policy.getPermissionKey();
            if (key.contains("*")) {
                if (!key.matches("^[a-z_*]+\\.[a-z_*]+\\.[a-z_*]+$")) {
                    throw new IllegalArgumentException("Invalid permission pattern: " + key);
                }
            } else {
                permissionRepository.findByKey(key)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Permission not found: " + key));
            }
        }
    }

    private String cacheKey(String permissionKey, String resourceType) {
        String perm = permissionKey != null ? permissionKey : "*";
        String res = resourceType != null ? resourceType : "*";
        return perm + ":" + res;
    }
}
