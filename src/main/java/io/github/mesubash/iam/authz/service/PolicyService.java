package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.Policy;
import io.github.mesubash.iam.authz.repository.PermissionRepository;
import io.github.mesubash.iam.authz.repository.PolicyRepository;
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
    private final io.github.mesubash.iam.authz.repository.ContextAttributeRepository contextAttributeRepository;

    @Transactional(readOnly = true)
    public List<Policy> getAll() {
        return policyRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<Policy> getById(UUID id) {
        return policyRepository.findById(id);
    }

    /** All active policies, cached — for bulk evaluations over many permissions. */
    @Transactional(readOnly = true)
    public List<Policy> getAllActiveOrdered() {
        List<CacheService.PolicySnapshot> cached = cacheService.getCachedPolicies("_all");
        if (cached != null) {
            return cached.stream().map(CacheService.PolicySnapshot::toPolicy).collect(Collectors.toList());
        }
        List<Policy> ordered = policyRepository.findAllActive().stream()
                .sorted(Comparator.comparing(Policy::getPriority).reversed())
                .collect(Collectors.toList());
        cacheService.cachePolicies("_all", ordered.stream()
                .map(CacheService.PolicySnapshot::fromPolicy).collect(Collectors.toList()));
        return ordered;
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

        validateConditionFields(policy.getConditions());
    }

    // Fail-fast: reject conditions referencing context.additional.<k> attributes
    // that aren't registered — a typo'd policy dies at authoring, not at runtime.
    private void validateConditionFields(java.util.Map<String, Object> conditions) {
        if (conditions == null || conditions.isEmpty()) {
            return;
        }
        java.util.Set<String> registered = new java.util.HashSet<>(contextAttributeRepository.findAllNames());
        java.util.List<String> unknown = new java.util.ArrayList<>();
        collectUnknownContextFields(conditions, registered, unknown);
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(
                    "Unknown context attribute(s) in policy conditions: " + String.join(", ", unknown)
                            + ". Register them under /api/v1/context-attributes first.");
        }
    }

    @SuppressWarnings("unchecked")
    private void collectUnknownContextFields(Object node, java.util.Set<String> registered,
                                             java.util.List<String> unknown) {
        if (node instanceof java.util.Map<?, ?> map) {
            Object field = map.get("field");
            if (field instanceof String f && f.startsWith("context.additional.")) {
                String attr = f.substring("context.additional.".length());
                if (!registered.contains(attr) && !unknown.contains(attr)) {
                    unknown.add(attr);
                }
            }
            for (Object child : map.values()) {
                collectUnknownContextFields(child, registered, unknown);
            }
        } else if (node instanceof java.util.List<?> list) {
            for (Object child : list) {
                collectUnknownContextFields(child, registered, unknown);
            }
        }
    }

    private String cacheKey(String permissionKey, String resourceType) {
        String perm = permissionKey != null ? permissionKey : "*";
        String res = resourceType != null ? resourceType : "*";
        return perm + ":" + res;
    }
}
