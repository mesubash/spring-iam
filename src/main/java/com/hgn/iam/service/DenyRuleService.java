package com.hgn.iam.service;

import com.hgn.iam.entity.DenyRule;
import com.hgn.iam.repository.DenyRuleRepository;
import com.hgn.iam.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class DenyRuleService {

    private final DenyRuleRepository denyRuleRepository;
    private final PermissionRepository permissionRepository;
    private final CacheService cacheService;

    @Transactional(readOnly = true)
    public List<DenyRule> getBySubjectId(String subjectId) {
        return denyRuleRepository.findAllActiveDenyRulesForSubject(
                subjectId, Instant.now());
    }

    @Transactional
    public DenyRule create(String subjectId, String permissionKey,
                           UUID scopeId, String reason, String referenceId,
                           String createdBy, Instant expiresAt) {

        // Validate permission exists (unless wildcard)
        if (!"*.*.*".equals(permissionKey)) {
            permissionRepository.findByKey(permissionKey)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permissionKey));
        }

        DenyRule denyRule = DenyRule.builder()
                .subjectId(subjectId)
                .permissionKey(permissionKey)
                .scopeId(scopeId)
                .reason(reason)
                .referenceId(referenceId)
                .createdBy(createdBy)
                .expiresAt(expiresAt)
                .active(true)
                .build();

        DenyRule saved = denyRuleRepository.save(denyRule);

        // Invalidate cache
        cacheService.invalidateDenyRules(subjectId);

        log.warn("Created DENY rule: subject={}, permission={}, reason={}",
                subjectId, permissionKey, reason);

        return saved;
    }

    @Transactional
    public void remove(UUID denyRuleId) {
        DenyRule denyRule = denyRuleRepository.findById(denyRuleId)
                .orElseThrow(() -> new IllegalArgumentException("Deny rule not found"));

        denyRule.setActive(false);
        denyRuleRepository.save(denyRule);

        // Invalidate cache
        cacheService.invalidateDenyRules(denyRule.getSubjectId());

        log.info("Removed DENY rule: subject={}, permission={}",
                denyRule.getSubjectId(), denyRule.getPermissionKey());
    }
}
