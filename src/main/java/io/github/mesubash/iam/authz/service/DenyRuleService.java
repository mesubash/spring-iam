package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.DenyRule;
import io.github.mesubash.iam.authz.repository.DenyRuleRepository;
import io.github.mesubash.iam.authz.repository.PermissionRepository;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
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
    private final DelegatedManagementGuard delegationGuard;

    @Transactional(readOnly = true)
    public List<DenyRule> getBySubjectId(String subjectId) {
        return denyRuleRepository.findAllActiveDenyRulesForSubject(
                subjectId, Instant.now());
    }

    @Transactional
    public DenyRule create(UserPrincipal caller, String subjectId, String permissionKey,
                           UUID scopeId, String reason, String referenceId,
                           Instant expiresAt) {

        // Enforce scope containment: caller must have authority over the target scope
        if (scopeId != null) {
            delegationGuard.assertCanManageScope(caller, scopeId);
        }

        // Validate permission exists (unless wildcard pattern — wildcard deny rules require SuperAdmin)
        if (permissionKey.contains("*")) {
            if (!permissionKey.matches("^[a-z_*]+\\.[a-z_*]+\\.[a-z_*]+$")) {
                throw new IllegalArgumentException("Invalid permission pattern: " + permissionKey);
            }
            if (!delegationGuard.isPlatformAdmin(caller)) {
                throw new ForbiddenException(
                        "Wildcard deny rules can only be created by SuperAdmin.");
            }
        } else {
            permissionRepository.findByKey(permissionKey)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permissionKey));
        }

        String createdBy = caller.getId().toString();

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
    public void remove(UUID denyRuleId, UserPrincipal caller) {
        DenyRule denyRule = denyRuleRepository.findById(denyRuleId)
                .orElseThrow(() -> new IllegalArgumentException("Deny rule not found"));

        // Enforce scope containment: caller must have authority over the deny rule's scope
        if (denyRule.getScopeId() != null) {
            delegationGuard.assertCanManageScope(caller, denyRule.getScopeId());
        }

        denyRule.setActive(false);
        denyRuleRepository.save(denyRule);

        // Invalidate cache
        cacheService.invalidateDenyRules(denyRule.getSubjectId());

        log.info("Removed DENY rule: subject={}, permission={}",
                denyRule.getSubjectId(), denyRule.getPermissionKey());
    }
}
