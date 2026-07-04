package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.entity.Scope;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.authz.repository.ScopeClosureRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AssignmentService {

    private final AssignmentRepository assignmentRepository;
    private final RoleRepository roleRepository;
    private final ScopeRepository scopeRepository;
    private final ScopeClosureRepository scopeClosureRepository;
    private final CacheService cacheService;
    private final DelegatedManagementGuard delegationGuard;

    @Transactional(readOnly = true)
    public List<Assignment> getAll() {
        return assignmentRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<Assignment> getBySubjectId(String subjectId) {
        return assignmentRepository.findActiveAssignments(subjectId, Instant.now());
    }

    @Transactional(readOnly = true)
    public Optional<Assignment> getById(UUID id) {
        return assignmentRepository.findById(id);
    }

    @Transactional
    public Assignment create(UserPrincipal caller, String subjectId, String subjectType,
                             UUID roleId, UUID scopeId,
                             Instant expiresAt, Map<String, Object> conditions) {

        // Enforce scope containment: caller must have authority over the target scope
        delegationGuard.assertCanManageScope(caller, scopeId);

        // Validate role exists
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        // Validate scope exists
        Scope scope = scopeRepository.findById(scopeId)
                .orElseThrow(() -> new IllegalArgumentException("Scope not found"));

        // Tenant-scoped role: only assignable within its owning subtree
        if (role.getOwnerScopeId() != null
                && !scopeClosureRepository.scopeContains(role.getOwnerScopeId(), scopeId)) {
            throw new IllegalArgumentException(
                    "Role '" + role.getName() + "' belongs to another subtree and cannot be assigned here");
        }

        // Check if assignment already exists
        Optional<Assignment> existing = assignmentRepository.findBySubjectRoleScope(
                subjectId, roleId, scopeId);

        if (existing.isPresent() && existing.get().getActive()) {
            throw new IllegalArgumentException("Assignment already exists");
        }

        String grantedBy = caller.getId().toString();

        Assignment assignment = Assignment.builder()
                .subjectId(subjectId)
                .subjectType(subjectType != null ? subjectType : "USER")
                .roleId(roleId)
                .scopeId(scopeId)
                .grantedBy(grantedBy)
                .expiresAt(expiresAt)
                .conditions(conditions != null ? conditions : new HashMap<>())
                .active(true)
                .build();

        Assignment saved = assignmentRepository.save(assignment);

        // Invalidate cache
        cacheService.invalidateUserPermissions(subjectId);
        cacheService.incrementAssignmentVersion(subjectId);

        log.info("Created assignment: subject={}, role={}, scope={}",
                subjectId, role.getName(), scope.getName());

        return saved;
    }

    /**
     * Emergency time-boxed elevation. Short mandatory expiry, origin BREAK_GLASS
     * for reporting; rides the normal pipeline (deny rules still override).
     */
    @Transactional
    public Assignment createBreakGlass(UserPrincipal caller, String subjectId, UUID roleId,
                                       UUID scopeId, int durationMinutes, String reason, String referenceId) {
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("A reason is required for break-glass access");
        }
        int capped = Math.min(Math.max(durationMinutes, 1), 240); // hard cap 4h

        delegationGuard.assertCanManageScope(caller, scopeId);
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));
        scopeRepository.findById(scopeId)
                .orElseThrow(() -> new IllegalArgumentException("Scope not found"));

        Instant now = Instant.now();
        Assignment assignment = assignmentRepository.save(Assignment.builder()
                .subjectId(subjectId)
                .subjectType("USER")
                .roleId(roleId)
                .scopeId(scopeId)
                .grantedBy(caller.getId().toString())
                .grantedAt(now)
                .expiresAt(now.plusSeconds(capped * 60L))
                .origin("BREAK_GLASS")
                .conditions(new HashMap<>())
                .active(true)
                .build());

        cacheService.invalidateUserPermissions(subjectId);
        cacheService.incrementAssignmentVersion(subjectId);

        log.warn("BREAK-GLASS granted: subject={}, role={}, scope={}, minutes={}, reason='{}', ref={}",
                subjectId, role.getName(), scopeId, capped, reason, referenceId);
        return assignment;
    }

    @Transactional
    public Assignment revoke(UUID assignmentId, UserPrincipal caller, String reason) {
        Assignment assignment = assignmentRepository.findById(assignmentId)
                .orElseThrow(() -> new IllegalArgumentException("Assignment not found"));

        // Enforce scope containment: caller must have authority over the assignment's scope
        delegationGuard.assertCanManageScope(caller, assignment.getScopeId());

        String revokedBy = caller.getId().toString();

        assignment.setActive(false);
        assignment.setRevokedAt(Instant.now());
        assignment.setRevokedBy(revokedBy);
        assignment.setRevokeReason(reason);

        Assignment updated = assignmentRepository.save(assignment);

        // Invalidate cache
        cacheService.invalidateUserPermissions(assignment.getSubjectId());
        cacheService.incrementAssignmentVersion(assignment.getSubjectId());

        log.info("Revoked assignment: subject={}, reason={}",
                assignment.getSubjectId(), reason);

        return updated;
    }

    @Transactional(readOnly = true)
    public long countActiveAssignments(String subjectId) {
        return assignmentRepository.countActiveAssignmentsBySubject(subjectId);
    }
}
