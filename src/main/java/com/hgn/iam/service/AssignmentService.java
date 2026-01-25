package com.hgn.iam.service;

import com.hgn.iam.entity.Assignment;
import com.hgn.iam.entity.Role;
import com.hgn.iam.entity.Scope;
import com.hgn.iam.repository.AssignmentRepository;
import com.hgn.iam.repository.RoleRepository;
import com.hgn.iam.repository.ScopeRepository;
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
    private final CacheService cacheService;

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
    public Assignment create(String subjectId, String subjectType,
                             UUID roleId, UUID scopeId, String grantedBy,
                             Instant expiresAt, Map<String, Object> conditions) {

        // Validate role exists
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new IllegalArgumentException("Role not found"));

        // Validate scope exists
        Scope scope = scopeRepository.findById(scopeId)
                .orElseThrow(() -> new IllegalArgumentException("Scope not found"));

        // Check if assignment already exists
        Optional<Assignment> existing = assignmentRepository.findBySubjectRoleScope(
                subjectId, roleId, scopeId);

        if (existing.isPresent() && existing.get().getActive()) {
            throw new IllegalArgumentException("Assignment already exists");
        }

        Assignment assignment = Assignment.builder()
                .subjectId(subjectId)
                .subjectType(subjectType != null ? subjectType : "USER")
                .roleId(roleId)
                .scopeId(scopeId)
                .effect("ALLOW")
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

    @Transactional
    public Assignment revoke(UUID assignmentId, String revokedBy, String reason) {
        Assignment assignment = assignmentRepository.findById(assignmentId)
                .orElseThrow(() -> new IllegalArgumentException("Assignment not found"));

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
