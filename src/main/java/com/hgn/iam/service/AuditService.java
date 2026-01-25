package com.hgn.iam.service;

import com.hgn.iam.entity.AuthorizationAudit;
import com.hgn.iam.repository.AuthorizationAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuthorizationAuditRepository auditRepository;

    @Transactional(readOnly = true)
    public List<AuthorizationAudit> getBySubjectId(String subjectId, int limit) {
        List<AuthorizationAudit> audits = auditRepository
                .findBySubjectIdOrderByTimestampDesc(subjectId);

        return audits.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<AuthorizationAudit> getByResource(String resourceType,
                                                  String resourceId,
                                                  int limit) {
        List<AuthorizationAudit> audits = auditRepository
                .findByResourceOrderByTimestampDesc(resourceType, resourceId);

        return audits.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getStatistics(String subjectId, Instant since) {
        List<AuthorizationAudit> audits = auditRepository
                .findBySubjectIdOrderByTimestampDesc(subjectId);

        long total = audits.stream()
                .filter(a -> a.getTimestamp().isAfter(since))
                .count();

        long allowed = audits.stream()
                .filter(a -> a.getTimestamp().isAfter(since))
                .filter(AuthorizationAudit::getDecision)
                .count();

        long denied = total - allowed;

        Map<String, Long> byPermission = audits.stream()
                .filter(a -> a.getTimestamp().isAfter(since))
                .collect(Collectors.groupingBy(
                        a -> a.getPermissionKey() != null ? a.getPermissionKey() : "unknown",
                        Collectors.counting()
                ));

        Map<String, Object> stats = new HashMap<>();
        stats.put("total", total);
        stats.put("allowed", allowed);
        stats.put("denied", denied);
        stats.put("allowRate", total > 0 ? (double) allowed / total : 0.0);
        stats.put("byPermission", byPermission);

        return stats;
    }
}