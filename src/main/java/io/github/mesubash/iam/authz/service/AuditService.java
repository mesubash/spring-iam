package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.entity.AuthorizationAudit;
import io.github.mesubash.iam.authz.repository.AuthorizationAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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
    public List<AuthorizationAudit> getBySubjectId(String subjectId, int limit, int page) {
        return auditRepository.findBySubjectIdOrderByTimestampDesc(subjectId, page(limit, page));
    }

    @Transactional(readOnly = true)
    public List<AuthorizationAudit> getByResource(String resourceType,
                                                  String resourceId,
                                                  int limit,
                                                  int page) {
        return auditRepository.findByResourceOrderByTimestampDesc(resourceType, resourceId,
                page(limit, page));
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getStatistics(String subjectId, Instant since) {
        List<AuthorizationAudit> audits = auditRepository
                .findBySubjectIdOrderByTimestampDesc(subjectId, Pageable.unpaged());

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

    // Paged in the database: the audit table is large and was previously loaded whole.
    private static Pageable page(int limit, int page) {
        return PageRequest.of(Math.max(0, page), Math.clamp(limit, 1, 1000));
    }
}