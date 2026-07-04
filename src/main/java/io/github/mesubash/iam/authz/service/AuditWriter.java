package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.entity.AuthorizationAudit;
import io.github.mesubash.iam.authz.repository.AuthorizationAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Writes authorization audit records off the decision hot path. Separate
 * bean on purpose: @Async is proxy-based and never fires on self-invocation.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditWriter {

    private final AuthorizationAuditRepository auditRepository;

    @Async("auditExecutor")
    @Transactional
    public void write(UUID auditId, AuthorizationRequest request, boolean decision,
                      String reason, List<Map<String, Object>> shadowResults) {
        try {
            Map<String, Object> context = new HashMap<>();
            if (request.getContext() != null && request.getContext().getAdditionalContext() != null) {
                context.putAll(request.getContext().getAdditionalContext());
            }
            if (shadowResults != null) {
                context.put("shadowResults", shadowResults);
            }

            auditRepository.save(AuthorizationAudit.builder()
                    .id(auditId)
                    .subjectId(request.getSubject())
                    .permissionKey(request.getPermission())
                    .resourceType(request.getResource().getType())
                    .resourceId(request.getResource().getId())
                    .scopeId(request.getResource().getScopeId())
                    .decision(decision)
                    .reason(reason)
                    .context(context)
                    .requestId(request.getContext() != null ? request.getContext().getRequestId() : null)
                    .ipAddress(request.getContext() != null ? request.getContext().getIpAddress() : null)
                    .userAgent(request.getContext() != null ? request.getContext().getUserAgent() : null)
                    .timestamp(Instant.now())
                    .build());
        } catch (Exception e) {
            log.error("Failed to save audit log", e);
        }
    }
}
