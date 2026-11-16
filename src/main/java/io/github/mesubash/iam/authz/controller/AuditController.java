package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authz.entity.AdminAuditLog;
import io.github.mesubash.iam.authz.entity.AuthorizationAudit;
import io.github.mesubash.iam.authz.repository.AdminAuditRepository;
import io.github.mesubash.iam.authz.service.AuditService;
import io.github.mesubash.iam.shared.dto.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
@Tag(name = "Audit", description = "Authorization audit logs")
public class AuditController {

    private final AuditService auditService;
    private final AdminAuditRepository adminAuditRepository;

    @GetMapping("/admin-actions")
    @Operation(summary = "Admin action trail",
            description = "Successful mutating calls to the admin API, newest first. Optional actorId filter.")
    public ResponseEntity<PageResponse<AdminAuditLog>> getAdminActions(
            @RequestParam(required = false) UUID actorId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        PageRequest pageable = PageRequest.of(Math.max(0, page), Math.clamp(size, 1, 200));
        return ResponseEntity.ok(PageResponse.of(actorId != null
                ? adminAuditRepository.findByActorIdOrderByCreatedAtDesc(actorId, pageable)
                : adminAuditRepository.findAllByOrderByCreatedAtDesc(pageable)));
    }

    @GetMapping("/subject/{subjectId}")
    public ResponseEntity<List<AuthorizationAudit>> getAuditBySubject(
            @PathVariable String subjectId,
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(defaultValue = "0") int page) {

        List<AuthorizationAudit> audits = auditService.getBySubjectId(subjectId, limit, page);
        return ResponseEntity.ok(audits);
    }

    @GetMapping("/resource/{resourceType}/{resourceId}")
    public ResponseEntity<List<AuthorizationAudit>> getAuditByResource(
            @PathVariable String resourceType,
            @PathVariable String resourceId,
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(defaultValue = "0") int page) {

        List<AuthorizationAudit> audits = auditService.getByResource(
                resourceType, resourceId, limit, page);
        return ResponseEntity.ok(audits);
    }

    @GetMapping("/statistics/{subjectId}")
    public ResponseEntity<Map<String, Object>> getStatistics(
            @PathVariable String subjectId,
            @RequestParam(required = false) Long sinceDaysAgo) {

        Instant since = sinceDaysAgo != null
                ? Instant.now().minus(sinceDaysAgo, ChronoUnit.DAYS)
                : Instant.now().minus(7, ChronoUnit.DAYS);

        Map<String, Object> stats = auditService.getStatistics(subjectId, since);
        return ResponseEntity.ok(stats);
    }
}
