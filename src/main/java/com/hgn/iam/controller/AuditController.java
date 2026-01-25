package com.hgn.iam.controller;

import com.hgn.iam.entity.AuthorizationAudit;
import com.hgn.iam.service.AuditService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
@Tag(name = "Audit", description = "Authorization audit logs")
public class AuditController {

    private final AuditService auditService;

    @GetMapping("/subject/{subjectId}")
    public ResponseEntity<List<AuthorizationAudit>> getAuditBySubject(
            @PathVariable String subjectId,
            @RequestParam(defaultValue = "100") int limit) {

        List<AuthorizationAudit> audits = auditService.getBySubjectId(subjectId, limit);
        return ResponseEntity.ok(audits);
    }

    @GetMapping("/resource/{resourceType}/{resourceId}")
    public ResponseEntity<List<AuthorizationAudit>> getAuditByResource(
            @PathVariable String resourceType,
            @PathVariable String resourceId,
            @RequestParam(defaultValue = "100") int limit) {

        List<AuthorizationAudit> audits = auditService.getByResource(
                resourceType, resourceId, limit);
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
