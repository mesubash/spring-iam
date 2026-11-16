package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.entity.SecurityEvent;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.repository.SecurityEventRepository;
import io.github.mesubash.iam.shared.dto.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

/**
 * Admin read of the authentication event log (logins, lockouts, password and MFA changes, admin
 * actions on accounts). The events are already written by SecurityEventService; this only reads
 * them. Gated with the rest of /api/v1/audit/** in SecurityConfig.
 */
@RestController
@RequestMapping("/api/v1/audit/security-events")
@RequiredArgsConstructor
@Tag(name = "Audit", description = "Authorization audit logs")
public class SecurityAuditController {

    private final SecurityEventRepository securityEventRepository;

    public record SecurityEventView(UUID id, UUID identityId, SecurityEventType eventType,
                                    String ipAddress, String userAgent, Map<String, Object> metadata,
                                    OffsetDateTime createdAt) {
        static SecurityEventView from(SecurityEvent e) {
            return new SecurityEventView(e.getId(), e.getIdentity().getId(), e.getEventType(),
                    e.getIpAddress(), e.getUserAgent(), e.getMetadata(), e.getCreatedAt());
        }
    }

    @GetMapping
    @Operation(summary = "Security event log",
            description = "Newest first. Filters: identityId, eventType, since. An unknown eventType matches nothing.")
    public ResponseEntity<PageResponse<SecurityEventView>> search(
            @RequestParam(required = false) UUID identityId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) OffsetDateTime since,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        PageRequest pageable = PageRequest.of(Math.max(0, page), Math.clamp(size, 1, 100));

        SecurityEventType type = null;
        if (eventType != null && !eventType.isBlank()) {
            try {
                type = SecurityEventType.valueOf(eventType.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.ok(PageResponse.of(Page.empty(pageable)));
            }
        }

        OffsetDateTime floor = since != null ? since : OffsetDateTime.ofInstant(Instant.EPOCH, ZoneOffset.UTC);
        return ResponseEntity.ok(PageResponse.of(securityEventRepository
                .search(identityId, type, floor, pageable)
                .map(SecurityEventView::from)));
    }
}
