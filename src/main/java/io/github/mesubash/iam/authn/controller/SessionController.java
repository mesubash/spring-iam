package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.entity.Session;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.security.token.SessionService;
import io.github.mesubash.iam.shared.dto.ApiResponse;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth/sessions")
@RequiredArgsConstructor
@PreAuthorize("isAuthenticated()")
@Tag(name = "Sessions", description = "Active device sessions of the current user")
public class SessionController {

    private final SessionService sessionService;

    @GetMapping
    @Operation(summary = "List my sessions", description = "Active sessions (devices) for the current user")
    public ResponseEntity<ApiResponse<List<SessionView>>> listSessions(
            @AuthenticationPrincipal UserPrincipal principal) {
        List<SessionView> sessions = sessionService.listActiveSessions(principal.getId()).stream()
                .map(SessionView::from)
                .toList();
        return ResponseEntity.ok(ApiResponse.success("Active sessions", sessions));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Revoke a session", description = "Log out one device")
    public ResponseEntity<ApiResponse<Void>> revokeSession(
            @AuthenticationPrincipal UserPrincipal principal,
            @PathVariable UUID id) {
        boolean owned = sessionService.listActiveSessions(principal.getId()).stream()
                .anyMatch(s -> s.getId().equals(id));
        if (!owned) {
            throw new ResourceNotFoundException("Session not found");
        }
        sessionService.revokeSession(id, "LOGOUT");
        return ResponseEntity.ok(ApiResponse.success("Session revoked", null));
    }

    @Data
    @Builder
    public static class SessionView {
        private UUID id;
        private String deviceLabel;
        private String createdIp;
        private Instant createdAt;
        private Instant lastUsedAt;

        static SessionView from(Session s) {
            return SessionView.builder()
                    .id(s.getId())
                    .deviceLabel(s.getDeviceLabel())
                    .createdIp(s.getCreatedIp())
                    .createdAt(s.getCreatedAt())
                    .lastUsedAt(s.getLastUsedAt())
                    .build();
        }
    }
}
