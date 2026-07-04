package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.service.AssignmentService;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/break-glass")
@RequiredArgsConstructor
@Tag(name = "Break-glass", description = "Emergency time-boxed elevated access")
public class BreakGlassController {

    private final AssignmentService assignmentService;
    private final FeatureFlags featureFlags;

    @PostMapping
    @Operation(summary = "Grant break-glass access",
            description = "Creates a short-lived assignment (origin BREAK_GLASS); mandatory reason")
    public ResponseEntity<Assignment> grant(
            @AuthenticationPrincipal UserPrincipal caller,
            @jakarta.validation.Valid @RequestBody BreakGlassRequest request) {
        if (!featureFlags.isBreakGlass()) {
            throw new ResourceNotFoundException("Break-glass is not enabled");
        }
        Assignment assignment = assignmentService.createBreakGlass(
                caller, request.getSubjectId(), request.getRoleId(), request.getScopeId(),
                request.getDurationMinutes() != null ? request.getDurationMinutes() : 60,
                request.getReason(), request.getReferenceId());
        return ResponseEntity.status(HttpStatus.CREATED).body(assignment);
    }

    @Data
    public static class BreakGlassRequest {
        @NotBlank
        private String subjectId;
        @NotNull
        private UUID roleId;
        @NotNull
        private UUID scopeId;
        private Integer durationMinutes;
        @NotBlank
        private String reason;
        private String referenceId;
    }
}
