package io.github.mesubash.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Data
public class CreateDenyRuleRequest {
    @NotBlank(message = "Subject ID is required")
    private String subjectId;

    // USER (default) | SERVICE | GROUP — GROUP denies every member
    private String subjectType;

    @NotBlank(message = "Permission key is required")
    private String permissionKey;

    private UUID scopeId;

    @NotBlank(message = "Reason is required")
    private String reason;

    private String referenceId;

    private Instant expiresAt;
}