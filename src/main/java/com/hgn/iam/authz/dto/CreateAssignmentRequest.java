package com.hgn.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Data
public class CreateAssignmentRequest {
    @NotBlank
    private String subjectId;

    private String subjectType = "USER";

    @NotNull
    private UUID roleId;

    @NotNull
    private UUID scopeId;

    private Instant expiresAt;
    private Map<String, Object> conditions;
}
