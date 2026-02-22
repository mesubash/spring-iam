package com.hgn.iam.authz.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationResponse {
    private Boolean authorized;
    private String reason;
    private List<String> effectivePermissions;
    private UUID auditId;
    private Instant timestamp;
    private Long latencyMs;  // For monitoring
}
