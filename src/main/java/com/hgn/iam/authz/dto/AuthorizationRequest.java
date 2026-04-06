package com.hgn.iam.authz.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationRequest {

    @NotBlank(message = "subject is required")
    private String subject;

    @NotBlank(message = "permission is required")
    private String permission;

    @NotNull(message = "resource is required")
    @Valid
    private ResourceContext resource;

    private RequestContext context;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceContext {
        private String type;
        private String id;

        @NotNull(message = "resource.scopeId is required")
        private UUID scopeId;

        private Map<String, Object> metadata;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RequestContext {
        private Instant timestamp;
        private String ipAddress;
        private String userAgent;
        private String sessionId;
        private String requestId;
        private Map<String, Object> additionalContext;
    }
}