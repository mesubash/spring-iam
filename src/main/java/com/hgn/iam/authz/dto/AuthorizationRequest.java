package com.hgn.iam.authz.dto;

import lombok.*;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthorizationRequest {

    private String subject;
    private String permission;
    private ResourceContext resource;
    private RequestContext context;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ResourceContext {
        private String type;
        private String id;
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