package io.github.mesubash.iam.authz.dto;

import lombok.Data;

import java.util.Map;
import java.util.UUID;

@Data
public class UpdatePolicyRequest {
    private String description;
    private String permissionKey;
    private String resourceType;
    private UUID scopeId;
    private String effect;
    private Integer priority;
    private Map<String, Object> conditions;
    private Boolean active;
}
