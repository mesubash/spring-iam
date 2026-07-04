package io.github.mesubash.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Map;
import java.util.UUID;

@Data
public class CreateScopeRequest {
    @NotBlank
    private String type;  // GLOBAL, COUNTRY, REGION, ORG, DEPT, TEAM

    @NotBlank
    private String name;

    private String code;

    private UUID parentId;

    private Map<String, Object> metadata;
}
