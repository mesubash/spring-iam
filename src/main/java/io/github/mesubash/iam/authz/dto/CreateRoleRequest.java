package io.github.mesubash.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class CreateRoleRequest {
    @NotBlank
    private String name;

    private String displayName;
    private String description;
    private String orgType;

    // NULL = global role; set = role belongs to that scope's subtree
    private UUID ownerScopeId;

    private List<UUID> permissionIds;
}
