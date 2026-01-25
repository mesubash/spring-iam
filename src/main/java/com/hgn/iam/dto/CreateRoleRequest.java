package com.hgn.iam.dto;

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
    private List<UUID> permissionIds;
}
