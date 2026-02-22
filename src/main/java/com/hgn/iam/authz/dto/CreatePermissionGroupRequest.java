package com.hgn.iam.authz.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.UUID;

@Data
public class CreatePermissionGroupRequest {
    @NotBlank
    private String name;
    private String description;
    private UUID parentGroupId;
}
