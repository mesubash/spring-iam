package com.hgn.iam.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class CreateRoleHierarchyRequest {
    @NotNull
    private UUID parentRoleId;
    @NotNull
    private UUID childRoleId;
}
