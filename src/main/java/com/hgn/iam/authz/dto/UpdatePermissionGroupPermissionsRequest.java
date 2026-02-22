package com.hgn.iam.authz.dto;

import lombok.Data;

import java.util.List;
import java.util.UUID;

@Data
public class UpdatePermissionGroupPermissionsRequest {
    private List<UUID> permissionIds;
}
