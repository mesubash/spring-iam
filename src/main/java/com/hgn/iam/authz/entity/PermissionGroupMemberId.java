package com.hgn.iam.authz.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PermissionGroupMemberId implements Serializable {
    private UUID groupId;
    private UUID permissionId;
}
