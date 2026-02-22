package com.hgn.iam.authz.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RoleHierarchyId implements Serializable {
    private UUID parentRoleId;
    private UUID childRoleId;
}
