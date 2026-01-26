package com.hgn.iam.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Table(name = "role_hierarchy")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@IdClass(RoleHierarchyId.class)
public class RoleHierarchy {

    @Id
    @Column(name = "parent_role_id", nullable = false)
    private UUID parentRoleId;

    @Id
    @Column(name = "child_role_id", nullable = false)
    private UUID childRoleId;
}
