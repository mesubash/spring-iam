package com.hgn.iam.authz.repository;

import com.hgn.iam.authz.entity.RoleHierarchy;
import com.hgn.iam.authz.entity.RoleHierarchyId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Set;
import java.util.UUID;

@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, RoleHierarchyId> {

    @Query("SELECT rh.parentRoleId FROM RoleHierarchy rh WHERE rh.childRoleId = :childRoleId")
    Set<UUID> findParentRoleIdsByChildId(@Param("childRoleId") UUID childRoleId);

    @Query("SELECT rh.childRoleId FROM RoleHierarchy rh WHERE rh.parentRoleId = :parentRoleId")
    Set<UUID> findChildRoleIdsByParentId(@Param("parentRoleId") UUID parentRoleId);
}
