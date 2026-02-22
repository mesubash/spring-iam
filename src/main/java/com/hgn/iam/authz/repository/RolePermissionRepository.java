package com.hgn.iam.authz.repository;


import com.hgn.iam.authz.entity.Permission;
import com.hgn.iam.authz.entity.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {

    /**
     * Get all permission keys for a role
     * This is CRITICAL for authorization checks!
     */
    @Query("SELECT p.key FROM RolePermission rp " +
            "JOIN Permission p ON p.id = rp.permissionId " +
            "WHERE rp.roleId = :roleId " +
            "AND p.isDeprecated = false")
    Set<String> findPermissionKeysByRoleId(@Param("roleId") UUID roleId);

    @Query("SELECT DISTINCT p.key FROM RolePermission rp " +
            "JOIN Permission p ON p.id = rp.permissionId " +
            "WHERE rp.roleId IN :roleIds " +
            "AND p.isDeprecated = false")
    Set<String> findPermissionKeysByRoleIds(@Param("roleIds") Set<UUID> roleIds);

    /**
     * Get all permissions for a role (full objects)
     */
    @Query("SELECT p FROM RolePermission rp " +
            "JOIN Permission p ON p.id = rp.permissionId " +
            "WHERE rp.roleId = :roleId " +
            "AND p.isDeprecated = false")
    List<Permission> findPermissionsByRoleId(@Param("roleId") UUID roleId);

    @Query("SELECT DISTINCT p FROM RolePermission rp " +
            "JOIN Permission p ON p.id = rp.permissionId " +
            "WHERE rp.roleId IN :roleIds " +
            "AND p.isDeprecated = false")
    List<Permission> findPermissionsByRoleIds(@Param("roleIds") Set<UUID> roleIds);

    /**
     * Check if a specific role-permission mapping exists
     */
    @Query("SELECT COUNT(rp) > 0 FROM RolePermission rp " +
            "WHERE rp.roleId = :roleId AND rp.permissionId = :permissionId")
    boolean existsByRoleAndPermission(@Param("roleId") UUID roleId,
                                      @Param("permissionId") UUID permissionId);

    /**
     * Delete all permissions for a role (for bulk update)
     */
    @Modifying
    @Query("DELETE FROM RolePermission rp WHERE rp.roleId = :roleId")
    void deleteByRoleId(@Param("roleId") UUID roleId);

    /**
     * Get all roles that have a specific permission
     */
    @Query("SELECT DISTINCT rp.roleId FROM RolePermission rp " +
            "WHERE rp.permissionId = :permissionId")
    Set<UUID> findRoleIdsByPermissionId(@Param("permissionId") UUID permissionId);
}
