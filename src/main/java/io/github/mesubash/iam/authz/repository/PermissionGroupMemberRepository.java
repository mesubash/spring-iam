package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.PermissionGroupMember;
import io.github.mesubash.iam.authz.entity.PermissionGroupMemberId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Repository
public interface PermissionGroupMemberRepository
        extends JpaRepository<PermissionGroupMember, PermissionGroupMemberId> {

    @Query("SELECT pgm.permissionId FROM PermissionGroupMember pgm WHERE pgm.groupId = :groupId")
    Set<UUID> findPermissionIdsByGroupId(@Param("groupId") UUID groupId);

    @Query("SELECT pgm.groupId FROM PermissionGroupMember pgm WHERE pgm.permissionId = :permissionId")
    Set<UUID> findGroupIdsByPermissionId(@Param("permissionId") UUID permissionId);

    @Query("SELECT pgm FROM PermissionGroupMember pgm WHERE pgm.groupId = :groupId")
    List<PermissionGroupMember> findByGroupId(@Param("groupId") UUID groupId);

    @Modifying
    @Query("DELETE FROM PermissionGroupMember pgm WHERE pgm.groupId = :groupId")
    void deleteByGroupId(@Param("groupId") UUID groupId);
}
