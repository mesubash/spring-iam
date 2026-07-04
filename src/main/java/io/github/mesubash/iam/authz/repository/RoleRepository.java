package io.github.mesubash.iam.authz.repository;
import io.github.mesubash.iam.authz.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    // Global roles only — tenant roles share names across subtrees
    Optional<Role> findByOwnerScopeIdIsNullAndName(String name);

    @Query("SELECT r FROM Role r WHERE r.name = :name AND " +
           "((:owner IS NULL AND r.ownerScopeId IS NULL) OR r.ownerScopeId = :owner)")
    Optional<Role> findByOwnerAndName(@Param("owner") UUID ownerScopeId, @Param("name") String name);

    List<Role> findByOrgType(String orgType);

    @Query("SELECT r FROM Role r WHERE r.active = true")
    List<Role> findAllActive();
}
