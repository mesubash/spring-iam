package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.Policy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, UUID> {

    Optional<Policy> findByName(String name);

    @Query("SELECT p FROM Policy p " +
            "WHERE p.active = true " +
            "AND (p.permissionKey IS NULL " +
            "     OR p.permissionKey = :permissionKey " +
            "     OR p.permissionKey LIKE '%*%') " +
            "AND (p.resourceType IS NULL OR p.resourceType = :resourceType)")
    List<Policy> findCandidatePolicies(@Param("permissionKey") String permissionKey,
                                       @Param("resourceType") String resourceType);

    @Query("SELECT p FROM Policy p WHERE p.active = true")
    List<Policy> findAllActive();
}
