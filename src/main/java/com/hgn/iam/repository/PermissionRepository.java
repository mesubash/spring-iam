package com.hgn.iam.repository;

import com.hgn.iam.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    Optional<Permission> findByKey(String key);

    List<Permission> findByDomain(String domain);

    @Query("SELECT p FROM Permission p WHERE p.isDeprecated = false")
    List<Permission> findAllActive();

    @Query("SELECT p FROM Permission p WHERE p.key IN :keys AND p.isDeprecated = false")
    List<Permission> findByKeysAndActive(@Param("keys") Set<String> keys);

    boolean existsByKey(String key);
}

