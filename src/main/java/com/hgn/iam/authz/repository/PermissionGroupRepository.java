package com.hgn.iam.authz.repository;

import com.hgn.iam.authz.entity.PermissionGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PermissionGroupRepository extends JpaRepository<PermissionGroup, UUID> {
    Optional<PermissionGroup> findByName(String name);
}
