package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.ScopeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ScopeTypeRepository extends JpaRepository<ScopeType, UUID> {

    Optional<ScopeType> findByName(String name);
}
