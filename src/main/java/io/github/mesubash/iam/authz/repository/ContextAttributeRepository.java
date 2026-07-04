package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.ContextAttribute;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ContextAttributeRepository extends JpaRepository<ContextAttribute, UUID> {

    @Query("SELECT c.name FROM ContextAttribute c")
    List<String> findAllNames();
}
