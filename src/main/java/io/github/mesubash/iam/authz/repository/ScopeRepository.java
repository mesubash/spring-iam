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
public interface ScopeRepository extends JpaRepository<Scope, UUID> {

    List<Scope> findByType(String type);

    @Query(value = "SELECT * FROM scopes s WHERE s.path::text LIKE CONCAT(:path, '%') AND s.active = true",
            nativeQuery = true)
    List<Scope> findDescendants(@Param("path") String path);

    @Query("SELECT s FROM Scope s WHERE s.active = true")
    List<Scope> findAllActive();

    @Query("SELECT s FROM Scope s WHERE s.parentId = :parentId AND s.active = true")
    List<Scope> findByParentId(@Param("parentId") UUID parentId);

    @Query("SELECT s FROM Scope s WHERE s.parentId IS NULL")
    Optional<Scope> findRoot();

    @Query("SELECT s.active FROM Scope s WHERE s.id = :id")
    Optional<Boolean> findActiveFlag(@Param("id") UUID id);
}
