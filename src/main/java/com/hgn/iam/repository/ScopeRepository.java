package com.hgn.iam.repository;
import com.hgn.iam.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
@Repository
public interface ScopeRepository extends JpaRepository<Scope, UUID> {

    Optional<Scope> findByCode(String code);

    List<Scope> findByType(String type);

    @Query("SELECT s FROM Scope s WHERE s.path LIKE CONCAT(:path, '%') AND s.active = true")
    List<Scope> findDescendants(@Param("path") String path);

    @Query("SELECT s FROM Scope s WHERE s.active = true")
    List<Scope> findAllActive();

    @Query("SELECT s FROM Scope s WHERE s.parentId = :parentId AND s.active = true")
    List<Scope> findByParentId(@Param("parentId") UUID parentId);

    boolean existsByCode(String code);
}
