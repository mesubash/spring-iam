package com.hgn.iam.authz.repository;

import com.hgn.iam.authz.entity.ScopeClosure;
import com.hgn.iam.authz.entity.ScopeClosureId;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

@Repository
public interface ScopeClosureRepository extends JpaRepository<ScopeClosure, ScopeClosureId> {

    /**
     * Check if ancestor scope contains descendant scope
     * This is the MOST IMPORTANT query - used in every authorization check!
     */
    @Query("SELECT CASE WHEN COUNT(sc) > 0 THEN true ELSE false END " +
            "FROM ScopeClosure sc " +
            "WHERE sc.ancestorId = :ancestorId AND sc.descendantId = :descendantId")
    boolean scopeContains(@Param("ancestorId") UUID ancestorId,
                          @Param("descendantId") UUID descendantId);

    /**
     * Get all descendants of a scope
     */
    @Query("SELECT sc.descendantId FROM ScopeClosure sc WHERE sc.ancestorId = :ancestorId")
    Set<UUID> findAllDescendants(@Param("ancestorId") UUID ancestorId);

    /**
     * Get all ancestors of a scope
     */
    @Query("SELECT sc.ancestorId FROM ScopeClosure sc WHERE sc.descendantId = :descendantId")
    Set<UUID> findAllAncestors(@Param("descendantId") UUID descendantId);

    /**
     * Get all direct children (depth = 1)
     */
    @Query("SELECT sc.descendantId FROM ScopeClosure sc " +
            "WHERE sc.ancestorId = :ancestorId AND sc.depth = 1")
    Set<UUID> findDirectChildren(@Param("ancestorId") UUID ancestorId);

    /**
     * Delete all closure entries for a scope (for cleanup)
     */
    @Query("DELETE FROM ScopeClosure sc " +
            "WHERE sc.ancestorId = :scopeId OR sc.descendantId = :scopeId")
    void deleteByScope(@Param("scopeId") UUID scopeId);

    /**
     * Get the full closure tree for a scope
     */
    @Query("SELECT sc FROM ScopeClosure sc WHERE sc.ancestorId = :ancestorId ORDER BY sc.depth")
    List<ScopeClosure> findClosureTree(@Param("ancestorId") UUID ancestorId);
}
