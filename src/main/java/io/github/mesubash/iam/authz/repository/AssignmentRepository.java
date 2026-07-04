package io.github.mesubash.iam.authz.repository;
import io.github.mesubash.iam.authz.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AssignmentRepository extends JpaRepository<Assignment, UUID> {

    @Query("SELECT a FROM Assignment a " +
            "WHERE a.subjectId = :subjectId " +
            "AND a.active = true " +
            "AND (a.expiresAt IS NULL OR a.expiresAt > :now)")
    List<Assignment> findActiveAssignments(@Param("subjectId") String subjectId,
                                           @Param("now") Instant now);

    // Subject plus its group ids — one query covers direct and group grants
    @Query("SELECT a FROM Assignment a " +
            "WHERE a.subjectId IN :subjectIds " +
            "AND a.active = true " +
            "AND (a.expiresAt IS NULL OR a.expiresAt > :now)")
    List<Assignment> findActiveAssignmentsForSubjects(@Param("subjectIds") Collection<String> subjectIds,
                                                      @Param("now") Instant now);

    // Point-in-time reconstruction: assignments whose validity interval covers :asOf.
    @Query("SELECT a FROM Assignment a " +
            "WHERE a.subjectId IN :subjectIds " +
            "AND a.grantedAt <= :asOf " +
            "AND (a.revokedAt IS NULL OR a.revokedAt > :asOf) " +
            "AND (a.expiresAt IS NULL OR a.expiresAt > :asOf)")
    List<Assignment> findAssignmentsAsOf(@Param("subjectIds") Collection<String> subjectIds,
                                         @Param("asOf") Instant asOf);

    @Query("SELECT a FROM Assignment a " +
            "WHERE a.subjectId = :subjectId " +
            "AND a.roleId = :roleId " +
            "AND a.scopeId = :scopeId " +
            "AND a.active = true")
    Optional<Assignment> findBySubjectRoleScope(@Param("subjectId") String subjectId,
                                                @Param("roleId") UUID roleId,
                                                @Param("scopeId") UUID scopeId);

    @Query("SELECT COUNT(a) FROM Assignment a " +
            "WHERE a.subjectId = :subjectId AND a.active = true")
    long countActiveAssignmentsBySubject(@Param("subjectId") String subjectId);

    // Subjects whose assignment scope contains the given scope (ancestor-or-self).
    @Query(value = "SELECT DISTINCT a.subject_id FROM assignments a " +
            "JOIN scope_closure c ON c.ancestor_id = a.scope_id " +
            "WHERE c.descendant_id = :scopeId AND a.active = true " +
            "AND (a.expires_at IS NULL OR a.expires_at > NOW())",
            nativeQuery = true)
    List<String> findSubjectsWithAssignmentCoveringScope(@Param("scopeId") UUID scopeId);

    @Query(value = "SELECT EXISTS (" +
            "SELECT 1 FROM assignments a " +
            "WHERE a.subject_id = :subjectId " +
            "AND a.active = true " +
            "AND (a.expires_at IS NULL OR a.expires_at > :now) " +
            "AND a.conditions IS NOT NULL " +
            "AND a.conditions <> '{}'::jsonb" +
            ")", nativeQuery = true)
    boolean existsActiveConditionalAssignments(@Param("subjectId") String subjectId,
                                               @Param("now") Instant now);
}
