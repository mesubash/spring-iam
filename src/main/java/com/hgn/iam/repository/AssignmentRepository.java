package com.hgn.iam.repository;
import com.hgn.iam.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AssignmentRepository extends JpaRepository<Assignment, UUID> {

    @Query("SELECT a FROM Assignment a " +
            "WHERE a.subjectId = :subjectId " +
            "AND a.active = true " +
            "AND a.effect = 'ALLOW' " +
            "AND (a.expiresAt IS NULL OR a.expiresAt > :now)")
    List<Assignment> findActiveAssignments(@Param("subjectId") String subjectId,
                                           @Param("now") Instant now);

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
}

