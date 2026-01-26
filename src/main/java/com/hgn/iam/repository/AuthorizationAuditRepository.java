package com.hgn.iam.repository;
import com.hgn.iam.entity.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
@Repository
public interface AuthorizationAuditRepository extends JpaRepository<AuthorizationAudit, AuthorizationAuditId> {

    @Query("SELECT aa FROM AuthorizationAudit aa " +
            "WHERE aa.subjectId = :subjectId " +
            "ORDER BY aa.timestamp DESC")
    List<AuthorizationAudit> findBySubjectIdOrderByTimestampDesc(@Param("subjectId") String subjectId);

    @Query("SELECT aa FROM AuthorizationAudit aa " +
            "WHERE aa.resourceType = :resourceType " +
            "AND aa.resourceId = :resourceId " +
            "ORDER BY aa.timestamp DESC")
    List<AuthorizationAudit> findByResourceOrderByTimestampDesc(@Param("resourceType") String resourceType,
                                                                @Param("resourceId") String resourceId);
}
