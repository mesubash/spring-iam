package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.ResourceGrant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface ResourceGrantRepository extends JpaRepository<ResourceGrant, UUID> {

    @Query("SELECT g FROM ResourceGrant g WHERE g.subjectId IN :subjectIds " +
           "AND g.resourceType = :resourceType AND g.resourceId = :resourceId " +
           "AND g.revokedAt IS NULL AND (g.expiresAt IS NULL OR g.expiresAt > :now)")
    List<ResourceGrant> findActiveForResource(@Param("subjectIds") Collection<String> subjectIds,
                                              @Param("resourceType") String resourceType,
                                              @Param("resourceId") String resourceId,
                                              @Param("now") Instant now);

    @Query("SELECT g FROM ResourceGrant g WHERE g.subjectId = :subjectId AND g.revokedAt IS NULL " +
           "AND (g.expiresAt IS NULL OR g.expiresAt > :now)")
    List<ResourceGrant> findActiveBySubject(@Param("subjectId") String subjectId, @Param("now") Instant now);

    @Query("SELECT g FROM ResourceGrant g WHERE g.resourceType = :resourceType " +
           "AND g.resourceId = :resourceId AND g.revokedAt IS NULL " +
           "AND (g.expiresAt IS NULL OR g.expiresAt > :now)")
    List<ResourceGrant> findActiveByResource(@Param("resourceType") String resourceType,
                                             @Param("resourceId") String resourceId,
                                             @Param("now") Instant now);
}
