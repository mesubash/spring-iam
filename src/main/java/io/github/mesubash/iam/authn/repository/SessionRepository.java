package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

// Explicit bean name — spring-session-data-redis already owns "sessionRepository"
@Repository("iamSessionRepository")
public interface SessionRepository extends JpaRepository<Session, UUID> {

    @Query("SELECT s FROM Session s WHERE s.identityId = :identityId AND s.revokedAt IS NULL " +
           "AND s.expiresAt > :now ORDER BY s.lastUsedAt DESC")
    List<Session> findActiveByIdentity(@Param("identityId") UUID identityId, @Param("now") Instant now);

    @Query("SELECT s FROM Session s WHERE s.revokedAt > :since ORDER BY s.revokedAt")
    List<Session> findRevokedSince(@Param("since") Instant since);
}
