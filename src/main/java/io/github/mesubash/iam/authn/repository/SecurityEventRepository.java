package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.SecurityEvent;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.UUID;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    Page<SecurityEvent> findByIdentityIdOrderByCreatedAtDesc(UUID identityId, Pageable pageable);

    Page<SecurityEvent> findByEventTypeOrderByCreatedAtDesc(SecurityEventType eventType, Pageable pageable);

    @Query("SELECT e FROM SecurityEvent e " +
            "WHERE (:identityId IS NULL OR e.identity.id = :identityId) " +
            "AND (:eventType IS NULL OR e.eventType = :eventType) " +
            "AND e.createdAt >= :since " +
            "ORDER BY e.createdAt DESC")
    Page<SecurityEvent> search(@Param("identityId") UUID identityId,
                               @Param("eventType") SecurityEventType eventType,
                               @Param("since") OffsetDateTime since,
                               Pageable pageable);
}
