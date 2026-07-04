package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.SecurityEvent;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {

    Page<SecurityEvent> findByIdentityIdOrderByCreatedAtDesc(UUID identityId, Pageable pageable);

    Page<SecurityEvent> findByEventTypeOrderByCreatedAtDesc(SecurityEventType eventType, Pageable pageable);
}
