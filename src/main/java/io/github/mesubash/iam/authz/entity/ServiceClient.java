package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * A registered consumer service: its own PDP API key (SHA-256 stored)
 * and the permission domains it owns for manifest sync.
 */
@Entity
@Table(name = "services")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class ServiceClient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(name = "display_name", nullable = false, length = 150)
    private String displayName;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "owned_domains", columnDefinition = "text[]")
    @Builder.Default
    private List<String> ownedDomains = new ArrayList<>();

    // Never serialize the key hash in list/detail responses
    @com.fasterxml.jackson.annotation.JsonIgnore
    @Column(name = "api_key_hash", nullable = false, length = 128)
    private String apiKeyHash;

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;
}
