package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "policies")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Policy {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 120)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "permission_key", length = 100)
    private String permissionKey;

    @Column(name = "resource_type", length = 100)
    private String resourceType;

    @Column(name = "scope_id")
    private UUID scopeId;

    @Column(length = 10, nullable = false)
    private String effect;

    @Column(nullable = false)
    private Integer priority;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> conditions = new HashMap<>();

    // SHADOW: evaluated and audited, never affects the decision
    @Column(name = "enforcement_mode", length = 10)
    private String enforcementMode = "ENFORCE";

    @Column(nullable = false)
    private Boolean active = true;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "created_by", length = 100)
    private String createdBy;

    @PrePersist
    protected void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        if (updatedAt == null) {
            updatedAt = now;
        }
        if (priority == null) {
            priority = 0;
        }
        if (effect == null) {
            effect = "ALLOW";
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}
