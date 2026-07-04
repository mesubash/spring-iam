package io.github.mesubash.iam.authz.entity;

import io.github.mesubash.iam.config.LTreeJdbcType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcType;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "scopes")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Scope {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    // Free-form label; validated against scope_types when the registry has rows
    @Column(nullable = false, length = 50)
    private String type;

    @Column(nullable = false, length = 200)
    private String name;

    // ltree path segment; unique among siblings (DB index)
    @Column(nullable = false, length = 50)
    private String code;

    @Column(name = "parent_id")
    private UUID parentId;

    @JdbcType(LTreeJdbcType.class)
    @Column(nullable = false, columnDefinition = "ltree")
    private String path;  // Materialized path

    @Column(nullable = false)
    @Builder.Default
    private Integer depth = 0;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "created_by", length = 100)
    private String createdBy;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}