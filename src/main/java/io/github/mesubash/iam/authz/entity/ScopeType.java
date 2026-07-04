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
 * Deployment-defined hierarchy level. Empty table = free-form scopes;
 * any rows = strict mode (type and parent validated on scope creation).
 */
@Entity
@Table(name = "scope_types")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class ScopeType {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 50)
    private String name;

    @Column(name = "display_name", nullable = false, length = 100)
    private String displayName;

    // Empty = this type may only sit directly under ROOT
    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "allowed_parent_types", columnDefinition = "text[]")
    @Builder.Default
    private List<String> allowedParentTypes = new ArrayList<>();

    @Column(name = "level_order")
    private Integer levelOrder;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;
}
