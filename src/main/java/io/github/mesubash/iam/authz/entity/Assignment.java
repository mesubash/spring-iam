package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "assignments")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Assignment {

    @Id
    @GeneratedValue(strategy = jakarta.persistence.GenerationType.UUID)
    private UUID id;

    @Column(name = "subject_id", nullable = false, length = 255)
    private String subjectId;

    @Column(name = "subject_type", length = 20)
    @Builder.Default
    private String subjectType = "USER";

    @Column(name = "role_id", nullable = false)
    private UUID roleId;

    @Column(name = "scope_id", nullable = false)
    private UUID scopeId;

    // STANDARD | BREAK_GLASS | MIGRATION
    @Column(length = 20)
    @Builder.Default
    private String origin = "STANDARD";

    @Column(name = "granted_by", nullable = false)
    private String grantedBy;

    @Column(name = "granted_at")
    private Instant grantedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> conditions = new HashMap<>();

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_by")
    private String revokedBy;

    @Column(name = "revoke_reason", columnDefinition = "TEXT")
    private String revokeReason;

    @PrePersist
    protected void onCreate() {
        if (grantedAt == null) {
            grantedAt = Instant.now();
        }
    }
}
