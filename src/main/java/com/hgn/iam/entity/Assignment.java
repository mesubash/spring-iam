package com.hgn.iam.entity;

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

    @Column(name = "subject_id", nullable = false, length = 100)
    private String subjectId;

    @Column(name = "subject_type", length = 20)
    private String subjectType = "USER";

    @Column(name = "role_id", nullable = false)
    private UUID roleId;

    @Column(name = "scope_id", nullable = false)
    private UUID scopeId;

    @Column(length = 10)
    private String effect = "ALLOW";

    @Column(name = "granted_by", nullable = false)
    private String grantedBy;

    @Column(name = "granted_at")
    private Instant grantedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> conditions = new HashMap<>();

    @Column(nullable = false)
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
