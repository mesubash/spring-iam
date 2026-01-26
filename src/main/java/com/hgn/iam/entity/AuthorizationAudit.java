package com.hgn.iam.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Immutable;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "authorization_audit")
@Immutable
@IdClass(AuthorizationAuditId.class)
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthorizationAudit {

    @Id
    private UUID id;

    @Column(name = "subject_id", nullable = false)
    private String subjectId;

    @Column(name = "permission_key")
    private String permissionKey;

    @Column(name = "resource_type")
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @Column(name = "scope_id")
    private UUID scopeId;

    @Column(nullable = false)
    private Boolean decision;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String reason;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> context = new HashMap<>();

    @Column(name = "request_id")
    private String requestId;

    @org.hibernate.annotations.ColumnTransformer(write = "CAST(? AS inet)")
    @Column(name = "ip_address", columnDefinition = "inet")
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Id
    @Column(nullable = false)
    private Instant timestamp;

    @PrePersist
    protected void onCreate() {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
