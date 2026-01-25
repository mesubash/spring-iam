package com.hgn.iam.entity;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Type;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Table(name = "authorization_audit")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@TypeDef(name = "jsonb", typeClass = JsonBinaryType.class)
public class AuthorizationAudit {

    @Id
    @GeneratedValue
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

    @Type(type = "jsonb")
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> context = new HashMap<>();

    @Column(name = "request_id")
    private String requestId;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    private String userAgent;

    @Column(nullable = false)
    private Instant timestamp;

    @PrePersist
    protected void onCreate() {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
