package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "deny_rules")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DenyRule {

    @Id
    @GeneratedValue(strategy =  GenerationType.UUID)
    private UUID id;

    @Column(name = "subject_id", nullable = false, length = 255)
    private String subjectId;

    @Column(name = "subject_type", length = 20)
    @Builder.Default
    private String subjectType = "USER";

    @Column(name = "permission_key", nullable = false, length = 150)
    private String permissionKey;

    @Column(name = "scope_id")
    private UUID scopeId;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String reason;

    @Column(name = "reference_id", length = 100)
    private String referenceId;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}

