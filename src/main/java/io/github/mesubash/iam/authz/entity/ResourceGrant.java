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

import java.time.Instant;
import java.util.UUID;

/**
 * Direct per-instance permission: subject S may do P on resource type+id.
 * An additional allow path — deny rules still win, roles are not involved.
 */
@Entity
@Table(name = "resource_grants")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class ResourceGrant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "subject_id", nullable = false, length = 255)
    private String subjectId;

    @Column(name = "subject_type", length = 20)
    @Builder.Default
    private String subjectType = "USER";

    // Exact key, or wildcard on the action segment only (doc.file.*)
    @Column(name = "permission_key", nullable = false, length = 150)
    private String permissionKey;

    @Column(name = "resource_type", nullable = false, length = 100)
    private String resourceType;

    @Column(name = "resource_id", nullable = false, length = 255)
    private String resourceId;

    // Optional fence: grant only fires when the resource scope is inside this
    @Column(name = "scope_id")
    private UUID scopeId;

    @Column(name = "granted_by", nullable = false, length = 100)
    private String grantedBy;

    @Column(name = "granted_at", updatable = false)
    private Instant grantedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "revoked_by", length = 100)
    private String revokedBy;
}
