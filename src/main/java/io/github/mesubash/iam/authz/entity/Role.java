package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = jakarta.persistence.GenerationType.UUID)
    private UUID id;

    // Unique per owner scope (DB index) — tenant roles may share names
    @Column(nullable = false, length = 100)
    private String name;

    @Column(name = "display_name", length = 200)
    private String displayName;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "is_system_role")
    private Boolean isSystemRole = false;

    @Column(name = "org_type", length = 50)
    private String orgType;

    // NULL = global role; set = usable only within this scope's subtree
    @Column(name = "owner_scope_id")
    private UUID ownerScopeId;

    @Column(nullable = false)
    private Boolean active = true;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "created_by")
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
