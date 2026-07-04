package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "permissions")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 150)
    private String key;  // domain.<resource-path>.action, 3-6 segments

    @Column(nullable = false, length = 50)
    private String domain;

    @Column(nullable = false, length = 100)
    private String resource;

    @Column(nullable = false, length = 50)
    private String action;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "is_deprecated")
    private Boolean isDeprecated = false;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "created_by")
    private String createdBy;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

}
