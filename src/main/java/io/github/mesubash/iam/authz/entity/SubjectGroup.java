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

/** Flat subject group: one assignment/deny can cover every member. No nesting. */
@Entity
@Table(name = "subject_groups")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class SubjectGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 100)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false)
    @Builder.Default
    private Boolean active = true;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "created_by", length = 100)
    private String createdBy;
}
