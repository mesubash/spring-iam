package io.github.mesubash.iam.authz.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "subject_group_members")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
@IdClass(SubjectGroupMember.Key.class)
public class SubjectGroupMember {

    @Id
    @Column(name = "group_id", nullable = false)
    private UUID groupId;

    @Id
    @Column(name = "subject_id", nullable = false, length = 255)
    private String subjectId;

    @Column(name = "added_at", updatable = false)
    private Instant addedAt;

    @Column(name = "added_by", length = 100)
    private String addedBy;

    @Getter @Setter
    @NoArgsConstructor @AllArgsConstructor
    public static class Key implements Serializable {
        private UUID groupId;
        private String subjectId;
    }
}
