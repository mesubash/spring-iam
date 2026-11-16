package io.github.mesubash.iam.authn.mfa;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "mfa_recovery_codes")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class MfaRecoveryCode {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "identity_id", nullable = false)
    private UUID identityId;

    @Column(name = "code_hash", nullable = false)
    private String codeHash;

    @Column(name = "used_at")
    private OffsetDateTime usedAt;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @PrePersist
    void onCreate() { if (createdAt == null) createdAt = OffsetDateTime.now(); }
}
