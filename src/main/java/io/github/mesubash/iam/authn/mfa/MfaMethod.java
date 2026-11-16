package io.github.mesubash.iam.authn.mfa;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Table(name = "mfa_methods")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class MfaMethod {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "identity_id", nullable = false)
    private UUID identityId;

    @Column(nullable = false)
    private String type;                 // TOTP

    @Column(name = "secret_enc", nullable = false)
    private String secretEnc;            // AES-GCM(base32 secret)

    @Column(name = "confirmed_at")
    private OffsetDateTime confirmedAt;  // null = pending

    @Column(name = "last_step")
    private Long lastStep;               // replay guard

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @PrePersist
    void onCreate() { if (createdAt == null) createdAt = OffsetDateTime.now(); }
}
