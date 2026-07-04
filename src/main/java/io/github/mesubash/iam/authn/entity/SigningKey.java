package io.github.mesubash.iam.authn.entity;

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

@Entity
@Table(name = "signing_keys")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class SigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String kid;

    @Column(nullable = false, length = 10)
    @Builder.Default
    private String algorithm = "RS256";

    // Base64 DER (X.509)
    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    // Base64 DER (PKCS#8); AES-GCM-encrypted when a key-encryption key is configured
    @Column(name = "private_key", nullable = false, columnDefinition = "TEXT")
    private String privateKey;

    // ACTIVE signs; ROTATED verifies until not_after; REVOKED is gone
    @Column(nullable = false, length = 20)
    @Builder.Default
    private String status = "ACTIVE";

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "rotated_at")
    private Instant rotatedAt;

    @Column(name = "not_after")
    private Instant notAfter;
}
