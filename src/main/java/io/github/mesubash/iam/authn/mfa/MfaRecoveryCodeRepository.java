package io.github.mesubash.iam.authn.mfa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface MfaRecoveryCodeRepository extends JpaRepository<MfaRecoveryCode, UUID> {
    List<MfaRecoveryCode> findByIdentityIdAndUsedAtIsNull(UUID identityId);
    void deleteByIdentityId(UUID identityId);
}
