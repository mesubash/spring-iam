package io.github.mesubash.iam.authn.mfa;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface MfaMethodRepository extends JpaRepository<MfaMethod, UUID> {
    Optional<MfaMethod> findByIdentityIdAndType(UUID identityId, String type);
    void deleteByIdentityId(UUID identityId);
}
