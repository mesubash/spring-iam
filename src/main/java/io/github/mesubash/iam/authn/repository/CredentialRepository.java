package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CredentialRepository extends JpaRepository<Credential, UUID> {

    Optional<Credential> findByCredentialTypeAndIdentifier(CredentialType credentialType, String identifier);

    Optional<Credential> findByCredentialTypeAndIdentifierAndIsActiveTrue(CredentialType credentialType, String identifier);

    List<Credential> findByIdentityId(UUID identityId);

    Optional<Credential> findByIdentityIdAndCredentialType(UUID identityId, CredentialType credentialType);

    boolean existsByCredentialTypeAndIdentifier(CredentialType credentialType, String identifier);
}
