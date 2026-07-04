package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.SigningKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

    Optional<SigningKey> findByStatus(String status);

    Optional<SigningKey> findByKid(String kid);

    List<SigningKey> findByStatusIn(List<String> statuses);
}
