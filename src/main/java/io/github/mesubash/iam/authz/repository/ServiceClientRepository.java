package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.ServiceClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ServiceClientRepository extends JpaRepository<ServiceClient, UUID> {

    Optional<ServiceClient> findByName(String name);

    Optional<ServiceClient> findByApiKeyHashAndActiveTrue(String apiKeyHash);
}
