package io.github.mesubash.iam.shared.repository;

import io.github.mesubash.iam.shared.entity.IdentityProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface IdentityProfileRepository extends JpaRepository<IdentityProfile, UUID> {
}
