package com.hgn.iam.authn.repository;

import com.hgn.iam.authn.entity.Identity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface IdentityRepository extends JpaRepository<Identity, UUID> {

    Optional<Identity> findByPrimaryEmail(String primaryEmail);

    boolean existsByPrimaryEmail(String primaryEmail);
}
