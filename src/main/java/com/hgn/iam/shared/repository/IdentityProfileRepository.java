package com.hgn.iam.shared.repository;

import com.hgn.iam.shared.entity.IdentityProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface IdentityProfileRepository extends JpaRepository<IdentityProfile, UUID> {
}
