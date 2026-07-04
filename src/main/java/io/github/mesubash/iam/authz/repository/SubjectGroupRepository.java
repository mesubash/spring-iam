package io.github.mesubash.iam.authz.repository;

import io.github.mesubash.iam.authz.entity.SubjectGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface SubjectGroupRepository extends JpaRepository<SubjectGroup, UUID> {

    Optional<SubjectGroup> findByName(String name);
}
