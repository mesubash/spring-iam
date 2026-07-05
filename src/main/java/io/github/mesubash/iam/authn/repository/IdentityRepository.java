package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IdentityRepository extends JpaRepository<Identity, UUID> {

    Optional<Identity> findByPrimaryEmail(String primaryEmail);

    boolean existsByPrimaryEmail(String primaryEmail);

    // `query` is a lowercase substring ("" matches all — avoids binding a typeless
    // NULL string param, which Postgres rejects as lower(bytea)).
    @Query("""
            SELECT i FROM Identity i
            WHERE LOWER(i.primaryEmail) LIKE CONCAT('%', :query, '%')
              AND (:status IS NULL OR i.accountStatus = :status)
            ORDER BY i.primaryEmail
            """)
    List<Identity> search(@Param("query") String query,
                          @Param("status") AccountStatus status,
                          Pageable pageable);
}
