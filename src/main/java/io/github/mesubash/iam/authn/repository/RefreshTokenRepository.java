package io.github.mesubash.iam.authn.repository;

import io.github.mesubash.iam.authn.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Atomically marks a chain head as replaced. Returns 0 when a concurrent
     * refresh won the race — the loser must serve the cached retry response.
     */
    @Modifying
    @Query("UPDATE RefreshToken t SET t.replacedBy = :newId, t.replacedAt = :now " +
           "WHERE t.id = :id AND t.replacedBy IS NULL")
    int markReplaced(@Param("id") UUID id, @Param("newId") UUID newId, @Param("now") Instant now);
}
