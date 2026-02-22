package com.hgn.iam.authn.repository;

import com.hgn.iam.authn.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHashAndRevokedAtIsNull(String tokenHash);

    boolean existsByTokenHashAndRevokedAtIsNull(String tokenHash);

    boolean existsByTokenHash(String tokenHash);

    List<RefreshToken> findByIdentityIdAndRevokedAtIsNull(UUID identityId);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revokedAt = :now, rt.revokeReason = :reason " +
           "WHERE rt.identity.id = :identityId AND rt.revokedAt IS NULL")
    int revokeAllByIdentityId(@Param("identityId") UUID identityId,
                              @Param("now") OffsetDateTime now,
                              @Param("reason") String reason);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") OffsetDateTime now);

    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.expiresAt < :now")
    long countExpiredTokens(@Param("now") OffsetDateTime now);
}
