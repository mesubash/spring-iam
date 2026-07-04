package io.github.mesubash.iam.authn.service.impl;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.RefreshToken;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.repository.RefreshTokenRepository;
import io.github.mesubash.iam.authn.service.RefreshTokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Uses the refresh_tokens table with revoked_at model instead of separate blacklist table.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenBlacklistServiceImpl implements RefreshTokenBlacklistService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final IdentityRepository identityRepository;

    @Override
    @Transactional
    public void blacklistToken(String token, UUID identityId, OffsetDateTime expiresAt, String reason) {
        if (token == null || token.isBlank()) return;

        String tokenHash = hashToken(token);

        // Check if already tracked
        if (refreshTokenRepository.existsByTokenHash(tokenHash)) {
            // Mark as revoked if not already
            refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(tokenHash)
                    .ifPresent(rt -> {
                        rt.setRevokedAt(OffsetDateTime.now());
                        rt.setRevokeReason(reason != null ? reason : "LOGOUT");
                        refreshTokenRepository.save(rt);
                    });
            return;
        }

        // Create a revoked entry
        Identity identity = identityRepository.findById(identityId).orElse(null);
        if (identity == null) return;

        RefreshToken refreshToken = RefreshToken.builder()
                .identity(identity)
                .tokenHash(tokenHash)
                .expiresAt(expiresAt)
                .revokedAt(OffsetDateTime.now())
                .revokeReason(reason != null ? reason : "LOGOUT")
                .build();

        refreshTokenRepository.save(refreshToken);
        log.info("Blacklisted refresh token for identity {} (reason: {})", identityId, reason);
    }

    @Override
    @Transactional
    public void blacklistToken(String token, UUID identityId, OffsetDateTime expiresAt) {
        blacklistToken(token, identityId, expiresAt, "LOGOUT");
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isBlacklisted(String token) {
        if (token == null || token.isBlank()) return false;
        String tokenHash = hashToken(token);
        // Token is blacklisted if it exists AND has been revoked, OR doesn't exist at all
        // We only need to check if it's explicitly revoked
        return refreshTokenRepository.existsByTokenHash(tokenHash)
                && !refreshTokenRepository.existsByTokenHashAndRevokedAtIsNull(tokenHash);
    }

    @Override
    @Transactional
    public int cleanupExpiredTokens() {
        OffsetDateTime now = OffsetDateTime.now();
        long expiredCount = refreshTokenRepository.countExpiredTokens(now);
        if (expiredCount == 0) return 0;

        int deleted = refreshTokenRepository.deleteExpiredTokens(now);
        log.info("Cleaned up {} expired refresh tokens", deleted);
        return deleted;
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}
