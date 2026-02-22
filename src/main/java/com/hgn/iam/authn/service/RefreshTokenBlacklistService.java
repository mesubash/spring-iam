package com.hgn.iam.authn.service;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * Service for managing refresh token blacklisting using the refresh_tokens table.
 */
public interface RefreshTokenBlacklistService {

    void blacklistToken(String token, UUID identityId, OffsetDateTime expiresAt, String reason);

    void blacklistToken(String token, UUID identityId, OffsetDateTime expiresAt);

    boolean isBlacklisted(String token);

    int cleanupExpiredTokens();
}
