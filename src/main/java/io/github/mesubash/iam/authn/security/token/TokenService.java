package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.entity.enums.TokenType;

/**
 * One-time tokens (email verification, password reset, reactivation).
 * Refresh tokens live in SessionService; access-token revocation in
 * TokenBlacklistService.
 */
public interface TokenService {

    void store(String userId, String token, TokenType tokenType);

    /** Returns the owning user id, or null if unknown/expired. */
    String getTokenUserId(String token, TokenType tokenType);

    void revoke(String userId, String token, TokenType tokenType);
}
