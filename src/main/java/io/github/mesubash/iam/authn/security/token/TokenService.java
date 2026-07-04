package io.github.mesubash.iam.authn.security.token;

import io.github.mesubash.iam.authn.entity.enums.TokenType;
import io.github.mesubash.iam.shared.exception.TokenReuseException;

/**
 * Service interface for managing authentication tokens (refresh, password reset, email verification).
 */
public interface TokenService {

    void store(String userId, String token, TokenType tokenType) throws TokenReuseException;

    void rotate(String userId, String oldToken, String newToken, TokenType tokenType) throws TokenReuseException;

    boolean validate(String userId, String token, TokenType tokenType);

    void revokeAll(String userId, TokenType tokenType);

    void revoke(String userId, String token, TokenType tokenType);

    String getTokenUserId(String token, TokenType tokenType);

    void blacklistToken(String token, long durationMs);

    boolean isTokenBlacklisted(String token);
}
