package com.hgn.iam.authn.security;

import com.hgn.iam.authn.config.JwtConfig;
import com.hgn.iam.authn.entity.enums.TokenType;
import com.hgn.iam.authn.security.token.TokenService;
import com.hgn.iam.shared.exception.InvalidTokenException;
import com.hgn.iam.shared.exception.TokenExpiredException;
import com.hgn.iam.shared.exception.TokenReuseException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtConfig jwtConfig;
    private final TokenService tokenService;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate JWT access token with roles list from AuthZ.
     */
    public String generateToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtConfig.getExpiration());

        String token = Jwts.builder()
                .subject(userPrincipal.getId().toString())
                .claim("roles", userPrincipal.getRoles())
                .claim("type", "access")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();

        log.debug("Generated access token for user ID: {} (roles: {})", userPrincipal.getId(), userPrincipal.getRoles());
        return token;
    }

    public String generateRefreshToken(Authentication authentication) {
        return generateRefreshToken(authentication, true);
    }

    public String generateRefreshToken(Authentication authentication, boolean persist) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtConfig.getRefreshExpiration());

        String token = Jwts.builder()
                .subject(userPrincipal.getId().toString())
                .claim("type", "refresh")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();

        if (persist) {
            try {
                tokenService.store(userPrincipal.getId().toString(), token, TokenType.REFRESH);
            } catch (Exception e) {
                log.warn("Failed to store refresh token for user {}", userPrincipal.getId(), e);
            }
        }

        log.debug("Generated refresh token for user: {}", userPrincipal.getEmail());
        return token;
    }

    public String rotateRefreshToken(String oldRefreshToken) {
        Claims claims = parseToken(oldRefreshToken);
        String type = claims.get("type", String.class);
        if (!"refresh".equals(type)) throw new RuntimeException("Provided token is not a refresh token");

        String userId = claims.getSubject();
        if (tokenService.isTokenBlacklisted(oldRefreshToken)) {
            throw new TokenReuseException("Refresh token has been already used or blacklisted");
        }

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtConfig.getRefreshExpiration());

        String newToken = Jwts.builder()
                .subject(userId)
                .claim("type", "refresh")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();

        try {
            tokenService.rotate(userId, oldRefreshToken, newToken, TokenType.REFRESH);
            tokenService.blacklistToken(oldRefreshToken, 900000);
            return newToken;
        } catch (TokenReuseException tre) {
            try {
                tokenService.revokeAll(userId, TokenType.REFRESH);
                tokenService.blacklistToken(oldRefreshToken, 900000);
            } catch (Exception e) {
                log.warn("Failed to revoke tokens after detected reuse for user {}", userId, e);
            }
            throw tre;
        }
    }

    public boolean validateRefreshToken(String token) {
        try {
            Claims claims = parseToken(token);
            String type = claims.get("type", String.class);
            if (!"refresh".equals(type)) return false;
            String userId = claims.getSubject();
            return tokenService.validate(userId, token, TokenType.REFRESH);
        } catch (Exception e) {
            log.debug("Refresh token validation failed", e);
            return false;
        }
    }

    public String getUserIdFromToken(String token) {
        return parseToken(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        Claims claims = parseToken(token);
        Object roles = claims.get("roles");
        if (roles instanceof List<?>) {
            return (List<String>) roles;
        }
        return List.of();
    }

    public Claims parseToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired", e);
        } catch (UnsupportedJwtException e) {
            throw new InvalidTokenException("Unsupported JWT token", e);
        } catch (MalformedJwtException e) {
            throw new InvalidTokenException("Invalid JWT token", e);
        } catch (JwtException e) {
            throw new InvalidTokenException("Invalid JWT signature", e);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("JWT claims string is empty", e);
        }
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (SignatureException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
            throw new InvalidTokenException("Invalid JWT signature", ex);
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
            throw new InvalidTokenException("Invalid JWT token", ex);
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token: {}", ex.getMessage());
            throw new TokenExpiredException("Expired JWT token", ex);
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token: {}", ex.getMessage());
            throw new InvalidTokenException("Unsupported JWT token", ex);
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
            throw new InvalidTokenException("JWT claims string is empty", ex);
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public Date getExpirationDateFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration();
    }

    public long getTokenExpiryDuration(String accessToken) {
        Date expiration = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(accessToken)
                .getPayload()
                .getExpiration();
        return expiration.getTime() - System.currentTimeMillis();
    }

    public long getExpirationTime(String token) {
        try {
            return getTokenExpiryDuration(token);
        } catch (Exception e) {
            return 0;
        }
    }
}
