package io.github.mesubash.iam.authn.security;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.security.token.SigningKeyService;
import io.github.mesubash.iam.shared.exception.InvalidTokenException;
import io.github.mesubash.iam.shared.exception.TokenExpiredException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

/**
 * Issues and verifies RS256 access tokens. Signing uses the ACTIVE key from
 * SigningKeyService; verification resolves the key by the token's kid header,
 * so rotated keys keep verifying until their grace window ends.
 * Refresh tokens are opaque and live in SessionService — not JWTs.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    // ROOT scope — permissions-mode claims are computed here
    private static final UUID ROOT_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000001");

    private final JwtConfig jwtConfig;
    private final SigningKeyService signingKeyService;
    // Only used in permissions mode; optional so unit contexts stay light
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private io.github.mesubash.iam.shared.service.AuthzQueryService authzQueryService;

    public String generateAccessToken(UserPrincipal principal, UUID sessionId) {
        SigningKeyService.ActiveKey key = signingKeyService.activeKey();
        Date now = new Date();
        String mode = jwtConfig.getClaimsMode() != null ? jwtConfig.getClaimsMode() : "roles";

        var builder = Jwts.builder()
                .header().keyId(key.kid()).and()
                .subject(principal.getId().toString())
                .id(UUID.randomUUID().toString())                     // jti — blacklist handle
                .claim("sid", sessionId != null ? sessionId.toString() : null)
                .claim("typ", "access")
                .claim("email_verified", principal.getIdentity() != null
                        && Boolean.TRUE.equals(principal.getIdentity().getEmailVerified()));

        if (!"minimal".equalsIgnoreCase(mode)) {
            builder.claim("roles", principal.getRoles());
        }
        if ("permissions".equalsIgnoreCase(mode) && authzQueryService != null) {
            try {
                builder.claim("perms", authzQueryService.getEffectivePermissions(
                                principal.getId(), ROOT_SCOPE))
                        .claim("scope", ROOT_SCOPE.toString());
            } catch (Exception e) {
                log.warn("permissions-mode claim computation failed for {}: {}",
                        principal.getId(), e.getMessage());
            }
        }

        return builder
                .issuedAt(now)
                .expiration(new Date(now.getTime() + jwtConfig.getExpiration()))
                .signWith(key.privateKey(), Jwts.SIG.RS256)
                .compact();
    }

    public Claims parseToken(String token) {
        try {
            return Jwts.parser()
                    .keyLocator(header -> resolveKey((ProtectedHeader) header))
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

    public boolean validateToken(String token) {
        parseToken(token);
        return true;
    }

    public String getUserIdFromToken(String token) {
        return parseToken(token).getSubject();
    }

    public String getJti(Claims claims) {
        return claims.getId();
    }

    public UUID getSid(Claims claims) {
        String sid = claims.get("sid", String.class);
        return sid != null ? UUID.fromString(sid) : null;
    }

    /** Remaining lifetime in ms; 0 if expired or unparseable. */
    public long getExpirationTime(String token) {
        try {
            return parseToken(token).getExpiration().getTime() - System.currentTimeMillis();
        } catch (Exception e) {
            return 0;
        }
    }

    private Key resolveKey(ProtectedHeader header) {
        Key key = signingKeyService.publicKeyFor(header.getKeyId());
        if (key == null) {
            throw new InvalidTokenException("Unknown or retired signing key");
        }
        return key;
    }
}
