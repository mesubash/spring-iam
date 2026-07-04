package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.token.TokenBlacklistService;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * RFC 7662-shaped live token check for consumers that can't tolerate the
 * access-token TTL as their revocation window. Internal callers only.
 */
@RestController
@RequestMapping("/api/v1/token")
@RequiredArgsConstructor
@Tag(name = "Token", description = "Token introspection")
public class TokenIntrospectionController {

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;
    private final FeatureFlags featureFlags;

    @PostMapping("/introspect")
    @Operation(summary = "Introspect a token", description = "Signature + expiry + revocation check")
    public ResponseEntity<Map<String, Object>> introspect(@RequestBody Map<String, String> body) {
        if (!featureFlags.isIntrospection()) {
            throw new ResourceNotFoundException("Introspection is not enabled");
        }
        Map<String, Object> result = new HashMap<>();
        try {
            Claims claims = jwtTokenProvider.parseToken(body.get("token"));
            boolean revoked = tokenBlacklistService.isBlacklisted(
                    claims.getId(), jwtTokenProvider.getSid(claims));
            result.put("active", !revoked);
            result.put("sub", claims.getSubject());
            result.put("sid", claims.get("sid"));
            result.put("exp", claims.getExpiration().toInstant().getEpochSecond());
            result.put("roles", claims.get("roles"));
        } catch (Exception e) {
            result.put("active", false);
        }
        return ResponseEntity.ok(result);
    }
}
