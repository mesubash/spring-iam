package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.repository.SessionRepository;
import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.token.TokenBlacklistService;
import io.github.mesubash.iam.config.FeatureFlags;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
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
    private final SessionRepository sessionRepository;
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

    @GetMapping("/revocations")
    @Operation(summary = "Revoked sessions since a timestamp",
            description = "For offline/edge consumers that poll instead of introspecting per request")
    public ResponseEntity<List<Map<String, Object>>> revocations(@RequestParam Instant since) {
        if (!featureFlags.isRevocationFeed()) {
            throw new ResourceNotFoundException("Revocation feed is not enabled");
        }
        List<Map<String, Object>> feed = sessionRepository.findRevokedSince(since).stream()
                .map(s -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("sid", s.getId().toString());
                    m.put("subject", s.getIdentityId().toString());
                    m.put("revokedAt", s.getRevokedAt());
                    m.put("reason", s.getRevokeReason());
                    return m;
                })
                .toList();
        return ResponseEntity.ok(feed);
    }
}
