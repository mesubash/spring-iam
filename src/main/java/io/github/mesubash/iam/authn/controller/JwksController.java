package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.security.token.SigningKeyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Keys", description = "Public signing keys and rotation")
public class JwksController {

    private final SigningKeyService signingKeyService;

    @GetMapping("/.well-known/jwks.json")
    @Operation(summary = "JWKS", description = "Public keys for local JWT verification by consuming services")
    public ResponseEntity<Map<String, List<Map<String, String>>>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(Map.of("keys", signingKeyService.jwks()));
    }

    @PostMapping("/api/v1/keys/rotate")
    @PreAuthorize("hasRole('SuperAdmin')")
    @Operation(summary = "Rotate signing key",
            description = "New key signs immediately; the old key verifies until its grace window ends")
    public ResponseEntity<Map<String, String>> rotate() {
        return ResponseEntity.ok(Map.of("kid", signingKeyService.rotate()));
    }
}
