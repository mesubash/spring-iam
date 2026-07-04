package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.dto.AuthorizationResponse;
import io.github.mesubash.iam.authz.service.AuthorizationService;
import io.github.mesubash.iam.authz.dto.EffectivePermissionsRequest;
import io.github.mesubash.iam.authz.dto.EffectivePermissionsResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Tag(name = "Authorization", description = "Authorization check API")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    /**
     * THE MOST IMPORTANT ENDPOINT!
     *
     * This is called by ALL services for EVERY authorization check.
     *
     * Expected volume: 10,000-100,000 requests/second
     * Target latency: < 5ms (with cache)
     */
    @PostMapping("/authorize")
    @Operation(summary = "Check authorization",
            description = "Check if subject can perform action on resource")
    public ResponseEntity<AuthorizationResponse> authorize(
            @Valid @RequestBody AuthorizationRequest request,
            HttpServletRequest httpRequest) {

        // Enrich context with server-side IP and User-Agent if not provided by caller
        enrichRequestContext(request, httpRequest);

        log.debug("Authorization request: subject={}, permission={}",
                request.getSubject(), request.getPermission());

        AuthorizationResponse response = authorizationService.authorize(request);

        log.info("Authorization decision: subject={}, permission={}, decision={}, latency={}ms",
                request.getSubject(), request.getPermission(),
                response.getAuthorized(), response.getLatencyMs());

        return ResponseEntity.ok(response);
    }

    private static final int MAX_BATCH_SIZE = 50;

    /**
     * Batch authorization check (for efficiency)
     * Check multiple permissions at once. Maximum 50 items per batch.
     */
    @PostMapping("/authorize/batch")
    @Operation(summary = "Batch authorization check")
    public ResponseEntity<Map<String, AuthorizationResponse>> authorizeBatch(
            @Valid @RequestBody List<AuthorizationRequest> requests) {

        if (requests == null || requests.isEmpty()) {
            return ResponseEntity.ok(Map.of());
        }

        if (requests.size() > MAX_BATCH_SIZE) {
            throw new IllegalArgumentException(
                    "Batch size exceeds maximum of " + MAX_BATCH_SIZE
                    + ". Received: " + requests.size());
        }

        Map<String, AuthorizationResponse> responses = new HashMap<>();

        for (AuthorizationRequest request : requests) {
            String key = request.getPermission() + ":"
                    + (request.getResource() != null ? request.getResource().getId() : "null");
            responses.put(key, authorizationService.authorize(request));
        }

        return ResponseEntity.ok(responses);
    }

    /**
     * Bootstrap endpoint: returns effective permissions for a subject in a scope.
     * Useful for UI capability loading or service-side caching.
     */
    @PostMapping("/effective-permissions")
    @Operation(summary = "Get effective permissions for a subject/scope")
    public ResponseEntity<EffectivePermissionsResponse> effectivePermissions(
            @RequestBody EffectivePermissionsRequest request) {

        EffectivePermissionsResponse response = authorizationService.getEffectivePermissions(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Enrich the authorization request context with server-side values.
     * If the caller did not provide IP address or User-Agent, extract them from the HTTP request.
     * This ensures audit logs always have these fields regardless of caller cooperation.
     */
    private void enrichRequestContext(AuthorizationRequest request, HttpServletRequest httpRequest) {
        if (request.getContext() == null) {
            request.setContext(AuthorizationRequest.RequestContext.builder().build());
        }

        AuthorizationRequest.RequestContext ctx = request.getContext();

        // Server-side IP extraction (prefer X-Forwarded-For for proxied requests)
        if (ctx.getIpAddress() == null || ctx.getIpAddress().isBlank()) {
            String forwarded = httpRequest.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                ctx.setIpAddress(forwarded.split(",")[0].trim());
            } else {
                ctx.setIpAddress(httpRequest.getRemoteAddr());
            }
        }

        // Server-side User-Agent extraction
        if (ctx.getUserAgent() == null || ctx.getUserAgent().isBlank()) {
            ctx.setUserAgent(httpRequest.getHeader("User-Agent"));
        }
    }
}
