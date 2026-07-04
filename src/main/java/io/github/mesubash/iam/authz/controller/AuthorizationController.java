package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authz.dto.AccessListEntry;
import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.dto.AuthorizationResponse;
import io.github.mesubash.iam.authz.dto.ExplainResponse;
import io.github.mesubash.iam.authz.dto.FilterResourcesRequest;
import io.github.mesubash.iam.authz.dto.SimulateRequest;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;


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
    @Operation(summary = "Get effective permissions for a subject/scope",
            description = "Pass ?asOf=<ISO-8601> for point-in-time reconstruction from assignment history")
    public ResponseEntity<EffectivePermissionsResponse> effectivePermissions(
            @RequestBody EffectivePermissionsRequest request,
            @RequestParam(required = false) Instant asOf) {

        if (asOf != null) {
            UUID scopeId = request.getScopeId() != null ? request.getScopeId()
                    : (request.getResource() != null ? request.getResource().getScopeId() : null);
            return ResponseEntity.ok(authorizationService.getEffectivePermissionsAsOf(
                    request.getSubject(), scopeId, asOf));
        }
        return ResponseEntity.ok(authorizationService.getEffectivePermissions(request));
    }

    @PostMapping("/authorize/explain")
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','AccessAdmin','SecurityAdmin','AuditViewer')")
    @Operation(summary = "Explain a decision",
            description = "Dry-run trace of the pipeline; writes no audit record")
    public ResponseEntity<ExplainResponse> explain(
            @Valid @RequestBody AuthorizationRequest request,
            HttpServletRequest httpRequest) {
        enrichRequestContext(request, httpRequest);
        return ResponseEntity.ok(authorizationService.explain(request));
    }

    @PostMapping("/authorize/simulate")
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','AccessAdmin')")
    @Operation(summary = "Simulate a decision with a hypothetical assignment set")
    public ResponseEntity<ExplainResponse> simulate(@Valid @RequestBody SimulateRequest request) {
        return ResponseEntity.ok(authorizationService.simulate(request));
    }

    @PostMapping("/filter-resources")
    @Operation(summary = "Filter a list of resource ids to the subset the subject may act on")
    public ResponseEntity<Map<String, Object>> filterResources(
            @Valid @RequestBody FilterResourcesRequest request) {
        if (request.getResourceIds().size() > 500) {
            throw new IllegalArgumentException("resourceIds exceeds maximum of 500");
        }
        List<String> allowed = authorizationService.filterResources(request);
        return ResponseEntity.ok(Map.of("allowed", allowed));
    }

    @GetMapping("/access-list")
    @PreAuthorize("hasAnyRole('SuperAdmin','CountryAdmin','AccessAdmin','SecurityAdmin','AuditViewer')")
    @Operation(summary = "Reverse lookup: who holds permission P at scope S")
    public ResponseEntity<List<AccessListEntry>> accessList(
            @RequestParam String permission,
            @RequestParam UUID scopeId) {
        return ResponseEntity.ok(authorizationService.accessList(permission, scopeId));
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
