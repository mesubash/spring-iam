package com.hgn.iam.controller;

import com.hgn.iam.dto.AuthorizationRequest;
import com.hgn.iam.dto.AuthorizationResponse;
import com.hgn.iam.service.AuthorizationService;
import com.hgn.iam.dto.EffectivePermissionsRequest;
import com.hgn.iam.dto.EffectivePermissionsResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
            @Valid @RequestBody AuthorizationRequest request) {

        log.debug("Authorization request: subject={}, permission={}",
                request.getSubject(), request.getPermission());

        AuthorizationResponse response = authorizationService.authorize(request);

        log.info("Authorization decision: subject={}, permission={}, decision={}, latency={}ms",
                request.getSubject(), request.getPermission(),
                response.getAuthorized(), response.getLatencyMs());

        return ResponseEntity.ok(response);
    }

    /**
     * Batch authorization check (for efficiency)
     * Check multiple permissions at once
     */
    @PostMapping("/authorize/batch")
    @Operation(summary = "Batch authorization check")
    public ResponseEntity<Map<String, AuthorizationResponse>> authorizeBatch(
            @RequestBody List<AuthorizationRequest> requests) {

        Map<String, AuthorizationResponse> responses = new HashMap<>();

        for (AuthorizationRequest request : requests) {
            String key = request.getPermission() + ":" + request.getResource().getId();
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
}
