package com.hgn.iam.authz.controller;

import com.hgn.iam.authz.dto.CreatePolicyRequest;
import com.hgn.iam.authz.dto.UpdatePolicyRequest;
import com.hgn.iam.authz.entity.Policy;
import com.hgn.iam.authz.service.PolicyService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/policies")
@RequiredArgsConstructor
@Tag(name = "Policies", description = "Policy management for ABAC/ReBAC rules")
public class PolicyController {

    private final PolicyService policyService;

    @GetMapping
    public ResponseEntity<List<Policy>> getPolicies() {
        return ResponseEntity.ok(policyService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Policy> getPolicy(@PathVariable UUID id) {
        return policyService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<Policy> createPolicy(
            @Valid @RequestBody CreatePolicyRequest request) {

        Policy policy = Policy.builder()
                .name(request.getName())
                .description(request.getDescription())
                .permissionKey(request.getPermissionKey())
                .resourceType(request.getResourceType())
                .scopeId(request.getScopeId())
                .effect(request.getEffect() != null ? request.getEffect() : "ALLOW")
                .priority(request.getPriority() != null ? request.getPriority() : 0)
                .conditions(request.getConditions())
                .active(request.getActive() != null ? request.getActive() : true)
                .createdBy(request.getCreatedBy() != null ? request.getCreatedBy() : "system")
                .build();

        return ResponseEntity.status(HttpStatus.CREATED).body(policyService.create(policy));
    }

    @PutMapping("/{id}")
    public ResponseEntity<Policy> updatePolicy(
            @PathVariable UUID id,
            @RequestBody UpdatePolicyRequest request) {

        Policy updated = Policy.builder()
                .description(request.getDescription())
                .permissionKey(request.getPermissionKey())
                .resourceType(request.getResourceType())
                .scopeId(request.getScopeId())
                .effect(request.getEffect())
                .priority(request.getPriority())
                .conditions(request.getConditions())
                .active(request.getActive())
                .build();

        return ResponseEntity.ok(policyService.update(id, updated));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deactivatePolicy(@PathVariable UUID id) {
        policyService.deactivate(id);
        return ResponseEntity.ok().build();
    }
}
