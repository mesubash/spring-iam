package com.hgn.iam.authz.controller;

import com.hgn.iam.authz.dto.CreateScopeRequest;
import com.hgn.iam.authz.entity.Scope;
import com.hgn.iam.authz.service.ScopeService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/scopes")
@RequiredArgsConstructor
@Tag(name = "Scopes", description = "Scope hierarchy management")
public class ScopeController {

    private final ScopeService scopeService;

    @GetMapping
    public ResponseEntity<List<Scope>> getAllScopes(
            @RequestParam(required = false) String type) {

        List<Scope> scopes = type != null
                ? scopeService.getByType(type)
                : scopeService.getAllActive();

        return ResponseEntity.ok(scopes);
    }

    @GetMapping("/{id}")
    public ResponseEntity<Scope> getScope(@PathVariable UUID id) {
        return scopeService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/descendants")
    public ResponseEntity<List<Scope>> getDescendants(@PathVariable UUID id) {
        List<Scope> descendants = scopeService.getDescendants(id);
        return ResponseEntity.ok(descendants);
    }

    @PostMapping
    public ResponseEntity<Scope> createScope(
            @Valid @RequestBody CreateScopeRequest request) {

        Scope scope = scopeService.create(
                request.getType(),
                request.getName(),
                request.getCode(),
                request.getParentId(),
                request.getMetadata()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(scope);
    }
}
