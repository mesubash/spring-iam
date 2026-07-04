package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authz.entity.ContextAttribute;
import io.github.mesubash.iam.authz.repository.ContextAttributeRepository;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/context-attributes")
@RequiredArgsConstructor
@Tag(name = "Context Attributes", description = "Policy vocabulary registry")
public class ContextAttributeController {

    private final ContextAttributeRepository repository;

    @GetMapping
    @PreAuthorize("hasAnyRole('SuperAdmin','AccessAdmin')")
    public ResponseEntity<List<ContextAttribute>> list() {
        return ResponseEntity.ok(repository.findAll());
    }

    @PostMapping
    @PreAuthorize("hasRole('SuperAdmin')")
    public ResponseEntity<ContextAttribute> create(@Valid @RequestBody CreateRequest request) {
        ContextAttribute saved = repository.save(ContextAttribute.builder()
                .name(request.getName())
                .valueType(request.getValueType() != null ? request.getValueType() : "STRING")
                .description(request.getDescription())
                .createdAt(Instant.now())
                .build());
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('SuperAdmin')")
    public ResponseEntity<Void> delete(@PathVariable UUID id) {
        repository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    @Data
    public static class CreateRequest {
        @NotBlank
        private String name;
        private String valueType;
        private String description;
    }
}
