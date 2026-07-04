package io.github.mesubash.iam.controller;

import io.github.mesubash.iam.config.FeatureFlags;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/meta")
@RequiredArgsConstructor
@Tag(name = "Meta", description = "Deployment feature discovery")
public class MetaController {

    private final FeatureFlags featureFlags;

    @GetMapping("/features")
    @Operation(summary = "Enabled features", description = "Lets clients (e.g. the admin console) hide disabled modules")
    public ResponseEntity<Map<String, Boolean>> features() {
        return ResponseEntity.ok(featureFlags.asMap());
    }
}
