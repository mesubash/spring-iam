package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.DenyRule;
import io.github.mesubash.iam.authz.dto.CreateDenyRuleRequest;
import io.github.mesubash.iam.authz.service.DenyRuleService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/deny-rules")
@RequiredArgsConstructor
@Tag(name = "Deny Rules", description = "Deny rule management")
public class DenyRuleController {

    private final DenyRuleService denyRuleService;

    @GetMapping
    public ResponseEntity<List<DenyRule>> getDenyRules(
            @RequestParam(required = false) String subjectId) {

        if (subjectId != null) {
            List<DenyRule> rules = denyRuleService.getBySubjectId(subjectId);
            return ResponseEntity.ok(rules);
        }

        return ResponseEntity.ok(List.of());
    }

    @PostMapping
    public ResponseEntity<DenyRule> createDenyRule(
            @AuthenticationPrincipal UserPrincipal caller,
            @Valid @RequestBody CreateDenyRuleRequest request) {

        DenyRule denyRule = denyRuleService.create(
                caller,
                request.getSubjectId(),
                request.getPermissionKey(),
                request.getScopeId(),
                request.getReason(),
                request.getReferenceId(),
                request.getExpiresAt()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(denyRule);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> removeDenyRule(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id) {
        denyRuleService.remove(id, caller);
        return ResponseEntity.ok().build();
    }
}
