package com.hgn.iam.controller;

import com.hgn.iam.entity.DenyRule;
import com.hgn.iam.dto.CreateDenyRuleRequest;
import com.hgn.iam.service.DenyRuleService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
            @Valid @RequestBody CreateDenyRuleRequest request) {

        DenyRule denyRule = denyRuleService.create(
                request.getSubjectId(),
                request.getPermissionKey(),
                request.getScopeId(),
                request.getReason(),
                request.getReferenceId(),
                request.getCreatedBy(),
                request.getExpiresAt()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(denyRule);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> removeDenyRule(@PathVariable UUID id) {
        denyRuleService.remove(id);
        return ResponseEntity.ok().build();
    }
}
