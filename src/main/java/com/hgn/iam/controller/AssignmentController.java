package com.hgn.iam.controller;

import com.hgn.iam.dto.CreateAssignmentRequest;
import com.hgn.iam.entity.Assignment;
import com.hgn.iam.service.AuthorizationService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/assignments")
@RequiredArgsConstructor
@Tag(name = "Assignments", description = "Role assignment management")
public class AssignmentController {

    private final AssignmentService assignmentService;
    private final AuthorizationService authorizationService;

    @GetMapping
    public ResponseEntity<List<Assignment>> getAssignments(
            @RequestParam(required = false) String subjectId) {

        List<Assignment> assignments = subjectId != null
                ? assignmentService.getBySubjectId(subjectId)
                : assignmentService.getAll();

        return ResponseEntity.ok(assignments);
    }

    @PostMapping
    public ResponseEntity<Assignment> createAssignment(
            @Valid @RequestBody CreateAssignmentRequest request) {

        Assignment assignment = assignmentService.create(
                request.getSubjectId(),
                request.getSubjectType(),
                request.getRoleId(),
                request.getScopeId(),
                request.getGrantedBy(),
                request.getExpiresAt(),
                request.getConditions()
        );

        // Invalidate cache when new assignment is created
        authorizationService.invalidateUserCache(request.getSubjectId());

        return ResponseEntity.status(HttpStatus.CREATED).body(assignment);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revokeAssignment(
            @PathVariable UUID id,
            @RequestParam String revokedBy,
            @RequestParam(required = false) String reason) {

        Assignment assignment = assignmentService.revoke(id, revokedBy, reason);

        // Invalidate cache when assignment is revoked
        authorizationService.invalidateUserCache(assignment.getSubjectId());

        return ResponseEntity.ok().build();
    }
}
