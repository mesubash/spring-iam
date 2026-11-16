package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.dto.CreateAssignmentRequest;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.service.AuthorizationService;
import io.github.mesubash.iam.authz.service.AssignmentService;
import io.github.mesubash.iam.shared.dto.PageResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/assignments")
@RequiredArgsConstructor
@Tag(name = "Assignments", description = "Role assignment management")
public class AssignmentController {

    private final AssignmentService assignmentService;
    private final AuthorizationService authorizationService;

    /**
     * Without {@code page} the full list is returned (the original shape); with it, the full
     * listing comes back as a {@link PageResponse}, newest grant first. A subject's own list is
     * small and is never paged.
     */
    @GetMapping
    public ResponseEntity<?> getAssignments(
            @RequestParam(required = false) String subjectId,
            @RequestParam(required = false) Integer page,
            @RequestParam(defaultValue = "50") int size) {

        if (subjectId != null) {
            return ResponseEntity.ok(assignmentService.getBySubjectId(subjectId));
        }
        if (page != null) {
            PageRequest pageable = PageRequest.of(Math.max(0, page), Math.clamp(size, 1, 200),
                    Sort.by("grantedAt").descending());
            return ResponseEntity.ok(PageResponse.of(assignmentService.getAll(pageable)));
        }
        return ResponseEntity.ok(assignmentService.getAll());
    }

    @PostMapping
    public ResponseEntity<Assignment> createAssignment(
            @AuthenticationPrincipal UserPrincipal caller,
            @Valid @RequestBody CreateAssignmentRequest request) {

        Assignment assignment = assignmentService.create(
                caller,
                request.getSubjectId(),
                request.getSubjectType(),
                request.getRoleId(),
                request.getScopeId(),
                request.getExpiresAt(),
                request.getConditions()
        );

        // Invalidate cache when new assignment is created
        authorizationService.invalidateUserCache(request.getSubjectId());

        return ResponseEntity.status(HttpStatus.CREATED).body(assignment);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> revokeAssignment(
            @AuthenticationPrincipal UserPrincipal caller,
            @PathVariable UUID id,
            @RequestParam(required = false) String reason) {

        Assignment assignment = assignmentService.revoke(id, caller, reason);

        // Invalidate cache when assignment is revoked
        authorizationService.invalidateUserCache(assignment.getSubjectId());

        return ResponseEntity.ok().build();
    }
}
