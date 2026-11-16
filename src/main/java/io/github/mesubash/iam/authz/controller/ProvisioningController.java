package io.github.mesubash.iam.authz.controller;

import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.authz.service.AssignmentService;
import io.github.mesubash.iam.shared.exception.ForbiddenException;
import io.github.mesubash.iam.shared.exception.ResourceNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Grant/revoke API for a resource server that reconciles its own users into IAM roles. Grants
 * made here carry origin PROVISIONED, and only those are listed or revocable, so a reconciler can
 * diff against exactly what it owns and never touches grants an administrator made.
 *
 * <p>The writes run as a SuperAdmin-equivalent principal (a service has no identity to delegate
 * from), and the class is reachable with ROLE_INTERNAL, which every API key gets. Without a
 * hard floor any key holder could grant itself platform administration, and the delegation
 * check cannot help because SuperAdmin bypasses it. So grants at ROOT and grants of system roles
 * (SuperAdmin and the other built-in administrator roles) are refused outright, both ways.
 */
@RestController
@RequestMapping("/api/v1/internal/provisioning")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('INTERNAL', 'SuperAdmin')")
@Tag(name = "Internal provisioning", description = "Role grants for resource servers (API key)")
public class ProvisioningController {

    private static final String ORIGIN = "PROVISIONED";
    private static final UUID ROOT_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SUPER_ADMIN_ROLE = UUID.fromString("10000000-0000-0000-0000-000000000001");

    private static final UserPrincipal SYSTEM = UserPrincipal.create(
            Identity.builder().id(new UUID(0, 0)).primaryEmail("system").build(), null, List.of("SuperAdmin"));

    private final AssignmentService assignmentService;
    private final AssignmentRepository assignmentRepository;
    private final RoleRepository roleRepository;

    public record Grant(String subjectId, UUID roleId, UUID scopeId) {}

    public record ProvisionedGrant(UUID assignmentId, String subjectId, UUID roleId, UUID scopeId) {}

    /** Idempotent: an existing active grant is left alone. */
    @PostMapping("/grants")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    @Operation(summary = "Grant a role (never at ROOT, never a system role)")
    public void grant(@RequestBody Grant req, Authentication caller) {
        refusePlatformEscalation(req.roleId(), req.scopeId());
        var existing = assignmentRepository.findBySubjectRoleScope(req.subjectId(), req.roleId(), req.scopeId());
        if (existing.isPresent() && Boolean.TRUE.equals(existing.get().getActive())) {
            return;
        }
        Assignment created = assignmentService.create(SYSTEM, req.subjectId(), "USER",
                req.roleId(), req.scopeId(), null, null);
        created.setOrigin(ORIGIN);
        created.setGrantedBy(caller.getName());
        assignmentRepository.save(created);
    }

    @GetMapping("/grants")
    @Operation(summary = "Active grants made through this API")
    public List<ProvisionedGrant> grants() {
        return assignmentRepository.findByOriginAndActiveTrue(ORIGIN).stream()
                .map(a -> new ProvisionedGrant(a.getId(), a.getSubjectId(), a.getRoleId(), a.getScopeId()))
                .toList();
    }

    @DeleteMapping("/grants/{assignmentId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    @Operation(summary = "Revoke a grant made through this API")
    public void revoke(@PathVariable UUID assignmentId, @RequestParam(required = false) String reason,
                       Authentication caller) {
        Assignment assignment = assignmentRepository.findById(assignmentId)
                .filter(a -> ORIGIN.equals(a.getOrigin()))
                .orElseThrow(() -> new ResourceNotFoundException("No provisioned grant " + assignmentId));
        refusePlatformEscalation(assignment.getRoleId(), assignment.getScopeId());
        assignmentService.revoke(assignmentId, SYSTEM, reason).setRevokedBy(caller.getName());
    }

    private void refusePlatformEscalation(UUID roleId, UUID scopeId) {
        if (ROOT_SCOPE.equals(scopeId)) {
            throw new ForbiddenException("Provisioning cannot assign or remove roles at the ROOT scope");
        }
        if (SUPER_ADMIN_ROLE.equals(roleId)
                || roleRepository.findById(roleId).map(Role::getIsSystemRole).orElse(false)) {
            throw new ForbiddenException("Provisioning cannot assign or remove a system role");
        }
    }
}
