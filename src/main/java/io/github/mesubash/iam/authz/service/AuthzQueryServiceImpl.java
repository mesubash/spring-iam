package io.github.mesubash.iam.authz.service;

import io.github.mesubash.iam.authz.dto.AuthorizationRequest;
import io.github.mesubash.iam.authz.dto.AuthorizationResponse;
import io.github.mesubash.iam.authz.entity.Assignment;
import io.github.mesubash.iam.authz.entity.Role;
import io.github.mesubash.iam.authz.entity.Scope;
import io.github.mesubash.iam.authz.repository.AssignmentRepository;
import io.github.mesubash.iam.authz.repository.RoleRepository;
import io.github.mesubash.iam.authz.repository.ScopeRepository;
import io.github.mesubash.iam.shared.dto.AuthorizationRequestDto;
import io.github.mesubash.iam.shared.dto.AuthorizationResultDto;
import io.github.mesubash.iam.shared.dto.RoleClaimsDto;
import io.github.mesubash.iam.shared.dto.ScopeSummaryDto;
import io.github.mesubash.iam.shared.service.AuthzQueryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthzQueryServiceImpl implements AuthzQueryService {

    private static final UUID ROOT_SCOPE = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SUPER_ADMIN_ROLE = UUID.fromString("10000000-0000-0000-0000-000000000001");

    private final AssignmentRepository assignmentRepository;
    private final RoleRepository roleRepository;
    private final ScopeRepository scopeRepository;
    private final AuthorizationService authorizationService;

    @Override
    @Transactional(readOnly = true)
    public AuthorizationResultDto authorize(AuthorizationRequestDto request) {
        AuthorizationRequest authzRequest = AuthorizationRequest.builder()
                .subject(request.getSubjectId().toString())
                .permission(request.getPermissionKey())
                .resource(AuthorizationRequest.ResourceContext.builder()
                        .scopeId(request.getScopeId())
                        .type(request.getResourceType())
                        .id(request.getResourceId())
                        .build())
                .context(request.getContext() != null
                        ? AuthorizationRequest.RequestContext.builder()
                            .additionalContext(request.getContext())
                            .build()
                        : null)
                .build();

        AuthorizationResponse response = authorizationService.authorize(authzRequest);

        return AuthorizationResultDto.builder()
                .authorized(Boolean.TRUE.equals(response.getAuthorized()))
                .reason(response.getReason())
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public RoleClaimsDto getRolesForIdentity(UUID identityId) {
        String subjectId = identityId.toString();

        List<Assignment> assignments = assignmentRepository.findActiveAssignments(
                subjectId, Instant.now());

        if (assignments.isEmpty()) {
            return RoleClaimsDto.builder()
                    .roles(List.of())
                    .build();
        }

        // SuperAdmin only counts where it was meant to live: at ROOT. Assigned anywhere else it
        // would still become a global ROLE_SuperAdmin authority.
        Set<UUID> roleIds = assignments.stream()
                .filter(a -> !SUPER_ADMIN_ROLE.equals(a.getRoleId()) || ROOT_SCOPE.equals(a.getScopeId()))
                .map(Assignment::getRoleId)
                .collect(Collectors.toSet());

        // Role names become Spring authorities (ROLE_<name>) that @PreAuthorize trusts, but names
        // are only unique per owner scope. A tenant role named like a built-in one ("SuperAdmin",
        // "SecurityAdmin", ...) would otherwise pass every check gated on the built-in role.
        List<Role> held = roleRepository.findAllById(roleIds);
        Set<String> globalNames = roleRepository.findByOwnerScopeIdIsNull().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());
        List<String> roleNames = held.stream()
                .filter(Role::getActive)
                .filter(r -> r.getOwnerScopeId() == null || !globalNames.contains(r.getName()))
                .map(Role::getName)
                .distinct()
                .collect(Collectors.toList());

        // Use the first assignment's scope as primary scope
        UUID primaryScope = assignments.get(0).getScopeId();

        return RoleClaimsDto.builder()
                .roles(roleNames)
                .primaryScope(primaryScope)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> getEffectivePermissions(UUID identityId, UUID scopeId) {
        var request = io.github.mesubash.iam.authz.dto.EffectivePermissionsRequest.builder()
                .subject(identityId.toString())
                .scopeId(scopeId)
                .build();

        var response = authorizationService.getEffectivePermissions(request);
        return List.copyOf(response.getPermissions());
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScopeSummaryDto> getScopesForIdentity(UUID identityId) {
        String subjectId = identityId.toString();

        List<Assignment> assignments = assignmentRepository.findActiveAssignments(
                subjectId, Instant.now());

        if (assignments.isEmpty()) {
            return List.of();
        }

        Set<UUID> scopeIds = assignments.stream()
                .map(Assignment::getScopeId)
                .collect(Collectors.toSet());

        return scopeRepository.findAllById(scopeIds).stream()
                .filter(Scope::getActive)
                .map(scope -> ScopeSummaryDto.builder()
                        .id(scope.getId())
                        .type(scope.getType())
                        .name(scope.getName())
                        .code(scope.getCode())
                        .build())
                .collect(Collectors.toList());
    }
}
