package com.hgn.iam.authz.service;

import com.hgn.iam.authz.dto.AuthorizationRequest;
import com.hgn.iam.authz.dto.AuthorizationResponse;
import com.hgn.iam.authz.entity.Assignment;
import com.hgn.iam.authz.entity.Role;
import com.hgn.iam.authz.entity.Scope;
import com.hgn.iam.authz.repository.AssignmentRepository;
import com.hgn.iam.authz.repository.RoleRepository;
import com.hgn.iam.authz.repository.ScopeRepository;
import com.hgn.iam.shared.dto.AuthorizationRequestDto;
import com.hgn.iam.shared.dto.AuthorizationResultDto;
import com.hgn.iam.shared.dto.RoleClaimsDto;
import com.hgn.iam.shared.dto.ScopeSummaryDto;
import com.hgn.iam.shared.service.AuthzQueryService;
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

        Set<UUID> roleIds = assignments.stream()
                .map(Assignment::getRoleId)
                .collect(Collectors.toSet());

        List<String> roleNames = roleRepository.findAllById(roleIds).stream()
                .filter(Role::getActive)
                .map(Role::getName)
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
        var request = com.hgn.iam.authz.dto.EffectivePermissionsRequest.builder()
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
