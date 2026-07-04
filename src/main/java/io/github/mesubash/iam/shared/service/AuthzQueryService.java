package io.github.mesubash.iam.shared.service;

import io.github.mesubash.iam.shared.dto.AuthorizationRequestDto;
import io.github.mesubash.iam.shared.dto.AuthorizationResultDto;
import io.github.mesubash.iam.shared.dto.RoleClaimsDto;
import io.github.mesubash.iam.shared.dto.ScopeSummaryDto;

import java.util.List;
import java.util.UUID;

public interface AuthzQueryService {

    AuthorizationResultDto authorize(AuthorizationRequestDto request);

    RoleClaimsDto getRolesForIdentity(UUID identityId);

    List<String> getEffectivePermissions(UUID identityId, UUID scopeId);

    List<ScopeSummaryDto> getScopesForIdentity(UUID identityId);
}
