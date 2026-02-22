package com.hgn.iam.shared.service;

import com.hgn.iam.shared.dto.AuthorizationRequestDto;
import com.hgn.iam.shared.dto.AuthorizationResultDto;
import com.hgn.iam.shared.dto.RoleClaimsDto;
import com.hgn.iam.shared.dto.ScopeSummaryDto;

import java.util.List;
import java.util.UUID;

public interface AuthzQueryService {

    AuthorizationResultDto authorize(AuthorizationRequestDto request);

    RoleClaimsDto getRolesForIdentity(UUID identityId);

    List<String> getEffectivePermissions(UUID identityId, UUID scopeId);

    List<ScopeSummaryDto> getScopesForIdentity(UUID identityId);
}
