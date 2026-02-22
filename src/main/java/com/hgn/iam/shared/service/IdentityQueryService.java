package com.hgn.iam.shared.service;

import com.hgn.iam.shared.dto.IdentitySummaryDto;

import java.util.Optional;
import java.util.UUID;

public interface IdentityQueryService {

    Optional<IdentitySummaryDto> getIdentitySummary(UUID identityId);

    boolean isAccountActive(UUID identityId);
}
