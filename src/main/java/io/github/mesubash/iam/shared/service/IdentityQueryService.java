package io.github.mesubash.iam.shared.service;

import io.github.mesubash.iam.shared.dto.IdentitySummaryDto;

import java.util.Optional;
import java.util.UUID;

public interface IdentityQueryService {

    Optional<IdentitySummaryDto> getIdentitySummary(UUID identityId);

    boolean isAccountActive(UUID identityId);
}
