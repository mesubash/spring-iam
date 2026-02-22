package com.hgn.iam.authn.service;

import com.hgn.iam.authn.entity.Identity;
import com.hgn.iam.authn.entity.enums.AccountStatus;
import com.hgn.iam.authn.repository.IdentityRepository;
import com.hgn.iam.shared.dto.IdentitySummaryDto;
import com.hgn.iam.shared.service.IdentityQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class IdentityQueryServiceImpl implements IdentityQueryService {

    private final IdentityRepository identityRepository;

    @Override
    @Transactional(readOnly = true)
    public Optional<IdentitySummaryDto> getIdentitySummary(UUID identityId) {
        return identityRepository.findById(identityId)
                .map(identity -> IdentitySummaryDto.builder()
                        .id(identity.getId())
                        .email(identity.getPrimaryEmail())
                        .accountStatus(identity.getAccountStatus().name())
                        .build());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isAccountActive(UUID identityId) {
        return identityRepository.findById(identityId)
                .map(identity -> identity.getAccountStatus() == AccountStatus.ACTIVE)
                .orElse(false);
    }
}
