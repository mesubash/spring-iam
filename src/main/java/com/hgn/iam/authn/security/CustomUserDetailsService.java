package com.hgn.iam.authn.security;

import com.hgn.iam.authn.entity.Credential;
import com.hgn.iam.authn.entity.Identity;
import com.hgn.iam.authn.entity.enums.CredentialType;
import com.hgn.iam.authn.repository.CredentialRepository;
import com.hgn.iam.authn.repository.IdentityRepository;
import com.hgn.iam.shared.dto.RoleClaimsDto;
import com.hgn.iam.shared.exception.EmailNotVerifiedException;
import com.hgn.iam.shared.service.AuthzQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final IdentityRepository identityRepository;
    private final CredentialRepository credentialRepository;
    private final AuthzQueryService authzQueryService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        if (!Boolean.TRUE.equals(identity.getEmailVerified())) {
            throw new EmailNotVerifiedException("Your email is not verified yet. Please verify your email first.");
        }

        // Get password credential
        Credential passwordCredential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElse(null);

        String passwordHash = passwordCredential != null ? passwordCredential.getSecretHash() : null;

        // Get roles from AuthZ module
        List<String> roles = getRolesForIdentity(identity.getId());

        return UserPrincipal.create(identity, passwordHash, roles);
    }

    @Transactional(readOnly = true)
    public UserDetails loadUserById(UUID identityId) throws UsernameNotFoundException {
        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + identityId));

        Credential passwordCredential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElse(null);

        String passwordHash = passwordCredential != null ? passwordCredential.getSecretHash() : null;

        List<String> roles = getRolesForIdentity(identity.getId());

        return UserPrincipal.create(identity, passwordHash, roles);
    }

    private List<String> getRolesForIdentity(UUID identityId) {
        try {
            RoleClaimsDto roleClaims = authzQueryService.getRolesForIdentity(identityId);
            return roleClaims != null && roleClaims.getRoles() != null ? roleClaims.getRoles() : List.of();
        } catch (Exception e) {
            // If AuthZ is not available, return empty roles
            return List.of();
        }
    }
}
