package io.github.mesubash.iam.authn.security;

import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.oauth2.OAuth2UserInfo;
import io.github.mesubash.iam.authn.security.oauth2.OAuth2UserInfoFactory;
import io.github.mesubash.iam.shared.dto.RoleClaimsDto;
import io.github.mesubash.iam.shared.service.AuthzQueryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Optional;

@Slf4j
@ConditionalOnProperty(prefix = "iam.features", name = "oauth2", havingValue = "true")
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final IdentityRepository identityRepository;
    private final CredentialRepository credentialRepository;
    private final AuthzQueryService authzQueryService;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (Exception ex) {
            log.error("Error processing OAuth2 user", ex);
            throw new OAuth2AuthenticationException(ex.getMessage() != null ? ex.getMessage() : "Unknown OAuth2 error");
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId, oAuth2User.getAttributes());

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

        CredentialType credentialType = CredentialType.valueOf(registrationId.toUpperCase());

        Optional<Identity> identityOptional = identityRepository.findByPrimaryEmail(oAuth2UserInfo.getEmail());
        Identity identity;

        if (identityOptional.isPresent()) {
            identity = identityOptional.get();

            Optional<Credential> existingCredential = credentialRepository
                    .findByIdentityIdAndCredentialType(identity.getId(), credentialType);

            if (existingCredential.isEmpty()) {
                // Auto-link only when the provider asserts the email as verified —
                // otherwise an attacker registering the victim's email at a lax
                // provider would inherit the victim's identity.
                if (!oAuth2UserInfo.isEmailVerified()) {
                    throw new OAuth2AuthenticationException(
                            "account_exists: sign in with your password, then link this provider");
                }
                Credential credential = Credential.builder()
                        .identity(identity)
                        .credentialType(credentialType)
                        .identifier(oAuth2UserInfo.getId())
                        .build();
                credentialRepository.save(credential);
                log.info("Linked {} credential to identity {}", credentialType, identity.getId());
            }

            if (!Boolean.TRUE.equals(identity.getEmailVerified()) && oAuth2UserInfo.isEmailVerified()) {
                identity.setEmailVerified(true);
                identityRepository.save(identity);
            }
        } else {
            identity = registerNewOAuthUser(credentialType, oAuth2UserInfo);
        }

        // Get roles from AuthZ
        List<String> roles = getRolesForIdentity(identity);

        return UserPrincipal.create(identity, null, roles, oAuth2User.getAttributes());
    }

    private Identity registerNewOAuthUser(CredentialType credentialType, OAuth2UserInfo oAuth2UserInfo) {
        Identity identity = Identity.builder()
                .primaryEmail(oAuth2UserInfo.getEmail())
                .emailVerified(oAuth2UserInfo.isEmailVerified())
                .accountStatus(AccountStatus.ACTIVE)
                .build();
        identity = identityRepository.save(identity);

        Credential credential = Credential.builder()
                .identity(identity)
                .credentialType(credentialType)
                .identifier(oAuth2UserInfo.getId())
                .build();
        credentialRepository.save(credential);

        return identity;
    }

    private List<String> getRolesForIdentity(Identity identity) {
        try {
            RoleClaimsDto roleClaims = authzQueryService.getRolesForIdentity(identity.getId());
            return roleClaims != null && roleClaims.getRoles() != null ? roleClaims.getRoles() : List.of();
        } catch (Exception e) {
            return List.of();
        }
    }
}
