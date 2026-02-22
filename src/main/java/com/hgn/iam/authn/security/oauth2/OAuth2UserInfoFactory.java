package com.hgn.iam.authn.security.oauth2;

import com.hgn.iam.authn.entity.enums.CredentialType;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(CredentialType.GOOGLE.name())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(CredentialType.APPLE.name())) {
            return new SimpleOAuth2UserInfo(attributes);
        } else {
            throw new IllegalArgumentException("Login with " + registrationId + " is not supported yet.");
        }
    }
}
