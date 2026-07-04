package io.github.mesubash.iam.authn.security.oauth2;

import java.util.Map;

/**
 * Fallback OAuth2 user info mapper for providers that expose GitHub-like fields
 * (id/name/email/avatar_url). Currently used for Apple placeholder support.
 */
public class SimpleOAuth2UserInfo extends OAuth2UserInfo {

    public SimpleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        Object id = attributes.get("id");
        return id != null ? id.toString() : null;
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
