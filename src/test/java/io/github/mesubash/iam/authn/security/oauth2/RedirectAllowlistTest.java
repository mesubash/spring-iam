package io.github.mesubash.iam.authn.security.oauth2;

import io.github.mesubash.iam.authn.config.JwtConfig;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class RedirectAllowlistTest {

    private HttpCookieOAuth2AuthorizationRequestRepository repo(String allowed) {
        var repo = new HttpCookieOAuth2AuthorizationRequestRepository(new JwtConfig());
        ReflectionTestUtils.setField(repo, "allowedRedirectUris", allowed);
        return repo;
    }

    @Test
    void matchesWholePathSegmentsOnly() {
        var repo = repo("https://app.example.com/oauth2/redirect");
        assertThat(repo.isAllowedRedirectUri("https://app.example.com/oauth2/redirect")).isTrue();
        assertThat(repo.isAllowedRedirectUri("https://app.example.com/oauth2/redirect/web")).isTrue();
        assertThat(repo.isAllowedRedirectUri("https://app.example.com/oauth2/redirect-evil")).isFalse();
        assertThat(repo.isAllowedRedirectUri("https://app.example.com/oauth2/redirect/../../admin")).isFalse();
    }

    @Test
    void rejectsOtherHosts() {
        var repo = repo("https://app.example.com/cb");
        assertThat(repo.isAllowedRedirectUri("https://app.example.com.evil.test/cb")).isFalse();
        assertThat(repo.isAllowedRedirectUri("https://app.example.com@evil.test/cb")).isFalse();
    }

    @Test
    void customSchemeDeepLinks() {
        var repo = repo("myapp://auth/oauth2/redirect");
        assertThat(repo.isAllowedRedirectUri("myapp://auth/oauth2/redirect")).isTrue();
        assertThat(repo.isAllowedRedirectUri("otherapp://auth/oauth2/redirect")).isFalse();
    }
}
