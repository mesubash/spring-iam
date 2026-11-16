package io.github.mesubash.iam.authn.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RedirectAllowlistTest {

    private RedirectAllowlist repo(String allowed) {
        return new RedirectAllowlist(allowed, "", "http://localhost:3000");
    }

    @Test
    void matchesWholePathSegmentsOnly() {
        var repo = repo("https://app.example.com/oauth2/redirect");
        assertThat(repo.isAllowed("https://app.example.com/oauth2/redirect")).isTrue();
        assertThat(repo.isAllowed("https://app.example.com/oauth2/redirect/web")).isTrue();
        assertThat(repo.isAllowed("https://app.example.com/oauth2/redirect-evil")).isFalse();
        assertThat(repo.isAllowed("https://app.example.com/oauth2/redirect/../../admin")).isFalse();
    }

    @Test
    void rejectsOtherHosts() {
        var repo = repo("https://app.example.com/cb");
        assertThat(repo.isAllowed("https://app.example.com.evil.test/cb")).isFalse();
        assertThat(repo.isAllowed("https://app.example.com@evil.test/cb")).isFalse();
    }

    @Test
    void customSchemeDeepLinks() {
        var repo = repo("myapp://auth/oauth2/redirect");
        assertThat(repo.isAllowed("myapp://auth/oauth2/redirect")).isTrue();
        assertThat(repo.isAllowed("otherapp://auth/oauth2/redirect")).isFalse();
    }
}
