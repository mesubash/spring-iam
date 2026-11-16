package io.github.mesubash.iam.util;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    @Test
    void usesRightmostForwardedHopNotTheSpoofableLeftmost() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("10.0.0.1");
        req.addHeader("X-Forwarded-For", "6.6.6.6, 203.0.113.7");
        assertThat(ClientIpResolver.resolve(req)).isEqualTo("203.0.113.7");
    }

    @Test
    void fallsBackToSocketAddress() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setRemoteAddr("[2001:db8::1]");
        assertThat(ClientIpResolver.resolve(req)).isEqualTo("2001:db8::1");
    }

    @Test
    void normalizesForInetColumn() {
        assertThat(ClientIpResolver.normalize("[2001:db8::1]:443")).isEqualTo("2001:db8::1");
        assertThat(ClientIpResolver.normalize("2001:db8::1")).isEqualTo("2001:db8::1");
        assertThat(ClientIpResolver.normalize(" 1.2.3.4:5678 ")).isEqualTo("1.2.3.4");
        assertThat(ClientIpResolver.normalize("evil.example.com")).isNull();
        assertThat(ClientIpResolver.normalize("")).isNull();
        assertThat(ClientIpResolver.normalize(null)).isNull();
    }
}
