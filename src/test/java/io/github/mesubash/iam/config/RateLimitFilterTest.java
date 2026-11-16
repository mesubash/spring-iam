package io.github.mesubash.iam.config;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** /refresh is limited per session at its own cap; other auth endpoints per IP. */
class RateLimitFilterTest {

    private final Map<String, Long> counters = new HashMap<>();
    private final RateLimitFilter filter;

    @SuppressWarnings("unchecked")
    RateLimitFilterTest() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        when(ops.increment(anyString())).thenAnswer(inv -> counters.merge(inv.getArgument(0), 1L, Long::sum));
        filter = new RateLimitFilter(redis);
        ReflectionTestUtils.setField(filter, "maxRequests", 2);
        ReflectionTestUtils.setField(filter, "refreshMaxRequests", 3);
        ReflectionTestUtils.setField(filter, "refreshCookieName", "__Host-Refresh");
        ReflectionTestUtils.setField(filter, "windowSeconds", 60);
        ReflectionTestUtils.setField(filter, "failMode", "closed");
    }

    private int call(String path, String cookie) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setRemoteAddr("203.0.113.9");
        if (cookie != null) request.setCookies(new Cookie("__Host-Refresh", cookie));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response.getStatus();
    }

    @Test
    void refreshIsCappedPerSessionNotPerIp() throws Exception {
        for (int i = 0; i < 3; i++) assertThat(call("/api/auth/refresh", "session-a")).isEqualTo(200);
        assertThat(call("/api/auth/refresh", "session-a")).isEqualTo(429);

        // Same IP, another session: its own budget.
        assertThat(call("/api/auth/refresh", "session-b")).isEqualTo(200);
        assertThat(counters.keySet()).noneMatch(k -> k.contains("session-a"));
    }

    @Test
    void cookielessRefreshAndOtherEndpointsAreCappedPerIp() throws Exception {
        for (int i = 0; i < 3; i++) assertThat(call("/api/auth/refresh", null)).isEqualTo(200);
        assertThat(call("/api/auth/refresh", null)).isEqualTo(429);

        for (int i = 0; i < 2; i++) assertThat(call("/api/auth/login", "session-a")).isEqualTo(200);
        assertThat(call("/api/auth/login", "session-c")).isEqualTo(429);
    }
}
