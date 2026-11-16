package io.github.mesubash.iam.config;

import io.github.mesubash.iam.util.ClientIpResolver;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String RATE_LIMIT_PREFIX = "rate_limit:";

    // Refresh is frequent and self-protecting (opaque 256-bit token, rotation, reuse detection),
    // so it gets a looser cap keyed per session: a per-IP cap would be shared by everyone behind
    // one NAT and burn out on multi-tab clients.
    static final String REFRESH_PATH = "/api/auth/refresh";

    private static final Set<String> RATE_LIMITED_PATHS = Set.of(
            "/api/auth/login",
            // Every code-checking MFA call: without these a stolen session could brute-force the
            // 6-digit TOTP to strip MFA off the account.
            "/api/auth/mfa/verify",
            "/api/auth/mfa/setup",
            "/api/auth/mfa/enable",
            "/api/auth/mfa/disable",
            "/api/auth/mfa/recovery-codes",
            "/api/auth/register",
            REFRESH_PATH,
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/resend-verification",
            "/api/auth/request-reactivation"
    );

    private final StringRedisTemplate redisTemplate;

    @Value("${iam.rate-limit.max-requests:10}")
    private int maxRequests;

    @Value("${iam.rate-limit.refresh-max-requests:60}")
    private int refreshMaxRequests;

    @Value("${app.jwt.refresh-token-cookie-name:__Host-Refresh}")
    private String refreshCookieName;

    @Value("${iam.rate-limit.window-seconds:60}")
    private int windowSeconds;

    // open = allow when Redis is down (availability) | closed = reject (strict)
    @Value("${iam.rate-limit.fail-mode:closed}")
    private String failMode;

    public RateLimitFilter(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();

        if (!RATE_LIMITED_PATHS.contains(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        boolean refresh = REFRESH_PATH.equals(path);
        int limit = refresh ? refreshMaxRequests : maxRequests;
        String key = RATE_LIMIT_PREFIX + path + ":" + (refresh ? refreshKey(request) : ClientIpResolver.resolve(request));

        try {
            Long count = redisTemplate.opsForValue().increment(key);
            if (count != null && count == 1) {
                redisTemplate.expire(key, windowSeconds, TimeUnit.SECONDS);
            }

            if (count != null && count > limit) {
                Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.setHeader("Retry-After", String.valueOf(ttl != null ? ttl : windowSeconds));
                response.setHeader("X-RateLimit-Limit", String.valueOf(limit));
                response.setHeader("X-RateLimit-Remaining", "0");
                response.setHeader("X-RateLimit-Retry-After-Seconds", String.valueOf(ttl != null ? ttl : windowSeconds));
                response.getWriter().write(
                        "{\"success\":false,\"message\":\"Too many requests. Please try again later.\"}");
                return;
            }

            long remaining = limit - (count != null ? count : 0);
            response.setHeader("X-RateLimit-Limit", String.valueOf(limit));
            response.setHeader("X-RateLimit-Remaining", String.valueOf(Math.max(0, remaining)));
        } catch (RedisConnectionFailureException ex) {
            if ("closed".equalsIgnoreCase(failMode)) {
                log.error("Redis unavailable for rate limiting — rejecting (fail-mode=closed)");
                response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
                response.setContentType("application/json");
                response.getWriter().write(
                        "{\"success\":false,\"message\":\"Rate limiter unavailable. Please retry.\"}");
                return;
            }
            log.error("Redis unavailable for rate limiting — allowing request (fail-mode=open)");
        }

        filterChain.doFilter(request, response);
    }

    // Per session: the refresh cookie, hashed so the token never becomes a Redis key.
    // Cookieless calls fall back to the IP so they stay bounded.
    private String refreshKey(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (refreshCookieName.equals(cookie.getName()) && !cookie.getValue().isEmpty()) {
                    return "sess:" + sha256(cookie.getValue());
                }
            }
        }
        return ClientIpResolver.resolve(request);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
