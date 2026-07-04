package io.github.mesubash.iam.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
import java.util.Set;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String RATE_LIMIT_PREFIX = "rate_limit:";

    private static final Set<String> RATE_LIMITED_PATHS = Set.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/resend-verification",
            "/api/auth/request-reactivation"
    );

    private final StringRedisTemplate redisTemplate;

    @Value("${iam.rate-limit.max-requests:10}")
    private int maxRequests;

    @Value("${iam.rate-limit.window-seconds:60}")
    private int windowSeconds;

    // open = allow when Redis is down (availability) | closed = reject (strict)
    @Value("${iam.rate-limit.fail-mode:open}")
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

        String clientIp = getClientIp(request);
        String key = RATE_LIMIT_PREFIX + path + ":" + clientIp;

        try {
            Long count = redisTemplate.opsForValue().increment(key);
            if (count != null && count == 1) {
                redisTemplate.expire(key, windowSeconds, TimeUnit.SECONDS);
            }

            if (count != null && count > maxRequests) {
                Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.setHeader("Retry-After", String.valueOf(ttl != null ? ttl : windowSeconds));
                response.setHeader("X-RateLimit-Limit", String.valueOf(maxRequests));
                response.setHeader("X-RateLimit-Remaining", "0");
                response.setHeader("X-RateLimit-Retry-After-Seconds", String.valueOf(ttl != null ? ttl : windowSeconds));
                response.getWriter().write(
                        "{\"success\":false,\"message\":\"Too many requests. Please try again later.\"}");
                return;
            }

            long remaining = maxRequests - (count != null ? count : 0);
            response.setHeader("X-RateLimit-Limit", String.valueOf(maxRequests));
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

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
