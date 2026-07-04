package io.github.mesubash.iam.shared.security;

import io.github.mesubash.iam.authz.repository.ServiceClientRepository;
import io.github.mesubash.iam.config.FeatureFlags;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private static final String API_KEY_HEADER = "X-Internal-Api-Key";
    private static final String API_KEY_PREFIX = "ApiKey ";

    private final ServiceClientRepository serviceClientRepository;
    private final FeatureFlags featureFlags;

    @Value("${iam.security.internal-api-key:}")
    private String internalApiKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        boolean singleKeyConfigured = internalApiKey != null && !internalApiKey.isBlank();
        if ((!singleKeyConfigured && !featureFlags.isServiceRegistry()) || isExcluded(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String providedKey = request.getHeader(API_KEY_HEADER);
        if (providedKey == null || providedKey.isBlank()) {
            if (authHeader != null && authHeader.startsWith(API_KEY_PREFIX)) {
                providedKey = authHeader.substring(API_KEY_PREFIX.length()).trim();
            }
        }

        // No API key provided — pass through to let other filters handle auth
        if (providedKey == null || providedKey.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String principal = null;
        if (singleKeyConfigured && timingSafeEquals(internalApiKey, providedKey)) {
            principal = "internal-client";
        } else if (featureFlags.isServiceRegistry()) {
            // Per-service keys: only the SHA-256 is stored, lookup is by hash
            principal = serviceClientRepository
                    .findByApiKeyHashAndActiveTrue(sha256(providedKey))
                    .map(service -> {
                        service.setLastSeenAt(java.time.Instant.now());
                        serviceClientRepository.save(service);
                        return "service:" + service.getName();
                    })
                    .orElse(null);
        }

        if (principal == null) {
            log.warn("Invalid API key attempt from IP: {}", request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Invalid API key\"}");
            return;
        }

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_INTERNAL")));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks on API key validation.
     */
    private boolean timingSafeEquals(String expected, String actual) {
        byte[] expectedBytes = expected.getBytes(StandardCharsets.UTF_8);
        byte[] actualBytes = actual.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(expectedBytes, actualBytes);
    }

    private boolean isExcluded(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/v1/health")
                || path.startsWith("/actuator")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/api-docs")
                || path.startsWith("/v3/api-docs");
    }
}
