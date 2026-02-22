package com.hgn.iam.authn.security;

import com.hgn.iam.authn.security.token.TokenService;
import com.hgn.iam.shared.exception.InvalidTokenException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService customUserDetailsService;
    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Skip if already authenticated (by ApiKeyAuthFilter or service-to-service JwtAuthFilter)
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt)) {
                try {
                    if (jwtTokenProvider.validateToken(jwt)) {
                        if (tokenService.isTokenBlacklisted(jwt)) {
                            log.warn("Rejected blacklisted token for path: {}", request.getRequestURI());
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                            return;
                        }

                        String userIdStr = jwtTokenProvider.getUserIdFromToken(jwt);
                        UUID userId = UUID.fromString(userIdStr);

                        UserDetails userDetails = customUserDetailsService.loadUserById(userId);

                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        log.debug("Set authentication for user ID: {}", userId);
                    }
                } catch (InvalidTokenException ex) {
                    log.debug("Invalid token for path {}: {}", request.getRequestURI(), ex.getMessage());
                } catch (Exception ex) {
                    log.debug("JWT validation failed for path {}: {}", request.getRequestURI(), ex.getMessage());
                }
            }
        } catch (Exception ex) {
            log.warn("Unexpected error in JWT filter for path {}: {}", request.getRequestURI(), ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/oauth2/") ||
               path.startsWith("/api/oauth2/") ||
               path.startsWith("/login/oauth2/") ||
               path.startsWith("/api/login/oauth2/") ||
               path.startsWith("/api/auth/register") ||
               path.startsWith("/api/auth/login") ||
               path.startsWith("/api/auth/refresh") ||
               path.startsWith("/api/auth/verify-email") ||
               path.startsWith("/api/auth/forgot-password") ||
               path.startsWith("/api/auth/reset-password") ||
               path.startsWith("/api/auth/resend-verification") ||
               path.equals("/") ||
               path.equals("/health") ||
               path.startsWith("/actuator") ||
               path.endsWith(".html") ||
               path.endsWith(".css") ||
               path.endsWith(".js") ||
               path.endsWith(".ico") ||
               path.startsWith("/swagger-ui") ||
               path.startsWith("/api-docs") ||
               path.startsWith("/v3/api-docs");
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
