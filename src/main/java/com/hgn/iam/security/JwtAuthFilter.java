package com.hgn.iam.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    @Value("${iam.security.jwt.secret:}")
    private String jwtSecret;

    @Value("${iam.security.jwt.issuer:}")
    private String issuer;

    @Value("${iam.security.jwt.audience:}")
    private String audience;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        if (jwtSecret == null || jwtSecret.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (issuer != null && !issuer.isBlank() && !issuer.equals(claims.getIssuer())) {
                log.warn("JWT issuer mismatch: expected={}, actual={}", issuer, claims.getIssuer());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            if (audience != null && !audience.isBlank()) {
                Object aud = claims.get("aud");
                if (!audienceMatches(aud)) {
                    log.warn("JWT audience mismatch: expected={}, actual={}", audience, aud);
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            }

            String subject = claims.getSubject();
            Collection<SimpleGrantedAuthority> authorities = extractAuthorities(claims);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(subject, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private Collection<SimpleGrantedAuthority> extractAuthorities(Claims claims) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        Object roles = claims.get("roles");
        if (roles instanceof List<?> list) {
            for (Object role : list) {
                addAuthority(authorities, role);
            }
        } else if (roles instanceof String roleString) {
            for (String role : roleString.split(",")) {
                addAuthority(authorities, role.trim());
            }
        }

        Object scope = claims.get("scope");
        if (scope instanceof String scopeString) {
            for (String role : scopeString.split(" ")) {
                addAuthority(authorities, role.trim());
            }
        }

        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return authorities;
    }

    private void addAuthority(List<SimpleGrantedAuthority> authorities, Object roleObj) {
        if (roleObj == null) {
            return;
        }
        String role = roleObj.toString().trim();
        if (role.isEmpty()) {
            return;
        }
        if (!role.startsWith("ROLE_")) {
            role = "ROLE_" + role;
        }
        authorities.add(new SimpleGrantedAuthority(role));
    }

    private boolean audienceMatches(Object audClaim) {
        if (audience == null || audience.isBlank()) {
            return true;
        }
        if (audClaim == null) {
            return false;
        }
        if (audClaim instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (item != null && audience.equals(item.toString())) {
                    return true;
                }
            }
            return false;
        }
        return audience.equals(audClaim.toString());
    }
}
