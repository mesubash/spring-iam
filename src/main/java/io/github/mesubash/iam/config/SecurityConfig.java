package io.github.mesubash.iam.config;

import io.github.mesubash.iam.authn.security.CustomOAuth2UserService;
import io.github.mesubash.iam.authn.security.CustomUserDetailsService;
import io.github.mesubash.iam.authn.security.JwtAuthenticationEntryPoint;
import io.github.mesubash.iam.authn.security.JwtAuthenticationFilter;
import io.github.mesubash.iam.authn.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import io.github.mesubash.iam.authn.security.oauth2.OAuth2AuthenticationFailureHandler;
import io.github.mesubash.iam.authn.security.oauth2.OAuth2AuthenticationSuccessHandler;
import io.github.mesubash.iam.shared.security.ApiKeyAuthFilter;
import io.github.mesubash.iam.shared.security.JwtAuthFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    // AuthN components
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;


    // OAuth2 — present only when iam.features.oauth2=true
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private CustomOAuth2UserService customOAuth2UserService;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    // AuthZ components
    private final ApiKeyAuthFilter apiKeyAuthFilter;
    private final JwtAuthFilter jwtAuthFilter;

    // Infrastructure
    private final RateLimitFilter rateLimitFilter;

    @Value("${cors.allowed-origins:http://localhost:3000,http://localhost:5173,http://localhost:8080}")
    private String allowedOrigins;

    @Value("${cors.allowed-methods:GET,POST,PUT,PATCH,DELETE,OPTIONS}")
    private String allowedMethods;

    @Value("${cors.allowed-headers:*}")
    private String allowedHeaders;

    @Value("${cors.allow-credentials:true}")
    private boolean allowCredentials;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    private DaoAuthenticationProvider buildAuthenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(buildAuthenticationProvider());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(exception -> exception.authenticationEntryPoint(jwtAuthenticationEntryPoint))
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .headers(headers -> headers
                    .frameOptions(frame -> frame.deny())
                    .contentTypeOptions(contentType -> contentType.disable())
                    .xssProtection(xss -> xss.disable())
                    .contentSecurityPolicy(csp -> csp
                        .policyDirectives(
                            "default-src 'self'; " +
                            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                            "style-src 'self' 'unsafe-inline'; " +
                            "img-src 'self' data: https: blob:; " +
                            "font-src 'self' data:; " +
                            "connect-src 'self'; " +
                            "frame-ancestors 'none';"
                        )
                    )
                    .httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                    )
                )
                .authorizeHttpRequests(authz -> authz
                        // Public - docs, health, static, JWKS
                        .requestMatchers(
                                "/",
                                "/health",
                                "/actuator/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/api-docs/**",
                                "/v3/api-docs/**",
                                "/.well-known/**",
                                "/error",
                                "/*.css", "/*.js", "/*.ico"
                        ).permitAll()

                        // AuthN public endpoints
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/refresh",
                                "/api/auth/oauth/**",
                                "/api/auth/verify-email",
                                "/api/auth/verify-email-and-setup-password",
                                "/api/auth/resend-verification",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password",
                                "/api/auth/request-reactivation",
                                "/api/auth/verify-reactivation",
                                "/api/auth/verify-email-change",
                                "/oauth2/**",
                                "/login/oauth2/**"
                        ).permitAll()

                        // Admin-facing decision tooling — method security refines the roles
                        .requestMatchers(
                                "/api/v1/authorize/explain",
                                "/api/v1/authorize/simulate",
                                "/api/v1/access-list"
                        ).authenticated()

                        // AuthZ runtime endpoints — API key (INTERNAL) or system JWT
                        .requestMatchers(
                                "/api/v1/authorize",
                                "/api/v1/authorize/batch",
                                "/api/v1/effective-permissions",
                                "/api/v1/filter-resources"
                        ).hasAnyRole("INTERNAL", "SuperAdmin", "CountryAdmin")

                        // Permissions, scopes, and structural data: SuperAdmin only.
                        // These are production-hardcoded and must never be created by lower hierarchy.
                        .requestMatchers(
                                "/api/v1/permissions/**",
                                "/api/v1/scopes/**",
                                "/api/v1/permission-groups/**",
                                "/api/v1/role-hierarchy/**",
                                "/api/v1/policies/**"
                        ).hasRole("SuperAdmin")

                        // Audit: senior admins and dedicated audit viewers only
                        .requestMatchers(
                                "/api/v1/audit/**"
                        ).hasAnyRole("SuperAdmin", "CountryAdmin", "AccessAdmin", "SecurityAdmin", "AuditViewer")

                        // Token introspection: internal/service callers only
                        .requestMatchers(
                                "/api/v1/token/**"
                        ).hasAnyRole("INTERNAL", "SuperAdmin")

                        // Manifest sync: the service's own API key or an admin token
                        .requestMatchers(
                                "/api/v1/services/*/permissions"
                        ).hasAnyRole("INTERNAL", "SuperAdmin")

                        // Roles, assignments, deny-rules, grants, groups, services, meta:
                        // authenticated — service layer / method security enforce the rest
                        .requestMatchers(
                                "/api/v1/roles/**",
                                "/api/v1/assignments/**",
                                "/api/v1/deny-rules/**",
                                "/api/v1/resource-grants/**",
                                "/api/v1/groups/**",
                                "/api/v1/services/**",
                                "/api/v1/break-glass/**",
                                "/api/v1/identities/**",
                                "/api/v1/meta/**"
                        ).authenticated()

                        // Everything else requires authentication
                        .anyRequest().authenticated()
                )
                ;

        // OAuth2 login only when the feature is enabled (beans present)
        if (customOAuth2UserService != null) {
            http.oauth2Login(oauth2 -> oauth2
                    .authorizationEndpoint(authorization -> authorization
                            .authorizationRequestRepository(authorizationRequestRepository)
                    )
                    .loginPage("/api/auth/oauth/login")
                    .userInfoEndpoint(userInfo -> userInfo
                            .userService(customOAuth2UserService)
                    )
                    .successHandler(oAuth2AuthenticationSuccessHandler)
                    .failureHandler(oAuth2AuthenticationFailureHandler)
            );
        }

        http.authenticationProvider(buildAuthenticationProvider());

        // Filter chain order: RateLimit → ApiKey → Service JWT → User JWT
        http.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(apiKeyAuthFilter, RateLimitFilter.class);
        http.addFilterAfter(jwtAuthFilter, ApiKeyAuthFilter.class);
        http.addFilterAfter(jwtAuthenticationFilter, JwtAuthFilter.class);

        return http.build();
    }

    @Bean
    public HttpFirewall httpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowedHttpMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"));
        return firewall;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(HttpFirewall firewall) {
        return web -> web.httpFirewall(firewall);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        List<String> originList = parseAndValidateOrigins(allowedOrigins);

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(originList);

        config.setAllowedMethods(Arrays.stream(allowedMethods.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .collect(Collectors.toList()));

        List<String> headerList = Arrays.stream(allowedHeaders.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .filter(h -> !"*".equals(h))
                .collect(Collectors.toList());

        if (headerList.isEmpty() || "*".equals(allowedHeaders.trim())) {
            headerList = List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "X-Requested-With",
                "X-Api-Key",
                "X-Internal-Api-Key"
            );
        }

        config.setAllowedHeaders(headerList);
        config.setExposedHeaders(List.of(
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Retry-After-Seconds",
            "Retry-After"
        ));
        config.setAllowCredentials(allowCredentials);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private List<String> parseAndValidateOrigins(String origins) {
        if (!StringUtils.hasText(origins)) {
            log.warn("CORS allowed-origins not configured. Using localhost defaults.");
            return List.of("http://localhost:3000", "http://localhost:8080");
        }

        return Arrays.stream(origins.split(","))
            .map(String::trim)
            .filter(origin -> {
                if (!origin.startsWith("http://") && !origin.startsWith("https://")) {
                    log.warn("Invalid CORS origin (must start with http:// or https://): {}", origin);
                    return false;
                }
                if (origin.contains("*")) {
                    log.warn("Wildcard CORS origins not allowed: {}", origin);
                    return false;
                }
                return true;
            })
            .collect(Collectors.toList());
    }
}
