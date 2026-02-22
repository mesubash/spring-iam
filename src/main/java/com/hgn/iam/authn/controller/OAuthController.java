package com.hgn.iam.authn.controller;

import com.hgn.iam.shared.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth2 Controller for handling social login endpoints
 */
@Slf4j
@RestController
@RequestMapping("/api/auth/oauth")
@RequiredArgsConstructor
@Tag(name = "OAuth2 Authentication", description = "OAuth2 social login endpoints")
public class OAuthController {

    @Value("${server.port:8089}")
    private String serverPort;

    private static final List<String> SUPPORTED_PROVIDERS = List.of("google");

    /**
     * Get list of supported OAuth providers
     */
    @GetMapping("/providers")
    @Operation(summary = "Get supported OAuth providers", description = "Returns list of available OAuth providers")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getSupportedProviders() {
        Map<String, Object> response = new HashMap<>();
        response.put("providers", SUPPORTED_PROVIDERS);
        response.put("baseUrl", "http://localhost:" + serverPort);

        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("google", "/api/auth/oauth/login/google");
        response.put("endpoints", endpoints);

        return ResponseEntity.ok(ApiResponse.success("OAuth providers retrieved", response));
    }

    /**
     * Initiate Google OAuth login
     */
    @GetMapping("/login/google")
    @Operation(summary = "Initiate Google OAuth login", description = "Redirects to Google OAuth authorization. Requires a redirect URI.")
    @Parameters({
            @Parameter(
                    name = "redirectUri",
                    in = ParameterIn.QUERY,
                    required = false,
                    description = "Frontend/mobile redirect URI after OAuth completes. Must match one of app.frontend.allowed-redirect-uris " +
                            "(scheme + host [+ optional path]). Provide either redirectUri or redirectUrl.",
                    examples = {
                            @ExampleObject(name = "web", value = "https://himalayanguardian.com/oauth2/redirect"),
                            @ExampleObject(name = "mobile", value = "hgn://auth/oauth2/redirect")
                    }
            ),
            @Parameter(
                    name = "redirectUrl",
                    in = ParameterIn.QUERY,
                    required = false,
                    description = "Alternate name for redirectUri. Provide either redirectUri or redirectUrl.",
                    examples = {
                            @ExampleObject(name = "web", value = "https://himalayanguardian.com/oauth2/redirect"),
                            @ExampleObject(name = "mobile", value = "hgn://auth/oauth2/redirect")
                    }
            )
    })
    public void loginWithGoogle(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        initiateOAuthLogin("google", request, response);
    }

    /**
     * Generic OAuth login initiation
     */
    @GetMapping("/login/{provider}")
    @Operation(summary = "Initiate OAuth login", description = "Generic OAuth login endpoint for any provider. Requires a redirect URI.")
    @Parameters({
            @Parameter(
                    name = "redirectUri",
                    in = ParameterIn.QUERY,
                    required = false,
                    description = "Frontend/mobile redirect URI after OAuth completes. Must match one of app.frontend.allowed-redirect-uris " +
                            "(scheme + host [+ optional path]). Provide either redirectUri or redirectUrl.",
                    examples = {
                            @ExampleObject(name = "web", value = "https://himalayanguardian.com/oauth2/redirect"),
                            @ExampleObject(name = "mobile", value = "hgn://auth/oauth2/redirect")
                    }
            ),
            @Parameter(
                    name = "redirectUrl",
                    in = ParameterIn.QUERY,
                    required = false,
                    description = "Alternate name for redirectUri. Provide either redirectUri or redirectUrl.",
                    examples = {
                            @ExampleObject(name = "web", value = "https://himalayanguardian.com/oauth2/redirect"),
                            @ExampleObject(name = "mobile", value = "hgn://auth/oauth2/redirect")
                    }
            )
    })
    public void initiateOAuthLogin(
            @PathVariable String provider,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // Validate provider
        if (!SUPPORTED_PROVIDERS.contains(provider.toLowerCase())) {
            log.error("Invalid OAuth provider requested: {}", provider);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                "Invalid OAuth provider. Supported providers: " + SUPPORTED_PROVIDERS);
            return;
        }

        // Generate state token for CSRF protection
        String state = UUID.randomUUID().toString();

        // Store state in session
        request.getSession().setAttribute("oauth_state_" + provider, state);
        request.getSession().setAttribute("oauth_state_timestamp", System.currentTimeMillis());


        // Store referer for fallback redirect
        String referer = request.getHeader("Referer");
        if (referer != null) {
            request.getSession().setAttribute("oauth_referer", referer);
            log.debug("Stored referer: {}", referer);
        }

        // Require a redirect URI for post-authentication redirect.
        String redirectUri = request.getParameter("redirectUri");
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = request.getParameter("redirectUrl");
        }
        if (!StringUtils.hasText(redirectUri)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing redirectUri or redirectUrl");
            return;
        }

        // Persist redirect URI in session as a fallback if cookies are blocked.
        request.getSession().setAttribute("oauth_redirect_url", redirectUri);

        // Construct OAuth authorization URL
        String authUrl = "/oauth2/authorization/" + provider.toLowerCase();
        String separator = authUrl.contains("?") ? "&" : "?";
        authUrl = authUrl
                + separator
                + "redirectUri="
                + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

        log.info("Redirecting to OAuth provider: {} with state: {}", provider, state);

        // Redirect to Spring Security OAuth2 endpoint
        response.sendRedirect(authUrl);
    }

//    /**
//     * Get OAuth configuration (for frontend)
//     */
//    @GetMapping("/config")
//    @Operation(summary = "Get OAuth configuration", description = "Returns OAuth configuration for frontend")
//    public ResponseEntity<ApiResponse<Map<String, Object>>> getOAuthConfig() {
//        Map<String, Object> config = new HashMap<>();
//
//        config.put("redirectUrl", frontendOAuthRedirectUrl);
//        config.put("providers", SUPPORTED_PROVIDERS);
//
//        Map<String, String> loginUrls = new HashMap<>();
//        loginUrls.put("google", "/api/auth/oauth/login/google");
//        config.put("loginUrls", loginUrls);
//
//        return ResponseEntity.ok(ApiResponse.success("OAuth configuration retrieved", config));
//    }
}
