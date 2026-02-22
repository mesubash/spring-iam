package com.hgn.iam.authn.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final String DEFAULT_ERROR_CODE = "oauth2_error";
    private static final String DEFAULT_ERROR_MESSAGE = "OAuth2 authentication failed";
    private static final String INVALID_GRANT_CODE = "invalid_grant";
    private static final String INVALID_GRANT_MESSAGE =
            "Authorization code expired or already used. Please try again.";

    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    @Value("${app.frontend.url:https://himalayanguardian.com}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        String targetUrl = resolveRedirectUrl(request);
        if (!StringUtils.hasText(targetUrl)) {
            log.warn("Missing or invalid redirectUri/redirectUrl; refusing to redirect after OAuth2 failure.");
            cleanupOAuthState(request, response);
            sendFallbackErrorRedirect(response, "missing_redirect", "Missing or invalid redirectUri or redirectUrl");
            return;
        }

        String errorCode = DEFAULT_ERROR_CODE;
        String errorMessage = DEFAULT_ERROR_MESSAGE;

        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            OAuth2Error error = oauth2Exception.getError();
            if (error != null && StringUtils.hasText(error.getErrorCode())) {
                errorCode = error.getErrorCode();
            }
        }

        if (INVALID_GRANT_CODE.equals(errorCode)) {
            errorMessage = INVALID_GRANT_MESSAGE;
        }

        log.warn("OAuth2 authentication failed: {}", errorCode);
        log.debug("OAuth2 authentication failure details", exception);

        // Clean up session state and cookies
        cleanupOAuthState(request, response);

        String separator = targetUrl.contains("?") ? "&" : "?";
        String redirectUrl = targetUrl
                + separator
                + "error=" + URLEncoder.encode(errorCode, StandardCharsets.UTF_8)
                + "&error_description=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        response.sendRedirect(redirectUrl);
    }

    private String resolveRedirectUrl(HttpServletRequest request) {
        String redirectUrl = authorizationRequestRepository.getRedirectUriFromCookie(request);
        if (!StringUtils.hasText(redirectUrl)) {
            String sessionRedirect = (String) request.getSession().getAttribute("oauth_redirect_url");
            if (StringUtils.hasText(sessionRedirect)
                    && authorizationRequestRepository.isAllowedRedirectUri(sessionRedirect)) {
                redirectUrl = sessionRedirect;
            }
        }
        return redirectUrl;
    }

    private void cleanupOAuthState(HttpServletRequest request, HttpServletResponse response) {
        request.getSession().removeAttribute("oauth_state_google");
        request.getSession().removeAttribute("oauth_state_timestamp");
        request.getSession().removeAttribute("oauth_redirect_url");
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private void sendFallbackErrorRedirect(HttpServletResponse response, String errorCode, String errorMessage) throws IOException {
        if (StringUtils.hasText(frontendBaseUrl)) {
            String separator = frontendBaseUrl.contains("?") ? "&" : "?";
            String target = frontendBaseUrl
                + separator
                + "oauthError=" + URLEncoder.encode(errorCode, StandardCharsets.UTF_8)
                + "&error_description=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
            response.sendRedirect(target);
            return;
        }
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("""
            <html>
              <head><title>OAuth Error</title></head>
              <body>
                <h2>OAuth login failed</h2>
                <p>Missing or invalid redirect URI. Please try again from the login page.</p>
              </body>
            </html>
            """);
    }
}
