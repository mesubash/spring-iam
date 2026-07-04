package io.github.mesubash.iam.authn.security.oauth2;

import io.github.mesubash.iam.authn.config.JwtConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Stores the OAuth2 authorization request in an HttpOnly cookie instead of the HTTP session.
 * This avoids {@code authorization_request_not_found} errors when callbacks hit a different
 * server instance or the browser drops the JSESSIONID cookie.
 */
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
@ConditionalOnProperty(prefix = "iam.features", name = "oauth2", havingValue = "true")
@Component
@RequiredArgsConstructor
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_COOKIE_NAME = "oauth_redirect_uri";
    public static final String REDIRECT_URI_PARAM_NAME = "redirectUri";
    public static final String REDIRECT_URL_PARAM_NAME = "redirectUrl";
    private static final int COOKIE_EXPIRE_SECONDS = 180;

    @Value("${app.auth.cookie-domain:localhost}")
    private String cookieDomain;

    @Value("${app.auth.secure-cookie:false}")
    private boolean secureCookie;

    @Value("${app.frontend.allowed-redirect-uris:}")
    private String allowedRedirectUris;

    @Value("${cors.allowed-origins:}")
    private String extraAllowedRedirectUris;

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendBaseUrl;

    private final JwtConfig jwtConfig;

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.<OAuth2AuthorizationRequest>deserializeSigned(cookie.getValue(), jwtConfig.getSecret()))
                .orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest,
            HttpServletRequest request,
            HttpServletResponse response) {

        if (authorizationRequest == null) {
            removeAuthorizationRequestCookies(request, response);
            return;
        }

        String normalizedDomain = StringUtils.hasText(cookieDomain) ? cookieDomain : null;
        CookieUtils.addCookie(
                response,
                OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                CookieUtils.serializeAndSign(authorizationRequest, jwtConfig.getSecret()),
                COOKIE_EXPIRE_SECONDS,
                secureCookie,
                normalizedDomain
        );

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_NAME);
        if (!StringUtils.hasText(redirectUriAfterLogin)) {
            redirectUriAfterLogin = request.getParameter(REDIRECT_URL_PARAM_NAME);
        }
        if (!StringUtils.hasText(redirectUriAfterLogin)) {
            redirectUriAfterLogin = (String) request.getSession().getAttribute("oauth_redirect_url");
        }

        if (StringUtils.hasText(redirectUriAfterLogin)) {
            if (!isAllowedRedirect(redirectUriAfterLogin)) {
                return;
            }
            CookieUtils.addCookie(
                    response,
                    REDIRECT_URI_COOKIE_NAME,
                    CookieUtils.signRaw(redirectUriAfterLogin, jwtConfig.getSecret()),
                    COOKIE_EXPIRE_SECONDS,
                    secureCookie,
                    normalizedDomain
            );
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
            HttpServletRequest request,
            HttpServletResponse response) {

        OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);
        removeAuthorizationRequestCookies(request, response);
        return authorizationRequest;
    }

    public void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        String normalizedDomain = StringUtils.hasText(cookieDomain) ? cookieDomain : null;
        CookieUtils.deleteCookie(
                request,
                response,
                OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME,
                secureCookie,
                normalizedDomain
        );
        CookieUtils.deleteCookie(
                request,
                response,
                REDIRECT_URI_COOKIE_NAME,
                secureCookie,
                normalizedDomain
        );
    }

    public String getRedirectUriFromCookie(HttpServletRequest request) {
        return CookieUtils.getCookie(request, REDIRECT_URI_COOKIE_NAME)
                .map(cookie -> CookieUtils.verifySignedRaw(cookie.getValue(), jwtConfig.getSecret()))
                .filter(uri -> uri != null && isAllowedRedirect(uri))
                .orElse(null);
    }

    public boolean isAllowedRedirectUri(String uri) {
        return uri != null && isAllowedRedirect(uri);
    }

    // Redirects must match the configured allowlist; with no allowlist
    // configured, only the frontend base URL's origin is accepted.
    private boolean isAllowedRedirect(String uri) {
        if (!StringUtils.hasText(uri)) {
            return false;
        }
        try {
            URI candidate = new URI(uri);
            if (!StringUtils.hasText(candidate.getScheme())) {
                return false;
            }

            List<URI> allowed = parseAllowedRedirects();
            if (allowed.isEmpty() && StringUtils.hasText(frontendBaseUrl)) {
                try {
                    allowed = List.of(new URI(frontendBaseUrl));
                } catch (URISyntaxException ignored) {
                    return false;
                }
            }

            return allowed.stream().anyMatch(a -> isMatch(candidate, a));
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private List<URI> parseAllowedRedirects() {
        List<URI> allowed = new ArrayList<>();

        // Merge both envs
        String merged =
                Stream.of(allowedRedirectUris, extraAllowedRedirectUris)
                        .filter(StringUtils::hasText)
                        .collect(Collectors.joining(","));

        if (StringUtils.hasText(merged)) {
            for (String part : merged.split(",")) {
                String trimmed = part.trim();
                if (!StringUtils.hasText(trimmed)) {
                    continue;
                }
                try {
                    URI uri = new URI(trimmed);
                    if (StringUtils.hasText(uri.getScheme()) && StringUtils.hasText(uri.getHost())) {
                        allowed.add(uri);
                    }
                } catch (URISyntaxException ignored) {
                }
            }
        }
        return allowed;
    }



    private boolean isMatch(URI candidate, URI allowed) {
        if (!allowed.getScheme().equalsIgnoreCase(candidate.getScheme())) {
            return false;
        }
        if (!allowed.getHost().equalsIgnoreCase(candidate.getHost())) {
            return false;
        }
        if (allowed.getPort() != -1 && allowed.getPort() != candidate.getPort()) {
            return false;
        }
        String allowedPath = allowed.getPath();
        if (StringUtils.hasText(allowedPath) && !"/".equals(allowedPath)) {
            String candidatePath = candidate.getPath() == null ? "" : candidate.getPath();
            if (!candidatePath.startsWith(allowedPath)) {
                return false;
            }
        }
        return true;
    }
}
