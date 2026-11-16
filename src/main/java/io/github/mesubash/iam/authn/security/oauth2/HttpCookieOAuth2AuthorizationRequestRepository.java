package io.github.mesubash.iam.authn.security.oauth2;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.security.RedirectAllowlist;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;


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
    public static final String AUDIENCE_COOKIE_NAME = "oauth_audience";
    public static final String AUDIENCE_PARAM_NAME = "audience";
    private static final int COOKIE_EXPIRE_SECONDS = 180;

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    // Same cookie settings as the refresh cookie. These used to read app.auth.* keys that
    // never existed, so the OAuth state cookies were never Secure.
    @Value("${app.cookie.secure:true}")
    private boolean secureCookie;

    private final RedirectAllowlist redirectAllowlist;
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

        // Validated at the code exchange, against app.jwt.allowed-audiences; here only bounded.
        String audience = request.getParameter(AUDIENCE_PARAM_NAME);
        if (StringUtils.hasText(audience) && audience.length() <= 200) {
            CookieUtils.addCookie(response, AUDIENCE_COOKIE_NAME,
                    CookieUtils.serializeAndSign(audience, jwtConfig.getSecret()),
                    COOKIE_EXPIRE_SECONDS, secureCookie, normalizedDomain);
        }

        String redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_NAME);
        if (!StringUtils.hasText(redirectUriAfterLogin)) {
            redirectUriAfterLogin = request.getParameter(REDIRECT_URL_PARAM_NAME);
        }
        if (!StringUtils.hasText(redirectUriAfterLogin)) {
            redirectUriAfterLogin = (String) request.getSession().getAttribute("oauth_redirect_url");
        }

        if (StringUtils.hasText(redirectUriAfterLogin)) {
            if (!isAllowedRedirectUri(redirectUriAfterLogin)) {
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
        CookieUtils.deleteCookie(request, response, AUDIENCE_COOKIE_NAME, secureCookie, normalizedDomain);
    }

    /** The audience the flow was started for (?audience=), or null. Not yet validated. */
    public String getAudienceFromCookie(HttpServletRequest request) {
        return CookieUtils.getCookie(request, AUDIENCE_COOKIE_NAME)
                .map(cookie -> CookieUtils.<String>deserializeSigned(cookie.getValue(), jwtConfig.getSecret()))
                .orElse(null);
    }

    public String getRedirectUriFromCookie(HttpServletRequest request) {
        return CookieUtils.getCookie(request, REDIRECT_URI_COOKIE_NAME)
                .map(cookie -> CookieUtils.verifySignedRaw(cookie.getValue(), jwtConfig.getSecret()))
                .filter(uri -> isAllowedRedirectUri(uri))
                .orElse(null);
    }

    public boolean isAllowedRedirectUri(String uri) {
        return redirectAllowlist.isAllowed(uri);
    }
}
