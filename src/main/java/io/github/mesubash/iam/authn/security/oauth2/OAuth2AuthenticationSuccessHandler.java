package io.github.mesubash.iam.authn.security.oauth2;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.TokenType;
import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.security.token.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final JwtConfig jwtConfig;
    private final TokenEncryptionUtil tokenEncryptionUtil;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;
    private final TokenService tokenService;

    public OAuth2AuthenticationSuccessHandler(
            JwtTokenProvider tokenProvider,
            JwtConfig jwtConfig,
            TokenEncryptionUtil tokenEncryptionUtil,
            HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository,
            TokenService tokenService) {
        this.tokenProvider = tokenProvider;
        this.jwtConfig = jwtConfig;
        this.tokenEncryptionUtil = tokenEncryptionUtil;
        this.authorizationRequestRepository = authorizationRequestRepository;
        this.tokenService = tokenService;
    }

    @Value("${app.cookie.domain:}")
    private String cookieDomain;

    @Value("${app.cookie.secure:false}")
    private boolean secureCookie;

    @Value("${app.jwt.refresh-token-cookie-name:__Host-Session-Id}")
    private String refreshTokenCookieName;

    @Value("${app.jwt.encrypt-cookies:true}")
    private boolean encryptCookies;

    @Value("${app.cookie.same-site:Lax}")
    private String sameSiteCookie;

    @Value("${app.frontend.url:https://himalayanguardian.com}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        // Check account status
        AccountStatus status = userPrincipal.getIdentity().getAccountStatus();
        if (status != AccountStatus.ACTIVE) {
            String reason = switch (status) {
                case LOCKED -> "Account is locked. Please contact support.";
                case SUSPENDED -> "Account is suspended. Please contact support.";
                case DEACTIVATED -> "Account is deactivated. Please reactivate your account.";
                default -> "Account is not active. Please contact support.";
            };
            cleanupOAuthState(request, response);
            sendFallbackErrorRedirect(response, "account_inactive", reason);
            return;
        }

        if (!Boolean.TRUE.equals(userPrincipal.getIdentity().getEmailVerified())) {
            cleanupOAuthState(request, response);
            sendFallbackErrorRedirect(response, "email_not_verified", "Email address is not verified.");
            return;
        }

        String redirectUrl = resolveRedirectUrl(request);
        if (!StringUtils.hasText(redirectUrl)) {
            cleanupOAuthState(request, response);
            sendFallbackErrorRedirect(response, "missing_redirect", "Missing or invalid redirectUri or redirectUrl");
            return;
        }

        String accessToken = tokenProvider.generateToken(authentication);
        String refreshToken = tokenProvider.generateRefreshToken(authentication, false);

        String userId = userPrincipal.getIdentity().getId().toString();
        tokenService.revokeAll(userId, TokenType.REFRESH);
        tokenService.store(userId, refreshToken, TokenType.REFRESH);

        String cookieValue = encryptCookies ? tokenEncryptionUtil.encrypt(refreshToken) : refreshToken;

        org.springframework.http.ResponseCookie.ResponseCookieBuilder builder =
            org.springframework.http.ResponseCookie.from(refreshTokenCookieName, cookieValue)
                .httpOnly(true)
                .secure(secureCookie)
                .maxAge(java.time.Duration.ofMillis(jwtConfig.getRefreshExpiration()))
                .path("/")
                .sameSite(sameSiteCookie);

        if (!refreshTokenCookieName.startsWith("__Host-") && StringUtils.hasText(cookieDomain)) {
            builder.domain(cookieDomain);
        }

        cleanupOAuthState(request, response);

        response.addHeader(org.springframework.http.HttpHeaders.SET_COOKIE, builder.build().toString());

        String separator = redirectUrl.contains("?") ? "&" : "?";
        String finalRedirectUrl = String.format("%s%stoken=%s", redirectUrl, separator, accessToken);

        response.sendRedirect(finalRedirectUrl);
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
