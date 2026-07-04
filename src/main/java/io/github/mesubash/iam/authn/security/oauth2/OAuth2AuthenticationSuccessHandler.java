package io.github.mesubash.iam.authn.security.oauth2;

import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.security.token.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

/**
 * Completes OAuth login without ever putting a token in a URL: creates a
 * session, stashes it under a 60-second single-use exchange code, and
 * redirects with only that code. The frontend swaps the code for tokens at
 * POST /api/auth/oauth/exchange.
 */
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
@ConditionalOnProperty(prefix = "iam.features", name = "oauth2", havingValue = "true")
@Component
@Slf4j
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String EXCHANGE_PREFIX = "authn:oauth:xchg:";
    private static final Duration EXCHANGE_TTL = Duration.ofSeconds(60);

    private final SessionService sessionService;
    private final TokenEncryptionUtil tokenEncryptionUtil;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;
    private final StringRedisTemplate redisTemplate;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendBaseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        AccountStatus status = userPrincipal.getIdentity().getAccountStatus();
        if (status != AccountStatus.ACTIVE) {
            cleanupOAuthState(request, response);
            sendErrorRedirect(response, "account_inactive", "Account is not active.");
            return;
        }

        if (!Boolean.TRUE.equals(userPrincipal.getIdentity().getEmailVerified())) {
            cleanupOAuthState(request, response);
            sendErrorRedirect(response, "email_not_verified", "Email address is not verified.");
            return;
        }

        String redirectUrl = resolveRedirectUrl(request);
        if (!StringUtils.hasText(redirectUrl)) {
            cleanupOAuthState(request, response);
            sendErrorRedirect(response, "missing_redirect", "Missing or invalid redirect URI");
            return;
        }

        SessionService.IssuedRefresh issued = sessionService.createSession(
                userPrincipal.getId(), request.getRemoteAddr(), request.getHeader("User-Agent"));

        // Single-use exchange code -> encrypted (identity, session, refresh) bundle
        byte[] codeBytes = new byte[16];
        secureRandom.nextBytes(codeBytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(codeBytes);

        String bundle = userPrincipal.getId() + "|" + issued.session().getId()
                + "|" + issued.rawToken();
        redisTemplate.opsForValue().set(EXCHANGE_PREFIX + code,
                tokenEncryptionUtil.encrypt(bundle), EXCHANGE_TTL);

        cleanupOAuthState(request, response);

        String separator = redirectUrl.contains("?") ? "&" : "?";
        response.sendRedirect(redirectUrl + separator + "code="
                + URLEncoder.encode(code, StandardCharsets.UTF_8));
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

    private void sendErrorRedirect(HttpServletResponse response, String errorCode,
                                   String errorMessage) throws IOException {
        if (StringUtils.hasText(frontendBaseUrl)) {
            String separator = frontendBaseUrl.contains("?") ? "&" : "?";
            response.sendRedirect(frontendBaseUrl + separator
                    + "oauthError=" + URLEncoder.encode(errorCode, StandardCharsets.UTF_8)
                    + "&error_description=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8));
            return;
        }
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, errorMessage);
    }
}
