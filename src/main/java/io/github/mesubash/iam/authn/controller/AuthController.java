package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.util.ClientIpResolver;
import io.github.mesubash.iam.authn.dto.*;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.shared.dto.ApiResponse;
import io.github.mesubash.iam.shared.dto.SuccessResponse;
import io.github.mesubash.iam.shared.exception.BadRequestException;
import io.github.mesubash.iam.shared.exception.UnauthorizedException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import io.github.mesubash.iam.authn.security.UserPrincipal;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and user management endpoints")
public class AuthController {

    private final AuthService authService;
    private final TokenEncryptionUtil tokenEncryptionUtil;
    private final io.github.mesubash.iam.authn.security.RedirectAllowlist redirectAllowlist;

    /** Where SSO authorize sends a browser with no usable session; gets ?continue=&lt;authorize URL&gt;. */
    @Value("${iam.sso.login-url:${app.frontend.url:http://localhost:3000}/login}")
    private String ssoLoginUrl;

    /** Page that asks before an app gets its first SSO code. Empty: no consent step. */
    @Value("${iam.sso.consent-url:}")
    private String ssoConsentUrl;

    @Value("${app.jwt.refresh-token-cookie-name:__Host-Refresh}")
    private String refreshTokenCookieName;

    @Value("${app.jwt.refresh-token-expiration-days:7}")
    private int refreshTokenExpirationDays;

    @Value("${app.cookie.secure:true}")
    private boolean secureCookie;

    @Value("${app.cookie.http-only:true}")
    private boolean httpOnlyCookie;

    @Value("${app.cookie.domain:#{null}}")
    private String cookieDomain;

    @Value("${app.jwt.encrypt-cookies:true}")
    private boolean encryptCookies;

    @Value("${app.cookie.same-site:Lax}")
    private String sameSiteCookie;

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Create a new user account. Email verification required before login.")
    public ResponseEntity<ApiResponse<SuccessResponse>> register(
            @Valid @RequestBody RegisterRequest request) {
        authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success(
                        "Registration successful! Please check your email to verify your account.",
                        SuccessResponse.of("A verification email has been sent to " + request.getEmail() +
                                ". Please verify your email before logging in.")
                ));
    }

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT tokens.")
    public ResponseEntity<ApiResponse<?>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        return loginResponse(authService.login(request, clientIp(httpRequest),
                httpRequest.getHeader("User-Agent")), response);
    }

    @PostMapping("/mfa/verify")
    @Operation(summary = "Second login step",
            description = "Verify a TOTP or recovery code against the challenge from /login or /oauth/exchange")
    public ResponseEntity<ApiResponse<?>> verifyMfa(
            @Valid @RequestBody io.github.mesubash.iam.authn.mfa.MfaRequests.Verify body,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        JwtResponse tokens = authService.verifyMfaAndIssue(body.challenge(), body.code(),
                clientIp(httpRequest), httpRequest.getHeader("User-Agent"));
        return loginResponse(io.github.mesubash.iam.authn.dto.LoginResult.ok(tokens), response);
    }

    /**
     * OK: refresh cookie + access token. MFA_REQUIRED: {status, challenge} for /mfa/verify.
     * MFA_ENROLLMENT_REQUIRED: {status, enrollmentToken} for /mfa/setup and /mfa/enable.
     */
    private ResponseEntity<ApiResponse<?>> loginResponse(io.github.mesubash.iam.authn.dto.LoginResult result,
                                                         HttpServletResponse response) {
        return switch (result.status()) {
            case MFA_REQUIRED -> ResponseEntity.ok(ApiResponse.success("MFA required",
                    Map.of("status", "MFA_REQUIRED", "challenge", result.mfaToken())));
            case MFA_ENROLLMENT_REQUIRED -> ResponseEntity.ok(ApiResponse.success("MFA enrollment required",
                    Map.of("status", "MFA_ENROLLMENT_REQUIRED", "enrollmentToken", result.mfaToken())));
            case OK -> {
                JwtResponse tokens = result.tokens();
                setRefreshTokenCookie(response, tokens.getRefreshToken());
                yield ResponseEntity.ok(ApiResponse.success("Login successful",
                        new JwtResponse(tokens.getAccessToken(), tokens.getExpiresIn(), tokens.getIdentity())));
            }
        };
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token", description = "Generate new access token using refresh token from HTTP-only cookie")
    public ResponseEntity<ApiResponse<JwtResponse>> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = getRefreshTokenFromCookie(request);

        JwtResponse jwtResponse = authService.refreshToken(refreshToken);

        setRefreshTokenCookie(response, jwtResponse.getRefreshToken());

        JwtResponse responseBody = new JwtResponse(jwtResponse.getAccessToken(), jwtResponse.getExpiresIn(), jwtResponse.getIdentity());

        return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", responseBody));
    }

    @PostMapping("/oauth/exchange")
    @Operation(summary = "Exchange OAuth code",
            description = "Swap the single-use code from the OAuth redirect for tokens")
    public ResponseEntity<ApiResponse<?>> exchangeOAuthCode(
            @RequestBody java.util.Map<String, String> body,
            HttpServletRequest httpRequest,
            HttpServletResponse response) {
        return loginResponse(authService.exchangeOAuthCode(body.get("code"), clientIp(httpRequest),
                httpRequest.getHeader("User-Agent")), response);
    }

    @GetMapping("/sso/authorize")
    @Operation(summary = "SSO authorize",
            description = "Single sign-on for apps on the redirect allowlist. With a live session cookie, "
                    + "redirects to redirect_uri?code=…&state=…; the app swaps the code at /oauth/exchange. "
                    + "Otherwise sends the browser to the login (or consent) page, or with prompt=none back "
                    + "to redirect_uri with error=login_required / consent_required. Optional audience "
                    + "(one of app.jwt.allowed-audiences) sets the app token's aud; an unknown one is a 400.")
    public void ssoAuthorize(
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "prompt", required = false) String prompt,
            @RequestParam(value = "audience", required = false) String audience,
            HttpServletRequest request,
            HttpServletResponse response) throws java.io.IOException {
        if (!redirectAllowlist.isAllowed(redirectUri)) {
            response.sendError(HttpStatus.BAD_REQUEST.value(), "redirect_uri is not allowed");
            return;
        }
        // prompt=none: a silent check that never shows a page; the app learns the answer from ?error=.
        boolean silent = "none".equalsIgnoreCase(prompt);
        String selfUrl = request.getRequestURL() + "?" + request.getQueryString();

        String code;
        try {
            code = authService.beginSso(getRefreshTokenFromCookie(request), originOf(redirectUri),
                    org.springframework.util.StringUtils.hasText(ssoConsentUrl), audience);
        } catch (UnauthorizedException noUsableSession) {
            response.sendRedirect(silent ? withParam(redirectUri, "error", "login_required", state)
                    : withParam(ssoLoginUrl, "continue", selfUrl, null));
            return;
        }
        if (code == null) {
            response.sendRedirect(silent ? withParam(redirectUri, "error", "consent_required", state)
                    : withParam(withParam(ssoConsentUrl, "redirect_uri", redirectUri, null), "continue", selfUrl, null));
            return;
        }
        response.sendRedirect(withParam(redirectUri, "code", code, state));
    }

    @PostMapping("/sso/consent")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "SSO consent",
            description = "Called by the consent page: the signed-in person agrees that the app at "
                    + "redirect_uri may sign them in. Body: { \"redirect_uri\": string }")
    public ResponseEntity<ApiResponse<SuccessResponse>> ssoConsent(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserPrincipal principal) {
        String redirectUri = body.get("redirect_uri");
        if (!redirectAllowlist.isAllowed(redirectUri)) {
            throw new io.github.mesubash.iam.shared.exception.BadRequestException("redirect_uri is not allowed");
        }
        authService.grantSsoConsent(principal.getId(), originOf(redirectUri));
        return ResponseEntity.ok(ApiResponse.success("Consent recorded",
                SuccessResponse.of("The app can now sign you in")));
    }

    /** Consent is per app origin: the code goes to whatever path, but the origin receives it. */
    private static String originOf(String uri) {
        java.net.URI u = java.net.URI.create(uri);
        return (u.getScheme() + "://" + u.getHost() + (u.getPort() == -1 ? "" : ":" + u.getPort()))
                .toLowerCase(java.util.Locale.ROOT);
    }

    private static String withParam(String url, String name, String value, String state) {
        StringBuilder out = new StringBuilder(url).append(url.contains("?") ? "&" : "?")
                .append(name).append('=').append(java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8));
        if (state != null && !state.isEmpty()) {
            out.append("&state=").append(java.net.URLEncoder.encode(state, java.nio.charset.StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "User logout", description = "Logout user and invalidate tokens")
    public ResponseEntity<ApiResponse<SuccessResponse>> logout(
            @RequestHeader("Authorization") String authHeader,
            HttpServletResponse response) {
        String accessToken = authHeader.replace("Bearer ", "");

        authService.logout(accessToken);

        clearRefreshTokenCookie(response);

        return ResponseEntity.ok(ApiResponse.success("Logged out successfully",
                SuccessResponse.of("User logged out successfully")));
    }

    @PostMapping("/logout-all")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Logout all sessions", description = "Revoke all refresh tokens for the current user")
    public ResponseEntity<ApiResponse<SuccessResponse>> logoutAll(
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletResponse response) {
        authService.logoutAll(principal.getId().toString());
        clearRefreshTokenCookie(response);

        return ResponseEntity.ok(ApiResponse.success("All sessions revoked",
                SuccessResponse.of("All sessions have been revoked successfully")));
    }

    @PostMapping("/request-reactivation")
    @Operation(summary = "Request account reactivation", description = "Request reactivation of a deactivated account")
    public ResponseEntity<ApiResponse<SuccessResponse>> requestReactivation(@RequestParam String email) {
        authService.requestReactivation(email);
        return ResponseEntity.ok(ApiResponse.success("Reactivation email sent",
                SuccessResponse.of("If the account is deactivated, a reactivation email has been sent")));
    }

    @PostMapping("/verify-reactivation")
    @Operation(summary = "Verify account reactivation", description = "Verify reactivation token and reactivate account")
    public ResponseEntity<ApiResponse<SuccessResponse>> verifyReactivation(@RequestParam String token) {
        authService.verifyReactivation(token);
        return ResponseEntity.ok(ApiResponse.success("Account reactivated",
                SuccessResponse.of("Your account has been reactivated. You can now log in.")));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Forgot password", description = "Send password reset email")
    public ResponseEntity<ApiResponse<SuccessResponse>> forgotPassword(@RequestParam String email) {
        authService.forgotPassword(email);
        return ResponseEntity.ok(ApiResponse.success("Password reset email sent",
                SuccessResponse.of("If the email exists, you will receive password reset instructions")));
    }

    /** token + newPassword as a JSON body; query params still work for older callers. */
    public record ResetPasswordRequest(String token, String newPassword) {}

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Reset password using reset token")
    public ResponseEntity<ApiResponse<SuccessResponse>> resetPassword(
            @RequestParam(required = false) String token,
            @RequestParam(required = false) String newPassword,
            @RequestBody(required = false) ResetPasswordRequest body) {
        // A password in a query string lands in every access log on the way, so prefer the body.
        String resetToken = token != null ? token : body != null ? body.token() : null;
        String password = newPassword != null ? newPassword : body != null ? body.newPassword() : null;
        if (resetToken == null || resetToken.isBlank() || password == null || password.isBlank()) {
            throw new BadRequestException("token and newPassword are required");
        }
        authService.resetPassword(resetToken, password);
        return ResponseEntity.ok(ApiResponse.success("Password reset successful",
                SuccessResponse.of("Your password has been reset successfully")));
    }

    @PostMapping("/change-email")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Change login email", description = "Requires current password; verification is sent to the new address")
    public ResponseEntity<ApiResponse<SuccessResponse>> changeEmail(
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserPrincipal principal) {
        authService.changeEmail(principal.getEmail(), body.get("newEmail"), body.get("currentPassword"));
        return ResponseEntity.ok(ApiResponse.success("Verification sent",
                SuccessResponse.of("Check the new address to confirm the change")));
    }

    @PostMapping("/verify-email-change")
    @Operation(summary = "Confirm email change", description = "Consume the token sent to the new address")
    public ResponseEntity<ApiResponse<SuccessResponse>> verifyEmailChange(@RequestParam String token) {
        authService.verifyEmailChange(token);
        return ResponseEntity.ok(ApiResponse.success("Email updated",
                SuccessResponse.of("Your login email has been updated")));
    }

    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Change password", description = "Change user password")
    public ResponseEntity<ApiResponse<SuccessResponse>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @AuthenticationPrincipal UserPrincipal principal) {
        authService.changePassword(principal.getEmail(), request);
        return ResponseEntity.ok(ApiResponse.success("Password changed successfully",
                SuccessResponse.of("Your password has been changed successfully")));
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verify email", description = "Verify user email using verification token")
    public ResponseEntity<ApiResponse<SuccessResponse>> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(ApiResponse.success("Email verified successfully",
                SuccessResponse.of("Your email has been verified successfully")));
    }

    @PostMapping("/verify-email-and-setup-password")
    @Operation(summary = "Verify email & set password",
            description = "Verify invited user email and immediately set a password using the same token")
    public ResponseEntity<ApiResponse<SuccessResponse>> verifyEmailAndSetupPassword(
            @Valid @RequestBody VerifyEmailAndPasswordRequest request) {
        authService.verifyEmailAndSetupPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(ApiResponse.success("Account activated successfully",
                SuccessResponse.of("Email verified and password set. You can now log in.")));
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend verification email", description = "Resend email verification")
    public ResponseEntity<ApiResponse<SuccessResponse>> resendVerification(@RequestParam String email) {
        authService.resendVerification(email);
        return ResponseEntity.ok(ApiResponse.success("Verification email sent",
                SuccessResponse.of("If the account exists and is unverified, a verification email has been sent")));
    }

    private String clientIp(HttpServletRequest request) {
        return ClientIpResolver.resolve(request);
    }

    // --- Cookie helpers ---

    // Browsers reject __Host-/__Secure- cookies without Secure. In non-secure
    // (dev) mode, drop the prefix so the cookie is still accepted.
    private String effectiveCookieName() {
        if (!secureCookie && (refreshTokenCookieName.startsWith("__Host-")
                || refreshTokenCookieName.startsWith("__Secure-"))) {
            return "Refresh-Session";
        }
        return refreshTokenCookieName;
    }

    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        String cookieValue = encryptCookies ? tokenEncryptionUtil.encrypt(refreshToken) : refreshToken;
        String name = effectiveCookieName();

        org.springframework.http.ResponseCookie.ResponseCookieBuilder builder =
            org.springframework.http.ResponseCookie.from(name, cookieValue)
                .httpOnly(httpOnlyCookie)
                .secure(secureCookie)
                .maxAge(java.time.Duration.ofDays(refreshTokenExpirationDays))
                .path("/")
                .sameSite(sameSiteCookie);

        if (!name.startsWith("__Host-")
                && cookieDomain != null && !cookieDomain.isEmpty()) {
            builder.domain(cookieDomain);
        }

        response.addHeader(org.springframework.http.HttpHeaders.SET_COOKIE, builder.build().toString());
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        String name = effectiveCookieName();
        if (request.getCookies() != null) {
            List<String> candidateCookies = Arrays.stream(request.getCookies())
                    .filter(cookie -> name.equals(cookie.getName()))
                    .map(Cookie::getValue)
                    .collect(Collectors.toList());

            if (candidateCookies.isEmpty()) {
                throw new UnauthorizedException("Refresh token not found in cookie");
            }

            // Refresh tokens are opaque — validity is decided by SessionService
            for (String cv : candidateCookies) {
                try {
                    return encryptCookies ? tokenEncryptionUtil.decrypt(cv) : cv;
                } catch (Exception e) {
                    log.debug("Failed to decrypt cookie value: {}", e.getMessage());
                }
            }

            throw new UnauthorizedException("No valid refresh token found in cookies");
        }
        throw new UnauthorizedException("No cookies found in request");
    }

    private void clearRefreshTokenCookie(HttpServletResponse response) {
        String name = effectiveCookieName();
        org.springframework.http.ResponseCookie.ResponseCookieBuilder builder =
            org.springframework.http.ResponseCookie.from(name, "")
                .httpOnly(true)
                .secure(secureCookie)
                .maxAge(0)
                .path("/")
                .sameSite(sameSiteCookie);

        if (!name.startsWith("__Host-")
                && cookieDomain != null && !cookieDomain.isEmpty()) {
            builder.domain(cookieDomain);
        }

        response.addHeader(org.springframework.http.HttpHeaders.SET_COOKIE, builder.build().toString());
    }

}
