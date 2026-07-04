package io.github.mesubash.iam.authn.controller;

import io.github.mesubash.iam.authn.dto.*;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.shared.dto.ApiResponse;
import io.github.mesubash.iam.shared.dto.SuccessResponse;
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
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and user management endpoints")
public class AuthController {

    private final AuthService authService;
    private final TokenEncryptionUtil tokenEncryptionUtil;

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
            HttpServletResponse response) {
        JwtResponse jwtResponse = authService.login(request);

        setRefreshTokenCookie(response, jwtResponse.getRefreshToken());
        JwtResponse responseBody = new JwtResponse(jwtResponse.getAccessToken(), jwtResponse.getExpiresIn(), jwtResponse.getIdentity());

        return ResponseEntity.ok(ApiResponse.success("Login successful", responseBody));
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
    public ResponseEntity<ApiResponse<JwtResponse>> exchangeOAuthCode(
            @RequestBody java.util.Map<String, String> body,
            HttpServletResponse response) {
        JwtResponse jwtResponse = authService.exchangeOAuthCode(body.get("code"));

        setRefreshTokenCookie(response, jwtResponse.getRefreshToken());
        JwtResponse responseBody = new JwtResponse(
                jwtResponse.getAccessToken(), jwtResponse.getExpiresIn(), jwtResponse.getIdentity());

        return ResponseEntity.ok(ApiResponse.success("Login successful", responseBody));
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

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Reset password using reset token")
    public ResponseEntity<ApiResponse<SuccessResponse>> resetPassword(
            @RequestParam String token,
            @RequestParam String newPassword) {
        authService.resetPassword(token, newPassword);
        return ResponseEntity.ok(ApiResponse.success("Password reset successful",
                SuccessResponse.of("Your password has been reset successfully")));
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
                SuccessResponse.of("Verification email has been sent to your email address")));
    }

    // --- Cookie helpers ---

    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        String cookieValue = encryptCookies ? tokenEncryptionUtil.encrypt(refreshToken) : refreshToken;

        org.springframework.http.ResponseCookie.ResponseCookieBuilder builder =
            org.springframework.http.ResponseCookie.from(refreshTokenCookieName, cookieValue)
                .httpOnly(httpOnlyCookie)
                .secure(secureCookie)
                .maxAge(java.time.Duration.ofDays(refreshTokenExpirationDays))
                .path("/")
                .sameSite(sameSiteCookie);

        if (!refreshTokenCookieName.startsWith("__Host-")
                && cookieDomain != null && !cookieDomain.isEmpty()) {
            builder.domain(cookieDomain);
        }

        response.addHeader(org.springframework.http.HttpHeaders.SET_COOKIE, builder.build().toString());
    }

    private String getRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            List<String> candidateCookies = Arrays.stream(request.getCookies())
                    .filter(cookie -> refreshTokenCookieName.equals(cookie.getName()))
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
        org.springframework.http.ResponseCookie.ResponseCookieBuilder builder =
            org.springframework.http.ResponseCookie.from(refreshTokenCookieName, "")
                .httpOnly(true)
                .secure(secureCookie)
                .maxAge(0)
                .path("/")
                .sameSite(sameSiteCookie);

        if (!refreshTokenCookieName.startsWith("__Host-")
                && cookieDomain != null && !cookieDomain.isEmpty()) {
            builder.domain(cookieDomain);
        }

        response.addHeader(org.springframework.http.HttpHeaders.SET_COOKIE, builder.build().toString());
    }

}
