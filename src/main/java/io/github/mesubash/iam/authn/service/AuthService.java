package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginResult;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.PasswordChangeRequest;
import io.github.mesubash.iam.authn.dto.RegisterRequest;

public interface AuthService {

    void register(RegisterRequest request);

    LoginResult login(LoginRequest request, String ipAddress, String userAgent);

    /** Second login step: a TOTP or recovery code against the challenge from login/exchange. */
    JwtResponse verifyMfaAndIssue(String challenge, String code, String ipAddress, String userAgent);

    JwtResponse refreshToken(String refreshToken);

    /** Swaps a one-time code from the OAuth redirect or from SSO authorize. */
    LoginResult exchangeOAuthCode(String code, String ipAddress, String userAgent);

    /**
     * SSO: a single-use code for the app at {@code redirectOrigin}, minted from the caller's
     * existing session (which is read, not rotated). Returns null when {@code askConsent} is set
     * and the person has not yet agreed for that origin. Throws {@code UnauthorizedException}
     * when there is no live session or it does not meet the current MFA requirement.
     */
    String beginSso(String refreshToken, String redirectOrigin, boolean askConsent);

    /** Remember that the person agreed to SSO into the app at {@code redirectOrigin}. */
    void grantSsoConsent(java.util.UUID identityId, String redirectOrigin);

    void logout(String accessToken);

    void changeEmail(String currentEmail, String newEmail, String currentPassword);

    void verifyEmailChange(String token);

    void forgotPassword(String email);

    void resetPassword(String token, String newPassword);

    void changePassword(String email, PasswordChangeRequest request);

    void verifyEmail(String token);

    void verifyEmailAndSetupPassword(String token, String newPassword);

    void resendVerification(String email);

    void logoutAll(String userId);

    void requestReactivation(String email);

    void verifyReactivation(String token);
}
