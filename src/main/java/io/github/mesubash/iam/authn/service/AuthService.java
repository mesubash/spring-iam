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

    LoginResult exchangeOAuthCode(String code, String ipAddress, String userAgent);

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
