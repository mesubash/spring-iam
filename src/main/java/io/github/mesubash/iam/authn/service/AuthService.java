package io.github.mesubash.iam.authn.service;

import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.PasswordChangeRequest;
import io.github.mesubash.iam.authn.dto.RegisterRequest;

public interface AuthService {

    void register(RegisterRequest request);

    JwtResponse login(LoginRequest request);

    JwtResponse refreshToken(String refreshToken);

    JwtResponse validateAndRefreshToken(String accessToken);

    void logout(String accessToken, String refreshToken);

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
