package com.hgn.iam.authn.service;

import com.hgn.iam.authn.dto.JwtResponse;
import com.hgn.iam.authn.dto.LoginRequest;
import com.hgn.iam.authn.dto.PasswordChangeRequest;
import com.hgn.iam.authn.dto.RegisterRequest;

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
