package io.github.mesubash.iam.authn.service.impl;

import io.github.mesubash.iam.authn.config.JwtConfig;
import io.github.mesubash.iam.authn.dto.JwtResponse;
import io.github.mesubash.iam.authn.dto.LoginRequest;
import io.github.mesubash.iam.authn.dto.PasswordChangeRequest;
import io.github.mesubash.iam.authn.dto.RegisterRequest;
import io.github.mesubash.iam.authn.entity.Credential;
import io.github.mesubash.iam.authn.entity.Identity;
import io.github.mesubash.iam.authn.entity.enums.AccountStatus;
import io.github.mesubash.iam.authn.entity.enums.CredentialType;
import io.github.mesubash.iam.authn.entity.enums.SecurityEventType;
import io.github.mesubash.iam.authn.entity.enums.TokenType;
import io.github.mesubash.iam.authn.repository.CredentialRepository;
import io.github.mesubash.iam.authn.repository.IdentityRepository;
import io.github.mesubash.iam.authn.security.JwtTokenProvider;
import io.github.mesubash.iam.authn.security.TokenEncryptionUtil;
import io.github.mesubash.iam.authn.security.UserPrincipal;
import io.github.mesubash.iam.authn.security.oauth2.OAuth2AuthenticationSuccessHandler;
import io.github.mesubash.iam.authn.security.token.SessionService;
import io.github.mesubash.iam.authn.security.token.TokenBlacklistService;
import io.github.mesubash.iam.authn.security.token.TokenService;
import io.github.mesubash.iam.authn.service.AuthService;
import io.github.mesubash.iam.authn.service.LoginAttemptService;
import io.github.mesubash.iam.authn.service.NotificationPort;
import io.github.mesubash.iam.authn.service.SecurityEventService;
import io.jsonwebtoken.Claims;
import io.github.mesubash.iam.shared.dto.RoleClaimsDto;
import io.github.mesubash.iam.shared.exception.*;
import io.github.mesubash.iam.shared.service.AuthzQueryService;
import io.github.mesubash.iam.shared.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final IdentityRepository identityRepository;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final TokenBlacklistService tokenBlacklistService;
    private final TokenEncryptionUtil tokenEncryptionUtil;
    private final org.springframework.data.redis.core.StringRedisTemplate stringRedisTemplate;
    private final JwtConfig jwtConfig;
    private final AuthzQueryService authzQueryService;
    private final SecurityEventService securityEventService;
    private final NotificationPort notificationPort;
    private final LoginAttemptService loginAttemptService;

    @Override
    @Transactional
    public void register(RegisterRequest request) {
        log.info("Registering new user with email: {}", request.getEmail());

        if (identityRepository.existsByPrimaryEmail(request.getEmail())) {
            throw new ConflictException("Email address already in use");
        }

        // Create identity
        Identity identity = Identity.builder()
                .primaryEmail(request.getEmail())
                .emailVerified(false)
                .accountStatus(AccountStatus.ACTIVE)
                .build();
        identity = identityRepository.save(identity);

        // Create password credential
        Credential credential = Credential.builder()
                .identity(identity)
                .credentialType(CredentialType.PASSWORD)
                .identifier(request.getEmail())
                .secretHash(passwordEncoder.encode(request.getPassword()))
                .build();
        credentialRepository.save(credential);

        // Generate verification token
        String verificationToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), verificationToken, TokenType.EMAIL_VERIFICATION);
        notificationPort.sendEmailVerification(request.getEmail(), verificationToken);

        log.info("User registered successfully: {}", request.getEmail());
    }

    @Override
    @Transactional
    public JwtResponse login(LoginRequest request, String ipAddress, String userAgent) {
        log.info("User attempting to login: {}", request.getEmail());

        // Check if account is locked before attempting auth (own tx)
        identityRepository.findByPrimaryEmail(request.getEmail())
                .ifPresent(loginAttemptService::unlockIfExpired);

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (BadCredentialsException ex) {
            // Runs in a separate committed tx so the counter survives the throw below
            loginAttemptService.recordFailure(request.getEmail());
            throw new UnauthorizedException("Invalid email or password");
        }

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        Identity identity = userPrincipal.getIdentity();

        if (!Boolean.TRUE.equals(identity.getEmailVerified())) {
            throw new UnauthorizedException("Email address is not verified. Please verify before logging in.");
        }

        ensureAccountActive(identity);

        // Update last login and reset failed attempts
        identity.setLastLoginAt(OffsetDateTime.now());
        identity.setFailedLoginAttempts(0);
        identity.setAccountLockedUntil(null);
        identityRepository.save(identity);

        // One session per device — other sessions stay alive
        SessionService.IssuedRefresh issued = sessionService.createSession(
                identity.getId(), ipAddress, userAgent);
        String accessToken = jwtTokenProvider.generateAccessToken(
                userPrincipal, issued.session().getId());
        long expiresIn = jwtConfig.getExpiration() / 1000;

        securityEventService.logEvent(identity, SecurityEventType.LOGIN_SUCCESS, null, null);
        log.info("User logged in successfully: {}", request.getEmail());

        return new JwtResponse(accessToken, issued.rawToken(), expiresIn, toIdentityInfo(identity));
    }

    @Override
    public JwtResponse refreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new InvalidTokenException("Refresh token is required");
        }

        SessionService.RotationResult rotation = sessionService.rotate(refreshToken);

        Identity identity = identityRepository.findById(rotation.session().getIdentityId())
                .orElseThrow(() -> new UnauthorizedException("Invalid or expired refresh token"));

        ensureAccountActive(identity);

        // Roles come fresh from AuthZ on every refresh — revocations propagate here
        List<String> roles = getRolesForIdentity(identity.getId());
        UserPrincipal userPrincipal = UserPrincipal.create(identity, null, roles);

        String newAccessToken = jwtTokenProvider.generateAccessToken(
                userPrincipal, rotation.session().getId());
        long expiresIn = jwtConfig.getExpiration() / 1000;

        return new JwtResponse(newAccessToken, rotation.rawToken(), expiresIn, toIdentityInfo(identity));
    }

    @Override
    public JwtResponse exchangeOAuthCode(String code) {
        if (code == null || code.isBlank()) {
            throw new InvalidTokenException("Exchange code is required");
        }

        // Single-use: GETDEL — a second exchange with the same code fails
        String encrypted = stringRedisTemplate.opsForValue()
                .getAndDelete(OAuth2AuthenticationSuccessHandler.EXCHANGE_PREFIX + code);
        if (encrypted == null) {
            throw new InvalidTokenException("Invalid or expired exchange code");
        }

        String[] bundle = tokenEncryptionUtil.decrypt(encrypted).split("\\|", 3);
        UUID identityId = UUID.fromString(bundle[0]);
        UUID sessionId = UUID.fromString(bundle[1]);
        String rawRefresh = bundle[2];

        Identity identity = identityRepository.findById(identityId)
                .orElseThrow(() -> new InvalidTokenException("Identity not found"));
        ensureAccountActive(identity);

        List<String> roles = getRolesForIdentity(identity.getId());
        UserPrincipal userPrincipal = UserPrincipal.create(identity, null, roles);

        String accessToken = jwtTokenProvider.generateAccessToken(userPrincipal, sessionId);
        long expiresIn = jwtConfig.getExpiration() / 1000;

        return new JwtResponse(accessToken, rawRefresh, expiresIn, toIdentityInfo(identity));
    }

    @Override
    @Transactional
    public void logout(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return;
        }
        try {
            Claims claims = jwtTokenProvider.parseToken(accessToken);
            long remaining = claims.getExpiration().getTime() - System.currentTimeMillis();
            tokenBlacklistService.blacklistJti(claims.getId(), remaining);

            UUID sid = jwtTokenProvider.getSid(claims);
            if (sid != null) {
                sessionService.revokeSession(sid, "LOGOUT");
            }
        } catch (Exception ex) {
            log.warn("Failed to process access token during logout: {}", ex.getMessage());
        }
    }

    @Override
    public void forgotPassword(String email) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        String resetToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), resetToken, TokenType.PASSWORD_RESET);
        notificationPort.sendPasswordReset(email, resetToken);
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        String userId = tokenService.getTokenUserId(token, TokenType.PASSWORD_RESET);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseThrow(() -> new ResourceNotFoundException("Password credential not found"));

        credential.setSecretHash(passwordEncoder.encode(newPassword));
        credentialRepository.save(credential);

        securityEventService.logEvent(identity, SecurityEventType.PASSWORD_RESET, null, null);
        tokenService.revoke(userId, token, TokenType.PASSWORD_RESET);
    }

    @Override
    @Transactional
    public void changePassword(String email, PasswordChangeRequest request) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseThrow(() -> new ResourceNotFoundException("Password credential not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), credential.getSecretHash())) {
            throw new BadRequestException("Current password is incorrect");
        }

        credential.setSecretHash(passwordEncoder.encode(request.getNewPassword()));
        credentialRepository.save(credential);

        securityEventService.logEvent(identity, SecurityEventType.PASSWORD_CHANGED, null, null);
    }

    private static final String EMAIL_CHANGE_PREFIX = "authn:ott:email_change:";

    @Override
    @Transactional
    public void changeEmail(String currentEmail, String newEmail, String currentPassword) {
        Identity identity = identityRepository.findByPrimaryEmail(currentEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseThrow(() -> new BadRequestException("Password change is required to change email"));
        if (!passwordEncoder.matches(currentPassword, credential.getSecretHash())) {
            throw new BadRequestException("Current password is incorrect");
        }
        if (identityRepository.existsByPrimaryEmail(newEmail)) {
            throw new ConflictException("Email address already in use");
        }

        // token -> "identityId|newEmail", verified against the NEW address
        String token = PasswordUtil.generateSecureToken(32);
        stringRedisTemplate.opsForValue().set(EMAIL_CHANGE_PREFIX + sha256(token),
                identity.getId() + "|" + newEmail, java.time.Duration.ofHours(24));

        notificationPort.sendEmailVerification(newEmail, token);
        log.info("Email change requested for identity {} -> new address notified; old address alerted", identity.getId());
    }

    @Override
    @Transactional
    public void verifyEmailChange(String token) {
        String key = EMAIL_CHANGE_PREFIX + sha256(token);
        String value = stringRedisTemplate.opsForValue().getAndDelete(key);
        if (value == null) {
            throw new InvalidTokenException("Invalid or expired email change token");
        }
        String[] parts = value.split("\\|", 2);
        Identity identity = identityRepository.findById(UUID.fromString(parts[0]))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        String newEmail = parts[1];
        if (identityRepository.existsByPrimaryEmail(newEmail)) {
            throw new ConflictException("Email address already in use");
        }

        identity.setPrimaryEmail(newEmail);
        identityRepository.save(identity);
        credentialRepository.findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .ifPresent(cred -> {
                    cred.setIdentifier(newEmail);
                    credentialRepository.save(cred);
                });

        securityEventService.logEvent(identity, SecurityEventType.EMAIL_CHANGED, null, null);
    }

    private static String sha256(String value) {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {
        String userId = tokenService.getTokenUserId(token, TokenType.EMAIL_VERIFICATION);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        identity.setEmailVerified(true);
        identityRepository.save(identity);

        tokenService.revoke(userId, token, TokenType.EMAIL_VERIFICATION);
    }

    @Override
    @Transactional
    public void verifyEmailAndSetupPassword(String token, String newPassword) {
        String userId = tokenService.getTokenUserId(token, TokenType.EMAIL_VERIFICATION);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        identity.setEmailVerified(true);
        identityRepository.save(identity);

        // Create or update password credential
        Credential credential = credentialRepository
                .findByIdentityIdAndCredentialType(identity.getId(), CredentialType.PASSWORD)
                .orElseGet(() -> Credential.builder()
                        .identity(identity)
                        .credentialType(CredentialType.PASSWORD)
                        .identifier(identity.getPrimaryEmail())
                        .build());

        credential.setSecretHash(passwordEncoder.encode(newPassword));
        credentialRepository.save(credential);

        tokenService.revoke(userId, token, TokenType.EMAIL_VERIFICATION);
    }

    @Override
    public void resendVerification(String email) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (Boolean.TRUE.equals(identity.getEmailVerified())) {
            throw new BadRequestException("Email already verified");
        }

        String verificationToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), verificationToken, TokenType.EMAIL_VERIFICATION);
        notificationPort.sendEmailVerification(email, verificationToken);
    }

    @Override
    @Transactional
    public void logoutAll(String userId) {
        sessionService.revokeAll(UUID.fromString(userId), "LOGOUT_ALL");

        identityRepository.findById(UUID.fromString(userId))
                .ifPresent(identity -> securityEventService.logEvent(
                        identity, SecurityEventType.TOKEN_REVOKED, null, null,
                        Map.of("action", "logout_all")));

        log.info("Revoked all sessions for user: {}", userId);
    }

    @Override
    public void requestReactivation(String email) {
        Identity identity = identityRepository.findByPrimaryEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (identity.getAccountStatus() != AccountStatus.DEACTIVATED) {
            throw new BadRequestException("Account is not deactivated");
        }

        String reactivationToken = PasswordUtil.generateSecureToken(32);
        tokenService.store(identity.getId().toString(), reactivationToken, TokenType.ACCOUNT_REACTIVATION);
        notificationPort.sendReactivation(email, reactivationToken);
    }

    @Override
    @Transactional
    public void verifyReactivation(String token) {
        String userId = tokenService.getTokenUserId(token, TokenType.ACCOUNT_REACTIVATION);
        if (userId == null) {
            throw new InvalidTokenException("Invalid or expired reactivation token");
        }

        Identity identity = identityRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (identity.getAccountStatus() != AccountStatus.DEACTIVATED) {
            throw new BadRequestException("Account is not deactivated");
        }

        identity.setAccountStatus(AccountStatus.ACTIVE);
        identity.setFailedLoginAttempts(0);
        identity.setAccountLockedUntil(null);
        identityRepository.save(identity);

        tokenService.revoke(userId, token, TokenType.ACCOUNT_REACTIVATION);
        log.info("Account reactivated for user: {}", userId);
    }

    private void ensureAccountActive(Identity identity) {
        AccountStatus status = identity.getAccountStatus();
        if (status != AccountStatus.ACTIVE) {
            String message = switch (status) {
                case LOCKED -> "Account is locked. Please try again later or contact support.";
                case SUSPENDED -> "Account is suspended. Please contact support.";
                case DEACTIVATED -> "Account is deactivated. Please reactivate your account.";
                default -> "Account is not active. Please contact support.";
            };
            throw new UnauthorizedException(message);
        }
    }

    private List<String> getRolesForIdentity(UUID identityId) {
        try {
            RoleClaimsDto roleClaims = authzQueryService.getRolesForIdentity(identityId);
            return roleClaims != null && roleClaims.getRoles() != null ? roleClaims.getRoles() : List.of();
        } catch (Exception e) {
            return List.of();
        }
    }

    private JwtResponse.IdentityInfo toIdentityInfo(Identity identity) {
        JwtResponse.IdentityInfo info = JwtResponse.IdentityInfo.builder()
                .id(identity.getId())
                .email(identity.getPrimaryEmail())
                .emailVerified(identity.getEmailVerified())
                .build();

        return info;
    }
}
